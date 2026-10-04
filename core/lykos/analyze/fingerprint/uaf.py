"""Use-after-free / double-free detector (CWE-416 / CWE-415), source-level.

The dynamic channel (heap_trace) finds a UAF only when the fuzzer actually drives the program down
the freeing path; a guarded or hard-to-reach cleanup path stays invisible to it. This flags the
STATIC shape -- a pointer is `free()`d, then used (dereferenced, indexed, passed to a call) or
`free()`d again, with no reassignment in between -- so the bug is reported even on a path the fuzzer
never reaches. Scoped to one function body (brace depth): a `free` at the end of one function and a
same-named variable in the next is not conflated.

A source heuristic, so findings are `candidate`: reassignment (`p = ...`, including the safe
`p = NULL;` idiom) clears the pointer and suppresses the flag, which keeps patched code quiet,
but it cannot prove the freeing branch and the use branch are the same dynamic path.

Pure parsing, stdlib based; a file it cannot read is skipped, never fatal.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import ArtifactDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage

_log = logging.getLogger(__name__)

UAF_STAGE = "uaf_scan"
TOOL = "uaf"
TOOL_VERSION = "uaf-1"

_MAX_FILES = 6000
_MAX_FILE = 4 << 20
_SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
_SKIP_SEGMENTS = {"examples", "example", "demo", "demos", "test", "tests", "third_party",
                  "3rdparty", "vendor", "node_modules"}

_IDENT = r"[A-Za-z_]\w*"
# the deallocators, across libc / kernel / FreeRTOS / glib / C++ (`delete p;`). The captured group
# is the pointer expression being freed.
_FREE = re.compile(rf"\b(?:free|cfree|kfree|kvfree|vfree|vPortFree|pvPortFree|g_free|"
                   rf"OPENSSL_free|CRYPTO_free)\s*\(\s*({_IDENT})\s*\)")
_DELETE = re.compile(rf"\bdelete\s*(?:\[\s*\])?\s+({_IDENT})\s*;")
# a reassignment of the pointer (clears the freed state): `p =` but not `==`, `<=`, `>=`, `!=`.
_WINDOW = 40            # lines after the free to look for a use, within the same function


def _assigns(line: str, var: str) -> bool:
    return re.search(rf"(?<![=!<>])\b{re.escape(var)}\s*=(?!=)", line) is not None


def _uses(line: str, var: str) -> "str | None":
    """How `var` is used on this line as a freed pointer (deref / index / member / call arg), or
    None. A bare `&var` (taking its address) or a reassignment LHS is not a use-after-free."""
    v = re.escape(var)
    for rx, kind in ((rf"\*\s*{v}\b", "deref *p"), (rf"\b{v}\s*->", "member p->"),
                     (rf"\b{v}\s*\[", "index p[]")):
        if re.search(rx, line):
            return kind
    # passed to a call: `foo(.. p ..)` where p is not immediately preceded by & (address-of)
    for m in re.finditer(rf"(?<![&\w]){v}\b", line):
        lhs = line[:m.start()]
        if "(" in lhs and not re.search(rf"\b{v}\s*=(?!=)", line):
            return "call arg"
    return None


def _scan_text(name: str, lines: list) -> list:
    findings: list = []
    freed: dict = {}          # var -> (line_index, dealloc_name)
    depth = 0
    for i, ln in enumerate(lines):
        # 1) record a use / double-free of anything freed and still live
        for var in list(freed):
            if _assigns(ln, var):
                freed.pop(var, None)                       # reassigned -> no longer a dangling ptr
                continue
            fi, dealloc = freed[var]
            if i == fi:
                continue
            ref = _FREE.search(ln) or _DELETE.search(ln)
            if ref and ref.group(1) == var:
                findings.append(_mk(name, fi, i, var, dealloc, "CWE-415", "Double-free",
                                    f"freed by {dealloc}() at line {fi + 1}, freed again"))
                freed.pop(var, None)
                continue
            how = _uses(ln, var)
            if how:
                findings.append(_mk(name, fi, i, var, dealloc, "CWE-416", "Use-after-free",
                                    f"freed by {dealloc}() at line {fi + 1}, then used ({how})"))
                freed.pop(var, None)
        # 2) record new frees on this line
        fm = _FREE.search(ln)
        if fm:
            freed[fm.group(1)] = (i, fm.group(0).split("(")[0].strip())
        dm = _DELETE.search(ln)
        if dm:
            freed[dm.group(1)] = (i, "delete")
        # 3) track function scope: on leaving the function body (brace depth back to 0), dangling
        # state does not carry into the next function -- a free in `void a(p){free(p);}` must not
        # flag a same-named `p` in the next function.
        depth += ln.count("{") - ln.count("}")
        if depth <= 0:
            depth = 0
            freed = {}
    return findings


def _mk(name, free_line, use_line, var, dealloc, cwe, label, detail_tail) -> dict:
    detail = f"{name}:{use_line + 1}: pointer '{var}' {detail_tail}"
    return {
        "cwe": cwe, "severity": "high",
        "title": f"{label} of '{var}' ({cwe})",
        "dedup_key": f"uaf:{name}:{free_line + 1}:{use_line + 1}:{var}",
        "evidence": [{"channel": "source", "detail": detail}]}


def scan_source(root: Path) -> list:
    """Every freed-then-used / freed-twice pointer across the source tree. Returns finding dicts
    (minus target/case ids), one per (free-site, use-site, pointer)."""
    findings: list = []
    n = 0
    for p in sorted(root.rglob("*")):
        if n >= _MAX_FILES:
            break
        if not p.is_file() or p.suffix.lower() not in _SRC_SUFFIXES:
            continue
        if _SKIP_SEGMENTS & {seg.lower() for seg in p.parts}:
            continue
        try:
            if p.stat().st_size > _MAX_FILE:
                continue
            lines = p.read_text("utf-8", "replace").splitlines()
        except OSError:
            continue
        n += 1
        findings.extend(_scan_text(p.name, lines))
    return findings


def uaf_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("uaf_scan requires a target_id")
    proj = next((a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
                 if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj is None:
        ctx.emit("uaf.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "uaf"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:
        ctx.emit("uaf.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}

    ctx.progress(msg="scanning for use-after-free / double-free")
    findings = scan_source(root)
    fd = FindingDAO(ctx.conn)
    for f in findings:
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "uaf",
            "title": f["title"], "evidence": f["evidence"],
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "candidate", "confidence": 0.45})
    ctx.emit("uaf.done", payload={"applicable": True, "findings": len(findings)})
    ctx.progress(pct=100, msg=f"{len(findings)} use-after-free / double-free candidate(s)")
    return {}


def register() -> None:
    register_stage(UAF_STAGE, uaf_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_uaf_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, UAF_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
