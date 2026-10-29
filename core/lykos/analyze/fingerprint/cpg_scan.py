"""Per-CWE source/sink/sanitizer queries with intraprocedural taint -- the discovery layer for
weakness classes the dedicated regex detectors (command/format sinks, int-overflow, use-after-free)
do not cover. This is the operational core of a code-property-graph query engine (source -> sink,
minus a sanitizer) done rule-based and offline: a declarative query table + the shared srctaint
intraprocedural link. It is INTRAPROCEDURAL (not a full interprocedural CPG yet), and deterministic
-- no LLM.

v1 classes, both taint-gated so a finding is never a bare pattern match:
  * CWE-120 -- unbounded copy into a buffer: strcpy/strcat/stpcpy/wcscpy/... of attacker-controlled
    data (the bounded variants strncpy/strlcpy/snprintf are the FIX and are never flagged); plus
    gets(), which is unsafe UNIVERSALLY (it reads unbounded stdin into a fixed buffer) and is flagged
    without a taint gate.
  * CWE-22 -- path traversal: a filesystem open/unlink/... whose path flows from untrusted input with
    no normalising guard (realpath / a `..` reject) in the enclosing function.

Findings are `candidate`; a taint-linked one earns the non-fuzzing weaponization floor (an overflow /
traversal recipe). Pure parsing, stdlib based; an unreadable file is skipped.
"""
from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from . import srctaint
from .source_sinks import _balanced_arg, _is_declaration, _is_literal, _split_args, _strip_comments
from .srcwalk import source_files

CPG_STAGE = "cpg_scan"
TOOL, TOOL_VERSION = "cpg", "cpg-1"
_MAX_RECIPES = 64

# sink -> (cwe, arg position to check, mode). mode: "copy"/"path" taint-check the arg; "gets" is a
# universal defect (no taint gate). The bounded copy variants are deliberately ABSENT -- they are the
# fix, not the bug.
_COPY = {"strcpy": 1, "strcat": 1, "stpcpy": 1, "wcscpy": 1, "wcscat": 1, "lstrcpy": 1, "lstrcat": 1}
_PATH = {"fopen": 0, "freopen": 0, "open": 0, "open64": 0, "openat": 1, "opendir": 0, "creat": 0,
         "unlink": 0, "remove": 0, "rmdir": 0}
_SINKS = {**{k: ("CWE-120", v, "copy") for k, v in _COPY.items()},
          "gets": ("CWE-120", 0, "gets"),
          **{k: ("CWE-22", v, "path") for k, v in _PATH.items()}}
_CALL = re.compile(rf"\b({'|'.join(sorted(_SINKS, key=len, reverse=True))})\s*\(")
#: tokens that mean the path was normalised / traversal-checked in the enclosing function.
_PATH_SANITIZERS = ("realpath", "canonicaliz", "PathCanon", "basename", '".."', "'..'", "secure_path")
#: an allowlist / prefix check compares the path against a string LITERAL (e.g.
#: `strncmp(deviceId, "/dev/video", 10)`, `if (path == "...")`) -- the caller restricts the path to a
#: known-safe set, so an open() guarded by one is not an uncontrolled traversal.
_ALLOWLIST_CMP = re.compile(
    r'\b(?:strncmp|strncasecmp|strcmp|strcasecmp|memcmp|_strnicmp|_stricmp|wcscmp|wcsncmp|'
    r'CompareString\w*)\s*\([^;]*"')


def _sanitized(lines: list, idx: int, base: str | None = None) -> bool:
    start, _ = srctaint.enclosing(lines, idx)
    body = "\n".join(lines[start:idx + 1])
    if any(s in body for s in _PATH_SANITIZERS):
        return True
    # an allowlist comparison of the path base against a string literal anywhere before the sink
    for m in _ALLOWLIST_CMP.finditer(body):
        if base is None or re.search(rf"\b{re.escape(base)}\b", body[m.start():m.start() + 120]):
            return True
    return False


def _mk(name, line, fn, arg, cwe, label, taint) -> dict:
    ev = [{"channel": "source", "detail": f"{name}:{line + 1}: {label}"}]
    if taint:
        ev.append({"channel": "source-flow",
                   "detail": f"the argument flows from {taint['source']} ({taint['via']})"})
    return {"cwe": cwe, "severity": "high", "title": f"{label} ({cwe})",
            "dedup_key": f"cpg:{cwe}:{name}:{line + 1}:{fn}", "fn": fn, "arg": arg,
            "file": name, "line": line + 1, "taint": taint, "evidence": ev}


def scan_source(root: Path) -> list:
    findings: list = []
    for label, _p, text in source_files(root):
        text = _strip_comments(text)
        lines = text.splitlines()
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("#"):
                continue
            for m in _CALL.finditer(ln):
                fn = m.group(1)
                if _is_declaration(ln[:m.start()]) or ln[:m.start()].rstrip().endswith((".", "->")):
                    continue
                cwe, pos, mode = _SINKS[fn]
                try:
                    args = _split_args(_balanced_arg(ln, ln.index("(", m.end() - 1)))
                except ValueError:
                    continue
                if mode == "gets":
                    # gets() is unsafe universally -- unbounded stdin read into a fixed buffer.
                    dst = args[0] if args else "buffer"
                    findings.append(_mk(label, i, fn, dst, "CWE-120",
                                        f"gets() reads unbounded stdin into '{dst}' (buffer overflow)",
                                        {"via": "input-reader", "source": "stdin via gets()"}))
                    continue
                if pos >= len(args):
                    continue
                arg = args[pos]
                if _is_literal(arg) or re.fullmatch(r"(?:NULL|0|nullptr)", arg.strip()):
                    continue
                # PRECISION: require a STRONG untrusted source (input reader / argv / a parser's or
                # main's parameter), not a generic parameter -- a path/buffer arg that is merely a
                # forwarded parameter of a helper is not established attacker-controlled.
                strength, taint = srctaint.untrusted_strength(lines, i, arg)
                if strength != "strong":
                    continue
                if mode == "path":
                    if _sanitized(lines, i, srctaint.base_ident(arg)):
                        continue
                    findings.append(_mk(label, i, fn, arg, "CWE-22",
                                        f"{fn}() opens a path from untrusted input ('{arg}') with "
                                        f"no traversal sanitisation", taint))
                else:                                            # copy
                    findings.append(_mk(label, i, fn, arg, "CWE-120",
                                        f"{fn}() copies untrusted data ('{arg}') into a buffer with "
                                        f"no length bound", taint))
    return findings


def _file_findings(ctx, target, findings) -> int:
    from ..poc.source_recipe import file_source_recipe
    fd = FindingDAO(ctx.conn)
    recipes = 0
    for f in findings:
        linked = bool(f.get("taint"))
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "cpg", "title": f["title"],
            "evidence": f["evidence"], "site_detail": f"{f['file']}:{f['line']}",
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "candidate", "confidence": 0.6 if linked else 0.4})
        if linked and recipes < _MAX_RECIPES:
            if file_source_recipe(ctx, target, cwe=f["cwe"], fn=f["fn"], arg=f["arg"],
                                  file=f["file"], line=f["line"], taint=f["taint"]) is not None:
                recipes += 1
    return recipes


def cpg_scan_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("cpg_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        ctx.emit("cpg_scan.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C/C++ source)"})
        return {}
    root = ctx.scratch() / "cpg"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:
        ctx.emit("cpg_scan.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}
    ctx.progress(msg="per-CWE source/sink queries (buffer-copy, path-traversal)")
    findings = scan_source(root)
    recipes = _file_findings(ctx, target, findings)
    ctx.emit("cpg_scan.done", payload={"applicable": True, "findings": len(findings),
             "recipes": recipes})
    ctx.progress(pct=100, msg=f"{len(findings)} per-CWE candidate(s), {recipes} recipe(s)")
    return {"metrics": {"findings": len(findings), "recipes": recipes}}


def register() -> None:
    register_stage(CPG_STAGE, cpg_scan_stage, resource_class="quick", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=180)


def enqueue_cpg_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CPG_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
