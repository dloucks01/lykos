"""Integer-overflow-into-allocation detector (CWE-190 / CWE-131), source-level.

The highest-severity FreeRTOS kernel bugs (CVE-2021-31571/31572, CVSS 9.8) are this exact shape:
a size computed as `a * b` (or `a + b`) from caller-supplied counts, with no overflow check, fed
to an allocator -- the product wraps, a too-small buffer is allocated, and the subsequent writes
run off it. The fix is an explicit guard (`SIZE_MAX / a >= b`, `__builtin_mul_overflow`, ...).

This flags an allocator whose size is such an arithmetic expression (directly, or via a size
variable) ONLY when no overflow guard appears nearby -- so patched code (FreeRTOS 11.x, which
added the guard) is NOT flagged, while the pre-fix shape is. A source heuristic, so findings are
`candidate`: it cannot prove the operands are attacker-controlled, only that the guard is absent.

Pure parsing, stdlib based; a file it cannot read is skipped, never fatal.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ...db.dao import ArtifactDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage

_log = logging.getLogger(__name__)

INT_OVERFLOW_STAGE = "int_overflow_scan"
TOOL = "int-overflow"
TOOL_VERSION = "int-overflow-1"

_MAX_FILES = 6000
_MAX_FILE = 4 << 20
_SRC_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
_SKIP_SEGMENTS = {"examples", "example", "demo", "demos", "test", "tests", "third_party",
                  "3rdparty", "vendor", "node_modules"}

# calloc/reallocarray are the SAFE allocators (they check the product internally) -> never flagged.
_ALLOC = re.compile(r"\b(malloc|realloc|aligned_alloc|alloca|valloc|pvPortMalloc|vPortMalloc|"
                    r"kmalloc|kzalloc|vmalloc|OPENSSL_malloc)\s*\(")
# risky arithmetic: a product / shift / sum where an operand is a NON-constant identifier.
_IDENT = r"[A-Za-z_]\w*"
_MUL = re.compile(rf"\b{_IDENT}\s*[*]\s*{_IDENT}\b|\b{_IDENT}\s*<<\s*{_IDENT}\b")
_ADD = re.compile(rf"\b{_IDENT}\s*[+]\s*{_IDENT}\b")
# tokens that mean "an overflow guard is present" in the window around the site. Each must be
# distinctive enough not to appear in ordinary prose -- a bare "overflow" matched the comment
# "no overflow check" and suppressed the very bug it described, so only the specific guard
# idioms are listed.
_GUARD = ("SIZE_MAX", "SSIZE_MAX", "INT_MAX", "UINT_MAX", "UINT32_MAX", "UINT64_MAX",
          "LONG_MAX", "ULONG_MAX", "__builtin_mul_overflow", "__builtin_add_overflow",
          "reallocarray")
_GUARD_BACK = 40        # lines before the site that an overflow check may sit in
_CONST_ONLY = re.compile(r"^\s*(?:sizeof\s*\([^)]*\)|\d+|0[xX][0-9a-fA-F]+|[-+*<>()\s])+\s*$")


def _balanced_arg(text: str, open_paren: int) -> str:
    """The text inside the parenthesis that starts at index open_paren ('('), balanced."""
    depth, i, n = 0, open_paren, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
        i += 1
    return text[open_paren + 1:min(n, open_paren + 400)]


def _risky_arith(expr: str) -> "str | None":
    """The risky sub-expression (a product/shift/sum of a non-constant identifier), or None.
    A product/sum of only literals and sizeof() is not risky."""
    for rx in (_MUL, _ADD):
        m = rx.search(expr)
        if m:
            frag = m.group(0)
            # at least one operand must be a variable (not sizeof / not a bare number / not a
            # single ALL_CAPS constant used alone)
            if not _CONST_ONLY.match(frag):
                return frag
    return None


def scan_source(root: Path) -> list:
    """Allocator calls whose size is unguarded overflow-prone arithmetic. Returns finding dicts
    (minus target/case ids). Two shapes: arithmetic directly in the alloc arg, and an alloc of a
    size variable that was assigned such arithmetic earlier in the same window."""
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
        # size variables assigned from risky arithmetic: var -> line index
        size_vars: dict = {}
        for i, ln in enumerate(lines):
            am = re.match(rf"\s*(?:\w[\w ]*\s+)?({_IDENT})\s*=\s*(.+);", ln)
            if am and _risky_arith(am.group(2)):
                size_vars[am.group(1)] = i
        for i, ln in enumerate(lines):
            m = _ALLOC.search(ln)
            if not m:
                continue
            arg = _balanced_arg(ln, ln.index("(", m.end() - 1))
            frag = _risky_arith(arg)
            via = None
            if not frag:
                for var, vi in size_vars.items():
                    if re.search(rf"\b{re.escape(var)}\b", arg) and 0 <= i - vi <= _GUARD_BACK:
                        frag, via = f"size variable '{var}'", var
                        break
            if not frag:
                continue
            window = "\n".join(lines[max(0, i - _GUARD_BACK):i + 2])
            if any(g in window for g in _GUARD):
                continue            # an overflow guard is present -> not flagged (e.g. fixed code)
            alloc = m.group(1)
            detail = (f"{p.name}:{i + 1}: {alloc}() size is overflow-prone arithmetic "
                      f"({frag}) with no nearby overflow check")
            findings.append({
                "cwe": "CWE-190", "severity": "medium",
                "title": f"Unchecked size arithmetic into {alloc}() (integer-overflow allocation)",
                "dedup_key": f"intovf:{p.name}:{i + 1}:{alloc}",
                "evidence": [{"channel": "source", "detail": detail}],
                "via": via})
    return findings


def int_overflow_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("int_overflow_scan requires a target_id")
    proj = next((a for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id)
                 if a.kind == "source-project"
                 and (a.meta or {}).get("binary_sha") == target.sha256), None)
    if proj is None:
        ctx.emit("int_overflow.done", payload={"applicable": False,
                 "note": "no archived source tree (this detector reads C source)"})
        return {}
    root = ctx.scratch() / "intovf"
    root.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                          mode="r:gz") as tf:
            for mem in tf.getmembers():
                if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                    tf.extract(mem, root)
    except Exception:
        ctx.emit("int_overflow.done", payload={"applicable": False,
                 "note": "could not unpack the archived source tree"})
        return {}

    ctx.progress(msg="scanning for integer-overflow allocations")
    findings = scan_source(root)
    fd = FindingDAO(ctx.conn)
    for f in findings:
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "int_overflow",
            "title": f["title"], "evidence": f["evidence"],
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "state": "candidate", "confidence": 0.45})
    ctx.emit("int_overflow.done", payload={"applicable": True, "findings": len(findings)})
    ctx.progress(pct=100, msg=f"{len(findings)} unguarded size-arithmetic allocation(s)")
    return {}


def register() -> None:
    register_stage(INT_OVERFLOW_STAGE, int_overflow_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_int_overflow_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, INT_OVERFLOW_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
