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

from ...db.dao import FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..source_lookup import source_project_for
from . import srctaint
from .srcwalk import source_files

_log = logging.getLogger(__name__)

INT_OVERFLOW_STAGE = "int_overflow_scan"
TOOL = "int-overflow"
TOOL_VERSION = "int-overflow-1"
#: cap on corroborated recipes filed per scan.
_MAX_SOURCE_RECIPES = 64


# calloc/reallocarray are the SAFE allocators (they check the product internally) -> never flagged.
_ALLOC = re.compile(r"\b(malloc|realloc|aligned_alloc|alloca|valloc|pvPortMalloc|vPortMalloc|"
                    r"kmalloc|kzalloc|vmalloc|OPENSSL_malloc)\s*\(")
# risky arithmetic: a product / shift / sum where an operand is a NON-constant identifier.
_IDENT = r"[A-Za-z_]\w*"
# `sizeof *p` is the canonical SAFE allocation size, not a product -- `sizeof` is never the left
# operand of a risky multiply.
_MUL = re.compile(rf"\b(?!sizeof\b){_IDENT}\s*[*]\s*{_IDENT}\b|\b{_IDENT}\s*<<\s*{_IDENT}\b")
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
_MACRO = re.compile(r"^(?:sizeof|[A-Z][A-Z0-9_]*)$")    # an ALL_CAPS compile-time constant
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _strip_comments(text: str) -> str:
    """Blank out C comments, preserving line structure: a commented-out `malloc(a * b)` is not an
    allocation, and a `SIZE_MAX` in a TODO comment is not a guard."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


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
            # at least one operand must be a variable (not sizeof / not a bare number / not an
            # ALL_CAPS compile-time constant: `COUNT * ELEM_SIZE` cannot be steered by input)
            if _CONST_ONLY.match(frag):
                continue
            if all(_MACRO.match(t) for t in re.findall(_IDENT, frag)):
                continue
            return frag
    return None


def scan_source(root: Path) -> list:
    """Allocator calls whose size is unguarded overflow-prone arithmetic. Returns finding dicts
    (minus target/case ids). Two shapes: arithmetic directly in the alloc arg, and an alloc of a
    size variable that was assigned such arithmetic earlier in the same window."""
    findings: list = []
    for label, _p, text in source_files(root):
        lines = _strip_comments(text).splitlines()
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
            # TAINT-LITE: are the size OPERANDS derived from an untrusted source? For a size variable
            # the operands live in its assignment; for inline arithmetic they are in `frag` itself.
            expr = lines[size_vars[via]] if (via and via in size_vars) else frag
            operands = [o for o in re.findall(_IDENT, expr) if not _MACRO.match(o)]
            taint = srctaint.any_untrusted(lines, i, operands)
            detail = (f"{label}:{i + 1}: {alloc}() size is overflow-prone arithmetic "
                      f"({frag}) with no nearby overflow check")
            ev = [{"channel": "source", "detail": detail}]
            if taint:
                ev.append({"channel": "source-flow",
                           "detail": f"a size operand flows from {taint['source']} ({taint['via']})"})
            findings.append({
                "cwe": "CWE-190", "severity": "medium",
                "title": f"Unchecked size arithmetic into {alloc}() (integer-overflow allocation)",
                "dedup_key": f"intovf:{label}:{i + 1}:{alloc}",
                "evidence": ev, "via": via,
                "fn": alloc, "arg": frag, "file": label, "line": i + 1, "taint": taint})
    return findings


def int_overflow_stage(ctx) -> dict:
    import io
    import tarfile

    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("int_overflow_scan requires a target_id")
    proj = source_project_for(ctx.conn, target)
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
    recipes = 0
    for f in findings:
        # An operand proven to flow from input makes this more than a guard-absence match: raise it
        # and give it the non-fuzzing weaponization FLOOR (a corroborated CWE-190 recipe).
        linked = bool(f.get("taint"))
        fd.upsert(target.id, target.case_id, {
            "cwe": f["cwe"], "severity": f["severity"], "detector": "int_overflow",
            "title": f["title"], "evidence": f["evidence"],
            "function_addr": None, "site_addr": None, "dedup_key": f["dedup_key"],
            "site_detail": f"{f['file']}:{f['line']}",
            "state": "candidate", "confidence": 0.6 if linked else 0.45})
        if linked and recipes < _MAX_SOURCE_RECIPES:
            from ..poc.source_recipe import file_source_recipe
            if file_source_recipe(ctx, target, cwe=f["cwe"], fn=f["fn"], arg=f["arg"],
                                  file=f["file"], line=f["line"], taint=f["taint"]) is not None:
                recipes += 1
    ctx.emit("int_overflow.done", payload={"applicable": True, "findings": len(findings),
             "recipes": recipes})
    ctx.progress(pct=100, msg=f"{len(findings)} unguarded size-arithmetic allocation(s), "
                             f"{recipes} recipe(s)")
    return {"metrics": {"findings": len(findings), "recipes": recipes}}


def register() -> None:
    register_stage(INT_OVERFLOW_STAGE, int_overflow_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_int_overflow_scan(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, INT_OVERFLOW_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
