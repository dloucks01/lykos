"""Allocation-size integer-overflow detector (CWE-190 -> CWE-787) -- precision-first, the sibling of
guard_gap for the second-largest FreeRDP CVE class. The shape: an allocation (or copy length) whose
size is a PRODUCT/SUM of attacker-controlled wire values with no overflow guard, so a 32-bit wrap
yields an undersized buffer and the following writes go out of bounds (e.g. CVE-2024-32039
clear_decompress_residual_data, CVE-2024-22211 freerdp_bitmap_planar_context_reset width*height*bpp).

Precision comes, as in guard_gap, from modeling how the code DOES bound the math:
  - `calloc(n, size)` is overflow-checked by the C runtime -> never flagged.
  - a 64-bit widening in the expression (`1ull *`, `(size_t)`, `(UINT64)`, `* 1ULL`) prevents a
    32-bit wrap -> treated as guarded (this is exactly how FreeRDP fixes these).
  - `__builtin_mul_overflow` / `__builtin_add_overflow`, or a division-form check
    (`a > SIZE_MAX / b`, `a > UINT32_MAX / b`), or an individual clamp `if (a > N)` on an operand.
Only a product/sum of >=2 operands with at least one wire-derived operand and NO such guard fires.

Pure string analysis over brace-matched bodies (shared with dispatcher_harness). No execution.
"""
from __future__ import annotations

import re
from .dispatcher_harness import _functions

#: a value read off the wire (same idiom as guard_gap).
_READ_RE = re.compile(r'Stream_Read_U?INT(?:8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.>\[\]-]*)')

#: an allocation / copy whose size argument we inspect. calloc is overflow-safe -> excluded.
_ALLOC_RE = re.compile(r'\b(?:malloc|realloc|_aligned_malloc|winpr_aligned_malloc|'
                       r'memcpy|memmove|Stream_Write)\s*\(')

#: a 64-bit widening that defuses a 32-bit multiply (also FreeRDP's fix idiom).
_WIDEN_RE = re.compile(r'1u?ll\b|1ULL\b|\(\s*(?:size_t|UINT64|uint64_t|INT64|int64_t|unsigned long long)\s*\)',
                       re.I)


def _base(v: str) -> str:
    return re.split(r'[.>\[\]-]+', v.strip())[-1] or v


def _arg_expr(text: str, open_idx: int) -> str:
    """The balanced-paren argument text starting at `open_idx` (the '(' of a call)."""
    depth, j, n = 0, open_idx, len(text)
    while j < n:
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:j]
        j += 1
    return text[open_idx + 1:open_idx + 200]


def _last_arg(expr: str) -> str:
    """The final top-level argument of a call expr (the size/length for memcpy/Stream_Write);
    for malloc/realloc the whole expr is the size."""
    depth, parts, cur = 0, [], []
    for ch in expr:
        if ch == "," and depth == 0:
            parts.append("".join(cur)); cur = []
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        cur.append(ch)
    parts.append("".join(cur))
    return parts[-1].strip()


def _guarded_math(body: str, size_expr: str, wire: set) -> bool:
    """True when the size math is bounded: a 64-bit widening inside it, a builtin overflow helper, a
    division-form check, or every wire operand in it is individually clamped by a branch."""
    if _WIDEN_RE.search(size_expr):
        return True
    if re.search(r'__builtin_(?:mul|add)_overflow', body):
        return True
    if re.search(r'(SIZE_MAX|UINT32_MAX|UINT_MAX|INT_MAX)\s*/', body):
        return True
    ops = {_base(o) for o in re.findall(r'[A-Za-z_][\w.>\[\]-]*', size_expr)} & {_base(w) for w in wire}
    if ops and all(re.search(rf'if\s*\([^)]*\b{re.escape(o)}\b[^)]*\)\s*\{{?\s*(return|goto|break)', body)
                   or re.search(rf'\b{re.escape(o)}\b\s*[<>]=?', body) for o in ops):
        return True
    return False


def find_alloc_overflows(text: str) -> list:
    """Allocation/copy sizes that are a product or sum of >=2 operands, at least one wire-derived,
    with no overflow guard. Returns {fn, size, line, cwe, kind}."""
    if "Stream_Read_" not in text:
        return []
    out = []
    search_from = 0
    for name, _static, _params, body in _functions(text):
        boff = text.find(body, search_from)
        search_from = boff + len(body) if boff >= 0 else search_from
        wire = {m.group(1) for m in _READ_RE.finditer(body)}
        if not wire:
            continue
        for am in _ALLOC_RE.finditer(body):
            call = am.group(0)
            expr = _arg_expr(body, am.end() - 1)
            size_expr = _last_arg(expr) if call.startswith(("memcpy", "memmove", "Stream_Write")) else expr
            # must be a multiply or add of >=2 identifiers (size math, not a single var)
            if not re.search(r'[A-Za-z_][\w.>\[\]-]*\s*[*+]\s*[A-Za-z_(]', size_expr):
                continue
            idents = {_base(i) for i in re.findall(r'[A-Za-z_][\w.>\[\]-]*', size_expr)}
            if not (idents & {_base(w) for w in wire}):          # at least one wire operand
                continue
            if _guarded_math(body, size_expr, wire):
                continue
            ln = text.count("\n", 0, boff + am.start()) + 1 if boff >= 0 else 0
            out.append({"fn": name, "size": size_expr.strip()[:80], "line": ln,
                        "cwe": "CWE-190", "kind": call.rstrip("(")})
    return out
