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

Two further precision rules:
  - operand WIDTHS are modeled: each wire value's width comes from its Stream_Read_UINT<n>, literals
    and sizeof(<primitive>) are exact, anything else is assumed to span the full 32 bits. The size
    math (assumed 32-bit -- a widening to size_t/64-bit is the guarded case above) can wrap only if
    the expression's MAXIMUM exceeds 2^32-1: `w16 * h16` cannot (0xFFFF*0xFFFF < 2^32), `w16 * h16 * 4`
    can (~2^34).
  - only wire reads that PRECEDE the allocation count: a value read after the malloc cannot be its
    size.

Pure string analysis over brace-matched bodies (shared with dispatcher_harness). No execution.
"""
from __future__ import annotations

import re
from .dispatcher_harness import _functions

#: a value read off the wire (same idiom as guard_gap).
_READ_RE = re.compile(r'Stream_Read_U?INT(8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.>\[\]-]*)')

#: an allocation / copy whose size argument we inspect. calloc is overflow-safe -> excluded.
_ALLOC_RE = re.compile(r'\b(?:malloc|realloc|_aligned_malloc|winpr_aligned_malloc|'
                       r'memcpy|memmove|Stream_Write)\s*\(')

#: a 64-bit widening that defuses a 32-bit multiply (also FreeRDP's fix idiom).
_WIDEN_RE = re.compile(r'1u?ll\b|1ULL\b|\(\s*(?:size_t|UINT64|uint64_t|INT64|int64_t|unsigned long long)\s*\)',
                       re.I)


#: the width of the size arithmetic. 32-bit is assumed (FreeRDP's UINT32/size math); a cast to
#: size_t/64-bit is already treated as a guard by _WIDEN_RE.
_ARITH_BITS = 32
_ARITH_MAX = (1 << _ARITH_BITS) - 1

#: byte sizes for sizeof(<primitive>) -- anything else in a sizeof is an unknown (full-width) operand
_SIZEOF = {"char": 1, "BYTE": 1, "UINT8": 1, "INT8": 1, "uint8_t": 1, "int8_t": 1, "BOOL": 4,
           "short": 2, "UINT16": 2, "INT16": 2, "WORD": 2, "uint16_t": 2, "int16_t": 2, "WCHAR": 2,
           "int": 4, "UINT32": 4, "INT32": 4, "DWORD": 4, "UINT": 4, "uint32_t": 4, "int32_t": 4,
           "float": 4, "UINT64": 8, "INT64": 8, "uint64_t": 8, "int64_t": 8, "double": 8,
           "size_t": 8, "QWORD": 8}

_TOK_RE = re.compile(r'\s*(0[xX][0-9A-Fa-f]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*(?:(?:\.|->)\w+|\[[^\]]*\])*'
                     r'|<<|>>|[-+*/()])')


def _tokens(expr: str):
    out, i = [], 0
    expr = expr.strip()
    while i < len(expr):
        m = _TOK_RE.match(expr, i)
        if not m or not m.group(1):
            return None                                       # unparseable -> caller treats as unknown
        out.append(m.group(1))
        i = m.end()
    return out


def _max_value(expr: str, widths: dict):
    """Upper bound of the size expression, or None when it cannot be bounded (an unknown construct).
    Wire identifiers are bounded by their read width, literals exactly, sizeof(<primitive>) exactly,
    any other identifier/call by the full arithmetic width (an assumption, never an under-estimate)."""
    toks = _tokens(expr)
    if not toks:
        return None
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek()
        pos[0] += 1
        return t

    def factor():
        t = take()
        if t is None:
            raise ValueError
        if t == "(":
            # a cast `(TYPE)x` (non-widening: widening casts were already a guard) or a parenthesis
            cand = toks[pos[0]] if pos[0] < len(toks) else ""
            after = toks[pos[0] + 2] if pos[0] + 2 < len(toks) else None
            if pos[0] + 1 < len(toks) and toks[pos[0] + 1] == ")" and re.match(r'[A-Za-z_]\w*$', cand) \
                    and (cand in _SIZEOF or cand.isupper() or cand.endswith("_t")) \
                    and after is not None and after not in ("*", "/", "+", "-", "<<", ">>", ")"):
                pos[0] += 2
                return factor()
            v = expr_()
            if take() != ")":
                raise ValueError
            return v
        if t[0].isdigit():
            return int(re.sub(r'[uUlL]+$', '', t), 0)
        if t == "sizeof":
            if take() != "(":
                raise ValueError
            inner = take()
            if take() != ")":
                raise ValueError
            return _SIZEOF.get(inner, _ARITH_MAX)
        if re.match(r'[A-Za-z_]', t):
            if peek() == "(":                                 # a call: unknown result
                depth = 0
                while True:
                    u = take()
                    if u is None:
                        raise ValueError
                    depth += (u == "(") - (u == ")")
                    if depth == 0:
                        break
                return _ARITH_MAX
            return widths.get(_base(t), _ARITH_MAX)
        raise ValueError

    def term():
        v = factor()
        while peek() in ("*", "/", "<<", ">>"):
            op = take()
            r = factor()
            if op == "*":
                v = v * r
            elif op == "<<":
                v = v << min(r, 64)
            # `/` and `>>` never raise the bound
        return v

    def expr_():
        v = term()
        while peek() in ("+", "-"):
            op = take()
            r = term()
            v = v + r if op == "+" else _ARITH_MAX + 1       # unsigned underflow may wrap: unknown
        return v

    try:
        v = expr_()
    except (ValueError, IndexError, OverflowError):
        return None
    return v if pos[0] == len(toks) else None


def _can_wrap(size_expr: str, widths: dict) -> bool:
    """True unless the expression's maximum provably fits the size arithmetic."""
    mx = _max_value(size_expr, widths)
    return mx is None or mx > _ARITH_MAX


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
        reads = [(m.start(), m.group(2), int(m.group(1))) for m in _READ_RE.finditer(body)]
        if not reads:
            continue
        for am in _ALLOC_RE.finditer(body):
            call = am.group(0)
            # only values read BEFORE this allocation can be its size
            wire = {v for at, v, _bits in reads if at < am.start()}
            if not wire:
                continue
            widths: dict = {}
            for at, v, bits in reads:
                if at < am.start():
                    widths[_base(v)] = max(widths.get(_base(v), 0), (1 << bits) - 1)
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
            if not _can_wrap(size_expr, widths):                # e.g. UINT16 * UINT16 fits 32 bits
                continue
            ln = text.count("\n", 0, boff + am.start()) + 1 if boff >= 0 else 0
            out.append({"fn": name, "size": size_expr.strip()[:80], "line": ln,
                        "cwe": "CWE-190", "kind": call.rstrip("(")})
    return out
