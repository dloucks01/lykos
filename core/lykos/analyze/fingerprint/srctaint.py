"""Shared source-level taint-lite: link a value to an UNTRUSTED SOURCE, intraprocedurally and
soundly, from pure C/C++ text.

Three source detectors want the same thing -- a CHECKABLE SYNTACTIC FACT that a value they flagged
(a sink argument, an allocation size, a freed pointer) is derived from input: a function parameter,
a known input reader (read/recv/fgets/fread/getenv), or argv. That fact raises a candidate above a
flat pattern match and earns it the non-fuzzing weaponization floor (a corroborated recipe). These
helpers UNDER-report by design -- a multi-line signature, a transitive copy, or a value they cannot
connect to input yields no link -- so a recipe is never filed on a fabricated flow. Precision is
paramount.
"""
from __future__ import annotations

import re

_IDENT = r"[A-Za-z_]\w*"
# a column-0 function-definition header: `<type> name(params)` ending at the body's `{` (on this
# line, body after it, or next line -> end of line). The two-identifier `<type> <name>` shape is
# what separates a definition from a bare call.
_SIG = re.compile(r"^[A-Za-z_][\w \t\*]*\b[A-Za-z_]\w*\s*\(([^;{]*)\)\s*(?:\{|$)")


def base_ident(expr: str):
    """The leading identifier of an l-value expression (`msg->fmt` -> `msg`, `&buf[0]` -> `buf`). A
    call or a literal has no simple base and yields None."""
    a = (expr or "").strip().lstrip("&").lstrip("*").strip()
    m = re.match(rf"({_IDENT})", a)
    if not m:
        return None
    if a[m.end():].lstrip().startswith("("):               # a function call, not a variable
        return None
    return m.group(1)


def param_idents(params: str) -> set:
    """Identifier names of a (single-line) function signature's parameter list."""
    out = set()
    for part in params.split(","):
        toks = re.findall(_IDENT, part)
        if toks and part.strip() not in ("void", ""):
            out.add(toks[-1])                              # the declared name is the last token
    return out


def enclosing(lines: list, idx: int):
    """Conservative enclosing-function bounds: start just after the previous function's column-0
    closing brace (normal multi-line C), but not earlier than the NEAREST column-0 signature above
    the sink (so a one-line definition, whose `}` is not at column 0, is handled too). Returns
    (signature_or_start_index, param_name_set); an empty set means the params could not be parsed."""
    start = 0
    for s in range(idx - 1, -1, -1):
        if lines[s][:1] == "}":
            start = s + 1
            break
    for s in range(idx, start - 1, -1):
        m = _SIG.match(lines[s])
        if m:
            return s, param_idents(m.group(1))
    return start, set()


def reader_source(body: str, base: str):
    """If `base` is filled by a known input reader in `body`, name that reader; else None. Readers
    are matched at the exact destination/return position so a count or fd argument is not mistaken
    for the data buffer."""
    b = re.escape(base)
    if re.search(rf"\b{b}\s*=\s*argv\s*\[", body):
        return "argv[]"
    for fn in ("getenv", "secure_getenv", "fgetln"):       # data-returning readers (assigned-from)
        if re.search(rf"\b{b}\s*=\s*{fn}\s*\(", body):
            return f"{fn}()"
    for fn in ("read", "recv", "recvfrom"):                # destination = 2nd argument
        if re.search(rf"\b{fn}\s*\(\s*[^,;()]+,\s*(?:&)?{b}\b", body):
            return f"{fn}()"
    for fn in ("fgets", "gets", "fread"):                  # destination = 1st argument
        if re.search(rf"\b{fn}\s*\(\s*(?:&)?{b}\b", body):
            return f"{fn}()"
    return None


def untrusted_link(lines: list, idx: int, expr: str):
    """Syntactic link from `expr` (an l-value) to an untrusted source in its enclosing function, or
    None. Returns {"via": "parameter"|"input-reader", "source": "<human label>"}."""
    base = base_ident(expr)
    if not base:
        return None
    start, params = enclosing(lines, idx)
    if base in params:
        extra = " (argv[])" if base == "argv" else ""
        return {"via": "parameter", "source": f"function parameter '{base}'{extra}"}
    rdr = reader_source("\n".join(lines[start:idx + 1]), base)
    if rdr:
        return {"via": "input-reader", "source": f"{rdr} into '{base}'"}
    return None


def any_untrusted(lines: list, idx: int, idents) -> "dict | None":
    """The first untrusted link among several candidate identifiers (for an expression with multiple
    operands, e.g. integer-overflow size arithmetic `a * b`). The first linked operand wins."""
    for ident in idents:
        link = untrusted_link(lines, idx, ident)
        if link:
            return link
    return None
