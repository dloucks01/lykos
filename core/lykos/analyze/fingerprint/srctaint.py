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


def enclosing_name(lines: list, idx: int):
    """The NAME of the function enclosing line `idx`, or None -- the identifier right before the
    enclosing signature's parameter list. Used to pick a candidate function to synthesize a driver
    for (then prove with the ladder)."""
    s, _ = enclosing(lines, idx)
    if s >= len(lines) or not _SIG.match(lines[s]) or "(" not in lines[s]:
        return None
    head = lines[s][:lines[s].index("(")]
    names = re.findall(_IDENT, head)
    return names[-1] if names else None


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


# numeric/string conversions that DERIVE a value from another: `n = atoi(v[1])` makes n as
# untrusted as v[1]. Used for one bounded transitive hop so a converted input is still traced.
_DERIVE_FNS = ("atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "strtod",
               "strtoull", "sscanf", "strtoumax", "strtoimax")
_DERIVE_RX = re.compile(r"=\s*(?:\([^)=;]*\)\s*)?(" + "|".join(_DERIVE_FNS) + r")\s*\(([^;]*)\)")


def untrusted_link(lines: list, idx: int, expr: str, _depth: int = 0):
    """Syntactic link from `expr` (an l-value) to an untrusted source in its enclosing function, or
    None. Returns {"via": "parameter"|"input-reader", "source": "<human label>"}."""
    base = base_ident(expr)
    if not base:
        return None
    start, params = enclosing(lines, idx)
    if base in params:
        extra = " (argv[])" if base == "argv" else ""
        return {"via": "parameter", "source": f"function parameter '{base}'{extra}"}
    body = "\n".join(lines[start:idx + 1])
    rdr = reader_source(body, base)
    if rdr:
        return {"via": "input-reader", "source": f"{rdr} into '{base}'"}
    # ONE transitive hop: `base = atoi(inner)` / `base = strtol(inner, ...)` -> base is as untrusted
    # as inner. This traces a converted input (the canonical `n = atoi(argv[1]); malloc(n * k)`)
    # without a general dataflow engine. Bounded to one hop so it cannot loop.
    if _depth < 1:
        m = re.search(rf"\b{re.escape(base)}\s*{_DERIVE_RX.pattern}", body)
        if m:
            for inner in re.findall(_IDENT, m.group(2)):
                if inner == base or inner in _DERIVE_FNS:
                    continue
                sub = untrusted_link(lines, idx, inner, _depth + 1)
                if sub:
                    return {"via": sub["via"],
                            "source": f"{sub['source']} via {m.group(1)}() into '{base}'"}
    return None


def any_untrusted(lines: list, idx: int, idents) -> "dict | None":
    """The first untrusted link among several candidate identifiers (for an expression with multiple
    operands, e.g. integer-overflow size arithmetic `a * b`). The first linked operand wins."""
    for ident in idents:
        link = untrusted_link(lines, idx, ident)
        if link:
            return link
    return None


# A function whose NAME marks it a wire/peer-data parser: its parameters carry attacker-controlled
# input. CONSERVATIVE on purpose (precision is paramount): it matches the specific verbs that denote
# RECEIVING or DECODING peer input -- `recv_pdu`, `parse_x`, `decode_frame`, `*_decompress`,
# `*_unpack`, `*_demarshal`, `on_data_received` -- but NOT generic nouns (`message`, `order`, `pdu`)
# that name container/struct types (MessageQueue), nor overbroad verbs (`read`/`process`/`handle`)
# that pervade local helpers (read_config, process_options). A missed real parser stays a
# corroborated candidate; a wrongly-"strong" wrapper would be a false positive.
_PARSER_ROLE = re.compile(
    r"(?i)(?:^|_)(?:recv|recvfrom|parse|decode|decompress|unpack|deserial|demarshal|"
    r"ondata|on_data|from_wire)")


def is_parser_name(name) -> bool:
    """True when the function name marks it a peer-data parser (its parameters are untrusted wire
    data). Conservative: a generic name is not a parser."""
    return bool(name and _PARSER_ROLE.search(name))


def untrusted_strength(lines: list, idx: int, expr: str):
    """(strength, link) where strength is 'strong' | 'weak' | None. This is the PRECISION layer over
    untrusted_link: a value is STRONGLY untrusted when it comes from a real input reader, is argv, or
    is a parameter of an ENTRY POINT (main) or a PEER-DATA PARSER (by role name) -- there the
    attacker genuinely controls it. A plain parameter of a generic function is only WEAKLY untrusted
    (a forwarding wrapper whose caller decides) -- not enough to call a site an exploitable finding
    without over-approximating every wrapper. No link at all -> (None, None).
    """
    link = untrusted_link(lines, idx, expr)
    if not link:
        return None, None
    if link["via"] == "input-reader" or "argv" in (link.get("source") or ""):
        return "strong", link
    fn = enclosing_name(lines, idx)                          # link["via"] == "parameter" here
    if fn == "main" or is_parser_name(fn):
        return "strong", link
    return "weak", link


def any_untrusted_strength(lines: list, idx: int, idents):
    """The strongest untrusted link among several candidate identifiers: (strength, link). 'strong'
    beats 'weak' beats None (so one genuinely-untrusted operand decides)."""
    best = (None, None)
    rank = {None: 0, "weak": 1, "strong": 2}
    for ident in idents:
        s, link = untrusted_strength(lines, idx, ident)
        if rank[s] > rank[best[0]]:
            best = (s, link)
            if s == "strong":
                break
    return best
