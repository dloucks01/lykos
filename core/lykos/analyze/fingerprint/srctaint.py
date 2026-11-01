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
    # Wire/stream readers -- the FreeRDP/WinPR wStream family and the common `Stream_Read` idiom.
    # Bytes read FROM a stream are peer input, exactly like recv()/read(): `Stream_Read_UINTxx(s, dst)`
    # and `Stream_Read(s, dst, n)` FILL the destination (2nd argument, macro-assigned, so no `&`), and
    # `Stream_Get*`/`Stream_Pointer(s)` RETURN a pointer into the peer buffer (assigned-from). This is
    # the ENTIRE attack surface of a protocol library (1,313 call sites in libfreerdp) -- without it a
    # wire-read length/size/count that feeds a malloc/memcpy is never seen as untrusted, so the whole
    # surface is invisible to the taint-gated detectors.
    if re.search(rf"\bStream_Read(?:_[A-Za-z0-9]+)?\s*\(\s*[^,;()]+,\s*(?:&)?{b}\b", body):
        return "Stream_Read()"
    if re.search(rf"\b{b}\s*=\s*(?:\([^)=;]*\)\s*)?Stream_(?:Get|Pointer|Buffer|ConstBuffer)\w*\s*\(", body):
        return "Stream_Get()"
    return None


# numeric/string conversions that DERIVE a value from another: `n = atoi(v[1])` makes n as
# untrusted as v[1]. Used for one bounded transitive hop so a converted input is still traced.
_DERIVE_FNS = ("atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull", "strtod",
               "strtoull", "sscanf", "strtoumax", "strtoimax")
_DERIVE_RX = re.compile(r"=\s*(?:\([^)=;]*\)\s*)?(" + "|".join(_DERIVE_FNS) + r")\s*\(([^;]*)\)")


def scan_return_taint(files, wire_fields: set | None = None) -> set:
    """Phase B (interprocedural): the set of function NAMES whose RETURN value is wire-derived, so a
    `len = f(s)` elsewhere inherits the taint. A function qualifies when any `return EXPR;` is strongly
    untrusted inside it (a reader/Stream_Read into the returned var, a wire-field, or a parser's own
    parameter) -- i.e. it hands back an attacker-CHOSEN value, not a safe derived bound. One extra hop:
    a function that returns a call to an already-qualifying function also qualifies. `files` is an
    iterable of (label, COMMENT-STRIPPED text)."""
    funcs: set = set()
    pending: list = []
    for _label, text in files:
        lines = text.splitlines()
        for j, ln in enumerate(lines):
            for m in re.finditer(r"\breturn\s+([^;{}]+);", ln):  # mid-line returns too (one-liners)
                expr = m.group(1).strip()
                fn = enclosing_name(lines, j)
                if not fn:
                    continue
                s, _ = untrusted_strength(lines, j, expr, wire_fields=wire_fields)
                if s == "strong":
                    funcs.add(fn)
                else:
                    mc = re.match(r"([A-Za-z_]\w*)\s*\(", expr)   # `return g(...)` -> 2-hop candidate
                    if mc:
                        pending.append((fn, mc.group(1)))
    for fn, callee in pending:                               # one hop: returns a call to a tainted fn
        if callee in funcs:
            funcs.add(fn)
    return funcs


def _returns_to(body: str, base: str, ret_funcs: set):
    """The tainted-returning function name if `base = f(...)` for some f in `ret_funcs`, else None."""
    m = re.search(rf"\b{re.escape(base)}\s*=\s*(?:\([^)=;]*\)\s*)?([A-Za-z_]\w*)\s*\(", body)
    return m.group(1) if (m and m.group(1) in ret_funcs) else None


def untrusted_link(lines: list, idx: int, expr: str, _depth: int = 0, ret_funcs: set | None = None):
    """Syntactic link from `expr` (an l-value) to an untrusted source in its enclosing function, or
    None. Returns {"via": "parameter"|"input-reader", "source": "<human label>"}. `ret_funcs` (Phase B)
    additionally treats `base = f(...)` as untrusted when f is a wire-deriving returner."""
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
    if ret_funcs:                                            # base = <wire-deriving function>(...)
        rf = _returns_to(body, base, ret_funcs)
        if rf:
            return {"via": "input-reader", "source": f"{rf}() return (wire-derived) into '{base}'"}
    # ONE transitive hop: `base = atoi(inner)` / `base = strtol(inner, ...)` -> base is as untrusted
    # as inner. This traces a converted input (the canonical `n = atoi(argv[1]); malloc(n * k)`)
    # without a general dataflow engine. Bounded to one hop so it cannot loop.
    if _depth < 1:
        m = re.search(rf"\b{re.escape(base)}\s*{_DERIVE_RX.pattern}", body)
        if m:
            for inner in re.findall(_IDENT, m.group(2)):
                if inner == base or inner in _DERIVE_FNS:
                    continue
                sub = untrusted_link(lines, idx, inner, _depth + 1, ret_funcs=ret_funcs)
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


#: a wire/stream parameter TYPE -- a function that takes one receives peer bytes to parse, so its
#: parameters are attacker-controlled regardless of the function's name (audin_process_formats(...,
#: wStream* s) is a parser even though "process" is too generic a name to rely on). A precise,
#: low-false-positive signal: these types exist to carry untrusted wire data.
_WIRE_PARAM = re.compile(r"\b(?:wStream|p?Stream|STREAM|BIO|wMessage)\s*\*")


def is_parser_sig(sig: str) -> bool:
    """True when the function SIGNATURE takes a wire/stream buffer -- its parameters are wire data."""
    return bool(sig and _WIRE_PARAM.search(sig))


# ---- interprocedural Phase A: struct-field taint ------------------------------------------------
# A struct FIELD filled from a wire read in ONE function is attacker-controlled wherever it is later
# read -- often in a DIFFERENT function (`Stream_Read_UINT32(s, hdr->length)` in a parser, then
# `memcpy(dst, p, obj->length)` in a handler). The intraprocedural link never sees that, so a whole
# class of wire-controlled lengths is invisible. `scan_wire_fields` pre-indexes the TYPE.field names
# that are wire-filled across the tree; `field_untrusted` then taints a read of such a field. Match is
# TYPE-QUALIFIED (the struct variable's declared type + the field name), so a common field name alone
# never taints -- keeping it precise.
_TYPE_KW = {"return", "sizeof", "if", "while", "for", "switch", "case", "const", "struct", "union",
            "else", "do", "static", "extern", "typedef", "goto", "break", "continue", "volatile"}


def resolve_type(lines: list, idx: int, var: str):
    """The declared type token of `var` visible at `idx` (the enclosing function's parameters and
    local declarations). Returns the type name (e.g. `rdpSettings` for `rdpSettings* settings`) or
    None. Pointer and value declarations both match; keywords are rejected so an assignment or a
    control statement is not mistaken for a declaration."""
    if not var:
        return None
    start, _ = enclosing(lines, idx)
    v = re.escape(var)
    rx_ptr = re.compile(rf"\b([A-Za-z_]\w+)\s*\*+\s*{v}\b")
    rx_val = re.compile(rf"\b([A-Za-z_]\w+)\s+{v}\s*[;=\[,)]")
    for j in range(start, min(idx + 1, len(lines))):
        for rx in (rx_ptr, rx_val):
            m = rx.search(lines[j])
            if m and m.group(1) not in _TYPE_KW:
                return m.group(1)
    return None


def _field_parts(expr: str):
    """(struct-variable, field) for the LAST `->`/`.` access in `expr` (`a->b->len` -> ('b','len')),
    or (None, None). The last access is the one being used as the value at the sink."""
    pairs = re.findall(r"([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)", expr or "")
    return pairs[-1] if pairs else (None, None)


_FIELD_WRITE = re.compile(
    r"\bStream_Read(?:_[A-Za-z0-9]+)?\s*\(\s*[^,;()]+,\s*&?\s*([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)")
_FIELD_ASSIGN = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)\s*=\s*[^;]*?\b(?:Stream_Read\w*|Stream_Get\w*|read|recv|recvfrom|fread)\s*\(")


def scan_wire_fields(files) -> set:
    """Index of `TYPE.field` names that are filled from a wire read anywhere in the project: the field
    is the destination of a `Stream_Read*`, or it is assigned from a reader/`Stream_Get*`. `files` is
    an iterable of (label, COMMENT-STRIPPED text). The struct variable's type is resolved at the write
    site; a field whose owner type cannot be resolved is skipped (type-qualified only -> precise)."""
    out: set = set()
    for _label, text in files:
        lines = text.splitlines()
        for i, ln in enumerate(lines):
            for rx in (_FIELD_WRITE, _FIELD_ASSIGN):
                for m in rx.finditer(ln):
                    var, field = m.group(1), m.group(2)
                    typ = resolve_type(lines, i, var)
                    if typ:
                        out.add(f"{typ}.{field}")
    return out


def field_untrusted(lines: list, idx: int, expr: str, wire_fields: set):
    """A link when `expr` reads a struct field that `wire_fields` records as wire-filled (TYPE-
    qualified), else None. This is the interprocedural source the intraprocedural link cannot see."""
    if not wire_fields:
        return None
    var, field = _field_parts(expr)
    if not field:
        return None
    typ = resolve_type(lines, idx, var)
    if typ and f"{typ}.{field}" in wire_fields:
        return {"via": "wire-field", "source": f"{typ}.{field} (wire-filled struct field)"}
    return None


def untrusted_strength(lines: list, idx: int, expr: str, wire_fields: set | None = None,
                       ret_funcs: set | None = None):
    """(strength, link) where strength is 'strong' | 'weak' | None. This is the PRECISION layer over
    untrusted_link: a value is STRONGLY untrusted when it comes from a real input reader, is argv, or
    is a parameter of an ENTRY POINT (main) or a PEER-DATA PARSER (by role name) -- there the
    attacker genuinely controls it. A plain parameter of a generic function is only WEAKLY untrusted
    (a forwarding wrapper whose caller decides) -- not enough to call a site an exploitable finding
    without over-approximating every wrapper. No link at all -> (None, None).

    `wire_fields` (Phase A) and `ret_funcs` (Phase B) are the interprocedural sources: a struct field
    this project fills from the wire, and a function whose return value is wire-derived. Both only
    RAISE strength, so a caller that supplies neither gets exactly the old intraprocedural behaviour.
    """
    link = untrusted_link(lines, idx, expr, ret_funcs=ret_funcs)
    if link:
        if link["via"] == "input-reader" or "argv" in (link.get("source") or ""):
            return "strong", link
        # link["via"] == "parameter": strong only in an entry point (main), a role-named parser, or a
        # function whose signature takes a wire/stream buffer (its parameters ARE wire data).
        start, _ = enclosing(lines, idx)
        fn = enclosing_name(lines, idx)
        sig = lines[start] if 0 <= start < len(lines) else ""
        if fn == "main" or is_parser_name(fn) or is_parser_sig(sig):
            return "strong", link
        # a weak intraprocedural link can still be RAISED to strong by a wire-field match
        fl = field_untrusted(lines, idx, expr, wire_fields) if wire_fields else None
        return ("strong", fl) if fl else ("weak", link)
    fl = field_untrusted(lines, idx, expr, wire_fields) if wire_fields else None
    if fl:
        return "strong", fl
    return None, None


def any_untrusted_strength(lines: list, idx: int, idents, wire_fields: set | None = None,
                           ret_funcs: set | None = None):
    """The strongest untrusted link among several candidate identifiers: (strength, link). 'strong'
    beats 'weak' beats None (so one genuinely-untrusted operand decides). `wire_fields` (Phase A) and
    `ret_funcs` (Phase B) are forwarded to the interprocedural sources (default None = intra only)."""
    best = (None, None)
    rank = {None: 0, "weak": 1, "strong": 2}
    for ident in idents:
        s, link = untrusted_strength(lines, idx, ident, wire_fields=wire_fields, ret_funcs=ret_funcs)
        if rank[s] > rank[best[0]]:
            best = (s, link)
            if s == "strong":
                break
    return best
