"""Taint from sources that fill a BUFFER rather than return the data.

`read(fd, buf, n)` returns a byte count; the untrusted bytes land in `buf`. Seeding taint on
the return register alone models `getchar()` correctly and every file-reading parser not at
all -- which is most of what this platform is pointed at.

Measured on a fixture with two paths to the SAME sink carrying the SAME untrusted data, one
via argv and one via `fread` into a buffer: the argv path was corroborated and the fread path
was not flagged. Cross-component taint never fired at all on the commonest shape there is --
a program that reads a file and hands the buffer to a library -- reporting
`cross_findings: 0` on a program/library pair whose library CWE-121 had already been detected
and whose link edge had already been resolved.
"""
from lykos.analyze.detect import taint
from lykos.analyze.detect.catalog import OUT_PARAM_SOURCES, SOURCES


class _Edge:
    def __init__(self, site, name, src="0x1000"):
        self.site_addr, self.dst_name, self.src_addr = site, name, src
        self.dst_addr, self.external = None, True


def _fn(*instrs):
    return {"blocks": [{"addr": "0x1000", "instructions": list(instrs)}]}


def _i(addr, *pcode):
    return {"addr": addr, "pcode": list(pcode)}


# x86-64: RBP-relative buffer, address staged into RDI, fread fills it, then strcpy reads it.
#   char line[0x210]; fread(line, 1, 0x1ff, f); strcpy(dst, line);
_BUF = "const:0xfffffffffffffdf0:8"          # -0x210, as the decompiler emits it (unsigned)
_DST = "const:0xfffffffffffffdb0:8"          # -0x250


def _fread_then_strcpy():
    return _fn(
        # &line -> RDI   (the address is built into a UNIQUE, then copied to a register)
        _i("0x10", f"INT_ADD reg:RBP:8 {_BUF} -> unique:0x9100:8",
                   "COPY unique:0x9100:8 -> reg:RAX:8"),
        _i("0x14", "COPY reg:RAX:8 -> reg:RDI:8"),
        _i("0x20", "CALL ram:0x2000:8"),                       # fread(line, ...)
        # strcpy(dst, line)
        _i("0x30", f"INT_ADD reg:RBP:8 {_BUF} -> unique:0x9100:8",
                   "COPY unique:0x9100:8 -> reg:RDX:8"),
        _i("0x34", f"INT_ADD reg:RBP:8 {_DST} -> unique:0x9200:8",
                   "COPY unique:0x9200:8 -> reg:RAX:8"),
        _i("0x38", "COPY reg:RDX:8 -> reg:RSI:8"),
        _i("0x3c", "COPY reg:RAX:8 -> reg:RDI:8"),
        _i("0x40", "CALL ram:0x3000:8"),                       # strcpy
    )


def test_a_buffer_filling_source_taints_the_buffer():
    edges = [_Edge("0x20", "fread"), _Edge("0x40", "strcpy")]
    flagged = taint.analyze_program({"0x1000": _fread_then_strcpy()}, edges, "x86-64")
    assert "0x40" in flagged, "fread fills `line`; strcpy(dst, line) is the flow"


def test_the_same_shape_with_a_non_buffer_source_is_not_flagged():
    """`getenv` returns its data, so nothing was written into the buffer and the strcpy reads
    whatever was already there. Tainting the buffer regardless would be inventing a flow."""
    edges = [_Edge("0x20", "getenv"), _Edge("0x40", "strcpy")]
    flagged = taint.analyze_program({"0x1000": _fread_then_strcpy()}, edges, "x86-64")
    assert "0x40" not in flagged


def test_the_address_of_tainted_memory_is_a_tainted_pointer():
    """And the rule has to run AFTER the generic one, which otherwise clears it: `RBP + const`
    has no tainted input, so the frame base looks clean even when the slot it names holds
    attacker bytes, and the generic `_define(..., False)` discards the fact on the very
    instruction that established it."""
    import inspect
    src = inspect.getsource(taint._apply)
    generic = src.index("_define(taint, outk, any(k in taint for k in ins))")
    rule = src.index("slots.get(outk) in taint")
    assert rule > generic, "the address-of-tainted-memory rule must come after the generic one"


def test_alias_tracking_follows_a_frame_address_through_a_unique():
    """The address is computed into a UNIQUE and then copied to a register:
        INT_ADD RBP,-0x210 -> unique ; COPY unique -> RAX ; COPY RAX -> RDI
    `_track_alias` returns early unless the output is a register, so the unique is never
    recorded, and the chain never starts -- leaving no register known to point into the frame,
    which is what a call site needs to recognise a buffer argument."""
    bases, aliases, consts, slots = {"RBP", "RSP"}, {}, {}, {}
    for pc in (f"INT_ADD reg:RBP:8 {_BUF} -> unique:0x9100:8",
               "COPY unique:0x9100:8 -> reg:RAX:8",
               "COPY reg:RAX:8 -> reg:RDI:8"):
        mnem, _ins, outk, toks = taint._parse(pc)
        if mnem == "INT_ADD" and outk is not None:
            sl = taint._frame_slot(toks, consts, bases, aliases)
            if sl:
                slots[outk] = sl
        taint._track_alias(outk, mnem, toks, consts, bases, aliases, slots)
    assert ("reg", "RDI") in aliases, aliases
    assert aliases[("reg", "RDI")] == aliases[("reg", "RAX")]


def test_the_out_param_table_agrees_with_the_source_list():
    """Every out-parameter source must be a source, and the two that genuinely RETURN their
    data must not be in the table."""
    assert set(OUT_PARAM_SOURCES) <= SOURCES
    for name in ("getchar", "fgetc", "getenv"):
        assert name not in OUT_PARAM_SOURCES, name
    for name in ("read", "fread", "recv", "fgets", "gets"):
        assert name in OUT_PARAM_SOURCES, name
