"""Can this copy actually exceed its destination?

The rule channel flags every memcpy/strncpy and the taint channel confirms "attacker data
reaches it", which on a file parser is true of nearly everything -- on jhead that produced 20
LOW findings amounting to "this program calls memcpy". Neither asks the question that decides
whether it is a bug.
"""
from lykos.analyze.detect import bounds


def _i(addr, pcode, text=""):
    return {"addr": addr, "text": text, "pcode": pcode}


# gcc -O0 x86-64 argument set-up for memcpy(<frame slot>, src, <constant>)
def _copy_block(disp_hex, length, site="0x100c"):
    return [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{disp_hex}:8 -> unique:0x9100:8",
                      "COPY unique:0x9100:8 -> reg:RAX:8"], "LEA RAX,[RBP+disp]"),
        _i("0x1004", [f"COPY const:{length:#x}:8 -> reg:RDX:8"], "MOV EDX,len"),
        _i("0x1008", ["COPY reg:RAX:8 -> reg:RDI:8"], "MOV RDI,RAX"),
        _i(site, ["CALL ram:0x9000:8"], "CALL memcpy"),
    ]


# Ghidra numbers frame variables from the return-address slot, so a variable it places at
# -0x1020 is addressed as RBP-0x1018 on x86-64 (one word up). Measured on jhead: exactly 8,
# in 8 of 8 resolvable sites.
_FRAME = {"ret_offset": 0, "vars": [{"name": "buf", "size": 64, "offset": -0x1020,
                                     "is_buffer": True, "type": "char[64]"}]}
_DISP = "0xffffffffffffefe8"          # -0x1018 == frame offset -0x1020 + 8


def test_a_constant_that_fits_is_provably_bounded():
    """`memcpy(buf, src, sizeof buf)` compiles to exactly this and is not a defect."""
    v = bounds.classify_site(_copy_block(_DISP, 64), "0x100c", "memcpy", _FRAME, "x86-64")
    assert v["verdict"] == bounds.SAFE
    assert v["buffer"] == "buf" and v["capacity"] == 64 and v["length"] == 64


def test_a_constant_that_does_not_fit_is_surfaced_but_never_asserted():
    """C locals in disjoint scopes SHARE stack slots, so a recovered frame can name the wrong
    variable and the wrong size for an address. jhead's ProcessFile is the worked example: the
    source has `char Comment[16001]` at RBP-0x3f50 and copies 16000 into it -- safe -- while
    Ghidra's frame table calls that exact offset `st`, a 144-byte struct stat from a sibling
    scope. Asserting an overflow there would fabricate a critical finding in correct code.
    """
    v = bounds.classify_site(_copy_block(_DISP, 4096), "0x100c", "memcpy", _FRAME, "x86-64")
    assert v["verdict"] == bounds.SUSPECT
    assert v["verdict"] != "overflow", "must not claim a confirmed overflow"
    assert "review" in v["why"] and "reused between scopes" in v["why"]


def test_a_non_constant_length_stays_unknown():
    """No arithmetic reason, no verdict -- the finding is left exactly as the rule left it."""
    blk = [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{_DISP}:8 -> unique:0x9100:8",
                      "COPY unique:0x9100:8 -> reg:RAX:8"]),
        _i("0x1004", ["INT_ADD reg:RBP:8 const:0xfffffffffffffffc:8 -> unique:0x8f00:8",
                      "LOAD const:0x1b1:4 unique:0x8f00:8 -> reg:RDX:8"]),   # a local, not a const
        _i("0x1008", ["COPY reg:RAX:8 -> reg:RDI:8"]),
        _i("0x100c", ["CALL ram:0x9000:8"]),
    ]
    v = bounds.classify_site(blk, "0x100c", "memcpy", _FRAME, "x86-64")
    assert v["verdict"] == bounds.UNKNOWN and "not a compile-time constant" in v["why"]


def test_an_address_with_no_recovered_variable_stays_unknown():
    """Matching an address that merely falls INSIDE a recovered variable invents an answer:
    the frame table is incomplete, and the real buffer may simply not be in it."""
    v = bounds.classify_site(_copy_block("0xfffffffffffff000", 64), "0x100c", "memcpy",
                             _FRAME, "x86-64")
    assert v["verdict"] == bounds.UNKNOWN
    assert "no variable recovered at exactly" in v["why"]


def test_frame_delta_is_derived_from_the_frames_own_return_slot():
    assert bounds.frame_delta({"ret_offset": 0}, 8) == 8
    assert bounds.frame_delta({"ret_offset": 0}, 4) == 4       # 32-bit
    assert bounds.frame_delta({"ret_offset": -8}, 8) == 16     # a differently numbered frame
    assert bounds.frame_delta({}, 8) == 8


def test_sinks_without_an_explicit_length_are_out_of_scope():
    """strcpy/strcat copy until NUL, so the bound is the SOURCE -- which this pass cannot see.
    Guessing there would be exactly the fabrication this design avoids."""
    assert "strcpy" not in bounds.COPY_ARGS
    assert "strcat" not in bounds.COPY_ARGS
    assert bounds.classify_site(_copy_block(_DISP, 64), "0x100c", "strcpy",
                                _FRAME, "x86-64") is None
