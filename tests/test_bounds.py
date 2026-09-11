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


# ---------------------------------------------------------------- dominating guards
# `if (n < sizeof buf) memcpy(buf, s, n);` is the shape of nearly every real bounds check, and
# it leaves the length a local rather than a constant -- 37 of jhead's 42 copy sites. Reading
# the dominating comparison is what turns those from "cannot tell" into a verdict.
_SLOT_DISP = "0xfffffffffffffffc"     # RBP-4, where the guarded length lives


def _len_from_slot():
    """memcpy(buf, src, n) with `n` loaded from RBP-4 instead of an immediate."""
    return [
        _i("0x2000", [f"INT_ADD reg:RBP:8 const:{_DISP}:8 -> unique:0x9100:8",
                      "COPY unique:0x9100:8 -> reg:RAX:8"], "LEA RAX,[RBP+disp]"),
        _i("0x2004", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x8f00:8",
                      "LOAD const:0x1b1:4 unique:0x8f00:8 -> reg:RDX:8"], "MOV EDX,[RBP-4]"),
        _i("0x2008", ["COPY reg:RAX:8 -> reg:RDI:8"], "MOV RDI,RAX"),
        _i("0x200c", ["CALL ram:0x9000:8"], "CALL memcpy"),
    ]


def _guard(cmp_pcode, mnemonic, taken="0x2000", fallthrough="0x3000"):
    """One block comparing [RBP-4] against a constant and branching on the result."""
    return {"addr": "0x1000", "succ": [taken, fallthrough], "instructions": [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x8f00:8",
                      "LOAD const:0x1b1:4 unique:0x8f00:8 -> unique:0x8f10:4"], "MOV EAX,[RBP-4]"),
        _i("0x1008", cmp_pcode + [f"CBRANCH ram:{taken}:8 unique:0x8f20:1"],
           f"{mnemonic} {taken}"),
    ]}


def _blocks(guard):
    return [guard,
            {"addr": "0x2000", "succ": [], "instructions": _len_from_slot()},
            {"addr": "0x3000", "succ": [], "instructions": []}]


def _classify(guard):
    return bounds.classify_site(_len_from_slot(), "0x200c", "memcpy", _FRAME, "x86-64",
                                blocks=_blocks(guard), site_block="0x2000")


_LESS_64 = ["INT_SLESS unique:0x8f10:4 const:0x40:4 -> unique:0x8f20:1"]
_LESSEQ_64 = ["INT_SLESSEQUAL unique:0x8f10:4 const:0x40:4 -> unique:0x8f20:1"]


def test_a_dominating_less_than_check_bounds_the_copy():
    """`if (n < 64) memcpy(buf, s, n)` on a 64-byte buf: the largest n that reaches is 63."""
    v = _classify(_guard(_LESS_64, "JL"))
    assert v["verdict"] == bounds.SAFE and v["bound"] == 63 and v["guard"] is True


def test_the_bound_is_inclusive_for_a_less_or_equal_check():
    """`n <= 64` admits exactly 64, which still fits -- off by one here would be a false alarm."""
    v = _classify(_guard(_LESSEQ_64, "JLE"))
    assert v["verdict"] == bounds.SAFE and v["bound"] == 64


def test_polarity_is_read_from_the_branch_not_assumed():
    """The guarded body is just as often the fall-through (`JGE skip`). Taking the taken-edge
    relation regardless of which way control went would invert every one of those, turning an
    unbounded copy into a confident 'safe'."""
    g = _guard(["INT_SLESS unique:0x8f10:4 const:0x40:4 -> unique:0x8f20:1"], "JGE",
               taken="0x3000", fallthrough="0x2000")
    v = _classify(g)
    assert v["verdict"] == bounds.SAFE and v["bound"] == 63


def test_a_check_that_does_not_protect_the_buffer_is_surfaced():
    """`if (n < 4096) memcpy(buf64, s, n)` is a bounds check that permits a 4 KiB overflow --
    the guard exists, so it reads as careful code, and it is still wrong."""
    g = _guard(["INT_SLESS unique:0x8f10:4 const:0x1000:4 -> unique:0x8f20:1"], "JL")
    v = _classify(g)
    assert v["verdict"] == bounds.SUSPECT and v["bound"] == 4095
    assert "does not protect the buffer" in v["why"]


def test_a_null_test_is_not_a_size_bound():
    """`if (p) memcpy(...)` compares against 0. Reading it as a length bound yielded 'at most
    0 bytes reach this copy' on jhead's DoCommand -- a safe verdict derived from an unrelated
    comparison, which is exactly how a real overflow gets silently demoted."""
    g = _guard(["INT_EQUAL unique:0x8f10:4 const:0x0:4 -> unique:0x8f20:1"], "JNE")
    v = _classify(g)
    assert v["verdict"] == bounds.UNKNOWN and "not a compile-time constant" in v["why"]


def test_an_unreadable_branch_polarity_makes_no_claim():
    """An unrecognised mnemonic must yield no bound. Guessing would manufacture 'safe'."""
    g = _guard(_LESS_64, "JXX")
    assert bounds.guard_bound(_blocks(g), "0x2000", ("RBP", -4)) is None


def test_a_non_dominating_check_is_ignored():
    """A check on only ONE path into the copy bounds nothing: the other path reaches it
    unchecked, and that path is where the bug lives."""
    g = _guard(_LESS_64, "JL")
    blks = _blocks(g) + [{"addr": "0x4000", "succ": ["0x2000"], "instructions": []}]
    blks[0]["succ"] = ["0x2000", "0x4000"]            # 0x4000 also falls into the copy
    blks[1]["succ"] = []
    # entry -> 0x4000 -> 0x2000 means 0x1000 still dominates; make the check its own block
    blks[0]["instructions"] = []
    blks.append({"addr": "0x5000", "succ": ["0x2000"],
                 "instructions": _guard(_LESS_64, "JL")["instructions"]})
    blks[0]["succ"] = ["0x5000", "0x4000"]
    assert bounds.guard_bound(blks, "0x2000", ("RBP", -4)) is None


def test_the_tightest_dominating_bound_wins():
    """Nested checks intersect: two guards mean the smaller limit is the one that holds."""
    outer = _guard(["INT_SLESS unique:0x8f10:4 const:0x1000:4 -> unique:0x8f20:1"], "JL",
                   taken="0x1800")
    inner = _guard(_LESS_64, "JL")
    inner["addr"] = "0x1800"
    blks = [outer, inner,
            {"addr": "0x2000", "succ": [], "instructions": _len_from_slot()},
            {"addr": "0x3000", "succ": [], "instructions": []}]
    assert bounds.guard_bound(blks, "0x2000", ("RBP", -4))[0] == 63


def test_dominators_are_computed_over_the_real_cfg():
    blks = [{"addr": "a", "succ": ["b", "c"]}, {"addr": "b", "succ": ["d"]},
            {"addr": "c", "succ": ["d"]}, {"addr": "d", "succ": []}]
    dom = bounds.dominators(blks)
    assert dom["d"] == {"a", "d"} and dom["b"] == {"a", "b"}
