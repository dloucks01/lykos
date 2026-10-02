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


# Some decompiler builds number locals from the FRAME POINTER directly (var offset == the RBP
# displacement), not from the return slot -- and ret_offset does not disambiguate the two. The
# destination then resolved one word off the recovered buffer, _capacity saw "no variable", and
# the safe idiom (memcpy/strncpy bounded to sizeof) read as corroborated. This is 2 of the 3
# CWE-120 corroborated false positives in the micro-corpus.
_FRAME_FP = {"ret_offset": 0, "vars": [{"name": "buf", "size": 64, "offset": -64,
                                        "is_buffer": True, "type": "char[64]"}]}
_FP_DISP = "0xffffffffffffffc0"        # RBP-64 == the buffer's frame offset (no ret-slot adjust)


def test_frame_pointer_numbered_buffer_is_resolved_by_calibration():
    """A buffer Ghidra numbers at its RBP displacement (identity convention) must still be found
    as the copy's destination, so a bounded copy into it is proven SAFE rather than left
    corroborated. Regression for the capacity calibration fallback."""
    v = bounds.classify_site(_copy_block(_FP_DISP, 63), "0x100c", "memcpy", _FRAME_FP, "x86-64")
    assert v["verdict"] == bounds.SAFE, v
    assert v["buffer"] == "buf" and v["capacity"] == 64 and v["length"] == 63


def test_calibration_never_attributes_a_copy_to_a_non_buffer():
    """The calibration fallback matches ONLY a variable recovered as a buffer, at its exact
    start -- it must not resurrect the interior/wrong-variable attribution the exact-match rule
    prevents. A non-buffer local at the displacement stays unknown, never a fabricated size."""
    frame = {"ret_offset": 0, "vars": [{"name": "st", "size": 144, "offset": -64,
                                        "is_buffer": False, "type": "struct stat"}]}
    v = bounds.classify_site(_copy_block(_FP_DISP, 16000), "0x100c", "memcpy", frame, "x86-64")
    assert v["verdict"] == bounds.UNKNOWN, v
    assert v.get("buffer") != "st"


def test_a_constant_that_does_not_fit_is_surfaced_but_never_asserted():
    """C locals in disjoint scopes SHARE stack slots, so a recovered frame can name the wrong
    variable and the wrong size for an address. jhead's ProcessFile is the worked example: the
    source has `char Comment[16001]` at RBP-0x3f50 and copies 16000 into it -- safe -- while
    Ghidra's frame table calls that exact offset `st`, a 144-byte struct stat from a sibling
    scope. Asserting an overflow there would fabricate a critical finding in correct code.

    A copy that clears the whole frame is past any variable it could have been, so that one
    is still surfaced -- for review, never as a confirmed overflow.
    """
    v = bounds.classify_site(_copy_block(_DISP, 1 << 20), "0x100c", "memcpy", _FRAME, "x86-64")
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
# it leaves the length a local rather than a constant -- 37 of jhead's 42 copy sites.
#
# The P-Code below is TRANSCRIBED from gcc -O0 output, not invented, because the whole point of
# reading the condition out of P-Code instead of off the branch mnemonic is that the mnemonic
# tables were an x86 fiction. Three idioms, measured on a 13-architecture fixture:
#   flag registers      x86/x86-32/aarch64/arm/m68k -- CF/OF/SF/ZF, each an explicit op, then
#                       boolean algebra (x86 JA is !(CF|ZF); aarch64 b.hi is CY & !ZR)
#   direct compare      riscv/loongarch/sh -- constant in a REGISTER, operands reversed
#   condition bitfield  ppc/ppc64 -- lt/gt/eq packed into cr0, one bit extracted to branch
_SLOT_DISP = "0xfffffffffffffffc"     # RBP-4, where the guarded length lives
_SLOT = ("RBP", -4)


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


# ---- x86: `CMP dword ptr [RBP-4],k` defines four flags with four separate comparisons
def _x86_cmp(k):
    return [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x6600:8",
            "LOAD const:0x1a1:4 unique:0x6600:8 -> unique:0x17200:4",
            "COPY unique:0x17200:4 -> unique:0x66100:4",
            f"INT_LESS unique:0x66100:4 const:{k:#x}:4 -> reg:CF:1",
            f"INT_SBORROW unique:0x66100:4 const:{k:#x}:4 -> reg:OF:1",
            f"INT_SUB unique:0x66100:4 const:{k:#x}:4 -> unique:0x66300:4",
            "INT_SLESS unique:0x66300:4 const:0x0:4 -> reg:SF:1",
            "INT_EQUAL unique:0x66300:4 const:0x0:4 -> reg:ZF:1"]


_X86_COND = {
    # signed >: ZF==0 && SF==OF
    "JG": (["BOOL_NEGATE reg:ZF:1 -> unique:0x18d00:1",
            "INT_EQUAL reg:OF:1 reg:SF:1 -> unique:0x18e00:1",
            "BOOL_AND unique:0x18d00:1 unique:0x18e00:1 -> unique:0x19000:1"], "unique:0x19000:1"),
    # unsigned >: !(CF || ZF)
    "JA": (["BOOL_OR reg:CF:1 reg:ZF:1 -> unique:0x25200:1",
            "BOOL_NEGATE unique:0x25200:1 -> unique:0x19000:1"], "unique:0x19000:1"),
    "JS": ([], "reg:SF:1"),          # sign of the difference; only sound against zero
    "JE": ([], "reg:ZF:1"),
}


def _x86_guard(k, cond, taken, fallthrough, addr="0x1000"):
    pre, varnode = _X86_COND[cond]
    return {"addr": addr, "succ": [taken, fallthrough], "instructions": [
        _i(addr, _x86_cmp(k), f"CMP dword ptr [RBP-4],{k:#x}"),
        _i("0x1008", pre + [f"CBRANCH ram:{taken}:8 {varnode}"], f"{cond} {taken}"),
    ]}


def _blocks(*guards):
    return list(guards) + [
        {"addr": "0x2000", "succ": [], "instructions": _len_from_slot()},
        {"addr": "0x3000", "succ": [], "instructions": []}]


def _classify(*guards, frame=None):
    blocks = _blocks(*guards)
    return bounds.classify_site(_len_from_slot(), "0x200c", "memcpy", frame or _FRAME,
                                "x86-64", blocks=blocks, site_block="0x2000")


# gcc compiles `if (n < 64) ...` to `cmp $0x3f,n; jg skip` -- the branch SKIPS the body.
def _lt64_signed(): return _x86_guard(63, "JG", "0x3000", "0x2000")
def _lt64_unsigned(): return _x86_guard(63, "JA", "0x3000", "0x2000")


def test_a_dominating_unsigned_check_bounds_the_copy():
    """`if (n < 64)` on an unsigned n: the largest value that reaches the copy is 63."""
    v = _classify(_lt64_unsigned())
    assert v["verdict"] == bounds.SAFE and v["bound"] == 63 and v["guard"] is True


def test_the_bound_is_inclusive_for_a_less_or_equal_check():
    """`n <= 64` admits exactly 64, which still fits -- off by one would be a false alarm."""
    v = _classify(_x86_guard(64, "JA", "0x3000", "0x2000"))
    assert v["verdict"] == bounds.SAFE and v["bound"] == 64


def test_polarity_is_read_from_the_condition_not_assumed():
    """The guarded body is as often the taken edge as the fall-through. Taking the taken-edge
    relation regardless of which way control went would invert every one of those, turning an
    unbounded copy into a confident 'safe'."""
    # here the branch jumps INTO the copy when n > 63, i.e. the copy is the unguarded path
    v = _classify(_x86_guard(63, "JA", "0x2000", "0x3000"))
    assert v["verdict"] == bounds.SUSPECT or v["verdict"] == bounds.UNKNOWN
    assert v["verdict"] != bounds.SAFE


def test_an_unreadable_condition_makes_no_claim():
    """A condition built from something the evaluator cannot follow must yield no bound.
    Guessing would manufacture 'safe' over a real overflow."""
    blk = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", _x86_cmp(63)),
        _i("0x1008", ["CALLOTHER const:0x7:4 -> unique:0x19000:1",
                      "CBRANCH ram:0x3000:8 unique:0x19000:1"], "J?? 0x3000")]}
    assert bounds.guard_bound(_blocks(blk), "0x2000", _SLOT, bases=("RBP",)) is None


def test_a_non_dominating_check_is_ignored():
    """A check on only ONE path into the copy bounds nothing: the other path reaches it
    unchecked, and that path is where the bug lives."""
    g = _lt64_unsigned()
    g["succ"] = ["0x3000", "0x4000"]
    blks = _blocks(g) + [{"addr": "0x4000", "succ": ["0x2000"], "instructions": []},
                         {"addr": "0x5000", "succ": ["0x2000"], "instructions": []}]
    blks[0]["succ"] = ["0x5000", "0x4000"]          # neither edge reaches the copy directly
    assert bounds.guard_bound(blks, "0x2000", _SLOT, bases=("RBP",)) is None


def test_the_tightest_dominating_bound_wins():
    """Nested checks intersect: two guards mean the smaller limit is the one that holds."""
    outer = _x86_guard(4095, "JA", "0x3000", "0x1800", addr="0x1000")
    inner = _x86_guard(63, "JA", "0x3000", "0x2000", addr="0x1800")
    got = bounds.guard_bound(_blocks(outer, inner), "0x2000", _SLOT, bases=("RBP",))
    assert got["bound"] == 63


def test_a_guard_block_may_have_more_than_two_successors():
    """x86-32 PIC puts `CALL __x86.get_pc_thunk.bx` in the guard block, so the call target
    sits between the taken edge and the fall-through. Assuming the first non-target successor
    was the fall-through lost every single-guard function on that ISA."""
    g = _lt64_unsigned()
    g["succ"] = ["0x10a0", "0x3000", "0x2000"]      # call target first
    v = bounds.classify_site(_len_from_slot(), "0x200c", "memcpy", _FRAME, "x86-64",
                             blocks=_blocks(g), site_block="0x2000")
    assert v["verdict"] == bounds.SAFE and v["bound"] == 63


def test_a_check_both_of_whose_edges_reach_the_copy_constrains_nothing():
    g = _x86_guard(63, "JA", "0x2000", "0x2000")   # both edges land on the copy
    assert bounds.guard_bound(_blocks(g), "0x2000", _SLOT, bases=("RBP",)) is None


# ------------------------------------------------------- signed lengths are not bounded
# `if (n < 64) memcpy(buf, s, n)` on an `int` reads as a careful bounds check and is not one:
# n = -1 passes it, and memcpy's size_t parameter takes that as 0xFFFFFFFFFFFFFFFF. Measured
# on a compiled fixture -- the site this used to call "bounded" segfaults at n = -1 (exit 139)
# while the two it still calls bounded reject it and return cleanly.
def test_a_signed_upper_bound_alone_is_not_a_bound():
    v = _classify(_lt64_signed())
    assert v["verdict"] == bounds.SIGNED
    assert v["bound"] == 63, "the upper bound is real -- it is just not the whole bound"
    assert "SIGNED" in v["why"] and "negative" in v["why"]


def test_an_unsigned_check_bounds_both_ends_at_once():
    """`unsigned n` / `size_t n` compile to the CF-based branches, and there `n < 64` really
    does prove 0 <= n <= 63. Flagging these would make the check useless on correct code."""
    assert _classify(_lt64_unsigned())["verdict"] == bounds.SAFE


def test_a_dominating_non_negative_check_closes_the_hazard():
    """`if (n >= 0 && n < 64)` -- gcc -O0 compiles the first half to `cmp $0,n; js skip`,
    which branches on the sign flag alone. That is sound only because subtracting zero cannot
    overflow, and it is the one idiom that actually fixes the hazard."""
    lo = _x86_guard(0, "JS", "0x3000", "0x1800", addr="0x1000")
    hi = _x86_guard(63, "JG", "0x3000", "0x2000", addr="0x1800")
    v = _classify(lo, hi)
    assert v["verdict"] == bounds.SAFE and v["bound"] == 63


def test_a_non_zero_check_is_not_a_lower_bound():
    """`if (n != 0 && n < 64)` still admits -1. The zero-compare is there, it just proves
    nothing about the sign -- reading it as a lower bound would reopen the hazard."""
    lo = _x86_guard(0, "JE", "0x3000", "0x1800", addr="0x1000")
    hi = _x86_guard(63, "JG", "0x3000", "0x2000", addr="0x1800")
    assert _classify(lo, hi)["verdict"] == bounds.SIGNED


def test_guard_bound_reports_the_two_halves_separately():
    assert bounds.guard_bound(_blocks(_lt64_unsigned()), "0x2000", _SLOT,
                              bases=("RBP",))["nonneg"] is True
    assert bounds.guard_bound(_blocks(_lt64_signed()), "0x2000", _SLOT,
                              bases=("RBP",))["nonneg"] is False


# ------------------------------------------------------- the other two ISA idioms
def test_a_direct_compare_against_a_register_constant_is_read():
    """RISC-V and loongarch have no flags: `li a5,0x3f; blt a5,a4` is one INT_SLESS whose
    CONSTANT lives in a register and whose operands are REVERSED. Matching a constant token
    in the comparison, as the x86-shaped first version did, reads nothing here."""
    blk = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", [f"COPY const:{_SLOT_DISP}:8 -> unique:0xf00:8",
                      "INT_ADD reg:RBP:8 unique:0xf00:8 -> unique:0x6700:8",
                      "LOAD const:0x1b1:8 unique:0x6700:8 -> unique:0x6800:4",
                      "INT_SEXT unique:0x6800:4 -> reg:R14:8"], "lw a4,-4(s0)"),
        _i("0x1004", ["COPY const:0x3f:8 -> reg:R15:8",
                      "INT_LESS reg:R15:8 reg:R14:8 -> unique:0x4200:1",
                      "CBRANCH ram:0x3000:8 unique:0x4200:1"], "bltu a5,a4,0x3000")]}
    got = bounds.guard_bound(_blocks(blk), "0x2000", _SLOT, bases=("RBP",))
    assert got == {"bound": 63, "nonneg": True,
                   "why": "guarded by a dominating check: at most 63 bytes reach this copy"}


def test_a_powerpc_condition_register_bitfield_is_read():
    """cmplwi packs lt/gt/eq into cr0 with shifts, and bgt extracts one bit. The unrelated
    xer_so bit is OR'd in from a value the evaluator cannot see, so it tracks WHICH BIT
    POSITIONS are unknown instead of discarding the whole field."""
    blk = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x1bd00:8",
                      "LOAD const:0x1a1:8 unique:0x1bd00:8 -> unique:0x5ba00:4",
                      "INT_ZEXT unique:0x5ba00:4 -> reg:R9:8"], "lwz r9,-4(r31)"),
        _i("0x1004", ["INT_ZEXT reg:_R9:4 -> unique:0x1b900:8",
                      "COPY unique:0x1b900:8 -> unique:0x2ec00:8",
                      "COPY const:0x3f:8 -> unique:0x2ed00:8",
                      "INT_LESS unique:0x2ec00:8 unique:0x2ed00:8 -> unique:0x2ee00:1",
                      "INT_LEFT unique:0x2ee00:1 const:0x3:4 -> unique:0x2ef00:1",
                      "INT_LESS unique:0x2ed00:8 unique:0x2ec00:8 -> unique:0x2f000:1",
                      "INT_LEFT unique:0x2f000:1 const:0x2:4 -> unique:0x2f100:1",
                      "INT_OR unique:0x2ef00:1 unique:0x2f100:1 -> unique:0x2f200:1",
                      "INT_EQUAL unique:0x2ec00:8 unique:0x2ed00:8 -> unique:0x2f300:1",
                      "INT_LEFT unique:0x2f300:1 const:0x1:4 -> unique:0x2f400:1",
                      "INT_OR unique:0x2f200:1 unique:0x2f400:1 -> unique:0x2f500:1",
                      "INT_AND reg:xer_so:1 const:0x1:1 -> unique:0x2f600:1",
                      "INT_OR unique:0x2f500:1 unique:0x2f600:1 -> reg:cr0:1"], "cmplwi r9,0x3f"),
        _i("0x1008", ["INT_SUB const:0x3:4 const:0x1:4 -> unique:0x1600:4",
                      "INT_RIGHT reg:cr0:1 unique:0x1600:4 -> unique:0x1800:1",
                      "INT_AND unique:0x1800:1 const:0x1:1 -> unique:0x17200:1",
                      "CBRANCH ram:0x3000:4 unique:0x17200:1"], "bgt 0x3000")]}
    got = bounds.guard_bound(_blocks(blk), "0x2000", _SLOT, bases=("RBP",))
    assert got["bound"] == 63 and got["nonneg"] is True


def test_a_superh_t_bit_compare_is_read():
    """SuperH has a single T bit and branches with `bt`, which tests it against 1."""
    blk = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x22700:4",
                      "LOAD const:0x1a1:8 unique:0x22700:4 -> reg:R2:4"], "mov.l @(disp,r1),r2"),
        _i("0x1004", ["COPY const:0x3f:4 -> reg:R1:4",
                      "INT_LESS reg:R1:4 reg:R2:4 -> reg:T:1"], "cmp/hi r1,r2"),
        _i("0x1008", ["INT_EQUAL reg:T:1 const:0x1:1 -> unique:0x8b00:1",
                      "CBRANCH ram:0x3000:4 unique:0x8b00:1"], "bt 0x3000")]}
    got = bounds.guard_bound(_blocks(blk), "0x2000", _SLOT, bases=("RBP",))
    assert got["bound"] == 63


def test_a_narrow_register_view_is_the_same_value():
    """PowerPC's `_r9` and loongarch's `t0_lo` are the low half of a tracked register, and
    treating them as unrelated lost the value between the load and the compare. `_hi` is a
    different half and must NOT be folded."""
    assert bounds._canon_reg("_r9") == "R9"
    assert bounds._canon_reg("t0_lo") == "T0"
    assert bounds._canon_reg("t0_hi") == "T0_HI"


def test_a_frame_base_stays_opaque_through_the_prologue():
    """aarch64's prologue is `INT_ADD reg:sp,-0x60 -> reg:sp`. Resolving that to an address
    made every later `sp + disp` carry the adjustment twice, so no slot ever matched and the
    whole ISA read as unguarded."""
    blk = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", ["INT_ADD reg:RBP:8 const:0xffffffffffffffa0:8 -> reg:RBP:8"], "prologue"),
        _i("0x1004", _x86_cmp(63)),
        _i("0x1008", _X86_COND["JA"][0] + ["CBRANCH ram:0x3000:8 unique:0x19000:1"], "JA")]}
    got = bounds.guard_bound(_blocks(blk), "0x2000", _SLOT, bases=("RBP",))
    assert got is not None and got["bound"] == 63


def test_base_offsets_are_derived_from_the_prologue():
    """One rule covers three conventions, so no per-ISA delta table is needed."""
    x86 = [{"addr": "0x0", "instructions": [
        _i("0x0", ["INT_SUB reg:RSP:8 const:0x8:8 -> reg:RSP:8"], "PUSH RBP"),
        _i("0x1", ["COPY reg:RSP:8 -> reg:RBP:8"], "MOV RBP,RSP")]}]
    assert bounds.base_offsets(x86, {"RBP", "RSP"}, "x86-64")["RBP"] == -8
    a64 = [{"addr": "0x0", "instructions": [
        _i("0x0", ["INT_ADD reg:SP:8 const:0xffffffffffffffa0:8 -> reg:SP:8"], "stp")]}]
    assert bounds.base_offsets(a64, {"SP", "X29"}, "aarch64")["SP"] == -96
    la = [{"addr": "0x0", "instructions": [
        _i("0x0", ["INT_ADD reg:SP:8 const:0xffffffffffffffa0:8 -> reg:SP:8"], "addi.d"),
        _i("0x4", ["INT_ADD reg:SP:8 const:0x60:8 -> reg:FP:8"], "addi.d fp,sp,0x60")]}]
    assert bounds.base_offsets(la, {"SP", "FP"}, "loongarch")["FP"] == 0


# ------------------------------------------------------- an overflow claim must clear the frame
def test_a_copy_that_fits_the_frame_does_not_claim_an_overflow():
    """Ghidra fragments buffers: on ppc64le it reported a char[64] as four 8-byte locals, so
    every correct function read as an overflow of an 8-byte variable. The address is right and
    the size is not. A copy that still fits the frame below the destination cannot be told
    apart from a fragmented buffer, so it stays unknown."""
    v = bounds.classify_site(_copy_block(_DISP, 4096), "0x100c", "memcpy", _FRAME, "x86-64")
    assert v["verdict"] == bounds.UNKNOWN and "fragments buffers" in v["why"]


def test_a_guard_that_overruns_the_whole_frame_is_surfaced():
    v = _classify(_x86_guard(1 << 20, "JA", "0x3000", "0x2000"))
    assert v["verdict"] == bounds.SUSPECT and "does not protect the buffer" in v["why"]


# ------------------------------------------------- strcpy, bounded by a check on strlen(src)
# COPY_ARGS excludes strcpy because "the bound is the SOURCE, which this pass cannot see". It
# can see one very common case: the program measures the source with strlen, spills the
# result, and a dominating check compares that slot against a constant. Both of gzip 1.3.5's
# high-severity CWE-121 candidates are that shape and both are safe -- `get_suffix` guards
# `strcpy(suffix,name)` with `nlen <= MAX_SUFFIX+2` against a 33-byte buffer.
def test_strcat_is_deliberately_not_bounded_this_way():
    """strcat APPENDS, so bounding strlen(src) says nothing without knowing what the
    destination already holds. Treating it like strcpy would demote real overflows."""
    assert "strcat" not in bounds.NUL_COPY_ARGS
    assert "strcpy" in bounds.NUL_COPY_ARGS


def test_a_spilled_return_value_is_found_after_the_call():
    """The backward slice stops at the call, but strlen's result is stored AFTER it -- which
    is the only place a guard can read it from."""
    instrs = [
        _i("0x100", ["CALL ram:0x9000:8"], "CALL strlen"),
        _i("0x104", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x10:8",
                     "STORE const:0x1b1:4 unique:0x10:8 reg:RAX:8"], "MOV [RBP-4],EAX"),
    ]
    assert bounds._spill_slot(instrs, "0x100", {("reg", "RAX")}, ("RBP",), 64) == ("RBP", -4)


def test_a_return_value_clobbered_by_another_call_is_not_tracked():
    """Once a second call runs, the return register no longer holds the length."""
    instrs = [
        _i("0x100", ["CALL ram:0x9000:8"], "CALL strlen"),
        _i("0x104", ["CALL ram:0x9100:8"], "CALL something_else"),
        _i("0x108", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x10:8",
                     "STORE const:0x1b1:4 unique:0x10:8 reg:RAX:8"], "MOV [RBP-4],EAX"),
    ]
    assert bounds._spill_slot(instrs, "0x100", {("reg", "RAX")}, ("RBP",), 64) is None


def _strlen_block(src_disp, guard_k):
    """`nlen = strlen(name); if (nlen <= K) ...` as gcc -O0 emits it."""
    return {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{src_disp}:8 -> unique:0x20:8",
                      "LOAD const:0x1b1:8 unique:0x20:8 -> reg:RDI:8"], "MOV RDI,[RBP+src]"),
        _i("0x1004", ["CALL ram:0x9000:8"], "CALL strlen"),
        _i("0x1008", [f"INT_ADD reg:RBP:8 const:{_SLOT_DISP}:8 -> unique:0x10:8",
                      "STORE const:0x1b1:4 unique:0x10:8 reg:RAX:8"], "MOV [RBP-4],EAX"),
        _i("0x100c", _x86_cmp(guard_k), f"CMP dword ptr [RBP-4],{guard_k:#x}"),
        _i("0x1010", _X86_COND["JA"][0] + ["CBRANCH ram:0x3000:8 unique:0x19000:1"],
           "JA 0x3000"),
    ]}


_SRC_DISP = "0xffffffffffffffe8"          # RBP-0x18, where the source pointer lives


def test_a_dominating_strlen_check_bounds_a_strcpy():
    blk = _strlen_block(_SRC_DISP, 32)
    blocks = _blocks(blk)
    src = ("load", "RBP", -0x18)
    got = bounds.strlen_bound(blocks, "0x2000", "0x200c", src, [("0x1004", "0x1000")],
                              ("RBP", "RSP"), 64, bounds.ARCH_ABI["x86-64"],
                              bounds.dominators(blocks))
    assert got is not None and got["bound"] == 32


def test_measuring_a_DIFFERENT_string_proves_nothing():
    """Bounding some other string's length would demote a real overflow on the strength of an
    unrelated check -- the exact failure this module exists to avoid."""
    blocks = _blocks(_strlen_block(_SRC_DISP, 32))
    other = ("load", "RBP", -0x40)                # not the pointer strlen measured
    assert bounds.strlen_bound(blocks, "0x2000", "0x200c", other, [("0x1004", "0x1000")],
                               ("RBP", "RSP"), 64, bounds.ARCH_ABI["x86-64"],
                               bounds.dominators(blocks)) is None


def test_an_unmeasured_strcpy_stays_unknown():
    """No strlen, no bound -- the finding is left exactly as the rule left it."""
    blocks = _blocks(_strlen_block(_SRC_DISP, 32))
    assert bounds.strlen_bound(blocks, "0x2000", "0x200c", ("load", "RBP", -0x18), [],
                               ("RBP", "RSP"), 64, bounds.ARCH_ABI["x86-64"],
                               bounds.dominators(blocks)) is None


def _argv1_load(out_reg):
    """`v[1]` as gcc -O0 emits it: *(*(RBP-0x50) + 8) -- a double indirection (load argv, add 8,
    deref). The slice must carry it as a canonical value so the same source correlates between a
    strlen guard and the strcpy it protects."""
    return [f"INT_ADD reg:RBP:8 const:0xffffffffffffffb0:8 -> unique:0x20:8",   # RBP-0x50
            "LOAD const:0x1b1:8 unique:0x20:8 -> reg:RAX:8",                     # RAX = argv
            "INT_ADD reg:RAX:8 const:0x8:8 -> reg:RAX:8",                        # RAX = argv + 8
            f"LOAD const:0x1b1:8 reg:RAX:8 -> reg:{out_reg}:8"]                  # out = argv[1]


_ARGV1 = ("loadp", ("load", "RBP", -0x50), 8)


def test_slice_resolves_double_indirection_argv1():
    """argv[1] -- a load through a loaded pointer -- resolves to a canonical ('loadp', ...) value
    instead of being dropped, which is what lets the source be correlated across blocks."""
    vals, _ = bounds._slice_block([_i("0x1000", _argv1_load("RDI"))], "0xffff", ("RBP",), 64)
    assert vals.get(("reg", "RDI")) == _ARGV1


def _x86_cmp_reg(reg, k):
    """`cmp reg, K` -- the length compared DIRECTLY in a register (no spill), as `if (strlen(x) <
    K)` emits at -O0 with the result still in the return register."""
    return [f"COPY reg:{reg}:8 -> unique:0x66100:4",
            f"INT_LESS unique:0x66100:4 const:{k:#x}:4 -> reg:CF:1",
            f"INT_SBORROW unique:0x66100:4 const:{k:#x}:4 -> reg:OF:1",
            f"INT_SUB unique:0x66100:4 const:{k:#x}:4 -> unique:0x66300:4",
            "INT_SLESS unique:0x66300:4 const:0x0:4 -> reg:SF:1",
            "INT_EQUAL unique:0x66300:4 const:0x0:4 -> reg:ZF:1"]


def test_strlen_guard_on_the_result_register_bounds_a_double_indirected_source():
    """`if (strlen(v[1]) < sizeof b) strcpy(b, v[1])`: the source is argv[1] (double indirection)
    and the guard compares the strlen RESULT REGISTER directly, with no spill. Both halves --
    correlating the source and reading the register guard -- must line up for the copy to be
    proven bounded. This is the 3rd CWE-120 corroborated false positive."""
    strlen_blk = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", _argv1_load("RDI"), "RDI = v[1]"),
        _i("0x1004", ["CALL ram:0x9000:8"], "CALL strlen"),
        _i("0x1008", _x86_cmp_reg("RAX", 0x3f), "CMP RAX,0x3f"),
        _i("0x100c", _X86_COND["JA"][0] + ["CBRANCH ram:0x3000:8 " + _X86_COND["JA"][1]],
           "JA 0x3000"),
    ]}
    blocks = [strlen_blk,
              {"addr": "0x2000", "succ": ["0x3000"], "instructions": []},  # the strcpy block
              {"addr": "0x3000", "succ": [], "instructions": []}]          # the skip block
    got = bounds.strlen_bound(blocks, "0x2000", "0x200c", _ARGV1, [("0x1004", "0x1000")],
                              ("RBP", "RSP"), 64, bounds.ARCH_ABI["x86-64"],
                              bounds.dominators(blocks))
    assert got is not None and got["bound"] == 0x3f and got["nonneg"] is True


def _heap_copy_block(slot_disp, length, site="0x100c"):
    """memcpy(p, src, <const>) where the destination pointer p is LOADED from a frame slot (a
    heap buffer), not a stack-buffer address."""
    return [
        _i("0x1000", [f"INT_ADD reg:RBP:8 const:{slot_disp}:8 -> unique:0x20:8",
                      "LOAD const:0x1b1:8 unique:0x20:8 -> reg:RDI:8"], "MOV RDI,[RBP+slot]"),
        _i("0x1004", [f"COPY const:{length:#x}:8 -> reg:RDX:8"], "MOV EDX,len"),
        _i(site, ["CALL ram:0x9000:8"], "CALL memcpy"),
    ]


def test_heap_destination_capacity_bounds_a_constant_copy():
    """A copy into a malloc()'d buffer of known size is judged against that size (exact, unlike a
    fragmented stack frame): a constant that fits is SAFE, one that exceeds it SUSPECT, and
    without a tracked capacity the destination is simply unknown."""
    caps = {("RBP", -8): 64}
    safe = bounds.classify_site(_heap_copy_block("0xfffffffffffffff8", 32), "0x100c", "memcpy",
                                {}, "x86-64", heap_caps=caps)
    assert safe["verdict"] == bounds.SAFE and safe["capacity"] == 64 and safe["length"] == 32
    over = bounds.classify_site(_heap_copy_block("0xfffffffffffffff8", 100), "0x100c", "memcpy",
                                {}, "x86-64", heap_caps=caps)
    assert over["verdict"] == bounds.SUSPECT
    unk = bounds.classify_site(_heap_copy_block("0xfffffffffffffff8", 32), "0x100c", "memcpy",
                               {}, "x86-64", heap_caps={})
    assert unk["verdict"] == bounds.UNKNOWN


def _alloc_spill(size_hex, slot_disp, call_site, store_addr):
    return [_i("0x1000", [f"COPY const:{size_hex}:8 -> reg:RDI:8"], "mov edi,size"),
            _i(call_site, ["CALL ram:0x9000:8"], "call malloc"),
            _i(store_addr, [f"INT_ADD reg:RBP:8 const:{slot_disp}:8 -> unique:0x30:8",
                            "STORE const:0x1b1:8 unique:0x30:8 reg:RAX:8"], "mov [RBP+slot],RAX")]


def test_heap_capacity_only_for_a_single_writer_slot():
    """A frame slot that holds a malloc(const) and is written ONCE can never be reassigned, so
    the size is a sound capacity. A slot written again (b = malloc(256); b = malloc(64)) is
    ambiguous and must be dropped, or a stale size would demote a real overflow."""
    from types import SimpleNamespace
    edge = SimpleNamespace(dst_name="malloc", site_addr="0x1004", src_addr="0x401000")
    once = [{"addr": "0x1000", "instructions": _alloc_spill("0x40", "0xfffffffffffffff8",
                                                            "0x1004", "0x1008")}]
    caps = bounds._heap_capacities({"0x401000": {"blocks": once}}, [edge], ("RBP", "RSP"), 64,
                                   "x86-64")
    assert caps.get("0x401000", {}).get(("RBP", -8)) == 64
    # a second store to the same slot -> ambiguous -> no capacity
    twice = [{"addr": "0x1000", "instructions": once[0]["instructions"] + [
        _i("0x100c", ["INT_ADD reg:RBP:8 const:0xfffffffffffffff8:8 -> unique:0x40:8",
                      "STORE const:0x1b1:8 unique:0x40:8 reg:RCX:8"], "mov [RBP-8],RCX")]}]
    caps2 = bounds._heap_capacities({"0x401000": {"blocks": twice}}, [edge], ("RBP", "RSP"), 64,
                                    "x86-64")
    assert ("RBP", -8) not in caps2.get("0x401000", {})


def _loadp_into(out_reg, slot_disp, deref_off):
    """`out = *(*(RBP+slot_disp) + deref_off)` -- a struct field read through a pointer, e.g.
    `p->len` where p is a spilled parameter."""
    seq = [f"INT_ADD reg:RBP:8 const:{slot_disp}:8 -> unique:0x20:8",
           "LOAD const:0x1b1:8 unique:0x20:8 -> reg:RAX:8"]            # RAX = *(RBP+slot) = p
    if deref_off:
        seq.append(f"INT_ADD reg:RAX:8 const:{deref_off:#x}:8 -> reg:RAX:8")
    seq.append(f"LOAD const:0x1b1:8 reg:RAX:8 -> reg:{out_reg}:8")      # out = *(p + off)
    return seq


def test_value_guard_bounds_a_pointer_dereferenced_length():
    """A length that is a struct field `p->len` (a loadp, not a frame slot) bounded by a
    dominating `if (p->len <= K)` is proven bounded -- correlated by the equality of the resolved
    value token, since there is no frame slot to match. The length-operand analog of the source
    correlation."""
    guard = {"addr": "0x1000", "succ": ["0x3000", "0x2000"], "instructions": [
        _i("0x1000", _loadp_into("EAX", "0xffffffffffffffb8", 0), "EAX = p->len"),   # p at RBP-0x48
        _i("0x1004", _x86_cmp_reg("EAX", 0x40), "CMP EAX,0x40"),
        _i("0x1008", _X86_COND["JA"][0] + ["CBRANCH ram:0x3000:8 " + _X86_COND["JA"][1]],
           "JA 0x3000"),
    ]}
    blocks = [guard,
              {"addr": "0x2000", "succ": ["0x3000"], "instructions": []},   # the memcpy block
              {"addr": "0x3000", "succ": [], "instructions": []}]
    value = ("loadp", ("load", "RBP", -0x48), 0)
    got = bounds.value_guard_bound(blocks, "0x2000", value, ("RBP", "RSP"), 64,
                                   bounds.dominators(blocks))
    assert got is not None and got["bound"] == 0x40 and got["nonneg"] is True
    # a DIFFERENT field (offset 4) is not what the guard measured -> no bound
    assert bounds.value_guard_bound(blocks, "0x2000", ("loadp", ("load", "RBP", -0x48), 4),
                                    ("RBP", "RSP"), 64, bounds.dominators(blocks)) is None


def test_a_dereference_with_a_dominating_bound_is_separated_from_one_without():
    """`tainted_deref` reports every place input reaches a pointer -- 122 of them on jhead --
    and said nothing about which was unchecked, so the list was inventory. The dominating-guard
    reasoning built for copy lengths answers exactly that about an index.

    Two shapes had to line up for this to work at all, and neither is obvious. Taint keys a
    frame slot `("stack", base, offset)` while the guard evaluator matches `(base, offset)`;
    and taint carries the displacement as the raw UNSIGNED constant, so -4 arrives as
    18446744073709551612. Either mismatch matches nothing, which reads exactly like "no guard
    here" -- the failure is silent and looks like a result."""
    from lykos.analyze.detect.bounds import _guard_slots
    d = {"via": [("reg", "RAX"), ("stack", "RBP", 18446744073709551612)]}
    assert _guard_slots(d) == [("RBP", -4)], "unsigned displacement, signed slot"
    assert _guard_slots({"via": [("reg", "RAX")]}) == [], "a register is not a frame slot"
    assert _guard_slots({}) == []
    # a 32-bit target's displacement wraps at 2**32
    assert _guard_slots({"via": [("stack", "EBP", 0xFFFFFFFC)]}) == [("EBP", -4)]


def test_an_index_that_cannot_be_checked_is_not_reported_as_unguarded():
    """The guard evaluator resolves a FRAME SLOT -- it recognises a load from
    `base + displacement` -- so an index the compiler keeps in a register is never asked
    about. Measured on a fixture with an explicit `if (i >= 0 && i < 256)`: the guard is found
    at -O0 and invisible at -O2.

    Reporting that as "no dominating check bounds this" is a silent failure that reads exactly
    like a real absence of one. On jhead it was 61 of 149 sites -- 41% of the verdicts were
    silence wearing the shape of a measurement."""
    from lykos.analyze.detect.bounds import GUARDED, UNCHECKABLE, classify_derefs

    # a dereference whose address came from a register only: nothing to ask about
    derefs = [{"kind": "load", "site_addr": "0x1004", "block_addr": "0x1000",
               "function_addr": "0x1000", "addr_key": ("reg", "RAX"),
               "via": [("reg", "RAX"), ("unique", "0x100")]}]
    irs = {"0x1000": {"blocks": [{"addr": "0x1000", "succ": [],
                                  "instructions": [{"addr": "0x1004", "pcode": []}]}]}}
    got = classify_derefs(irs, derefs, "x86-64")
    assert got["0x1004"]["verdict"] == UNCHECKABLE
    assert "not a frame slot" in got["0x1004"]["why"]
    assert GUARDED != UNCHECKABLE


# --- architectures that pass arguments on the STACK ---------------------------------------
# x86-32 and m68k put every memcpy argument in the outgoing argument area rather than in
# registers. Without the stack-argument pass the two produced no verdict at all -- every copy
# on them read as "destination is not a recovered stack buffer", which is indistinguishable
# from a copy into a heap pointer and silently gave up on two of the thirteen architectures.
#
# The P-Code is Ghidra's real i386 shape, verified against its output (see test_argv_taint):
#   PUSH EAX     COPY    reg:EAX:4 -> unique:0x41500:4
#                INT_SUB reg:ESP:4 const:0x4:4 -> reg:ESP:4
#                STORE   const:0x1a1:8 reg:ESP:4 unique:0x41500:4
# cdecl pushes right-to-left, so for memcpy(dst, src, len) the order is len, src, dst and the
# arguments end up at ESP+0, +4, +8 relative to the stack pointer AT THE CALL.

_X86_FRAME = {"ret_offset": 0, "vars": [{"name": "buf", "size": 64, "offset": -0x50,
                                         "is_buffer": True, "type": "char[64]"}]}
_X86_DISP = "0xffffffb4"           # -0x4c == frame offset -0x50 + 4 (one word for the ret slot)


def _push(src):
    return ["COPY %s -> unique:0x41500:4" % src,
            "INT_SUB reg:ESP:4 const:0x4:4 -> reg:ESP:4",
            "STORE const:0x1a1:8 reg:ESP:4 unique:0x41500:4"]


def _x86_copy_block(length, site="0x100c", len_is_const=True, dst_disp=_X86_DISP):
    ln = f"const:{length:#x}:4" if len_is_const else "reg:ECX:4"
    return [
        _i("0x1000", _push(ln), "PUSH len"),
        _i("0x1004", _push("reg:EAX:4"), "PUSH src"),
        _i("0x1008", [f"INT_ADD reg:EBP:4 const:{dst_disp}:4 -> unique:0x9000:4"]
           + _push("unique:0x9000:4"), "LEA/PUSH &buf"),
        _i(site, ["CALL ram:0x9000:4"], "CALL memcpy"),
    ]


def test_a_stack_passed_copy_that_fits_is_bounded_on_x86_32():
    v = bounds.classify_site(_x86_copy_block(64), "0x100c", "memcpy", _X86_FRAME,
                             "x86", bits=32)
    assert v is not None, "x86-32 produced no verdict at all"
    assert v["verdict"] == bounds.SAFE, v
    assert v["buffer"] == "buf" and v["capacity"] == 64 and v["length"] == 64


def test_a_stack_passed_copy_that_overruns_the_frame_is_surfaced_on_x86_32():
    v = bounds.classify_site(_x86_copy_block(0x400), "0x100c", "memcpy", _X86_FRAME,
                             "x86", bits=32)
    assert v is not None
    assert v["verdict"] in (bounds.SUSPECT, bounds.UNKNOWN)
    assert v.get("length") == 0x400


def test_a_non_constant_stack_passed_length_stays_unknown_on_x86_32():
    """Same shape, length in a register the block never defines: nothing is known about it,
    and a guess either way would be a claim the evidence does not support."""
    v = bounds.classify_site(_x86_copy_block(0, len_is_const=False), "0x100c", "memcpy",
                             _X86_FRAME, "x86", bits=32)
    assert v is not None
    assert v["verdict"] == bounds.UNKNOWN


def test_each_stack_argument_keeps_its_own_value():
    """The regression this guards: x86 reuses ONE P-Code temporary for all three pushes, so
    reading the block's final state gives the LAST argument three times -- the length would
    come back as the destination address and every site on the architecture would misjudge.
    The values have to be captured as the stores happen."""
    _vals, stack = bounds._slice_block(_x86_copy_block(64), "0x100c", {"EBP", "ESP"}, 32,
                                       sp="ESP")
    assert stack.get(0) is not None and stack[0][0] == "frame", f"dst slot {stack.get(0)!r}"
    assert stack.get(8) == ("const", 64), f"length slot {stack.get(8)!r}"
    assert stack[0] != stack[8], "all three pushes collapsed to one value"


def test_stack_slots_are_keyed_from_the_stack_pointer_at_the_call():
    """Each push moves ESP, so a slot key taken at the wrong moment reads the wrong argument.
    cdecl pushes right-to-left, which puts dst at +0 and len at +8 by the time CALL runs."""
    _vals, stack = bounds._slice_block(_x86_copy_block(64), "0x100c", {"EBP", "ESP"}, 32,
                                       sp="ESP")
    assert set(stack) >= {0, 8}, f"argument slots came out at {sorted(stack)}"


def test_the_slice_stops_before_the_call_instruction():
    """The CALL's own P-Code pushes the return address on x86 and m68k, which shifted every
    stack argument by one slot."""
    _vals, stack = bounds._slice_block(_x86_copy_block(64), "0x100c", {"EBP", "ESP"}, 32,
                                       sp="ESP")
    assert stack.get(8) == ("const", 64), "the call's own push shifted the arguments"


def test_a_store_of_an_unknown_value_clears_the_slot_rather_than_keeping_a_stale_one():
    """A slot written with something unknown must become unknown. Leaving the previous value
    there would have a later call read an argument that belonged to an earlier one."""
    instrs = [
        _i("0x1000", _push("const:0x40:4")),
        # overwrite the same slot with a value the block knows nothing about
        _i("0x1004", ["COPY reg:EDI:4 -> unique:0x41500:4",
                      "STORE const:0x1a1:8 reg:ESP:4 unique:0x41500:4"]),
        _i("0x1008", ["CALL ram:0x9000:4"]),
    ]
    _vals, stack = bounds._slice_block(instrs, "0x1008", {"EBP", "ESP"}, 32, sp="ESP")
    assert stack.get(0) is None, f"a stale value survived an unknown store: {stack.get(0)!r}"


def test_an_architecture_with_neither_argument_registers_nor_a_stack_abi_declines():
    """Better no verdict than a verdict read out of the wrong place."""
    assert bounds.classify_site(_copy_block(_DISP, 64), "0x100c", "memcpy", _FRAME,
                                "nosucharch") is None


def test_a_sink_that_is_not_a_bounded_copy_is_out_of_scope():
    assert bounds.classify_site(_copy_block(_DISP, 64), "0x100c", "printf", _FRAME,
                                "x86-64") is None


def test_every_architecture_can_find_its_copy_arguments_somehow():
    """An ABI with neither argument registers nor a stack convention is inert for the whole
    architecture, and silently: every site reads as "not a recovered stack buffer"."""
    for arch, abi in bounds.ARCH_ABI.items():
        assert abi.get("args") or (abi.get("stack_call") or {}).get("base"), \
            f"{arch} can locate no call arguments at all"


def test_confirmed_overflow_requires_a_second_source_agreeing_on_the_size():
    """P2.2: a copy past the buffer is ASSERTED (CONFIRMED) only when a second, independent source
    -- a memset of the same slot -- agrees with the recovered size. On agreement the overflow is
    confirmed; on disagreement (the fragmented-frame case) it stays conservative, never fabricated."""
    blk = _copy_block(_DISP, 128)                      # memcpy 128 bytes into the 64-byte buf
    slot = ("RBP", -0x1018)                            # the raw slice of the destination address
    v = bounds.classify_site(blk, "0x100c", "memcpy", _FRAME, "x86-64",
                             confirmed_sizes={slot: 64})
    assert v["verdict"] == bounds.CONFIRMED and v.get("confirmed"), v
    # a second source that DISAGREES (a fragment) must NOT assert -- the cardinal sin
    v2 = bounds.classify_site(blk, "0x100c", "memcpy", _FRAME, "x86-64",
                              confirmed_sizes={slot: 32})
    assert v2["verdict"] != bounds.CONFIRMED, v2
    # no second source at all -> the existing conservative verdict, never confirmed
    v3 = bounds.classify_site(blk, "0x100c", "memcpy", _FRAME, "x86-64")
    assert v3["verdict"] != bounds.CONFIRMED, v3
