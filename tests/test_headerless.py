"""Identifying a bare-metal firmware blob with no header.

A raw flash dump has no format, no entry point and no architecture field -- everything has to
come from the bytes. Both failure directions are costly: guessing wrong loads the image at the
wrong base so every recovered address is nonsense, while refusing to guess leaves the blob
unanalysable. So the module reports a confidence and its evidence, and the tests below are
mostly about when it must DECLINE.
"""
from __future__ import annotations

import random
import struct

import pytest
from lykos.analyze.firmware import headerless as hl


def _cortex_m(base=0x08000000, sp=0x20001000, n=16, endian="<", size=4096):
    """A plausible Cortex-M image: SP in SRAM, then Thumb handler addresses in flash.

    The handlers have to land INSIDE the image's own span -- a table pointing past the end of
    the blob it came from is exactly what `detect_cortex_m` refuses, and rightly.
    """
    words = [sp]
    for i in range(1, n):
        words.append((base + 0x100 + i * 4) | 1)          # odd == Thumb, within the image
    body = b"".join(struct.pack(endian + "I", w) for w in words)
    return body + b"\x00" * max(0, size - len(body))


# ---- the Cortex-M vector table -----------------------------------------------------------

def test_a_vector_table_yields_base_entry_and_endianness():
    got = hl.detect_cortex_m(_cortex_m())
    assert got is not None, "a textbook Cortex-M vector table was not recognised"
    assert got["arch"] == "arm" and got["sub"] == "cortex-m" and got["bits"] == 32
    assert got["endianness"] == "little"
    assert got["base_addr"] == 0x08000000
    assert got["entry"] % 2 == 0, "the Thumb bit must be stripped from the entry point"
    assert got["confidence"] >= 0.6
    assert "SP=" in got["evidence"] and "reset=" in got["evidence"]


def test_the_entry_point_is_the_reset_vector_with_its_thumb_bit_cleared():
    data = _cortex_m()
    reset = struct.unpack_from("<I", data, 4)[0]
    got = hl.detect_cortex_m(data)
    assert reset & 1, "the fixture's reset vector should be Thumb"
    assert got["entry"] == reset & ~1


@pytest.mark.parametrize("sram", [0x20000100, 0x10000100, 0x1FFF0100])
def test_each_plausible_sram_window_is_accepted(sram):
    assert hl.detect_cortex_m(_cortex_m(sp=sram)) is not None


def test_a_stack_pointer_outside_sram_is_not_a_vector_table():
    """Word 0 not pointing into RAM is the cheapest disqualifier, and skipping it would let
    any blob whose first words happen to be odd be called firmware."""
    assert hl.detect_cortex_m(_cortex_m(sp=0x00001000)) is None
    assert hl.detect_cortex_m(_cortex_m(sp=0xDEADBEEF)) is None


def test_even_handler_addresses_are_not_a_thumb_vector_table():
    """Cortex-M handlers are Thumb, so their addresses are odd. All-even means this is not a
    vector table -- it is data that happens to start with an SRAM-looking word."""
    words = [0x20001000] + [0x08000200 + i * 4 for i in range(1, 16)]
    data = b"".join(struct.pack("<I", w) for w in words) + b"\x00" * 256
    assert hl.detect_cortex_m(data) is None


def test_handlers_pointing_outside_the_image_are_not_accepted():
    """A table whose entries land nowhere near the flash region it would be loaded at is not
    this image's table."""
    words = [0x20001000] + [(0x90000000 + i * 4) | 1 for i in range(1, 16)]
    data = b"".join(struct.pack("<I", w) for w in words) + b"\x00" * 256
    assert hl.detect_cortex_m(data) is None


def test_a_mostly_empty_table_is_not_enough():
    words = [0x20001000, (0x08000201), 0, 0, 0, 0, 0, 0]
    data = b"".join(struct.pack("<I", w) for w in words) + b"\x00" * 256
    assert hl.detect_cortex_m(data) is None


def test_a_blob_too_small_to_hold_a_table_is_declined():
    assert hl.detect_cortex_m(b"") is None
    assert hl.detect_cortex_m(b"\x00" * 32) is None


# ---- prologue scoring --------------------------------------------------------------------

def test_arm_prologues_score_for_arm():
    body = b"".join(struct.pack("<I", 0xE92D4800) for _ in range(200))
    scores = hl.score_arch(body)
    assert scores["arm/little"] >= 199
    assert scores["arm/little"] > scores["mips/little"]


def test_mips_prologues_score_for_mips_in_both_byte_orders():
    for endian, key in (("<", "mips/little"), (">", "mips/big")):
        body = b"".join(struct.pack(endian + "I", 0x27BDFFE0) for _ in range(200))
        scores = hl.score_arch(body)
        assert scores[key] >= 199, key


def test_powerpc_prologues_score_for_ppc():
    body = b"".join(struct.pack(">I", 0x7C0802A6) for _ in range(200))
    assert hl.score_arch(body)["ppc/big"] >= 199


def test_scoring_an_empty_blob_is_all_zeroes_not_a_crash():
    scores = hl.score_arch(b"")
    assert scores and all(v == 0 for v in scores.values())


# ---- the combined verdict, and when it must refuse ---------------------------------------

def test_a_cortex_m_image_wins_outright_and_says_how_it_was_identified():
    got = hl.analyze_blob(_cortex_m())
    assert got["method"] == "cortex-m-vector-table"
    assert got["base_addr"] == 0x08000000


def test_dense_arm_code_is_identified_by_prologue_scoring():
    body = b"".join(struct.pack("<I", 0xE92D4800) + b"\x00" * 60 for _ in range(64))
    got = hl.analyze_blob(body)
    assert got.get("arch") == "arm", got
    assert got["method"] == "prologue-scoring"
    assert got["base_addr"] is None, "scoring cannot know a load address and must not claim one"
    assert "scores=" in got["evidence"], "the operator cannot check a verdict with no numbers"


def test_random_data_is_inconclusive_rather_than_guessed():
    """The expensive mistake: calling random data ARM loads it at a made-up base and every
    address derived afterwards is fiction. 16-bit Thumb patterns especially hit by chance."""
    rng = random.Random(1234)
    blob = bytes(rng.randrange(256) for _ in range(16384))
    got = hl.analyze_blob(blob)
    assert not got.get("arch"), f"random data was identified as {got.get('arch')}: {got}"


def test_all_zero_flash_is_inconclusive():
    assert not hl.analyze_blob(b"\x00" * 8192).get("arch")


def test_a_weak_signal_that_is_not_dominant_is_refused():
    """A handful of matching words in a large blob is noise, not code. Requiring the winner to
    beat the runner-up by a margin is what keeps a near-tie from becoming a confident answer."""
    body = bytearray(b"\x00" * 8192)
    for i in range(4):
        struct.pack_into("<I", body, i * 4, 0xE92D4800)
    assert not hl.analyze_blob(bytes(body)).get("arch")


def test_confidence_never_overstates_itself():
    for data in (_cortex_m(),
                 b"".join(struct.pack("<I", 0xE92D4800) + b"\x00" * 60 for _ in range(64))):
        got = hl.analyze_blob(data)
        if got.get("arch"):
            assert 0 < got["confidence"] <= 0.98, got


def test_thumb_density_is_measured_per_halfword_not_per_word():
    """The regression: the 32-bit patterns are counted once per WORD and the Thumb pattern
    once per HALFWORD, but both were divided by the word count. That doubled Thumb's apparent
    density and let noise through the gate -- 16 KB of random bytes scored 33 hits against a
    chance expectation of 32.0 and was reported as ARM/Thumb at 0.32 confidence.

    A headerless verdict is load-bearing: everything after it is addresses computed from a
    base the guess invented.
    """
    rng = random.Random(99)
    for size in (8192, 16384, 32768):
        blob = bytes(rng.randrange(256) for _ in range(size))
        got = hl.analyze_blob(blob)
        hits = hl.score_arch(blob)["thumb/little"]
        expected = (size // 2) / 256          # 0xB5xx is 1 in 256 halfwords
        assert hits < expected * 2, f"fixture is not noise-like: {hits} vs {expected}"
        assert not got.get("arch"), f"{size} bytes of noise identified as {got}"


def _thumb_image(n_funcs, gap):
    out = bytearray()
    for _ in range(n_funcs):
        out += struct.pack("<H", 0xB5F0)      # push {r4-r7, lr}
        out += b"\x00" * gap
    return bytes(out)


@pytest.mark.parametrize("n_funcs,gap", [(256, 30), (128, 62), (64, 126), (512, 14)])
def test_real_thumb_code_is_still_identified_after_the_tightening(n_funcs, gap):
    """Tightening a gate risks false negatives, which here means a genuine firmware image
    becoming unanalysable. Real code sits well clear of the noise floor at every plausible
    function density."""
    got = hl.analyze_blob(_thumb_image(n_funcs, gap))
    assert got.get("arch") == "arm" and got.get("sub") == "thumb", got
    assert got["confidence"] >= 0.5


def test_the_noise_floor_separates_code_from_random_data_by_a_real_margin():
    """If the two were close, the threshold would be a coin flip on every image."""
    rng = random.Random(7)
    noise = bytes(rng.randrange(256) for _ in range(8192))
    code = _thumb_image(64, 126)
    noise_d = hl.score_arch(noise)["thumb/little"] / (len(noise) // 2)
    code_d = hl.score_arch(code)["thumb/little"] / (len(code) // 2)
    assert code_d > noise_d * 3, f"code {code_d:.4f} vs noise {noise_d:.4f}"


def test_the_final_word_of_a_blob_is_scored():
    """`range(0, n - 4, 4)` stopped one word short, so the last instruction in an image was
    never counted."""
    body = b"".join(struct.pack("<I", 0xE92D4800) for _ in range(200))
    assert hl.score_arch(body)["arm/little"] == 200
