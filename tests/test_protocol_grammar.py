"""Structure-aware input grammar (analyze/protocol_grammar.py) — capabilities #4 and #3-solver.

The parser's Stream_Read_* sequence is the wire grammar; extracting it lets lykos emit a
structurally-valid message (reaching deep parser state) with one field driven to a trigger value.
overflow_values solves the integer-overflow-to-undersized-alloc class (ClearCodec) directly.
"""
from __future__ import annotations
from lykos.analyze import protocol_grammar as G


AUDIN_FORMATS = """
    if (!Stream_CheckAndLogRequiredLength(TAG, s, 8)) return;
    Stream_Read_UINT32(s, NumFormats);
    Stream_Seek_UINT32(s); /* cbSizeFormatsPacket */
    Stream_Read_UINT16(s, wFormatTag);
    Stream_Read_UINT16(s, cbSize);
    Stream_Read(s, format->data, cbSize);
"""


def test_extract_fields_reads_widths_and_order():
    fs = G.extract_fields(AUDIN_FORMATS)
    assert fs == [
        G.Field("int", 4, name="NumFormats"),
        G.Field("skip", 4),
        G.Field("int", 2, name="wFormatTag"),
        G.Field("int", 2, name="cbSize"),
        G.Field("blob", length_var="cbSize"),
    ]


def test_generate_is_little_endian_and_honors_overrides():
    fs = G.extract_fields(AUDIN_FORMATS)
    b = G.generate(fs, {"NumFormats": 3, "wFormatTag": 1, "cbSize": 2})
    # NumFormats=3 (LE u32), 4 skip bytes, wFormatTag=1 (u16), cbSize=2 (u16), then 2 blob bytes
    assert b[0:4] == (3).to_bytes(4, "little")
    assert b[4:8] == b"\x00\x00\x00\x00"
    assert b[8:10] == (1).to_bytes(2, "little")
    assert b[10:12] == (2).to_bytes(2, "little")
    assert b[12:14] == b"AA"                       # blob length driven by the cbSize override
    assert len(b) == 14


def test_generate_defaults_are_zero_filled_and_well_formed():
    fs = G.extract_fields("Stream_Read_UINT8(s, a); Stream_Read_UINT32(s, b);")
    assert G.generate(fs) == b"\x00" * 5


def test_overflow_values_solves_the_clearcodec_uint32_wrap():
    # (w * h * 4) as UINT32 must wrap to a SMALL value while w,h fit a 16-bit wire field
    sol = G.overflow_values(["w", "h"], 32, factor=4)
    assert sol is not None
    w, h = sol["w"], sol["h"]
    assert 0 < w <= 0xFFFF and 0 < h <= 0xFFFF
    prod = (w * h * 4) & 0xFFFFFFFF
    assert prod < 0x10000                           # wrapped buffer is tiny
    assert (w * h * 4) > (1 << 32)                  # genuine overflow, not just a small product


def test_overflow_values_none_when_unsolvable():
    assert G.overflow_values(["a", "b", "c"], 32) is None   # 3-var case not modelled -> honest None
