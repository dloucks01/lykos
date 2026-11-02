"""Directed triggers for JPEG/EXIF heap over-reads behind the container format
(analyze/poc/jpeg_overread.py).

A detector narrows to an unbounded EXIF section/offset read (jhead -- CVE-2020-26208 /
CVE-2018-6612 / CVE-2020-6625); each trigger builds the smallest VALID JPEG whose one malformed
marker or EXIF field drives the read past the allocated section -- no fuzzing. The test checks the
containers are structurally valid JPEGs with a well-formed APP1/TIFF directory and, when a C
compiler is present, reproduces the out-of-bounds read on a faithful fixture of the sink.
"""
from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from lykos.analyze.poc import jpeg_overread as jo


def _markers(data: bytes):
    """Walk the JPEG marker segments (SOI .. EOI), yielding (marker, segment_len)."""
    assert data[:2] == b"\xff\xd8"                      # SOI
    out, i = [], 2
    while i + 1 < len(data) and data[i] == 0xFF:
        m = data[i + 1]
        if m in (0xD9,):                                # EOI, no length
            out.append((m, 0)); break
        seg = struct.unpack(">H", data[i + 2:i + 4])[0]
        out.append((m, seg)); i += 2 + seg
    return out


def test_tiny_app1_is_a_valid_jpeg_with_a_two_byte_app1():
    d = jo.tiny_app1()
    ms = _markers(d)
    assert (0xE1, 2) in ms                              # APP1 with length 2 -- the CVE-2020-26208 shape
    assert d[:2] == b"\xff\xd8" and d[-2:] == b"\xff\xd9"


def test_short_exif_has_an_exif_section_shorter_than_16_bytes():
    d = jo.short_exif()
    ms = _markers(d)
    app1 = [seg for (m, seg) in ms if m == 0xE1][0]
    # section length counts itself; the Exif payload is length-2 and must be < 16 (CVE-2018-6612)
    assert app1 - 2 < 16
    assert b"Exif\x00\x00" in d


def test_gps_wrongfmt_builds_a_gps_subifd_with_a_non_rational_latitude():
    d = jo.gps_wrongfmt()
    assert b"Exif\x00\x00" in d
    tiff = d[d.index(b"Exif\x00\x00") + 6:]
    assert tiff[:2] == b"II"                            # little-endian TIFF
    # IFD0 has one entry: the GPSInfo pointer (tag 0x8825)
    n0 = struct.unpack("<H", tiff[8:10])[0]
    assert n0 == 1
    tag0 = struct.unpack("<H", tiff[10:12])[0]
    assert tag0 == jo._TAG_GPSINFO
    # the GPS sub-IFD's one entry is GPS_LAT with format ULONG (not URATIONAL) -- the bug
    gps_off = struct.unpack("<I", tiff[10 + 8:10 + 12])[0]
    tagg, fmt = struct.unpack("<HH", tiff[gps_off + 2:gps_off + 6])
    assert tagg == jo._TAG_GPS_LAT and fmt == jo.FMT_ULONG


def test_all_triggers_are_registered():
    names = [n for (n, _) in jo.TRIGGERS]
    assert names == ["tiny_app1", "short_exif", "gps_wrongfmt"]


# A faithful fixture of the tiny-APP1 sink: a 2-byte allocation that a 4-byte compare reads past.
_VULN = r"""
#include <stdlib.h>
#include <string.h>
int main(void){
    unsigned char *sec = malloc(2);          /* jhead's 2-byte APP1 section */
    sec[0] = 0; sec[1] = 2;
    /* ReadJpegSections: memcmp(Data+2, "Exif", 4) -- four bytes past a 2-byte buffer */
    volatile int r = memcmp(sec + 2, "Exif", 4);
    free((void*)sec);
    return r != 0;
}
"""


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_tiny_app1_shape_reproduces_an_out_of_bounds_read(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    src = tmp_path / "v.c"; src.write_text(_VULN)
    exe = tmp_path / "v"
    if subprocess.run([cc, "-g", "-O0", "-fsanitize=address", "-w", "-o", str(exe), str(src)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ASan fixture")
    r = subprocess.run([str(exe)], capture_output=True,
                       env={"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"})
    assert b"heap-buffer-overflow" in r.stderr and b"READ of size" in r.stderr, \
        "the 4-byte compare past the 2-byte section did not produce the expected OOB read"
