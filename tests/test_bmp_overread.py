"""Directed trigger for a BMP palette over-read (analyze/poc/bmp_overread.py).

Builds the smallest VALID 8-bit indexed BMP whose colour table is tiny and whose pixels are out of
range, so a decoder that indexes the table by the pixel value reads past it -- no fuzzing. Validates
the container by hand and, with a C compiler, reproduces the OOB read on a faithful BMP palette
expander that consumes the constructed bytes.
"""
from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from lykos.analyze.poc import bmp_overread as bo


def test_bmp_is_structurally_valid_and_carries_the_out_of_range_index():
    bmp = bo.bmp_overindexed(colors=2, index=255, width=8, height=2)
    assert bmp[:2] == b"BM"
    filesize, _, _, pixoff = struct.unpack("<IHHI", bmp[2:14])
    assert filesize == len(bmp)
    dibsize, w, h, planes, bpp = struct.unpack("<IiiHH", bmp[14:30])
    clrused = struct.unpack("<I", bmp[14 + 32:14 + 36])[0]
    assert dibsize == 40 and bpp == 8 and planes == 1 and clrused == 2 and (w, h) == (8, 2)
    assert pixoff == 14 + 40 + 2 * 4                 # headers + 2-entry BGRA table
    # every pixel byte (row padded to 4) is index 255, far past the 2-entry table
    row = bmp[pixoff:pixoff + 8]
    assert row == bytes([255]) * 8 and 255 >= clrused


def test_disclosure_oracle_is_sound_and_forgery_proof():
    def heap(idx):
        return ((0xA0 ^ idx) & 0xFF, (idx * 3 + 5) & 0xFF, (idx * 7 + 9) & 0xFF)

    def _index_of(bmp):
        pixoff = struct.unpack("<I", bmp[10:14])[0]
        return bmp[pixoff]

    def _rgb(idx):                                    # emitted-RGB of palette entry idx (oracle's formula)
        return ((idx * 17 + 1) & 0xFF, (idx * 29 + 7) & 0xFF, (idx * 43 + 13) & 0xFF)

    def vulnerable(bmp):
        idx = _index_of(bmp)
        return _rgb(idx) if idx < 2 else heap(idx)

    def safe(bmp):
        return _rgb(min(_index_of(bmp), 1))

    def echo(_bmp):
        return (1, 2, 3)

    assert bo.confirm_disclosure(vulnerable)["disclosed"] is True
    sv = bo.confirm_disclosure(safe)
    assert sv["disclosed"] is False and sv["control_ok"] is True
    ev = bo.confirm_disclosure(echo)
    assert ev["disclosed"] is False and ev["control_ok"] is False


# A faithful BMP palette expander (no zlib): parse the headers, read the colour table, index it by
# each pixel byte -- reads table[idx] without checking idx against clrused.
_VULN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *b = malloc(n); if (fread(b,1,n,f)!=(size_t)n) return 2; fclose(f);
    unsigned pixoff = *(unsigned*)(b+10);
    int w = *(int*)(b+18), h = *(int*)(b+22);
    unsigned clrused = *(unsigned*)(b+46);
    unsigned char *table = b + 14 + 40;                 /* colour table (clrused * 4 BGRA) */
    unsigned char *px = b + pixoff;
    unsigned long sink = 0;
    int rowsz = ((w + 3) / 4) * 4;
    for (int y=0;y<h;y++) for (int x=0;x<w;x++){
        int idx = px[y*rowsz + x];
        sink += table[idx*4];                           /* table[idx] -- OOB when idx>=clrused */
    }
    (void)clrused;
    printf("%lu\n", sink);
    return 0;
}
"""


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_the_constructed_bmp_reproduces_an_out_of_bounds_read(tmp_path):
    src = tmp_path / "v.c"
    src.write_text(_VULN)
    exe = tmp_path / "v"
    cc = shutil.which("gcc") or shutil.which("cc")
    if subprocess.run([cc, "-g", "-O0", "-fsanitize=address", "-o", str(exe), str(src)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ASan fixture")
    bmp = bo.bmp_overindexed(colors=2, index=200, width=8, height=2)
    inp = tmp_path / "in.bmp"
    inp.write_bytes(bmp)
    r = subprocess.run([str(exe), str(inp)], capture_output=True,
                       env={"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"})
    assert b"heap-buffer-overflow" in r.stderr and b"READ of size" in r.stderr, \
        "the out-of-range palette index did not produce the expected OOB read"
