"""Command injection carried by the INPUT FILE'S NAME (analyze/poc/filename_inject.py).

A program that pastes its argument path into a shell command (jhead `-rgt`/`-ce`,
CVE-2022-41751) is injectable through the NAME of a file it opens, a channel no stdin/argv/file-
bytes probe and no fuzzer reaches. The oracle is a marker SPLIT by an empty shell quote: only a
shell that executes the payload rejoins it, so a program that merely prints the filename cannot
forge a confirmation.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from lykos.analyze.poc import filename_inject as fni

_HAS_CC = shutil.which("gcc") or shutil.which("cc")


def test_marker_is_split_so_an_echo_of_the_name_cannot_confirm():
    m = "LYK1234ABCD"
    for p in fni.payloads(m):
        assert "/" not in p and "\x00" not in p          # a legal filename
        assert ("echo " + m) not in p                    # the joined marker is never in the name
    assert fni.confirm(b"output: LYK1234ABCD\n", m)       # joined -> the command ran
    assert not fni.confirm(b"in file 'x$(echo LYK1234''ABCD>&2).jpg'\n", m)   # printed, not run


def test_the_builtin_jpeg_seed_has_an_exif_thumbnail_at_the_segment_end():
    data = fni.jpeg_exif_thumbnail()
    assert data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"
    assert b"Exif\x00\x00" in data


def test_seed_files_offers_a_jpeg_when_the_strings_mention_exif():
    seeds = fni.seed_files([type("S", (), {"value": "Exif"})()])
    assert any(ext == "jpg" for _d, ext in seeds)


# A program that builds `sh -c "... <name>"` from its argument -- the CVE-2022-41751 shape.
_VULN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
    if (argc < 2) return 2;
    const char *name = argv[argc-1];
    FILE *f = fopen(name, "rb");          /* must be a real file: the tool opens it first */
    if (!f) { fprintf(stderr, "cannot open %s\n", name); return 1; }
    fclose(f);
    char cmd[4096];
    snprintf(cmd, sizeof cmd, "echo processing \"%s\" >/dev/null", name);
    return system(cmd);                   /* the name is pasted into a shell command */
}
"""

# A safe twin: it opens the file and never shells out. Must NOT confirm.
_SAFE = _VULN.replace('return system(cmd);', '(void)cmd; return 0;')


def _build(src, name, tmp_path):
    s = tmp_path / (name + ".c")
    s.write_text(src)
    if subprocess.run(["gcc", "-O0", "-w", "-o", str(tmp_path / name), str(s)],
                      capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    return str(tmp_path / name)


def _runner(exe, tmp_path):
    def run(argv, cwd_dir):
        try:
            r = subprocess.run([exe] + [str(a) for a in argv], capture_output=True,
                               timeout=10, cwd=str(cwd_dir))
        except subprocess.SubprocessError:
            return b""
        return (r.stdout or b"") + b"\n" + (r.stderr or b"")
    return run


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
def test_probe_confirms_the_filename_injection(tmp_path):
    exe = _build(_VULN, "vuln", tmp_path)
    hit = fni.probe(_runner(exe, tmp_path), strings=[], found={}, marker="LYKAAABBBCCC",
                    workdir=tmp_path / "w")
    assert hit is not None
    assert hit["name"].split(".")[0].startswith("x")     # the crafted name
    assert fni.confirm(hit["out"], "LYKAAABBBCCC")


@pytest.mark.skipif(not _HAS_CC, reason="no C compiler")
def test_a_program_that_does_not_shell_out_is_not_confirmed(tmp_path):
    exe = _build(_SAFE, "safe", tmp_path)
    hit = fni.probe(_runner(exe, tmp_path), strings=[], found={}, marker="LYKAAABBBCCC",
                    workdir=tmp_path / "w")
    assert hit is None
