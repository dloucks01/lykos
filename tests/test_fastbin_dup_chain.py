"""Leak-consuming fastbin dup -> control hijack (doc 58).

Fastbin dup is the double-free (CWE-415) route that needs NO use-after-free write: the dup hands
the same chunk out twice, so a normal edit of the reclaimed chunk forges the fd. It only applies
where fastbins still exist (gone ~glibc 2.43) and where a fake-chunk target with a valid size
field exists -- so `_fastbin_dup_chain` gates on both and declines honestly otherwise.

glibc 2.43 removed the exploitable fastbin, so this is validated against an OLDER glibc selected
from the host's container-overlay libc store (exactly the air-gapped-box scenario: an analysed
target that links an old glibc). Skips cleanly when no such glibc is present. Building/relinking a
fixture in dev/benchmark is allowed (the air-gap constraint is on the shipped tool).
"""
import re
import shutil
import struct
import subprocess
import sys

import pytest

from tests._env import find_old_glibc

from lykos.analyze.poc import chain_primitive

_OLD = find_old_glibc()                                    # (ver, libc.so.6, ld.so) or None
_HAVE = bool(shutil.which("gcc") and shutil.which("nm") and shutil.which("patchelf") and _OLD)

# A non-PIE number menu with a fake-chunk target (a 16-aligned fn-pointer with a valid fastbin
# size field 8 bytes before it). 1 alloc(size) · 2 free(idx) [no clear -> double-free/UAF] ·
# 3 view(idx) writes the raw fd · 4 edit(idx,len)+bytes · 5 use -> calls the fake chunk's pointer.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ puts("pwned{fastbin-dup}"); fflush(stdout); _exit(0); }
void defh(void){ }
/* Static initializer so the fake size 0x21 lives in .data (present in the ELF image for the
   target finder to read), not .bss. fp at a 16-aligned offset, size 8 bytes before it. */
struct { size_t a; size_t size; void (*fp)(void); } g __attribute__((aligned(16)))
    = {0, 0x21, defh};
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
        else if (c == 3) { long i = rdl(); write(1, slots[i], 8); putchar('\n'); }
        else if (c == 4) { long i = rdl(); long nn = rdl(); if (read(0, slots[i], nn) < 0) return 1; }
        else if (c == 5) { g.fp(); }
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
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-o", str(exe), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    # Relink onto the old glibc that still has an exploitable fastbin.
    libdir = str(__import__("pathlib").Path(libc).parent)
    pr = subprocess.run(["patchelf", "--set-interpreter", ld, "--set-rpath", libdir, str(exe)],
                        capture_output=True, text=True)
    if pr.returncode != 0:
        pytest.skip(f"patchelf failed: {pr.stderr[:200]}")
    exe.chmod(0o755)
    return exe


def _sym(exe, name):
    for ln in subprocess.check_output(["nm", str(exe)], text=True).splitlines():
        p = ln.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise AssertionError(f"{name} not found")


def _banner_addrs(exe):
    # The target (&g.fp) and win, read from the fixture's own banner (robust to layout).
    p = subprocess.run([str(exe)], input=b"9\n", capture_output=True, timeout=10)
    # No banner in this fixture; derive from symbols instead: fp is at offset 16 of g.
    return _sym(exe, "g") + 16, _sym(exe, "win")


def _plain_spawn(exe):
    return lambda: subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("nm")),
                    reason="needs gcc + nm")
def test_fastbin_fake_target_finder(tmp_path):
    # The finder must locate the 16-aligned fn-pointer whose preceding word is a valid fastbin size.
    if not shutil.which("patchelf") or not _OLD:
        # Still buildable against the host libc for the static finder check (no run needed).
        src = tmp_path / "menu.c"; src.write_text(_FIXTURE)
        exe = tmp_path / "menu"
        r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-o", str(exe), str(src)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            pytest.skip("build failed")
    else:
        exe = _build(tmp_path)
    tgt = _sym(exe, "g") + 16
    found = chain_primitive._fastbin_fake_targets(exe, exe.read_bytes())
    assert any(t == tgt and sz == 0x20 for t, sz in found), \
        f"finder missed the fake chunk at {tgt:#x}: {[(hex(t), hex(s)) for t, s in found]}"


@pytest.mark.skipif(not _HAVE, reason="needs gcc/nm/patchelf and an old glibc (<=2.42) with fastbins")
def test_fastbin_dup_defeats_aslr(tmp_path):
    exe = _build(tmp_path)
    tgt, win = _banner_addrs(exe)
    assert tgt % 16 == 0
    spawn = _plain_spawn(exe)

    keys = set()
    for _ in range(3):                                     # ASLR on -> keys vary
        key, out = chain_primitive._fastbin_dup_run(spawn, None, _ROLES, "5", tgt, 0x18, win,
                                                     _MODEL, safe=True, corrupt=False)
        assert key is not None, "the UAF view disclosed no recoverable heap key"
        assert b"pwned{fastbin-dup}" in out, "control did not reach win"
        keys.add(key)
    assert len(keys) > 1, f"heap key did not vary ({keys}) -- ASLR not exercised"

    _, neg = chain_primitive._fastbin_dup_run(spawn, None, _ROLES, "5", tgt, 0x18, win, _MODEL,
                                              safe=True, corrupt=True)
    assert b"pwned{fastbin-dup}" not in neg                 # negative control must not win


@pytest.mark.skipif(not _HAVE, reason="needs gcc/nm/patchelf and an old glibc (<=2.42) with fastbins")
def test_fastbin_dup_repro_script_wins(tmp_path):
    exe = _build(tmp_path)
    tgt, win = _banner_addrs(exe)
    script = chain_primitive._fastbin_dup_repro_script(win, _ROLES, "5", tgt, 0x18, True)
    sp = tmp_path / "exploit.py"
    sp.write_bytes(script)
    r = subprocess.run([sys.executable, str(sp), str(exe)], capture_output=True, timeout=40)
    assert b"pwned{fastbin-dup}" in r.stdout, f"repro did not win: {r.stdout[-120:]!r}"
