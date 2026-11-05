"""Behavioural library-ID for stripped static binaries: syscall-number wrappers and `system` are
named by what they do, so a glibc version FLIRT's byte signatures miss is still covered (jhead-3.04
stripped: FLIRT named 1 of 786 functions; system/execve/read stayed fcn.* and a CVE the symbolized
build exploits to L3 was missed)."""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.analyze import syswrap

_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    char b[64]; int fd = open(argc > 1 ? argv[1] : "/dev/null", O_RDONLY);
    if (fd < 0) return 1;
    ssize_t n = read(fd, b, sizeof b - 1); if (n <= 0) return 2; b[n] = 0;
    if (b[0] == '!') return system(b + 1);
    write(1, b, n); return 0; }
"""


def _syms(exe):
    out = subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout
    return {int(ln.split()[0], 16): ln.split()[2] for ln in out.splitlines()
            if len(ln.split()) == 3 and ln.split()[1] in "tTwW"}


def test_names_wrappers_and_system_on_a_stripped_static_binary(tmp_path, gcc):
    if not shutil.which("strip") or not shutil.which("nm"):
        pytest.skip("needs binutils")
    c = tmp_path / "s.c"; c.write_text(_SRC)
    exe = tmp_path / "s"
    if subprocess.run([gcc, "-O0", "-static", "-w", str(c), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("no static libc")
    truth = _syms(exe)
    # function list = every real function start with the gap to the next one as its size (what a
    # disassembler recovers on the stripped copy), under generic names
    starts = sorted(truth)
    funcs = [{"addr": hex(a), "name": f"fcn.{a:08x}", "size": (b - a), "calls": []}
             for a, b in zip(starts, starts[1:])]
    stripped = tmp_path / "s.stripped"
    shutil.copy(exe, stripped)
    subprocess.run(["strip", "-s", str(stripped)], check=True)
    named = syswrap.identify(stripped.read_bytes(), funcs)
    by_name = {}
    for hx, n in named.items():
        by_name.setdefault(n, []).append(truth.get(int(hx, 16), "?"))
    assert "system" in by_name and any("system" in t for t in by_name["system"]), by_name
    assert "read" in by_name and all("read" in t for t in by_name["read"]), by_name
    assert "open" in by_name, by_name
    # the names the detectors and channel logic act on must be EXACT (a sink/source label on the
    # wrong function would mislead); other labels are behavioural -- a function whose only
    # syscall is kill (glibc's cancel_handler) or writev (_dl_debug_vdprintf) does perform it
    key = {"system", "read", "open", "execve", "write", "recvfrom", "recvmsg", "pread"}
    wrong = [(n, t) for n, ts in by_name.items() if n in key for t in ts
             if n not in t.lower() and not (n == "open" and "open" in t)]
    assert not wrong, wrong


def test_a_symbolized_or_dynamic_binary_is_never_renamed(tmp_path, gcc):
    c = tmp_path / "d.c"; c.write_text(_SRC)
    exe = tmp_path / "d"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build")
    assert syswrap.identify(exe.read_bytes(), [{"addr": "0x1000", "name": "fcn.1000",
                                                "size": 64, "calls": []}]) == {}
