"""IFUNC resolution (analyze/ifunc.py) and the emulated harness on STATIC binaries.

A static glibc binary reaches memcpy/strlen/... through IRELATIVE `.plt` slots its startup fills
by calling a resolver. Nothing ran those resolvers, so the harness (and angr) jumped through the
on-disk slot value -- 0 -- on the first string call. These tests build a real static binary and
check that (a) every slot resolves to the routine's own implementation, (b) the harness now runs
a function that calls memcpy/strlen/malloc to a clean return, and (c) a heap overflow through
memcpy is still caught -- both when the routine is stubbed by name and when the stripped binary
runs glibc's own SSE2 memcpy natively under the redzone heap."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from lykos.analyze import ifunc
from lykos.analyze.harness.emulate import available, run_function

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

_SRC = r"""
#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) int scopy(char *buf, int len){
  char *p = malloc(16);
  if (!p) return -1;
  memcpy(p, buf, len);
  p[15] = 0;
  int r = (int)strlen(p);
  free(p);
  return r;
}
int main(int c, char **v){ return scopy(v[0], c); }
"""


def _nm(exe: Path) -> dict:
    out = {}
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3:
            out.setdefault(p[2], int(p[0], 16))
            out.setdefault(int(p[0], 16), p[2])
    return out


@pytest.fixture(scope="module")
def static_bin(tmp_path_factory):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("st")
    (d / "s.c").write_text(_SRC)
    exe = d / "s"
    r = subprocess.run([gcc, "-static", "-no-pie", "-O0", "-w", "-fno-builtin", str(d / "s.c"),
                        "-o", str(exe)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("cannot link a static binary here")
    stripped = d / "s.stripped"
    subprocess.run(["strip", "-o", str(stripped), str(exe)], check=True)
    return exe, stripped, _nm(exe)


def test_every_irelative_slot_resolves_to_its_routines_implementation(static_bin):
    exe, stripped, syms = static_bin
    data = exe.read_bytes()
    relocs = ifunc.irelative_relocs(data)
    assert relocs, "a static glibc binary has IRELATIVE slots"
    impls = ifunc.resolve(data)
    names = ifunc.slot_names(data)
    assert len(impls) == len(relocs) and len(names) == len(relocs)
    # memcpy's slot points at a memcpy/memmove implementation, not 0 and not the resolver
    mslot = next(s for s, n in names.items() if n == "memcpy")
    impl_name = syms.get(impls[mslot], "")
    assert impl_name.startswith(("__memmove", "__memcpy")), impl_name
    # the stripped twin resolves to the same addresses (no names needed)
    assert ifunc.resolve(stripped.read_bytes()) == impls
    assert ifunc.slot_names(stripped.read_bytes()) == {}
    assert ifunc.is_static(data)


def test_harness_runs_a_static_function_and_catches_its_heap_overflow(static_bin):
    exe, _stripped, syms = static_bin
    data = exe.read_bytes()
    ok = run_function(data, syms["scopy"], b"hello\x00" + b"\x00" * 10)
    assert ok.returned and not ok.crashed, ok.note
    bad = run_function(data, syms["scopy"], b"A" * 24)
    assert bad.crashed and bad.heap_kind == "heap-buffer-overflow" and bad.access == "write", (
        bad.note, bad.heap_detail)


def test_stripped_static_binary_runs_glibc_memcpy_natively_under_the_redzone_heap(static_bin):
    exe, stripped, syms = static_bin
    data = stripped.read_bytes()
    # what the function table would carry for a stripped binary after FLIRT: malloc/free named
    names = {syms["malloc"]: "malloc", syms["free"]: "free"}
    ok = run_function(data, syms["scopy"], b"hello\x00" + b"\x00" * 10, stub_names=names)
    assert ok.returned and not ok.crashed, ok.note
    bad = run_function(data, syms["scopy"], b"A" * 24, stub_names=names)
    assert bad.crashed and bad.heap_kind == "heap-buffer-overflow" and bad.access == "write", (
        bad.note, bad.heap_detail)
    # the write happened inside glibc's own memcpy implementation, not a stub
    assert "fault in" not in bad.note


def test_no_ifunc_image_is_a_no_op():
    assert ifunc.irelative_relocs(b"not an elf") == []
    assert ifunc.resolve(b"\x7fELF") == {}
    assert ifunc.summary(b"") is None


def test_a_harness_campaign_does_not_leak_emulators(static_bin):
    """Each execution builds a hooked Uc; without an explicit close they live until the cyclic GC
    runs (it counts Python objects, not native memory). Measured on static jhead-3.04: 3,000 execs
    = 2,055 MB without the close, 62 MB with it -- the autopilot run was OOM-killed. Run in a fresh
    interpreter so the peak RSS is this campaign's alone."""
    import sys
    exe, _stripped, syms = static_bin
    import os

    import lykos
    root = str(Path(lykos.__file__).resolve().parents[1])
    # sys.path pinned in the child and a clean cwd: with `-c` the CWD comes first on sys.path,
    # and other tests in the suite leave extracted (older) lykos copies around -- the child must
    # measure THIS tree's harness, which it checks by printing where lykos came from.
    code = (
        "import resource,sys\n"
        f"sys.path.insert(0,{root!r})\n"
        "import lykos\n"
        "from lykos.analyze.harness.fuzz import fuzz_function\n"
        f"blob=open({str(exe)!r},'rb').read()\n"
        f"fuzz_function(blob,{syms['scopy']},budget_execs=2000,budget_seconds=60)\n"
        "print(lykos.__file__)\n"
        "print(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss//1024)\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=240,
                       env=env, cwd=str(exe.parent))
    assert r.returncode == 0, r.stderr[-400:]
    out = r.stdout.strip().splitlines()
    assert out[-2].startswith(root), out
    assert int(r.stdout.strip().splitlines()[-1]) < 500, r.stdout
