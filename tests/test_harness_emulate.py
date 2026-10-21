"""T2 executor (doc 46): drive one function directly under unicorn with a fuzzed buffer, and
detect that a wild attacker-controlled address faults while a mapped one returns cleanly -- the
"binary libFuzzer" primitive, exercised without running the whole program."""
from __future__ import annotations

import subprocess

import pytest

from lykos.analyze.harness.emulate import available, run_function, _INPUT_ADDR

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

_SRC = r"""
#include <stdint.h>
int deref(char *buf, int len){
  if(len < 8) return 0;
  uint64_t a = *(uint64_t*)buf;   /* address straight from the input */
  return *(int*)a;                 /* deref -> faults on a bad address */
}
int main(void){ char z[8]={0}; return deref(z,8); }
"""


def _build(gcc, tmp_path):
    src = tmp_path / "t.c"
    src.write_text(_SRC)
    exe = tmp_path / "t"
    subprocess.run([gcc, "-no-pie", "-O0", "-w", str(src), "-o", str(exe)], check=True)
    addr = None
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "deref":
            addr = int(parts[0], 16)
    assert addr, "deref symbol not found"
    return exe.read_bytes(), addr


_SRC_LIBC = r"""
#include <string.h>
static int t[8] = {1,2,3,4,5,6,7,8};
int lookup(char *buf, int len){
  int idx = 0;
  memcpy(&idx, buf, 4);   /* external call: must be stubbed for the function to run */
  return t[idx];          /* OOB read when idx is out of range */
}
int main(void){ char z[4]={0}; return lookup(z,4); }
"""


def _build_named(gcc, tmp_path, src, sym, extra=()):
    s = tmp_path / "t.c"
    s.write_text(src)
    exe = tmp_path / "t"
    subprocess.run([gcc, "-no-pie", "-O0", "-w", *extra, str(s), "-o", str(exe)], check=True)
    addr = None
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == sym:
            addr = int(p[0], 16)
    assert addr, f"{sym} not found"
    return exe.read_bytes(), addr


def test_libc_stub_lets_a_function_run_and_still_catches_oob(gcc, tmp_path):
    import struct
    data, addr = _build_named(gcc, tmp_path, _SRC_LIBC, "lookup", extra=("-fno-builtin",))
    # in-bounds index: memcpy is stubbed so the function runs to a clean return (needs the TLS/
    # canary setup too -- a canary-protected function reads fs:[0x28] on entry).
    ok = run_function(data, addr, struct.pack("<i", 0))
    assert ok.returned and not ok.crashed, ok.note
    # out-of-range index: the OOB read faults -- reached ONLY because the memcpy call was stubbed.
    bad = run_function(data, addr, struct.pack("<i", 0x20000000))
    assert bad.crashed and bad.access == "read"


def test_executor_distinguishes_clean_return_from_fault(gcc, tmp_path):
    data, addr = _build(gcc, tmp_path)
    # a mapped address (the harness's own input window) -> the deref reads it -> clean return
    good = run_function(data, addr, _INPUT_ADDR.to_bytes(8, "little"))
    assert good.returned and not good.crashed, good.note
    # a wild address -> fault at exactly that address
    bad = run_function(data, addr, (0xDEADBEEF).to_bytes(8, "little"))
    assert bad.crashed and not bad.returned
    assert bad.fault_addr == 0xDEADBEEF
    assert bad.access == "read"
    assert bad.fault_pc and bad.blocks            # captured a faulting PC + coverage
