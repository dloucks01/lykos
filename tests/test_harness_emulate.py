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
