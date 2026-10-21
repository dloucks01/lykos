"""T2 fuzz loop (doc 46): coverage-guided fuzzing of a single function FINDS its bug from a benign
seed -- the bug-finding half of the binary libFuzzer. Deterministic (seeded RNG)."""
from __future__ import annotations

import subprocess

import pytest

from lykos.analyze.harness.emulate import available
from lykos.analyze.harness.fuzz import fuzz_function

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

_SRC = r"""
#include <string.h>
static int t[8] = {1,2,3,4,5,6,7,8};
int lookup(char *buf, int len){
  int idx = 0;
  memcpy(&idx, buf, 4);
  return t[idx];        /* OOB read when idx is out of range */
}
int main(void){ char z[4]={0}; return lookup(z,4); }
"""


def test_fuzz_finds_oob_from_benign_seed(gcc, tmp_path):
    s = tmp_path / "t.c"
    s.write_text(_SRC)
    exe = tmp_path / "t"
    subprocess.run([gcc, "-no-pie", "-O0", "-w", "-fno-builtin", str(s), "-o", str(exe)], check=True)
    addr = None
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == "lookup":
            addr = int(p[0], 16)
    assert addr
    fr = fuzz_function(exe.read_bytes(), addr, seeds=[b"\x00\x00\x00\x00"],
                       budget_execs=12000, budget_seconds=40, seed=1337)
    assert fr.crashes, f"fuzzer should find the OOB (execs={fr.execs}, cov={len(fr.blocks)})"
    assert any(c["result"].access == "read" for c in fr.crashes)
    assert fr.crashing_inputs                       # concrete reproducers for the L1->L3 ladder
