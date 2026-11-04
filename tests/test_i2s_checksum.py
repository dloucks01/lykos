"""Input-to-state checksum repair (REDQUEEN): get past a nested checksum gate to the code behind it.
A parser rejects any input whose embedded checksum doesn't match the body; i2s learns the layout and
repairs it so a mutated body is accepted and the guarded code runs -- the bugs there become reachable."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.fuzz import i2s

# magic "LYK!" at [0:4]; a 1-byte sum8 checksum of the body at [4]; body from [5:]. Rejects with
# "BADSUM" unless the checksum matches -- the classic integrity gate that stalls a fuzzer.
_SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main(void){
  unsigned char b[256];
  int n = read(0, b, sizeof b);
  if (n < 6) { write(1,"SHORT\n",6); return 0; }
  if (memcmp(b, "LYK!", 4)) { write(1,"BADMAGIC\n",9); return 0; }
  unsigned s = 0; for (int i = 5; i < n; i++) s = (s + b[i]) & 0xFF;
  if (s != b[4]) { write(1,"BADSUM\n",7); return 0; }
  write(1,"PARSED-OK\n",10);          /* the code behind the gate */
  return 0;
}
"""


@pytest.fixture
def gate_bin(tmp_path, gcc):
    c = tmp_path / "g.c"; c.write_text(_SRC)
    exe = tmp_path / "g"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build gate fixture")
    return exe


def _runner(exe):
    return lambda d: subprocess.run([str(exe)], input=d, capture_output=True, timeout=8).stdout


def test_i2s_repairs_checksum_past_the_gate(gate_bin):
    # a mutated body with the magic present but a WRONG checksum -> rejected at the integrity gate
    seed = b"LYK!" + b"\x00" + b"fuzzed-body-bytes"
    run = _runner(gate_bin)
    assert b"BADSUM" in run(seed)                      # the gate stalls the raw mutation
    layout, passing = i2s.solve_integrity_gate(run, seed, pass_marker=b"PARSED-OK")
    assert layout is not None and passing is not None
    assert b"PARSED-OK" in run(passing)               # i2s repair reached the code behind the gate


def test_learned_layout_reused_for_new_bodies(gate_bin):
    run = _runner(gate_bin)
    seed = b"LYK!" + b"\x00" + b"AAAA"
    layout, _ = i2s.solve_integrity_gate(run, seed, pass_marker=b"PARSED-OK")
    assert layout is not None
    # mutate the body freely; re-apply the learned layout -> still accepted (nested-checksum handling)
    for body in (b"LYK!\x00different", b"LYK!\x00" + bytes(range(20)), b"LYK!\x00x"):
        assert b"PARSED-OK" in run(i2s.repair(body, layout))


def test_no_gate_returns_none():
    # a runner that always accepts -> nothing to repair
    layout, _ = i2s.solve_integrity_gate(lambda d: b"ok", b"abcdef", pass_marker=b"PARSED-OK")
    assert layout is None
