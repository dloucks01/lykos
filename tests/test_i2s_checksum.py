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


# ---- runtime input-to-state offset localization (colorization) ----
def test_colorize_decode_roundtrip():
    buf = i2s.colorize(64)
    # a comparison observed 4 bytes from offset 8 of the colorized input -> decode recovers 8
    assert i2s.decode_offset(buf[8:12]) == 8
    assert i2s.decode_offset(buf[40:48]) == 40
    assert i2s.decode_offset(b"not-colorized!!") is None


def test_localize_maps_comparison_to_offset_and_value():
    buf = i2s.colorize(64)
    # the target compared our bytes at offset 8 against the magic "PASS" (captured by extract_secrets)
    observations = [(buf[8:12], b"PASS"), (b"random", b"ignored")]
    placements = i2s.localize(observations)
    assert (8, b"PASS") in placements
    # applying the placement puts the magic at the right offset -- no sweep
    out = i2s.place(b"\x00" * 64, placements)
    assert out[8:12] == b"PASS"


def test_localized_seeds_from_observations():
    buf = i2s.colorize(64)
    obs = [(buf[8:12], b"PASS"), (buf[20:24], b"GO")]
    seeds = i2s.localized_seeds(b"\x00" * 64, obs)
    assert any(s[8:12] == b"PASS" for s in seeds)
    assert any(s[20:22] == b"GO" for s in seeds)
    # the combined seed applies both
    assert any(s[8:12] == b"PASS" and s[20:22] == b"GO" for s in seeds)


def _tok_runner(exe):
    import re
    def run(d):
        o = subprocess.run([str(exe)], input=d, capture_output=True, timeout=8).stdout
        return set(re.findall(rb"[\x20-\x7e]{3,}", o))
    return run


def test_corpus_booster_repairs_real_gate(gate_bin):
    seed = b"LYK!\x00hello-body"
    out = i2s.repaired_corpus_seeds(str(gate_bin), [seed], run=_tok_runner(gate_bin), deadline_s=20)
    assert out and b"PARSED-OK" in subprocess.run([str(gate_bin)], input=out[0],
                                                  capture_output=True).stdout


# A target that RENDERS its computed values instead of gating on them: every input prints new tokens,
# so a naive "new output token" accept takes the first candidate. Generalization must reject it.
_ECHO = r"""
#include <stdio.h>
#include <unistd.h>
int main(void){ unsigned char b[256]; int n=read(0,b,sizeof b); if(n<2) return 0;
  unsigned s=0; for(int i=1;i<n;i++) s=(s+b[i])&0xFF;
  printf("got %02x want %02x\n", b[0], s); return 0; }
"""


def test_corpus_booster_rejects_value_rendering_target(tmp_path, gcc):
    c = tmp_path / "e.c"; c.write_text(_ECHO)
    exe = tmp_path / "e"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build echo fixture")
    out = i2s.repaired_corpus_seeds(str(exe), [b"\x00abcdef"], run=_tok_runner(exe), max_off=8,
                                    deadline_s=20)
    assert out == []


def test_learn_layout_honours_deadline():
    import time
    calls = []
    lay = i2s.learn_layout(b"x" * 40, lambda d: calls.append(1) or False,
                           deadline=time.monotonic() - 1)
    assert lay is None and calls == [1]       # only the initial "already accepted?" probe ran
