"""Audit regressions for the emulated single-function harness (analyze/harness)."""
from __future__ import annotations

import struct
import subprocess

import pytest
from lykos.analyze.harness import fuzz as hfuzz
from lykos.analyze.harness.emulate import HarnessResult, available, run_function
from lykos.analyze.harness.harness_stage import _fault_cwe

needs_unicorn = pytest.mark.skipif(not available(), reason="unicorn not installed")


def _build(gcc, tmp_path, src, sym, extra=("-no-pie",)):
    s = tmp_path / "t.c"
    s.write_text(src)
    exe = tmp_path / "t"
    subprocess.run([gcc, "-O0", "-w", "-fno-builtin", *extra, str(s), "-o", str(exe)], check=True)
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] == sym:
            return exe.read_bytes(), int(p[0], 16)
    raise AssertionError(f"{sym} not found")


_HUGE_LEN = r"""
#include <string.h>
#include <stdint.h>
char dst[64];
int f(char *buf, int len){
  uint64_t n; memcpy(&n, buf, 8);
  memcpy(dst, buf, (size_t)n);          /* attacker-controlled length */
  return dst[0];
}
int main(void){ char z[8]={0}; return f(z,8); }
"""


@needs_unicorn
def test_an_attacker_controlled_huge_length_is_a_fault_not_a_host_error(gcc, tmp_path):
    data, addr = _build(gcc, tmp_path, _HUGE_LEN, "f")
    r = run_function(data, addr, struct.pack("<Q", 0xFFFFFFFFFFFFFF00))
    assert r.crashed
    assert r.access == "read"          # the SOURCE runs off the mapping first: an over-read
    assert r.fault_addr is not None
    assert r.fault_pc is not None      # the faulting call site, not None


_SRC_OVERREAD = r"""
#include <string.h>
char dst[64];
int f(char *buf, int len){
  char *src; memcpy(&src, buf, 8);
  strcpy(dst, src);       /* source pointer straight from the input */
  return dst[0];
}
int main(void){ char z[8]={0}; return f(z,8); }
"""


@needs_unicorn
def test_strcpy_from_a_wild_source_is_a_read_not_a_write(gcc, tmp_path):
    data, addr = _build(gcc, tmp_path, _SRC_OVERREAD, "f")
    r = run_function(data, addr, struct.pack("<Q", 0xDEAD0000))
    assert r.crashed and r.access == "read", r.note
    assert r.fault_addr == 0xDEAD0000


_GETENV = r"""
#include <stdlib.h>
#include <string.h>
int f(char *buf, int len){
  char *e = getenv("HOME");     /* unknown to the harness: stubbed to return 0 */
  return (int)strlen(e) + buf[0];
}
int main(void){ char z[1]={0}; return f(z,1); }
"""


@needs_unicorn
def test_a_null_the_harness_invented_is_not_a_target_crash(gcc, tmp_path):
    data, addr = _build(gcc, tmp_path, _GETENV, "f")
    r = run_function(data, addr, b"x")
    assert not r.crashed
    assert "harness artifact" in r.note


_NULLDEREF = r"""
int f(char *buf, int len){
  int *p = (int*)0;
  if (len > 3 && buf[0] == 'N') return *p;   /* input-driven NULL deref */
  return 0;
}
int main(void){ char z[4]={0}; return f(z,4); }
"""


@needs_unicorn
@pytest.mark.parametrize("pie", [("-no-pie",), ("-pie", "-fPIE")])
def test_null_deref_faults_on_pie_and_non_pie(gcc, tmp_path, pie):
    data, addr = _build(gcc, tmp_path, _NULLDEREF, "f", extra=pie)
    ok = run_function(data, addr, b"AAAA")
    assert ok.returned and not ok.crashed, ok.note
    bad = run_function(data, addr, b"NAAA")
    assert bad.crashed and bad.fault_addr == 0, bad.note
    assert _fault_cwe(bad)[0] == "CWE-476"


def test_fault_cwe_mapping():
    assert _fault_cwe(HarnessResult(crashed=True, access="read", fault_addr=0x8))[0] == "CWE-476"
    assert _fault_cwe(HarnessResult(crashed=True, access="read", fault_addr=0xdead0000))[0] == "CWE-125"
    assert _fault_cwe(HarnessResult(crashed=True, access="write", fault_addr=None))[0] == "CWE-787"


def test_an_executor_error_does_not_lose_the_campaign(monkeypatch):
    calls = {"n": 0}

    def flaky(_elf, _addr, buf, **_kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return HarnessResult(crashed=True, access="write", fault_pc=0x401000, fault_addr=0x10)
        raise MemoryError("host")
    monkeypatch.setattr(hfuzz, "run_function", flaky)
    fr = hfuzz.fuzz_function(b"", 0x401000, budget_execs=5, budget_seconds=5)
    assert fr.execs == 5
    assert len(fr.crashes) == 1
    assert "executor error on 4" in fr.note
