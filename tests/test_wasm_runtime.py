"""Running a WebAssembly module: the trap is the fault, and the CONVENTION is the hazard.

A wasm module is not an executable -- no process, no argv, and unless it is a WASI command no
entry point at all. So a harness has to choose how to hand it the input, and a wrong choice
manufactures faults: call `set(index, value)` as if it were `parse(ptr, len)` and it stores to
buf[65536] and traps, for reasons that are the harness's fault and not the module's. The driver
re-checks every trap against an EMPTY input on a fresh instance for exactly that reason, and
that check is what most of this file pins down.
"""
import shutil
import subprocess

import pytest
from lykos.analyze import wasm
from lykos.analyze.dynamic import sandbox
from lykos.analyze.runtime_fault import managed_fault

# An offset taken straight from the input and never validated. NOT an unbounded copy: wasm
# linear memory holds the module's own globals, stack and heap, so overrunning a 64-byte buffer
# corrupts its neighbours and traps on nothing. Only an access past the END of memory traps.
_OOB_OFFSET = """static char buf[64];
__attribute__((export_name("parse")))
int parse(const unsigned char *s, int n){
  if (n < 4) return -1;
  int off = (int)(s[0] | (s[1]<<8) | (s[2]<<16) | (s[3]<<24));
  buf[off] = (char)s[3];
  return off; }
"""

# A two-argument export that is NOT (ptr, len): row-major table indexing, where the first
# argument is a ROW and gets multiplied by the stride. Handed a staged pointer it traps on every
# input including an empty one -- the false positive the driver's convention check exists to
# refuse.
#
# The stride matters. A bare `buf[idx] = val` handed the staged pointer stores INSIDE the page
# the driver just grew, so it lands harmlessly and never trapped -- which is why this uses a
# shape that multiplies the bad argument out past the end of memory.
_NOT_PTR_LEN = """static char tbl[64][1024];
__attribute__((export_name("row")))
int row(int r, int c){ return tbl[r][c]; }
"""


def _build(tmp_path, src, name):
    if shutil.which("clang") is None:
        pytest.skip("no clang")
    if shutil.which("node") is None:
        pytest.skip("no node to execute a wasm module")
    (tmp_path / (name + ".c")).write_text(src)
    out = tmp_path / (name + ".wasm")
    r = subprocess.run(["clang", "--target=wasm32", "-nostdlib", "-Wl,--no-entry", "-O0",
                        "-o", str(out), name + ".c"], cwd=str(tmp_path), capture_output=True)
    if r.returncode or not out.exists():
        pytest.skip("this clang cannot target wasm32")
    return out


def test_a_module_is_recognised_by_its_magic(tmp_path):
    mod = _build(tmp_path, _OOB_OFFSET, "ok")
    assert sandbox._is_wasm(mod)
    other = tmp_path / "plain.bin"
    other.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert not sandbox._is_wasm(other)


@pytest.mark.parametrize("msg,cwe", [
    ("memory access out of bounds", "CWE-119"),
    ("integer divide by zero", "CWE-369"),
    ("call stack exhausted", "CWE-674"),
    ("null function or function signature mismatch", "CWE-843"),
    ("unreachable", "CWE-617"),
    ("something no engine has ever printed", "CWE-248"),
])
def test_a_trap_message_names_the_defect(msg, cwe):
    assert wasm.classify_trap(msg)[1] == cwe


def test_a_specific_trap_beats_the_unreachable_catch_all():
    """clang compiles undefined behaviour and failed assertions alike to `unreachable`, and the
    word also turns up inside other engines' messages, so the specific match has to win."""
    assert wasm.classify_trap("unreachable executed: memory access out of bounds")[1] == "CWE-119"


def test_the_signal_name_round_trips():
    """The bug name is carried out of the sandbox where a native crash carries a signal. Bug
    names contain hyphens of their own ("out-of-bounds access"), so translating those too made
    the name unmatchable coming back -- and every wasm finding landed on the CWE-248 fallback."""
    for _needle, (bug, cwe, sev) in wasm.TRAP_CWE:
        sig = wasm.trap_signal(bug)
        assert wasm.cwe_for_trap(sig) == (cwe, sev), bug
        assert managed_fault(sig) == (cwe, sev, "the WebAssembly engine")
    assert wasm.cwe_for_trap("SIGSEGV") is None


def test_an_input_driven_oob_store_traps_and_a_valid_one_does_not(tmp_path):
    mod = _build(tmp_path, _OOB_OFFSET, "oob")
    clean = sandbox.run(mod, stdin=b"\x01\x00\x00\x00", timeout=30)
    assert clean.crashed is False, "an in-bounds offset must run clean"
    short = sandbox.run(mod, stdin=b"ab", timeout=30)
    assert short.crashed is False, "an input the module rejects must run clean"
    boom = sandbox.run(mod, stdin=b"AAAA", timeout=30)
    assert boom.crashed and boom.signal_name == wasm.trap_signal("out-of-bounds access")
    assert "parse" in (boom.note or ""), "the finding has to name the export that trapped"
    assert boom.fault_pc, "no instruction pointer exists, so the export+trap is the site"


def test_an_export_that_is_not_ptr_len_is_reported_as_undrivable(tmp_path):
    """The soundness check. `row(r, c)` handed a staged pointer traps on EVERY input, so a
    harness without this check would report an out-of-bounds read for every byte it fed in --
    a defect that is entirely the harness's own doing."""
    mod = _build(tmp_path, _NOT_PTR_LEN, "setonly")
    r = sandbox.run(mod, stdin=b"AAAA", timeout=30)
    assert r.crashed is False, "this trap is the calling convention, not a defect"
    assert "not-runnable" in r.isolation
    assert "does not take (ptr,len)" in (r.note or "")


def test_batching_is_refused_for_a_module(tmp_path):
    mod = _build(tmp_path, _OOB_OFFSET, "nobatch")
    assert sandbox.run_batch(mod, [b"AAAA", b"ab"]) is None
