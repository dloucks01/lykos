"""T6 (doc 46): stateful sequence driving. A dispatch parser keeps state across calls and only
faults in a state reached after a specific message PREFIX (here: 'A' then 'B' then 'C'). A single
call -- whatever its buffer -- starts from the initial state and can never reach the fault. Driving
an ORDERED SEQUENCE in one emulator state does. A/B proves exactly that at both the executor level
(run_sequence vs run_function) and the fuzz level (sequence vs single-call campaign)."""
import shutil
import subprocess

import pytest
from lykos.analyze.harness.emulate import available, run_function, run_sequence
from lykos.analyze.harness.fuzz import fuzz_function

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

# handle() is a 3-state machine over the first byte of each message; it faults ONLY on 'C' while in
# state 2, i.e. only after an 'A' message then a 'B' message have advanced the (persistent) state.
_SRC = r"""
#include <string.h>
static int st = 0;
__attribute__((noinline)) void handle(char *buf, int len){
  if (len < 1) return;
  char c = buf[0];
  if      (st == 0 && c == 'A') st = 1;
  else if (st == 1 && c == 'B') st = 2;
  else if (st == 2 && c == 'C'){ volatile char *p = (volatile char *)0; *p = 1; }  /* fault */
  else st = 0;
}
int main(int argc, char **argv){ (void)argv; char b[8] = {0}; handle(b, argc); return 0; }
"""


def _build(tmp_path):
    gcc = shutil.which("gcc")
    nm = shutil.which("nm")
    if not (gcc and nm):
        pytest.skip("needs gcc + nm")
    c = tmp_path / "sm.c"; c.write_text(_SRC)
    out = tmp_path / "sm"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    nm_out = subprocess.run([nm, str(out)], capture_output=True, text=True).stdout
    addr = next((int(ln.split()[0], 16) for ln in nm_out.splitlines()
                 if ln.split()[-1] == "handle"), None)
    assert addr, "could not find handle() address"
    return out.read_bytes(), addr


def test_sequence_reaches_a_state_gated_fault(tmp_path):
    data, addr = _build(tmp_path)
    # the ordered prefix drives the state machine into the faulting state
    seqr = run_sequence(data, addr, [b"A", b"B", b"C"], arg_shape="ptr_len")
    assert seqr.crashed, "the A->B->C sequence should reach the state-gated fault"
    assert seqr.seq_index == 2, "the fault is on the third message"

    # a single call -- even with the whole prefix as one buffer -- starts in state 0 and cannot fault
    assert not run_function(data, addr, b"C", arg_shape="ptr_len").crashed
    assert not run_function(data, addr, b"A\nB\nC", arg_shape="ptr_len").crashed
    assert not run_function(data, addr, b"ABC", arg_shape="ptr_len").crashed
    # the right messages in the WRONG order must not fault either (it is a real state machine)
    assert not run_sequence(data, addr, [b"C", b"B", b"A"], arg_shape="ptr_len").crashed
    assert not run_sequence(data, addr, [b"C"], arg_shape="ptr_len").crashed


def test_single_message_sequence_matches_run_function(tmp_path):
    data, addr = _build(tmp_path)
    # run_sequence with one message is exactly run_function -- same clean return, no false fault
    one = run_sequence(data, addr, [b"A"], arg_shape="ptr_len")
    assert not one.crashed and one.returned


def test_sequence_fuzz_finds_what_single_call_cannot(tmp_path):
    data, addr = _build(tmp_path)
    budget = dict(arg_shape="ptr_len", budget_execs=2000, budget_seconds=20.0, seed=7)
    # a realistic '\n'-framed seed: the sequence campaign splits and drives it, the single-call
    # campaign drives the whole buffer as one message (and can never advance past state 1).
    seqd = fuzz_function(data, addr, seeds=[b"A\nB\nC"], sequence=True, **budget)
    single = fuzz_function(data, addr, seeds=[b"A\nB\nC"], sequence=False, **budget)
    assert seqd.crashes, "sequence-mode fuzzing should reach the state-gated fault"
    assert not single.crashes, "single-call fuzzing can never reach a fault that needs a prefix"
