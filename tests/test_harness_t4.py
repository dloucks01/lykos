"""T4 (doc 46): constant-guided harness fuzzing. A parser gates on a magic value it checks the
input against; a blind mutator has to invent it byte by byte and never does within a budget. The
function's OWN comparison constant, fed back as a dictionary, gets past the gate -- so a bug HIDDEN
behind the magic value is reached. A/B on the SAME budget: without the dictionary the gate blocks
the campaign; with it, the fault past the gate is found."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.harness.emulate import available
from lykos.analyze.harness.fuzz import dictionary_from_ir, fuzz_function
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

# handle() faults ONLY past a 0xCAFEBABE magic gate -- the bug a blind mutator cannot reach.
_SRC = r"""
#include <string.h>
__attribute__((noinline)) void handle(char *buf){
  unsigned int magic;
  memcpy(&magic, buf, 4);
  if (magic == 0xCAFEBABE){
    volatile char *p = (volatile char *)0;   /* crash only AFTER the magic gate is passed */
    *p = 1;
  }
}
int main(int argc, char **argv){ (void)argv; char b[8] = {0}; handle(b); return argc; }
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_dictionary_reaches_a_bug_behind_a_magic_gate(store, case, pool, tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")
    c = tmp_path / "m.c"
    c.write_text(_SRC)
    out = tmp_path / "m"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="m")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)

    fdao = FunctionDAO(store.conn)
    handle = next((f for f in fdao.list_by_target(t.id) if (f.name or "").endswith("handle")), None)
    assert handle is not None, "decompiler did not recover handle()"
    addr = int(str(handle.addr), 16) if str(handle.addr).lower().startswith("0x") else int(handle.addr)
    ir = fdao.get(handle.id).ir
    data = store.content.path(t.sha256).read_bytes()

    # the function's own constant (0xCAFEBABE) is in the dictionary; a generic word list is not
    dict_words = dictionary_from_ir(ir)
    assert (0xCAFEBABE).to_bytes(4, "little") in dict_words, \
        f"the magic gate constant should be mined from the disassembly: {[w.hex() for w in dict_words]}"

    budget = dict(arg_shape="ptr", budget_execs=4000, budget_seconds=20.0, seed=7)
    without = fuzz_function(data, addr, dictionary=[], **budget)
    withd = fuzz_function(data, addr, dictionary=dict_words, **budget)
    assert not without.crashes, "the blind campaign should be blocked by the magic gate (baseline)"
    assert withd.crashes, "the constant dictionary should get past the magic gate and find the fault"
