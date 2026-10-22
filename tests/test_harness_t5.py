"""T5 (doc 46): richer harness oracles -- the unbounded-allocation detector (CWE-789/400 DoS).

A function that mallocs a size taken straight from its input lets an attacker drive an arbitrarily
large allocation from a few bytes -- a memory-exhaustion lead, not a memory-corruption fault, so the
crash oracle never fires on it. The allocation oracle does. A/B on the SAME budget: a function that
allocates a FIXED small size produces no oracle hit; a sibling that allocates the input's length
field does, and the witnessing input is reported."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.harness.emulate import _HUGE_ALLOC, available
from lykos.analyze.harness.fuzz import fuzz_function
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

# unsafe(): mallocs the attacker's 4-byte length field. safe(): mallocs a fixed small block.
_SRC = r"""
#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) void unsafe(char *buf){
  unsigned int len;
  memcpy(&len, buf, 4);
  char *p = malloc(len);                 /* attacker-controlled allocation SIZE */
  if (p){ p[0] = 1; free(p); }
}
__attribute__((noinline)) void safe(char *buf){
  (void)buf;
  char *p = malloc(16);                  /* fixed, bounded -- never the input's size */
  if (p){ p[0] = 1; free(p); }
}
int main(int argc, char **argv){ (void)argv; char b[8] = {0}; unsafe(b); safe(b); return argc; }
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


def _addr_of(fdao, target_id, name):
    # exact basename -- "unsafe".endswith("safe") is True, so a suffix match would confuse the two.
    def base(n):
        return (n or "").split(".")[-1]
    f = next((x for x in fdao.list_by_target(target_id) if base(x.name) == name), None)
    assert f is not None, f"decompiler did not recover {name}()"
    a = str(f.addr)
    return int(a, 16) if a.lower().startswith("0x") else int(a)


def test_allocation_oracle_flags_attacker_controlled_size(store, case, pool, tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")
    c = tmp_path / "a.c"
    c.write_text(_SRC)
    out = tmp_path / "a"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="a")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)

    fdao = FunctionDAO(store.conn)
    unsafe_addr = _addr_of(fdao, t.id, "unsafe")
    safe_addr = _addr_of(fdao, t.id, "safe")
    data = store.content.path(t.sha256).read_bytes()

    budget = dict(arg_shape="ptr", budget_execs=4000, budget_seconds=20.0, seed=7)
    hit = fuzz_function(data, unsafe_addr, **budget)
    clean = fuzz_function(data, safe_addr, **budget)

    assert hit.oracle_hits, "the allocation oracle should fire on malloc(attacker_length)"
    assert hit.oracle_hits[0]["result"].huge_alloc >= _HUGE_ALLOC
    assert not hit.crashes, "an unbounded allocation is a DoS lead, not a memory-corruption crash"
    assert not clean.oracle_hits, "a fixed-size malloc must not trip the allocation oracle"
