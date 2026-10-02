"""Inter-procedural guard reasoning (doc 30 Phase 1.3).

A length bounded in one function but USED in another was invisible: `classify_site`'s guard
reasoning is intra-procedural, so `unsigned n = cap(); memcpy(buf, src, n)` -- where `cap()`
provably returns a small value -- read as an unbounded copy. `bounds._return_bounds` now summarises
a function's provable constant return bound (a constant return, or a return slot a dominating guard
bounds -- reusing the sound `guard_bound`, which refuses a reassigned/clamped slot so nothing is
fabricated), and `classify_program` carries that bound to a caller's copy length when the length is
a SINGLE-WRITER slot holding that callee's return (so the slot always holds the bounded value --
the same soundness trust the heap-capacity channel uses). Gated by LYKOS_INTERPROC_BOUNDS.
"""
import os
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import bounds
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# cap() provably returns 64; f copies cap() bytes into a 128-byte buffer. The copy is safe, but
# only inter-procedural reasoning can see the length is bounded -- intra-procedurally `n` is just
# a call return with no dominating compare in f.
_SRC = r"""
#include <unistd.h>
#include <string.h>
static unsigned cap(void){ return 64; }
void f(const char *src){ char buf[128]; unsigned n = cap(); memcpy(buf, src, n);
  if(buf[0]) write(1,buf,1); }
int main(void){ char src[256]; if(read(0,src,256)<0) return 1; f(src); return 0; }
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


def _memcpy_verdicts(func_irs, edges, frames, arch, flag):
    os.environ["LYKOS_INTERPROC_BOUNDS"] = flag
    try:
        v = bounds.classify_program(func_irs, edges, frames, arch, bits=64)
    finally:
        os.environ["LYKOS_INTERPROC_BOUNDS"] = "1"
    return {a: i["verdict"] for a, i in v.items() if i.get("sink") == "memcpy"}


def test_callee_return_bound_demotes_a_caller_copy(store, case, pool, tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")

    c = tmp_path / "ip.c"
    c.write_text(_SRC)
    out = tmp_path / "ip"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="ip")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    arch = TargetDAO(store.conn).get(t.id).arch

    fdao = FunctionDAO(store.conn)
    func_irs, frames = {}, {}
    for f in fdao.list_by_target(t.id):
        full = fdao.get(f.id)
        if full and full.ir:
            func_irs[f.addr] = full.ir
        frames[f.addr] = (full.frame if full else None) or {}
    edges = CallEdgeDAO(store.conn).list_by_target(t.id)

    # cap() must be summarised as returning a bounded value
    rb = bounds._return_bounds(func_irs, arch, 64)
    assert any(v == 64 for v in rb.values()), "cap() should summarise as return bound 64"

    on = _memcpy_verdicts(func_irs, edges, frames, arch, "1")
    off = _memcpy_verdicts(func_irs, edges, frames, arch, "0")
    if not on:
        pytest.skip("toolchain did not place the copy destination in a recovered buffer")
    # with inter-proc reasoning the copy is proven bounded (SAFE); without it, unknown. The guard
    # came from cap(), a different function.
    assert bounds.SAFE in on.values(), on
    assert bounds.SAFE not in off.values(), off
