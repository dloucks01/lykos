"""Taint through computed/heap addresses (doc 30 Phase 1.2).

A STORE through a computed pointer (`heap[i] = input`) used to drop the taint: the address is a
register, not a named frame slot, so the attacker bytes that landed in the allocation became
invisible and a later `use(heap[j])` read back clean -- a missed finding (recall). `detect/taint.py`
now models each heap allocation as one coarse REGION, keyed by the frame slot that holds the
malloc'd pointer (reusing the bounds channel's single-writer slot provenance). A tainted store
through such a pointer taints the region; a load from it reads tainted. P1.1's cross-block origins
make the pointer's slot resolvable. Region-granular and conservative (the index is not modelled),
and gated by LYKOS_REGION_TAINT so the precision effect is measurable before/after.
"""
import os
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import bounds, taint
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# attacker byte -> heap[i] (store through a computed heap pointer), read back as heap[0], then used
# as a memcpy LENGTH (a sink). Only region taint connects the store to the downstream read.
_SRC = r"""
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
char dst[16], src[256];
int main(void){
  char *h = malloc(256); if(!h) return 1;
  int i=0; if(read(0,&i,4)!=4) return 1; i &= 255;
  char in=0; if(read(0,&in,1)!=1) return 1;
  h[i] = in;                                   /* tainted store into the heap region */
  unsigned n = (unsigned char)h[0];            /* load from the region -> tainted length */
  memcpy(dst, src, n);                         /* sink fed from heap memory */
  return dst[0];
}
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


def _flagged(func_irs, edges, arch, heap_regions, flag):
    os.environ["LYKOS_REGION_TAINT"] = flag
    try:
        return taint.analyze_program(func_irs, edges, arch, heap_regions=heap_regions)
    finally:
        os.environ["LYKOS_REGION_TAINT"] = "1"


def test_region_taint_carries_input_through_the_heap(store, case, pool, tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")

    c = tmp_path / "r.c"
    c.write_text(_SRC)
    out = tmp_path / "r"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="r")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    arch = TargetDAO(store.conn).get(t.id).arch

    fdao = FunctionDAO(store.conn)
    func_irs = {}
    for f in fdao.list_by_target(t.id):
        full = fdao.get(f.id)
        if full and full.ir:
            func_irs[f.addr] = full.ir
    edges = CallEdgeDAO(store.conn).list_by_target(t.id)
    ak = bounds._arch_key(arch)
    bases = (bounds.ARCH_ABI.get(ak) or {}).get("frame", ())
    caps = bounds._heap_capacities(func_irs, edges, bases, 64, ak)
    heap_regions = {fa: set(c.keys()) for fa, c in caps.items()}
    if not heap_regions:
        pytest.skip("toolchain did not place the allocation in a recoverable single-writer slot")

    on = _flagged(func_irs, edges, arch, heap_regions, "1")
    off = _flagged(func_irs, edges, arch, heap_regions, "0")
    # region taint connects the heap store to the downstream read -> the memcpy is flagged; without
    # it the taint is lost at the store and nothing downstream is attacker-influenced.
    assert on - off, "region taint should flag a sink fed from attacker-written heap memory"
    assert not off, "without region taint the heap round-trip is invisible (baseline)"
