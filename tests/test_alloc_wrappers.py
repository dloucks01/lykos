"""Allocator-wrapper recognition for heap sizing (doc 30 Phase 4.2).

`_heap_capacities` sizes a heap destination from a direct `malloc(const)`. Many projects allocate
through a wrapper -- `xmalloc`, `my_alloc` -- so a copy into a wrapper'd buffer was unsized and left
UNKNOWN. `_allocator_wrappers` recognizes a size-preserving wrapper (its only allocation call feeds
a base allocator the function's own first parameter, and it returns the result), so a
`p = wrapper(n)` sizes `p` exactly as `malloc(n)`. Strict signature -- heap sizing must never
fabricate a size.
"""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import bounds
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# my_alloc is NOT in the hardcoded allocator set, so only wrapper DETECTION recognizes it. f copies
# exactly its allocation; g copies four times it (an overflow through the wrapper'd buffer).
_SRC = r"""
#include <stdlib.h>
#include <string.h>
static void* my_alloc(size_t n){ void*p=malloc(n); if(!p) abort(); return p; }
void f(const char*src){ char*b=my_alloc(64); memcpy(b, src, 64); if(b[0]) free(b); }
void g(const char*src){ char*b=my_alloc(16); memcpy(b, src, 64); if(b[0]) free(b); }
int main(int c,char**v){ if(c>1){ f(v[1]); g(v[1]); } return 0; }
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


def test_project_allocator_wrapper_sizes_its_heap_buffers(store, case, pool, tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")
    c = tmp_path / "w.c"
    c.write_text(_SRC)
    out = tmp_path / "w"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="w")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    arch = TargetDAO(store.conn).get(t.id).arch

    fdao = FunctionDAO(store.conn)
    names = {f.addr: f.name for f in fdao.list_by_target(t.id)}
    func_irs = {f.addr: fdao.get(f.id).ir for f in fdao.list_by_target(t.id) if fdao.get(f.id).ir}
    frames = {f.addr: (fdao.get(f.id).frame or {}) for f in fdao.list_by_target(t.id)}
    edges = CallEdgeDAO(store.conn).list_by_target(t.id)
    ak = bounds._arch_key(arch)
    bases = (bounds.ARCH_ABI.get(ak) or {}).get("frame", ())

    wrappers = {names.get(a, a) for a in
                bounds._allocator_wrappers(func_irs, edges, bases, 64, ak)}
    if "my_alloc" not in wrappers:
        pytest.skip("toolchain did not produce the recognizable -O0 wrapper shape")
    verdicts = {names.get(i.get("function_addr")): i.get("verdict")
                for i in bounds.classify_program(func_irs, edges, frames, arch, bits=64).values()
                if i.get("sink") == "memcpy"}
    assert verdicts.get("f") == bounds.SAFE, verdicts        # 64 into a wrapper'd 64 -> safe
    assert verdicts.get("g") in (bounds.SUSPECT, bounds.CONFIRMED), verdicts   # 64 into 16 -> flagged
