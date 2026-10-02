"""argc as a size/range source (doc 30 Phase 1.4).

`argc` is deliberately kept OUT of the data-flow taint channel -- it is a count, not attacker data,
and tainting it would push taint through every `argc` guard. But the integer-overflow/allocation
classes still want it: `malloc(argc * K)` computes the size in 32-bit arithmetic that can wrap to a
tiny allocation. So the detect stage treats the entry function (which receives argc) as scanned for
the int-overflow shapes (`touched |= entry_seeds`), and `_intover_candidates` flags a narrow
arithmetic feeding an allocator's size argument (`int_overflow_alloc`, CWE-190) -- without adding
any data-flow taint.
"""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_BAD = r"""
#include <stdlib.h>
#include <string.h>
int main(int argc, char**argv){ (void)argv;
  char *b = malloc(argc * 4096);          /* 32-bit product feeds the 64-bit size -> can wrap */
  if(b){ memset(b, 0, argc * 4096); free(b); }
  return 0; }
"""

# a fixed, constant-size allocation has nothing attacker/argc-sized in the size -> no CWE-190 here
_GOOD = r"""
#include <stdlib.h>
#include <string.h>
int main(int argc, char**argv){ (void)argc; (void)argv;
  char *b = malloc(4096);
  if(b){ memset(b, 0, 4096); free(b); }
  return 0; }
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


def _alloc_cwe190(store, case, pool, tmp_path, src):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("needs a C compiler")
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")
    c = tmp_path / "a.c"
    c.write_text(src)
    out = tmp_path / "a"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="a")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    return [f for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "int_overflow_alloc"]


def test_argc_scaled_allocation_is_flagged(store, case, pool, tmp_path):
    hits = _alloc_cwe190(store, case, pool, tmp_path, _BAD)
    assert hits, "malloc(argc * K) should be flagged CWE-190 (allocation-size wrap)"
    assert all(h.cwe == "CWE-190" for h in hits)


def test_constant_allocation_is_not_flagged(store, case, pool, tmp_path):
    # the entry function is now scanned, but a constant-size allocation carries no wrapping
    # arithmetic, so the allocation-size channel stays silent (no argc-driven false positive).
    assert not _alloc_cwe190(store, case, pool, tmp_path, _GOOD)
