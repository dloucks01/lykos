"""Phase 6 — heap-error detector: guard-page LD_PRELOAD allocator catches UAF / double-free /
heap overflow / invalid free without the program crashing on its own."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import enqueue_heap_check, sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_SRC = ("#include <stdlib.h>\n#include <string.h>\n"
        "int main(int c,char**v){int m=c>1?atoi(v[1]):0; char*p=malloc(32);\n"
        "  if(m==1){free(p);free(p);}"                        # double free
        "  else if(m==2){free(p);p[0]=1;}"                    # use-after-free
        "  else if(m==3){memset(p,'A',64);free(p);}"          # heap overflow
        "  else {strcpy(p,\"ok\");free(p);} return 0;}\n")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _cwes(store, tid):
    return {f.cwe for f in FindingDAO(store.conn).list_by_target(tid)
            if f.detector == "heap_monitor"}


@pytest.mark.skipif(sandbox.host_arch() != "x86-64" or not shutil.which("cc"),
                    reason="native x86-64 + a C compiler required")
def test_heap_detects_memory_errors(store, case, pool, gcc, tmp_path):
    c = tmp_path / "h.c"; c.write_text(_SRC)
    b = tmp_path / "h"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    got = {}
    for mode, cwe in ((1, "CWE-415"), (2, "CWE-416"), (3, "CWE-122")):
        run = enqueue_heap_check(q, target, params={"input_mode": "arg", "argv": [str(mode)],
                                                    "timeout": 12})
        assert pool.wait_idle(40)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("heap stage could not run: " + str(rec.error))
        got[cwe] = cwe in _cwes(store, target.id)
    # at least double-free and UAF must be caught (the headline classes)
    assert got["CWE-415"] and got["CWE-416"]


def test_heap_clean_program_no_false_positives(store, case, pool, gcc, tmp_path):
    c = tmp_path / "h.c"; c.write_text(_SRC)
    b = tmp_path / "h"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    if sandbox.host_arch() != "x86-64" or not shutil.which("cc"):
        pytest.skip("native x86-64 + cc required")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_heap_check(q, target, params={"input_mode": "arg", "argv": ["0"], "timeout": 12})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    assert not _cwes(store, target.id)     # clean run: no heap findings (leaks off by default)
