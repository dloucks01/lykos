"""Uncontrolled allocation size (CWE-789): malloc/calloc/realloc whose SIZE is attacker-controlled
-- a huge allocation (DoS) or, if the size arithmetic wraps, an under-allocation that is then
overflowed. Modelled like the path-traversal / copy sinks: advisory on its own (every program
allocates), promoted to corroborated only when taint proves the size argument carries untrusted
input (e.g. a length field read straight from input)."""
from __future__ import annotations

import shutil
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect.detectors import DetectContext, dangerous_api
from lykos.analyze.detect.catalog import DANGEROUS, SINK_TAINT_ARGS
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.detect import enqueue_detect
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def test_alloc_sinks_registered():
    for fn in ("malloc", "calloc", "realloc", "reallocarray"):
        assert DANGEROUS[fn][0] == "CWE-789" and fn in SINK_TAINT_ARGS
    assert SINK_TAINT_ARGS["realloc"] == frozenset({1})   # realloc(ptr, SIZE)
    assert SINK_TAINT_ARGS["calloc"] == frozenset({0, 1})


def test_dangerous_api_flags_malloc():
    e = types.SimpleNamespace(dst_name="malloc", src_addr="0x1149", site_addr="0x1160")
    ctx = DetectContext(target_id="t", case_id="c", call_edges=[e], strings=[], functions=[],
                        frames={}, func_irs={}, bits=64, arch="x86-64")
    out = dangerous_api(ctx)
    assert out and out[0]["cwe"] == "CWE-789" and out[0]["state"] == "candidate"


@pytest.fixture
def gcc_or_skip():
    if sandbox.host_arch() != "x86-64" or not (shutil.which("gcc") or shutil.which("cc")):
        pytest.skip("native x86-64 + C compiler required")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _detect(store, case, pool, csrc, name):
    import subprocess as sp
    import tempfile
    from pathlib import Path
    from lykos.analyze.ingest import enqueue_triage
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = Path(tempfile.mkdtemp())
    (d / "s.c").write_text(csrc)
    exe = d / name
    if sp.run([gcc, "-no-pie", "-O0", str(d / "s.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    t = ingest(store, case.id, exe, filename=name)
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(90)
    return [tuple(r) for r in store.conn.execute(
        "SELECT state FROM finding WHERE target_id=? AND cwe='CWE-789'", (t.id,)).fetchall()]


def test_tainted_alloc_size_is_corroborated(store, case, pool, gcc_or_skip):
    rows = _detect(store, case, pool,
                   "#include <stdlib.h>\n#include <unistd.h>\n"
                   "int main(void){ unsigned long n; if(read(0,&n,sizeof n)!=sizeof n)return 0;"
                   " char*p=malloc(n); if(p){p[0]=1;free(p);} return 0; }\n", "al")
    assert any(state == "corroborated" for (state,) in rows), rows


def test_constant_alloc_size_not_corroborated(store, case, pool, gcc_or_skip):
    rows = _detect(store, case, pool,
                   "#include <stdlib.h>\nint main(void){ char*p=malloc(64);"
                   " if(p){p[0]=1;free(p);} return 0; }\n", "alc")
    assert not any(state == "corroborated" for (state,) in rows), rows
