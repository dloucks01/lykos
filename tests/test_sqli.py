"""Native SQL injection (CWE-89): a query string passed to a DB API (sqlite3_exec / mysql_query /
PQexec / ...) built from untrusted input. Was JVM-only; now native/ELF+source, via the same taint
model as path-traversal -- corroborated only when taint proves the query argument is attacker-
controlled."""
from __future__ import annotations

import shutil
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect.detectors import DetectContext, dangerous_api
from lykos.analyze.detect.catalog import DANGEROUS, SINK_TAINT_ARGS
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest, enqueue_triage
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.detect import enqueue_detect
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def test_sql_sinks_registered():
    for fn in ("sqlite3_exec", "sqlite3_prepare_v2", "mysql_query", "PQexec"):
        assert DANGEROUS[fn][0] == "CWE-89" and SINK_TAINT_ARGS[fn] == frozenset({1})


def test_dangerous_api_flags_mysql_query():
    e = types.SimpleNamespace(dst_name="mysql_query", src_addr="0x1149", site_addr="0x1160")
    ctx = DetectContext(target_id="t", case_id="c", call_edges=[e], strings=[], functions=[],
                        frames={}, func_irs={}, bits=64, arch="x86-64")
    out = dangerous_api(ctx)
    assert out and out[0]["cwe"] == "CWE-89"


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


def test_tainted_query_is_corroborated(store, case, pool, gcc_or_skip):
    import subprocess as sp
    import tempfile
    from pathlib import Path
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = Path(tempfile.mkdtemp())
    (d / "s.c").write_text("int mysql_query(void*c,const char*q){(void)c;(void)q;return 0;}\n"
                           "int main(int argc,char**argv){ if(argc<2)return 0;"
                           " mysql_query(0, argv[1]); return 0; }\n")
    exe = d / "sqli"
    if sp.run([gcc, "-no-pie", "-O0", str(d / "s.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    t = ingest(store, case.id, exe, filename="sqli")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(40)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(90)
    rows = store.conn.execute("SELECT state FROM finding WHERE target_id=? AND cwe='CWE-89'",
                              (t.id,)).fetchall()
    assert any(state == "corroborated" for (state,) in rows), rows
