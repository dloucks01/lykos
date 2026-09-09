"""Phase 8 (doc 17.3) — multi-process debugging: follow-fork + cross-boundary blame."""
from __future__ import annotations

import base64
import shutil
import subprocess

import pytest

from lykos.analyze import register
from lykos.analyze.debug import gdb
from lykos.analyze.debug.multidebug import enqueue_multi_debug
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# a parent that forks a child; the CHILD reads stdin into a 16-byte buffer and overflows
_FORKCRASH = """
#include <unistd.h>
#include <sys/wait.h>
int main(void){
  pid_t pid=fork();
  if(pid==0){ char b[16]; int n=read(0,b,4096); if(n<0) _exit(1); return b[0]; }
  int st; waitpid(pid,&st,0); return 0;
}
"""


@pytest.fixture
def gdbpath():
    if not shutil.which("gdb"):
        pytest.skip("gdb not installed")
    return gdb.locate_gdb()


@pytest.fixture
def forkcrash(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("md")
    c = d / "fc.c"; c.write_text(_FORKCRASH)
    out = d / "forkcrash"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build forkcrash")
    return out


def test_run_gdb_follow_catches_child_crash(gdbpath, forkcrash, tmp_path):
    sf = tmp_path / "in.bin"; sf.write_bytes(b"A" * 512)
    cap = gdb.run_gdb_follow(gdbpath, forkcrash, [], str(sf), timeout=20)
    assert cap["ok"] and cap["signal_name"] in ("SIGSEGV", "SIGBUS", "SIGILL")
    assert cap["forked"] and cap["child_pid"] and cap["multiproc"]
    assert cap["maps"]                       # captured the crashing child's image


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_multi_debug_stage_blames_fork_child(store, case, pool, gdbpath, forkcrash):
    t = ingest(store, case.id, forkcrash, filename="forkcrash")
    q = JobQueue(store.conn)
    run = enqueue_multi_debug(q, t, params={
        "input": base64.b64encode(b"A" * 512).decode(), "input_mode": "stdin"})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"

    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id)
          if f.detector == "multi_debug"]
    assert fs, "expected a multi_debug finding"
    f = fs[0]
    assert f.state == "confirmed" and f.cwe.startswith("CWE-")
    ev = " ".join(e.get("detail", "") for e in f.evidence)
    assert "multi-process debug" in ev
    assert "fork" in ev and "forkcrash" in ev


def test_multi_debug_reports_unsupported_without_gdb(store, case, pool, monkeypatch):
    # no gdb -> the stage degrades cleanly (does not raise, files no finding)
    monkeypatch.setattr("lykos.analyze.debug.gdb.locate_gdb", lambda *a, **k: None)
    sha = store.put_artifact(case.id, "x", data=b"AAAA").sha256
    t = store.targets.upsert(case.id, filename="svc", sha256=sha, size=4, arch="x86-64")
    q = JobQueue(store.conn)
    run = enqueue_multi_debug(q, t, params={"input": base64.b64encode(b"A" * 8).decode()})
    assert pool.wait_idle(20) and q.runs.get(run.id).status == "done"
    assert not [f for f in FindingDAO(store.conn).list_by_target(t.id)
                if f.detector == "multi_debug"]
