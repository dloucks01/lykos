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


def test_multi_debug_merges_its_evidence_without_re_crediting_the_defect(
        store, case, pool, gdbpath, forkcrash):
    """It keys on the CRASH's dedup key, so it MERGES into whatever already filed that crash.

    `detector` names who FOUND the defect, and it used to be last-writer-wins: five modules merge
    on that shared key, so a defect proven by `poc`/`primitive` ended up credited to whichever
    stage touched it last -- and STATIC_DETECTORS filtering reads that very field. The rule now
    lives in `FindingDAO.upsert`: the discoverer keeps the credit unless the newcomer is an
    `authoritative` classifier. This stage is not one, so it contributes evidence and no more.
    """
    fd = FindingDAO(store.conn)
    t = ingest(store, case.id, forkcrash, filename="forkcrash")
    q = JobQueue(store.conn)
    params = {"input": base64.b64encode(b"A" * 512).decode(), "input_mode": "stdin"}
    run = enqueue_multi_debug(q, t, params=params)
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    made = [f for f in fd.list_by_target(t.id) if f.detector == "multi_debug"]
    assert made, "expected a multi_debug finding"
    key, before = made[0].dedup_key, made[0].detector

    # A later, NON-authoritative channel on the same key: the credit must not move.
    fd.upsert(t.id, case.id, {"cwe": made[0].cwe, "title": "Reproduced crash", "severity": "high",
                              "state": "poc-backed", "confidence": 0.95, "detector": "poc",
                              "dedup_key": key})
    merged = next(f for f in fd.list_by_target(t.id) if f.dedup_key == key)
    assert merged.detector == before, "a corroborating channel took the credit"
    assert merged.state == "poc-backed", "the state must still advance on the stronger evidence"
    # ...and this stage's own evidence is still attached, which is what it is for.
    assert any("multi-process debug" in (e.get("detail") or "") for e in merged.evidence)

    # An AUTHORITATIVE classifier may take it -- that is how root_cause relabels a generic crash.
    fd.upsert(t.id, case.id, {"cwe": made[0].cwe, "title": "Root cause: heap-use-after-free",
                              "severity": "high", "state": "confirmed", "confidence": 0.95,
                              "detector": "root_cause", "authoritative": True, "dedup_key": key})
    assert next(f for f in fd.list_by_target(t.id)
                if f.dedup_key == key).detector == "root_cause"


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
