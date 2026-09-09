"""Phase 5 (coverage-guided) — AFL++ backend + `coverage_fuzz` stage.

AFL++ is an optional bundled tool. These tests cover the locator, the crash-harvest parser,
and graceful failure when AFL++ is absent; the full real-AFL campaign runs only when
`afl-fuzz` is actually installed (skipped otherwise, like the Ghidra real-run tests)."""
import base64
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.fuzz import aflpp, enqueue_coverage_fuzz
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_locate_afl_via_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AFL_PATH", raising=False)
    monkeypatch.setenv("LYKOS_AFL", str(tmp_path))          # dir with no afl-fuzz
    assert aflpp.locate_afl() is None
    fake = tmp_path / "afl-fuzz"
    fake.write_text("#!/bin/sh\n")
    assert aflpp.locate_afl() == fake                       # dir now resolves
    monkeypatch.setenv("LYKOS_AFL", str(fake))              # direct path also works
    assert aflpp.locate_afl() == fake


def test_harvest_crashes_dedups(tmp_path):
    out = tmp_path / "afl-out"
    cd = out / "default" / "crashes"
    cd.mkdir(parents=True)
    (cd / "README.txt").write_text("ignore me")
    (cd / "id:000000,sig:11").write_bytes(b"AAAA")
    (cd / "id:000001,sig:11").write_bytes(b"AAAA")           # duplicate content
    (cd / "id:000002,sig:06").write_bytes(b"BBBBBB")
    got = aflpp.harvest_crashes(out)
    assert sorted(got) == [b"AAAA", b"BBBBBB"]               # deduped, README skipped


def test_coverage_stage_errors_clearly_when_afl_absent(store, case, pool, gcc, tmp_path,
                                                       monkeypatch):
    monkeypatch.delenv("AFL_PATH", raising=False)
    monkeypatch.setenv("LYKOS_AFL", str(tmp_path / "nope"))  # force locator miss
    monkeypatch.setattr(aflpp, "locate_afl", lambda *a, **k: None)
    c = tmp_path / "t.c"; c.write_text(_CRASH_ON_A)
    b = tmp_path / "t"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_coverage_fuzz(q, target, params={"max_seconds": 5})
    assert pool.wait_idle(30)
    rec = q.runs.get(run.id)
    assert rec.status == "error" and "AFL++ not found" in (rec.error or "")


@pytest.mark.skipif(aflpp.locate_afl() is None, reason="AFL++ (afl-fuzz) not installed")
def test_coverage_fuzz_real_campaign_confirms(store, case, pool, gcc, tmp_path):
    c = tmp_path / "t.c"; c.write_text(_CRASH_ON_A)
    b = tmp_path / "t"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_coverage_fuzz(q, target, params={
        "input_mode": "stdin", "max_seconds": 25, "exec_timeout": 1,
        "seeds": [base64.b64encode(b"AAAA").decode()]})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "coverage_fuzz"]
    assert confirmed
    assert [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]
