"""Phase 4 — sandboxed dynamic analysis: crash detection + crash -> Confirmed finding."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.dynamic.stage import enqueue_dynamic
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH = "int main(){volatile int*p=0;*p=1;return 0;}\n"
_OK = "int main(){return 0;}\n"
_LOOP = "#include <unistd.h>\nint main(){while(1){}return 0;}\n"


@pytest.fixture(scope="module")
def bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("dynbins")
    out = {}
    for name, src in (("crash", _CRASH), ("ok", _OK), ("loop", _LOOP)):
        c = d / (name + ".c"); c.write_text(src)
        b = d / name
        r = subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True)
        if r.returncode == 0:
            out[name] = b
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=15, poll_interval=0.02, heartbeat_interval=3.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_host_arch():
    assert isinstance(sandbox.host_arch(), str) and sandbox.host_arch()


def test_sandbox_detects_crash(bins):
    if "crash" not in bins:
        pytest.skip("build failed")
    res = sandbox.run(bins["crash"], timeout=10)
    assert res.crashed and res.signal_name == "SIGSEGV"
    assert res.isolation in ("bwrap+netns", "rlimits-only")


def test_sandbox_clean_exit(bins):
    if "ok" not in bins:
        pytest.skip("build failed")
    res = sandbox.run(bins["ok"], timeout=10)
    assert not res.crashed and not res.timed_out and res.exit_code == 0


def test_sandbox_timeout(bins):
    if "loop" not in bins:
        pytest.skip("build failed")
    res = sandbox.run(bins["loop"], timeout=1)
    assert res.timed_out and not res.crashed


def test_dynamic_stage_crash_confirms_finding(store, case, pool, bins):
    from lykos.analyze.ingest import ingest
    if "crash" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["crash"])
    q = JobQueue(store.conn)
    run = enqueue_dynamic(q, target, params={"input_mode": "none", "timeout": 10})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"

    dr = DynResultDAO(store.conn).list_by_target(target.id)
    assert dr and dr[0].crashed and dr[0].signal_name == "SIGSEGV"

    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed"]
    assert confirmed and confirmed[0].detector == "dynamic"
    assert "dynamic" in {e["channel"] for e in confirmed[0].evidence}


def test_dynamic_stage_clean_no_confirmed(store, case, pool, bins):
    from lykos.analyze.ingest import ingest
    if "ok" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["ok"])
    q = JobQueue(store.conn)
    run = enqueue_dynamic(q, target, params={"input_mode": "none", "timeout": 10})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    dr = DynResultDAO(store.conn).list_by_target(target.id)
    assert dr and not dr[0].crashed
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "confirmed"]
