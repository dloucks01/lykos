"""JE-09..JE-14, JE-25 — worker pool end-to-end with fake stages."""
import time

import pytest

from lykos.jobs import JobConfig, JobQueue, WorkerPool
from lykos.jobs.registry import clear_stages, register_stage


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_stages()
    yield
    clear_stages()


@pytest.fixture
def pool(store):
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=5, poll_interval=0.02,
                             heartbeat_interval=1.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


# --- fake stages -------------------------------------------------------------
def _fast(ctx):
    ctx.log("hello")
    return None


def _emits_output(ctx):
    sha = ctx.put_artifact("triage-json", data=b'{"ok":true}')
    return {"output_shas": [sha]}


def _crash(ctx):
    raise RuntimeError("kaboom")


def _slow(ctx):
    for _ in range(2000):
        ctx.check_cancel()      # raises StageCancelled / StageTimeout
        time.sleep(0.02)
    return None


def _wait_status(q, run_id, status, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = q.runs.get(run_id)
        if r and r.status == status:
            return True
        time.sleep(0.02)
    return False


def _wait_running(q, run_id, timeout=5.0):
    return _wait_status(q, run_id, "running", timeout)


def test_fast_stage_completes(store, case, pool):
    register_stage("fast", _fast)
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "fast", input_hashes=["1"])
    assert pool.wait_idle(5)
    assert q.runs.get(r.id).status == "done"


def test_stage_output_linked(store, case, pool):
    register_stage("out", _emits_output)
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "out", input_hashes=["1"])
    assert pool.wait_idle(5)
    assert q.runs.get(r.id).status == "done"
    links = store.run_artifacts.list_by_run(r.id)
    assert len(links) == 1 and links[0].role == "output"


def test_crashing_stage_fails_but_worker_survives(store, case, pool):
    register_stage("crash", _crash)
    register_stage("fast", _fast)
    q = JobQueue(store.conn)
    rc = q.enqueue(case.id, "crash", input_hashes=["1"])
    assert pool.wait_idle(5)
    assert q.runs.get(rc.id).status == "error"
    # worker still processes work afterwards
    rf = q.enqueue(case.id, "fast", input_hashes=["2"])
    assert pool.wait_idle(5)
    assert q.runs.get(rf.id).status == "done"


def test_cancel_running_job(store, case, pool):
    register_stage("slow", _slow)
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "slow", input_hashes=["1"])
    assert _wait_running(q, r.id)
    q.cancel(r.id)
    assert _wait_status(q, r.id, "cancelled", timeout=5)


def test_timeout_marks_error(store, case, pool):
    register_stage("slowto", _slow, timeout=0.2)
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "slowto", input_hashes=["1"])
    assert pool.wait_idle(6)
    run = q.runs.get(r.id)
    assert run.status == "error" and run.error == "timeout"


def test_unknown_stage_errors(store, case, pool):
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "does-not-exist", input_hashes=["1"])
    assert pool.wait_idle(5)
    assert q.runs.get(r.id).status == "error"


def test_metrics_and_multiple_jobs(store, case, pool):
    register_stage("fast", _fast)
    q = JobQueue(store.conn)
    for i in range(10):
        q.enqueue(case.id, "fast", input_hashes=[str(i)])
    assert pool.wait_idle(8)
    m = pool.metrics()
    assert m.get("done", 0) >= 10
