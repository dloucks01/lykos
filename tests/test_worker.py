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


def _wedged_uninterruptible(ctx):
    # Never checks cancel and blocks in a bare sleep: simulates a stage stuck in an in-process
    # native call the heartbeat/cancel cannot interrupt -- the worker THREAD cannot be killed.
    import threading as _t
    _WEDGE_ENTERED.set()
    _t.Event().wait(30)


_WEDGE_ENTERED = None  # set per-test


def test_wedged_stage_does_not_starve_the_pool(store, case):
    """A stage wedged in an uninterruptible call must not permanently hold its concurrency slot:
    the supervisor reclaims the slot (release-once) and spawns a replacement worker, so other work
    of the same class still runs even at a cap of 1."""
    global _WEDGE_ENTERED
    import threading
    _WEDGE_ENTERED = threading.Event()
    register_stage("wedge", _wedged_uninterruptible, resource_class="quick", timeout=0.3)
    register_stage("fast", _fast, resource_class="quick", timeout=0.3)
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, class_caps={"quick": 1}, lease_seconds=2,
                             poll_interval=0.02, heartbeat_interval=0.3,
                             default_timeout=0.3, wedge_grace=0.4))
    p.start()
    try:
        q = JobQueue(store.conn)
        q.enqueue(case.id, "wedge", input_hashes=["1"])
        assert _WEDGE_ENTERED.wait(4), "wedge stage never started"
        # cap=1, one worker: without reclaim this second job could never run.
        rf = q.enqueue(case.id, "fast", input_hashes=["2"])
        assert _wait_status(q, rf.id, "done", timeout=8), "pool starved by the wedged stage"
        assert p.metrics().get("wedged_reclaimed", 0) >= 1
    finally:
        p.stop(grace=1.0)


def test_unknown_param_fails_loud_when_a_stage_declares_a_schema(store, case, pool):
    """P5.4: a stage that declares a param_schema fails a run carrying an undeclared key, loud and
    in the run record -- so a typo'd param is no longer a silent no-op. A stage with no schema is
    unaffected (opt-in)."""
    register_stage("schemad", _fast, param_schema={"mode", "argv"})
    register_stage("open", _fast)                      # no schema -> not validated
    q = JobQueue(store.conn)
    bad = q.enqueue(case.id, "schemad", input_hashes=["1"], params={"moed": "x"})  # typo
    assert pool.wait_idle(5)
    r = q.runs.get(bad.id)
    assert r.status == "error" and "unknown param" in (r.error or "")
    ok = q.enqueue(case.id, "schemad", input_hashes=["2"], params={"mode": "stdin"})
    assert pool.wait_idle(5)
    assert q.runs.get(ok.id).status == "done"
    free = q.enqueue(case.id, "open", input_hashes=["3"], params={"anything": 1})
    assert pool.wait_idle(5)
    assert q.runs.get(free.id).status == "done"        # no schema -> no restriction
