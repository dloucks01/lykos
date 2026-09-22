"""JE-02..JE-08, JE-17 — queue behaviors (single-threaded + concurrent claim)."""
import threading
import time

from lykos.db.connection import connect
from lykos.jobs.queue import JobQueue


def _events(q, case_id, type=None):
    evs = q.events.list(case_id=case_id, limit=1000)
    return [e for e in evs if (type is None or e.type == type)]


def test_enqueue_and_dedup(store, case):
    q = JobQueue(store.conn)
    r1 = q.enqueue(case.id, "ingest_triage", params={"a": 1}, tool_version="v1")
    r2 = q.enqueue(case.id, "ingest_triage", params={"a": 1}, tool_version="v1")
    assert r1.id == r2.id                      # deduped (same cache key, still pending)
    assert r1.status == "queued"
    assert len(_events(q, case.id, "job.queued")) == 1


def test_claim_complete_lifecycle(store, case):
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "s", input_hashes=["h"])
    rid = q.claim("w1", ["quick"], 30)
    assert rid == r.id
    run = q.runs.get(rid)
    assert run.status == "running" and run.attempts == 1 and run.claimed_by == "w1"
    assert q.claim("w1", ["quick"], 30) is None      # nothing left queued
    assert q.complete(rid) is True
    assert q.runs.get(rid).status == "done"
    assert q.complete(rid) is False                  # idempotent guard


def test_fail_retry_then_error(store, case):
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "s", input_hashes=["h"], max_attempts=2)
    q.claim("w1", ["quick"], 30)                     # attempts=1
    assert q.fail(r.id, "boom") == "queued"          # retryable, requeued
    q.claim("w1", ["quick"], 30)                     # attempts=2
    assert q.fail(r.id, "boom") == "error"           # exhausted
    assert q.runs.get(r.id).status == "error"


def test_cancel_queued_and_running(store, case):
    q = JobQueue(store.conn)
    r1 = q.enqueue(case.id, "s", input_hashes=["a"])
    assert q.cancel(r1.id) is True
    assert q.runs.get(r1.id).status == "cancelled"

    r2 = q.enqueue(case.id, "s", input_hashes=["b"])
    q.claim("w1", ["quick"], 30)
    q.cancel(r2.id)
    run = q.runs.get(r2.id)
    assert run.status == "running" and run.cancel_requested is True


def test_reap_requeues_expired(store, case):
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "s", input_hashes=["h"], max_attempts=3)
    q.claim("w1", ["quick"], 30)
    # force the lease into the past
    store.conn.execute("UPDATE analysis_run SET lease_expires_at=? WHERE id=?",
                       (int(time.time()) - 1, r.id))
    assert q.reap() == 1
    assert q.runs.get(r.id).status == "queued"       # reclaimed


def test_recover_orphans_on_boot(store, case):
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "s", input_hashes=["h"], max_attempts=2)
    q.claim("w1", ["quick"], 30)                     # now running
    assert q.recover_orphans() == 1
    assert q.runs.get(r.id).status == "queued"


def test_cache_short_circuit(store, case):
    q = JobQueue(store.conn)
    art = store.put_artifact(case.id, "triage-json", data=b"{}")
    r1 = q.enqueue(case.id, "triage", input_hashes=["fixed"], tool_version="v1")
    q.claim("w1", ["quick"], 30)
    q.complete(r1.id, [(art.sha256, "output")])
    # identical enqueue -> cache hit, new done run with copied outputs
    r2 = q.enqueue(case.id, "triage", input_hashes=["fixed"], tool_version="v1")
    assert r2.id != r1.id and r2.status == "done"
    links = q.runs and store.run_artifacts.list_by_run(r2.id)
    assert [a.artifact_sha256 for a in links] == [art.sha256]
    assert len(_events(q, case.id, "job.cachehit")) == 1


def test_no_double_claim_under_concurrency(store, case):
    q = JobQueue(store.conn)
    N = 25
    for i in range(N):
        q.enqueue(case.id, "s", input_hashes=[str(i)])   # distinct cache keys => no dedup
    claimed, lock = [], threading.Lock()

    def worker():
        c = connect(store.db_path)
        qq = JobQueue(c)
        try:
            while True:
                rid = qq.claim("w", ["quick"], 30)
                if rid is None:
                    break
                with lock:
                    claimed.append(rid)
        finally:
            c.close()

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(claimed) == N
    assert len(set(claimed)) == N          # every job claimed exactly once


# ---------------------------------------------------- engine correctness (Sept 2026 audit)
def test_a_result_from_a_reaped_worker_is_reported_not_silently_dropped(store, case):
    """The reaper requeues a 'running' job whose lease expired. A worker that was in fact
    still alive then finishes and reports against a row that has moved on. The drop is
    unavoidable -- another worker may already own the row -- but it used to happen with no
    trace at all, so a lost result looked exactly like a job that never ran.
    """
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "s", input_hashes=["h"], max_attempts=3)
    rid = q.claim("w1", ["quick"], lease_seconds=0)
    assert rid == run.id
    assert q.reap(now=_future()) == 1                 # lease expired -> back to queued
    assert q.runs.get(rid).status == "queued"

    assert q.complete(rid, [("sha", "output")], worker_id="w1") is False
    evs = [e for e in store.events.list(run_id=rid) if e.type == "job.result_discarded"]
    assert evs, "a discarded result must leave a trace"
    assert evs[-1].level == "warn"
    assert "lease" in evs[-1].payload["reason"] or "status" in evs[-1].payload["reason"]
    assert evs[-1].payload["worker"] == "w1"


def test_a_result_from_a_worker_that_lost_the_claim_is_rejected(store, case):
    """After a reap, another worker may re-claim the same run. The original worker must not
    be able to overwrite the new owner's job."""
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "s", input_hashes=["h"], max_attempts=3)
    q.claim("w1", ["quick"], lease_seconds=0)
    q.reap(now=_future())
    assert q.claim("w2", ["quick"], lease_seconds=60) == run.id   # re-claimed by someone else

    assert q.complete(run.id, worker_id="w1") is False            # the stale worker
    assert q.runs.get(run.id).status == "running"                 # w2 still owns it
    assert q.complete(run.id, worker_id="w2") is True             # the real owner may finish
    assert q.runs.get(run.id).status == "done"


def test_events_reach_the_consumer_only_after_commit(store, case):
    """The UI event stream tails this table live. Firing on_event inside the transaction let
    a consumer observe a job.done that a rollback then erased."""
    seen = []
    q = JobQueue(store.conn, on_event=seen.append)
    run = q.enqueue(case.id, "s", input_hashes=["h"])
    assert [e["type"] for e in seen] == ["job.queued"]
    assert store.conn.in_transaction is False         # delivered after the commit, not during

    seen.clear()
    q.claim("w1", ["quick"], 60)
    q.complete(run.id, worker_id="w1")
    assert "job.done" in [e["type"] for e in seen]
    # every delivered event is durable: it can be read back from the table
    ids = {e.id for e in store.events.list(limit=500)}
    assert all(e["id"] in ids for e in seen)


def test_enqueue_dedup_is_atomic_under_concurrency(store, case):
    """Read-then-insert let two workers both miss the same pending run and enqueue it twice --
    the duplicate work `dedup` exists to prevent."""
    import threading
    out, errors = [], []

    def go():
        from lykos.db.connection import connect
        conn = connect(store.db_path)
        try:
            out.append(JobQueue(conn).enqueue(case.id, "dup", input_hashes=["same"]).id)
        except Exception as e:      # noqa: BLE001
            errors.append(e)
        finally:
            conn.close()

    ts = [threading.Thread(target=go) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors
    rows = store.conn.execute(
        "SELECT COUNT(*) AS c FROM analysis_run WHERE stage='dup'").fetchone()["c"]
    assert rows == 1, f"dedup produced {rows} rows for one cache key"
    assert len(set(out)) == 1


def _future():
    import time
    return int(time.time()) + 10_000


def test_is_cancel_requested_reflects_a_cancel(store, case):
    """H9: the heartbeat reads this to stop renewing a cancelled-but-unresponsive job's lease so
    the reaper can reclaim it (a non-cooperative stage never observes the cancel itself)."""
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "s", resource_class="quick")
    q.claim("w1", ["quick"], 30)
    assert q.is_cancel_requested(run.id) is False
    assert q.cancel(run.id) is True
    assert q.is_cancel_requested(run.id) is True


def test_a_critical_writer_survives_a_briefly_held_write_lock(store, case):
    """H8: a queue writer whose BEGIN IMMEDIATE loses the write lock to a large single-writer
    transaction must retry and land, not raise -- a succeeded job recorded as `error` is worse
    than a slow one. Hold the lock from another connection briefly, then a critical writer
    (enqueue) must still commit."""
    dbfile = store.conn.execute("PRAGMA database_list").fetchall()[0][2]
    holding, released = threading.Event(), threading.Event()

    def _hold_lock():
        o = connect(dbfile)                     # a connection is single-thread: own it here
        o.execute("BEGIN IMMEDIATE")            # holds the RESERVED write lock
        holding.set()
        time.sleep(0.4)
        o.execute("ROLLBACK")
        o.close()
        released.set()

    threading.Thread(target=_hold_lock, daemon=True).start()
    assert holding.wait(2), "background lock holder never started"
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "s", resource_class="quick")   # waits ~0.4s on the lock, then lands
    assert released.is_set(), "writer returned before the lock was released -- it did not wait"
    assert run is not None and q.runs.get(run.id) is not None
