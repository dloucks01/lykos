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
    assert [l.artifact_sha256 for l in links] == [art.sha256]
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
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(claimed) == N
    assert len(set(claimed)) == N          # every job claimed exactly once
