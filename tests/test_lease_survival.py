"""A healthy stage must not be reaped because the database was busy.

Measured on /usr/bin/readelf, which is a plain 823 KB system binary and the least exotic target
in the corpus: `detect_cwe` heartbeat normally for 111 seconds, then lost three consecutive
beats while thirteen other stages started and finished inside the same 35-second window, and the
reaper marked a working stage `error`. The gate's own rule is that an error is never an
acceptable outcome for a capability -- a decline is -- so this is a defect in the engine and not
a property of the target.

Two things were wrong at once: the lease allowed exactly three beats, and a beat that failed on
a 5-second busy_timeout then waited a full 10-second interval before trying again, so a write
storm consumed a beat every 15 seconds and three failures burned the whole lease.
"""
import threading
import time

import lykos.jobs.worker as W
from lykos.jobs.config import JobConfig
from lykos.jobs.worker import _beat_wait


def test_the_lease_allows_enough_beats_to_survive_a_write_storm():
    """The margin is counted in BEATS, because that is what a busy database costs you. The
    suite's own tests had already noticed the default was too tight, overriding it to 60-120 in
    a dozen files -- which is a workaround, not a fix."""
    c = JobConfig()
    beats = c.lease_seconds / c.heartbeat_interval
    assert beats >= 6, (
        f"a lease of {c.lease_seconds}s with a {c.heartbeat_interval}s beat survives only "
        f"{beats:.0f} lost beats; readelf lost three in a row to ordinary write contention")


def test_a_failed_beat_is_retried_sooner_than_a_whole_interval():
    c = JobConfig(heartbeat_interval=10.0)
    assert _beat_wait(c, failed=False) == 10.0
    assert _beat_wait(c, failed=True) < 10.0, \
        "a failed beat waits a full interval again, so each lock costs a whole beat"
    # ...and never longer than the normal cadence, for a config with a very short interval.
    fast = JobConfig(heartbeat_interval=0.2)
    assert _beat_wait(fast, failed=True) <= 0.2


def test_the_heartbeat_keeps_trying_through_a_failing_database(tmp_path, monkeypatch):
    """The behaviour, not just the arithmetic: with every beat failing, the thread must make
    many attempts inside one interval rather than one per interval."""
    attempts = []

    class _FailingQueue:
        def __init__(self, conn):
            pass

        def is_cancel_requested(self, _run):
            attempts.append(time.time())
            raise RuntimeError("database is locked")

        def heartbeat(self, *a, **k):                    # pragma: no cover - never reached
            raise AssertionError("unreachable: the cancel probe raises first")

    monkeypatch.setattr(W, "JobQueue", _FailingQueue)
    monkeypatch.setattr(W, "_RETRY_BEAT_S", 0.02)
    cfg = JobConfig(heartbeat_interval=0.2)
    hb = W._Heartbeat(str(tmp_path / "x.db"), "run-1", "w-1", cfg)
    hb.start()
    time.sleep(0.9)
    hb.stop()
    hb.join(timeout=5)
    assert not hb.is_alive()
    # Without the fast retry this is one attempt per 0.2s interval: at most 4 in 0.9s. With it,
    # the first beat is at 0.2s and every 0.02s after, so well over ten.
    assert len(attempts) > 10, (
        f"only {len(attempts)} attempts in 0.9s -- a failing beat still costs a full interval")
    assert threading.active_count() >= 1


# ---------------------------------------------------------------- a slice is not a failure
def test_a_campaign_cut_off_by_its_budget_slice_is_not_an_error():
    """Measured on the libtiff tarball and on `zigzag`: `directed_fuzz` ended in `timeout` three
    times at 40s/32s/25s against slices of 41.7s/49.8s/23.3s. It was cut off at the end of its
    own slice every time, and every one was recorded as a stage ERROR -- which failed the gate's
    rule that an error is never an acceptable outcome for a capability, while nothing was wrong.

    A stage with NO slice that hits its registered ceiling is a different thing: that one really
    is a hang, and it must still fail."""
    import time as _t

    from lykos.jobs.worker import _slice_expired

    class _R:
        def __init__(self, ms):
            self.params = {"max_seconds": ms} if ms else {}

    now = _t.time()
    assert _slice_expired(_R(40), now - 38), "a campaign that used its whole slice reads as failed"
    assert not _slice_expired(_R(40), now - 5), "a hang five seconds into a 40s slice is excused"
    assert not _slice_expired(_R(None), now - 3600), "no slice was given: this is the real hang"
    assert not _slice_expired(_R("junk"), now - 10)


def test_the_worker_records_the_reason_it_stopped(tmp_path):
    """End to end through the queue: a cancelled row has to say WHY, or a reader of the case
    store cannot tell a budget cut-off from a user's stop."""
    from lykos.casestore import CaseStore
    from lykos.jobs import JobQueue
    store = CaseStore.open(tmp_path / "case")
    case = store.cases.create("x")
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "detect_cwe", tool="t", tool_version="1")
    claimed = q.claim("w-1", ["quick"], 60)
    assert claimed == run.id, (claimed, run.id)
    from lykos.jobs.worker import _SLICE_NOTE
    assert q.set_cancelled(run.id, note=_SLICE_NOTE)
    row = q.runs.get(run.id)
    assert row.status == "cancelled"
    assert row.error == _SLICE_NOTE, (row.status, row.error)
    store.close()


def test_a_budget_stop_is_cancelled_not_errored(tmp_path):
    """A lapsed lease means two opposite things and they must not record alike.

    The heartbeat thread stops renewing ON PURPOSE when a run passes its budget deadline, so
    "lease expired" there means "this stage ran out of the slice the budget gave it". Only an
    unmarked lapse is the wedge the reaper was written for. Recording the first as an ERROR made
    every oversized target fail the real-corpus gate on its own invariant -- "an error is never
    an acceptable outcome, a decline is" -- and it was measured on libsndfile 1.0.28, whose 8 MB
    ASan `sndfile-info` carries 801 functions and 271,495 instructions, so `detect_cwe` cannot
    finish inside its slice even on an idle machine:

        libsndfile-1.0.28.tar.gz ... ERR 1 ... FAIL: stage errored: detect_cwe
        detect_cwe | error | lease expired
    """
    from lykos.casestore import CaseStore
    from lykos.jobs import JobQueue
    store = CaseStore.open(tmp_path / "c")
    try:
        case = store.cases.create("budget")
        q = JobQueue(store.conn)
        # a run that the budget stopped: claimed, then cancel-flagged, then its lease lapses
        run = q.enqueue(case.id, "detect_cwe", params={})
        claimed = q.claim("w1", ["quick"], 1)
        assert claimed == run.id
        q.cancel(run.id)                                 # what the heartbeat now does on its way out
        store.conn.execute("UPDATE analysis_run SET lease_expires_at=1 WHERE id=?", (run.id,))
        store.conn.commit()
        assert q.reap() == 1
        row = q.runs.get(run.id)
        assert row.status == "cancelled", f"a budget stop recorded as {row.status}"
        assert "budget" in (row.error or "")

        # and a run nobody cancelled is still the wedge case: requeued or errored, as before
        run2 = q.enqueue(case.id, "disassemble", params={})
        c2 = q.claim("w1", ["quick"], 1)
        assert c2 == run2.id
        store.conn.execute("UPDATE analysis_run SET lease_expires_at=1 WHERE id=?", (run2.id,))
        store.conn.commit()
        assert q.reap() == 1
        assert q.runs.get(run2.id).status in ("queued", "error")
    finally:
        store.close()


def test_a_stage_the_budget_cut_off_is_reported_as_such(tmp_path):
    """The scorecard had two outcomes for a stage -- it worked, or it declined -- and a cancelled
    run was neither, so it fell out of the card entirely: `detect_cwe` vanished from a run that
    had scheduled it, and a reader saw 0 findings from a detector that was never allowed to
    finish. Calling it an error was the other half of the same mistake."""
    from lykos.analyze.budget import CaseBudget
    from lykos.analyze.orchestrate import _scorecard
    from lykos.casestore import CaseStore
    from lykos.jobs import JobQueue
    store = CaseStore.open(tmp_path / "c")
    try:
        case = store.cases.create("budget")
        target = store.targets.upsert(case.id, "t.bin", "0" * 64, size=1, file_type="elf")
        q = JobQueue(store.conn)
        run = q.enqueue(case.id, "detect_cwe", target_id=target.id, params={})
        assert q.claim("w1", ["quick"], 1) == run.id
        q.cancel(run.id)
        store.conn.execute("UPDATE analysis_run SET lease_expires_at=1 WHERE id=?", (run.id,))
        store.conn.commit()
        q.reap()
        cap = _scorecard(store, target, CaseBudget(60.0), {"state": "done"})["capability"]
        assert cap["cancelled"] == ["detect_cwe"]
        assert "detect_cwe" not in cap["errored"]
        assert "detect_cwe" not in cap["worked"]
    finally:
        store.close()
