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
