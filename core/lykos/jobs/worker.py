"""JE-09..JE-14, JE-28 — Worker pool + concurrency governor.

Thread-based workers, each with its OWN sqlite connection. Per-class semaphores enforce
concurrency caps; a coarse memory guard gates heavy classes; a reaper reclaims dead-worker
jobs; a supervisor respawns dead worker threads; graceful shutdown drains in-flight work.

NOTE (honest scope): process-level isolation of a *crashing native tool* (JE-09 true
multiprocessing) is deferred until native tools land (Phase 1+). Phase-0 stages are Python;
an exception is caught and the job fails without taking down the worker. The subprocess
helper (context.run_subprocess) already isolates + kills child process groups.
"""
from __future__ import annotations

import itertools
import logging
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

from .. import observe
from ..casestore import ContentStore
from ..db.connection import connect
from ..db.models import AnalysisRun
from .config import JobConfig
from .context import JobContext, StageCancelled, StageTimeout
from .queue import JobQueue
from .registry import StageDef, get_stage, validate_params

_log = logging.getLogger("lykos.jobs.worker")


class _Slot:
    """A per-execution concurrency-cap token released EXACTLY ONCE -- by the worker when its stage
    returns, OR by the supervisor when it gives up on a wedged worker. The release-once guard is
    what makes the supervisor's reclaim safe: if the stuck stage later returns and runs its own
    `finally`, the second release is a no-op instead of over-releasing the BoundedSemaphore."""

    __slots__ = ("_sem", "_lock", "_released")

    def __init__(self, sem: threading.BoundedSemaphore) -> None:
        self._sem = sem
        self._lock = threading.Lock()
        self._released = False

    def release(self) -> bool:
        with self._lock:
            if self._released:
                return False
            self._released = True
        self._sem.release()
        return True


class _Active:
    """What a worker is currently running: its slot and the HARD deadline past which it is judged
    wedged (a non-cooperative in-process call the heartbeat/cancel cannot interrupt)."""

    __slots__ = ("slot", "hard_deadline", "stage", "run_id")

    def __init__(self, slot: _Slot, hard_deadline: Optional[float], stage: str = "?",
                 run_id: str = "?") -> None:
        self.slot = slot
        self.hard_deadline = hard_deadline
        # So the supervisor can say WHICH stage wedged. It could only say "worker-2", and a
        # worker index is not a diagnosis -- the stage is the thing you go and fix.
        self.stage = stage
        self.run_id = run_id


class _Heartbeat(threading.Thread):
    """Periodically extends a running job's lease from its OWN connection."""

    def __init__(self, db_path: Path, run_id: str, worker_id: str, cfg: JobConfig,
                 deadline: Optional[float] = None, stage: str = "?"):
        super().__init__(daemon=True)
        self._db, self._run, self._wid, self._cfg = db_path, run_id, worker_id, cfg
        self._deadline = deadline
        # The STAGE, so the two messages below can say what wedged. They named the run's uuid,
        # which answers nothing: the question a reader has is "which stage hangs on this target",
        # and finding out meant going to the database with the uuid in hand. A real-corpus run
        # printed `run c7bbd521... is past its deadline` and that was the entire diagnosis.
        self._stage = stage
        self._stop = threading.Event()

    def run(self) -> None:
        conn = connect(self._db)
        q = JobQueue(conn)
        wait = self._cfg.heartbeat_interval
        try:
            while not self._stop.wait(wait):
                wait = self._cfg.heartbeat_interval
                # Stop RENEWING the lease once the job is past its deadline or a cancel was
                # requested. A non-cooperative stage (stuck in a native angr/unicorn/pypcode call
                # that never reaches a check) would otherwise have its lease extended forever, so
                # the reaper could never reclaim the row: the job sits 'running' indefinitely,
                # holding a worker and blocking the pipeline, and a UI cancel does nothing. Letting
                # the lease lapse lets reap() mark it failed/requeue so the case moves on; when the
                # stuck stage finally returns, complete() sees the lease lost and discards.
                if self._deadline is not None and time.time() > self._deadline:
                    _log.warning("stage %s (run %s) is past its deadline and unresponsive; "
                                 "letting its lease lapse so the reaper can reclaim it",
                                 self._stage, self._run)
                    # Say WHY before going, so the reaper records a cancellation rather than an
                    # error. The two outcomes look identical from the row -- a lapsed lease --
                    # and they mean opposite things: this one is "the budget ran out", which is
                    # a normal result for a big target, while an unmarked lapse is a stage that
                    # wedged. `cancel()` is the existing channel for "stop this run".
                    try:
                        q.cancel(self._run)
                    except Exception:                    # noqa: BLE001 -- best effort on the way out
                        _log.debug("could not flag run %s as budget-cancelled", self._run,
                                   exc_info=True)
                    return
                try:
                    if q.is_cancel_requested(self._run):
                        _log.info("stage %s (run %s) cancel-requested but unresponsive; letting "
                                  "its lease lapse for the reaper", self._stage, self._run)
                        return
                    q.heartbeat(self._run, self._wid, self._cfg.lease_seconds)
                except Exception:
                    # A transient failure (e.g. "database is locked") must not kill the heartbeat
                    # thread: if it dies the lease expires and a still-running job is requeued. Log
                    # and retry -- but SOON, not after another full interval. Waiting the whole
                    # interval after a 5s busy_timeout meant a write storm consumed a beat every
                    # 15s, so three failures burned the entire lease and a working stage was
                    # reaped. Retrying in a second turns each lost beat into one lost attempt
                    # instead of one lost interval.
                    wait = _beat_wait(self._cfg, failed=True)
                    _log.warning("heartbeat failed for run %s (worker %s); retrying in %.0fs",
                                 self._run, self._wid, wait, exc_info=True)
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()


def _run_timeout(run: AnalysisRun, sd: StageDef, cfg: JobConfig) -> float | None:
    """This run's deadline: the budget its CALLER gave it, else the stage's own default.

    A stage's registered timeout is a safety net sized for the worst case it might legitimately
    need -- `directed_fuzz` and `concolic` are both 3600s, and the queue default is 3600 too.
    That is the right ceiling for a stage launched on its own and the wrong one for a stage
    inside a case that has 420 seconds in total: measured, a single stage could claim eight
    times the whole run, and whatever was ordered after it never executed.

    So a caller that divides a budget (`analyze.budget.CaseBudget`) passes its slice as
    `max_seconds`, which `registry._COMMON_PARAMS` permits on every stage. The MINIMUM of the
    two wins: a per-run budget may tighten the ceiling, never raise it past what the stage
    author thought safe.
    """
    base = sd.timeout if sd.timeout is not None else cfg.default_timeout
    try:
        want = (run.params or {}).get("max_seconds")
        want = float(want) if want is not None else None
    except (TypeError, ValueError):
        want = None
    if want is None or want <= 0:
        return base
    # The caller's budget is the stage's CAMPAIGN LENGTH; the kill deadline has to sit just
    # beyond it, or the stage is killed at the exact moment it would have returned. Measured:
    # `directed_fuzz` ended in `timeout` on every one of four channels, having done the work --
    # the run was marked `error`, its summary never written, and the scorecard counted a stage
    # that had in fact succeeded as a failure.
    hard = want * _BUDGET_MARGIN + _BUDGET_GRACE_S
    return hard if base is None else min(float(base), hard)


#: How far the worker's kill deadline sits beyond the budget the caller gave the stage. Enough
#: for a campaign to finish its last batch and write its summary; not enough to matter to the
#: phase after it.
_BUDGET_MARGIN = 1.2
_BUDGET_GRACE_S = 10.0

#: How soon the heartbeat retries after a FAILED beat (a locked database), rather than waiting a
#: full `heartbeat_interval`. See the handler for the measurement behind it.
_RETRY_BEAT_S = 1.0

#: Recorded on a run the budget cut off, so a reader can tell it from a hang.
_SLICE_NOTE = "the budget slice ended while the stage was still working"
#: How much of its slice a stage must have used for the cut-off to be the SLICE's doing rather
#: than something else. A stage killed at a fifth of its slice did not run out of time.
_SLICE_USED = 0.8


def _slice_expired(run: AnalysisRun, started: float) -> bool:
    """Did this run stop because the budget slice it was given ran out?

    True only when a slice was given AND the stage actually used (nearly) all of it. Without the
    second half, any StageTimeout on a budgeted run would be excused, including a genuine hang in
    a stage whose slice happened to be generous.
    """
    try:
        want = float((run.params or {}).get("max_seconds") or 0)
    except (TypeError, ValueError):
        return False
    return want > 0 and (time.time() - started) >= want * _SLICE_USED


def _beat_wait(cfg: JobConfig, *, failed: bool) -> float:
    """How long to wait before the next heartbeat attempt.

    Spelled out as a function so the decision can be tested without timing a thread: after a
    FAILED beat the next attempt comes soon, because what failed is usually a 5s busy_timeout
    under a write storm and the lease is measured in beats, not in attempts.
    """
    return min(_RETRY_BEAT_S, cfg.heartbeat_interval) if failed else cfg.heartbeat_interval


class WorkerPool:
    def __init__(self, db_path: str | Path, content: ContentStore,
                 config: Optional[JobConfig] = None,
                 on_event: Optional[Callable[[dict], None]] = None) -> None:
        self.db_path = Path(db_path)
        self.content = content
        self.cfg = config or JobConfig()
        self.on_event = on_event
        self._stopping = threading.Event()
        self._threads: list[threading.Thread] = []
        self._spawn_gen = itertools.count()  # unique generation per spawned thread (worker-id)
        self._tlock = threading.Lock()   # guards _threads against the supervisor respawn race
        self._supervisor: Optional[threading.Thread] = None
        self._reaper: Optional[threading.Thread] = None
        # per-class concurrency caps shared across workers
        self._sems = {cls: threading.BoundedSemaphore(cap)
                      for cls, cap in self.cfg.class_caps.items()}
        self._classes = sorted(self.cfg.class_caps, key=lambda c: self.cfg.class_caps[c])
        self._metrics: dict[str, int] = defaultdict(int)
        self._mlock = threading.Lock()
        # What each worker index is currently executing, for the supervisor's wedge watchdog.
        self._active: dict[int, _Active] = {}
        self._alock = threading.Lock()
        # idx -> the spawn generation that currently OWNS that index. A wedged worker is abandoned
        # and replaced at the same idx; if its stuck stage ever returns, its loop must see it has
        # been replaced and EXIT -- otherwise it kept claiming jobs as an untracked surplus thread
        # with its own connection (invisible to stop(), so never joined, and over the pool size).
        self._owner: dict[int, int] = {}

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        # JE-07 boot recovery
        conn = connect(self.db_path)
        try:
            JobQueue(conn, self.on_event).recover_orphans()
        finally:
            conn.close()
        self._stopping.clear()
        with self._tlock:
            for i in range(self.cfg.workers):
                self._threads.append(self._spawn_worker(i))
        self._reaper = threading.Thread(target=self._reaper_loop, daemon=True, name="reaper")
        self._reaper.start()
        self._supervisor = threading.Thread(target=self._supervise, daemon=True, name="supervisor")
        self._supervisor.start()

    def stop(self, grace: Optional[float] = None) -> None:
        """JE-13 graceful shutdown: stop claiming, drain within grace."""
        grace = self.cfg.shutdown_grace if grace is None else grace
        self._stopping.set()   # supervisor observes this and stops respawning
        deadline = time.time() + grace
        with self._tlock:
            threads = list(self._threads)
            self._threads.clear()
        for t in threads:
            t.join(timeout=max(0.0, deadline - time.time()))

    # ------------------------------------------------------------------ workers
    def _spawn_worker(self, idx: int) -> threading.Thread:
        # A unique generation per spawn: a WEDGED worker is abandoned (still alive) and replaced at
        # the SAME idx, so an idx-only worker-id would be shared by both -- and the queue's
        # lease-lost guard (`claimed_by not in (None, worker_id)`) then can't tell a stale result
        # from the abandoned attempt apart from the fresh one's, letting stale outputs overwrite it.
        gen = next(self._spawn_gen)
        self._owner[idx] = gen                    # callers hold _tlock (start / _supervise)
        t = threading.Thread(target=self._worker_loop, args=(idx, gen), daemon=True,
                             name=f"worker-{idx}")
        t.start()
        return t

    def _worker_id(self, idx: int, gen: int) -> str:
        return f"{os.getpid()}-w{idx}-g{gen}"

    def _worker_loop(self, idx: int, gen: int) -> None:
        conn = connect(self.db_path)
        q = JobQueue(conn, self.on_event)
        wid = self._worker_id(idx, gen)
        try:
            while not self._stopping.is_set() and self._owns(idx, gen):
                if not self._try_one(q, wid, idx):
                    time.sleep(self.cfg.poll_interval)
            if not self._stopping.is_set():
                self._bump("retired_replaced")
                _log.warning("worker-%d (generation %d) returned after being replaced; retiring "
                             "it instead of running as a surplus worker", idx, gen)
        finally:
            conn.close()

    def _owns(self, idx: int, gen: int) -> bool:
        """Is this worker generation still the pool's worker for `idx`?"""
        return self._owner.get(idx) == gen

    def _try_one(self, q: JobQueue, wid: str, idx: int) -> bool:
        """Claim+run one job across allowed classes (honoring caps). True if one ran."""
        for cls in self._classes:
            sem = self._sems[cls]
            if not sem.acquire(blocking=False):
                continue
            slot = _Slot(sem)                      # released once, by us OR the wedge watchdog
            try:
                if not self._admit(cls):
                    continue
                rid = q.claim(wid, [cls], self.cfg.lease_seconds)
                if rid is None:
                    continue
                self._bump("claimed")
                self._execute(q, wid, rid, idx, slot)
                return True
            finally:
                slot.release()
        return False

    def _admit(self, cls: str) -> bool:
        """JE-12 coarse memory admission for heavy classes."""
        if cls not in self.cfg.heavy_classes:
            return True
        avail = _mem_available_mb()
        return avail is None or avail >= self.cfg.mem_min_mb_for_heavy

    def _execute(self, q: JobQueue, wid: str, run_id: str, idx: int, slot: "_Slot") -> None:
        run = q.runs.get(run_id)
        if run is None:
            return
        try:
            sd = get_stage(run.stage)
        except KeyError as e:
            q.fail(run_id, f"{e}", retryable=False, worker_id=wid)
            self._bump("error")
            return
        try:
            validate_params(run.stage, run.params)        # P5.4: a typo'd param fails loud here
        except ValueError as e:
            q.fail(run_id, f"{e}", retryable=False, worker_id=wid)
            self._bump("error")
            return

        timeout = _run_timeout(run, sd, self.cfg)
        deadline = (time.time() + timeout) if timeout else None
        # Register this execution so the supervisor can reclaim the slot if the stage wedges. Only
        # a stage WITH a deadline gets a hard deadline; an intentionally-unbounded stage does not.
        hard = (deadline + self.cfg.wedge_grace) if deadline else None
        active = _Active(slot, hard, stage=run.stage, run_id=run_id)
        with self._alock:
            self._active[idx] = active
        ctx = JobContext(q.conn, self.content, run, deadline=deadline, on_event=self.on_event)
        hb = _Heartbeat(self.db_path, run_id, wid, self.cfg, deadline=deadline,
                        stage=run.stage)
        hb.start()
        started = time.time()
        try:
            result = sd.fn(ctx)
            ctx.check_cancel()  # honor cancel/timeout requested during the stage
            outputs = [(sha, "output") for sha in (result or {}).get("output_shas", [])]
            # complete() returns False when the lease was lost (reaped/re-claimed) and the
            # result was discarded -- don't count that as a completed job.
            if q.complete(run_id, outputs or None, worker_id=wid):
                self._bump("done")
            else:
                self._bump("discarded")
        except StageCancelled:
            q.set_cancelled(run_id)
            self._bump("cancelled")
        except StageTimeout:
            # A campaign that runs out of its BUDGET SLICE has not failed -- it did as much work
            # as the run could afford, which is a decision the orchestrator made, not an error in
            # the stage. Both arrive here as StageTimeout, so they are told apart by whether a
            # slice was in play at all: `max_seconds` is set exactly when a caller divided a
            # budget (see `_run_timeout`).
            #
            # Measured on the libtiff tarball and on `zigzag`: `directed_fuzz` ended in `timeout`
            # three times at 40s/32s/25s against slices of 41.7s/49.8s/23.3s -- it was cut off at
            # the end of its own slice, every time, and each one was recorded as a stage error.
            # "An error is never an acceptable outcome for a capability; a decline is" is the rule
            # the gate holds us to, and these rows failed on it while nothing was wrong.
            #
            # A stage with NO slice that hits its registered ceiling is a different thing: that
            # one really is a hang, and it still fails.
            if _slice_expired(run, started):
                q.set_cancelled(run_id, note=_SLICE_NOTE)
                self._bump("slice_ended")
            else:
                q.fail(run_id, "timeout", retryable=False, worker_id=wid)
                self._bump("timeout")
        except Exception as e:  # crashing stage: fail the job, keep the worker alive
            q.fail(run_id, repr(e), worker_id=wid)
            self._bump("error")
        finally:
            # Deregister -- but only if the supervisor has not already retired us and handed idx to
            # a replacement worker (identity check avoids clobbering the replacement's record).
            with self._alock:
                if self._active.get(idx) is active:
                    self._active.pop(idx, None)
            hb.stop()
            ctx.cleanup()

    # ------------------------------------------------------------------ background loops
    def _reaper_loop(self) -> None:
        conn = connect(self.db_path)
        q = JobQueue(conn, self.on_event)
        interval = max(1.0, self.cfg.lease_seconds / 2)
        try:
            while not self._stopping.is_set():
                try:
                    q.reap(live=self._live_run_ids())
                except Exception:                        # noqa: BLE001 -- the reaper must survive
                    # A 'database is locked' that outlasts every retry used to kill this thread
                    # for good: nothing respawns the reaper, so from then on a crashed or
                    # wedged job's row stayed 'running' forever and the case never finished.
                    self._bump("reap_failed")
                    _log.warning("reaper pass failed; retrying next interval", exc_info=True)
                self._stopping.wait(interval)
        finally:
            conn.close()

    def _live_run_ids(self) -> set:
        """Runs a worker thread of THIS pool is executing right now and that are not past their
        hard deadline. Their lease can lapse only because the heartbeat lost a write-lock race
        (a write storm), never because nobody is working on them -- so the reaper must not mark
        them `error` and discard the result the stage is about to return. A run past its hard
        deadline is excluded: that is the wedge the reaper exists for."""
        now = time.time()
        with self._alock:
            return {a.run_id for a in self._active.values()
                    if a.hard_deadline is None or now <= a.hard_deadline}

    def _supervise(self) -> None:
        """JE-10 respawn dead worker threads, and reclaim WEDGED ones so the pool cannot deadlock."""
        while not self._stopping.is_set():
            # Hold the lock across the check-and-respawn and re-test _stopping inside it, so a
            # respawn can't race stop()'s clear() and leak an unjoined worker after shutdown.
            with self._tlock:
                if not self._stopping.is_set():
                    now = time.time()
                    for i, t in enumerate(self._threads):
                        if not t.is_alive():
                            self._threads[i] = self._spawn_worker(i)
                            self._bump("respawned")
                            continue
                        # Wedged: alive, but its stage is long past its hard deadline -- stuck in a
                        # non-cooperative in-process call the heartbeat/cancel could not interrupt
                        # (the heartbeat has already lapsed so the reaper reclaimed the DB row). We
                        # cannot kill a Python thread mid-native-call, so reclaim its concurrency
                        # slot (release-once, safe if it ever returns) and spawn a replacement; the
                        # stuck thread is abandoned but no longer blocks the pool.
                        with self._alock:
                            act = self._active.get(i)
                        if act is not None and act.hard_deadline is not None \
                                and now > act.hard_deadline:
                            if act.slot.release():
                                self._bump("wedged_reclaimed")
                                _log.error("worker-%d wedged in stage %s (run %s) past its hard "
                                           "deadline; reclaimed its concurrency slot and spawned "
                                           "a replacement (the stuck thread is abandoned)",
                                           i, act.stage, act.run_id)
                            with self._alock:
                                if self._active.get(i) is act:
                                    self._active.pop(i, None)
                            self._threads[i] = self._spawn_worker(i)
            self._stopping.wait(1.0)

    # ------------------------------------------------------------------ metrics + helpers
    def _bump(self, key: str, n: int = 1) -> None:
        with self._mlock:
            self._metrics[key] += n

    def metrics(self) -> dict[str, int]:
        with self._mlock:
            return dict(self._metrics)

    def wait_idle(self, timeout: float = 30.0, poll: float = 0.05) -> bool:
        """Block until no queued/running jobs remain (test/CLI helper)."""
        conn = connect(self.db_path)
        q = JobQueue(conn)
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                if q.pending_count() == 0:
                    return True
                time.sleep(poll)
            return q.pending_count() == 0
        finally:
            conn.close()


def _mem_available_mb() -> Optional[int]:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except Exception:
        observe.absorbed(_log, "answering None")
        return None
    return None
