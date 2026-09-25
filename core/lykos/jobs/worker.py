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

from ..casestore import ContentStore
from ..db.connection import connect
from .config import JobConfig
from .context import JobContext, StageCancelled, StageTimeout
from .queue import JobQueue
from .registry import get_stage

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

    __slots__ = ("slot", "hard_deadline")

    def __init__(self, slot: _Slot, hard_deadline: Optional[float]) -> None:
        self.slot = slot
        self.hard_deadline = hard_deadline


class _Heartbeat(threading.Thread):
    """Periodically extends a running job's lease from its OWN connection."""

    def __init__(self, db_path: Path, run_id: str, worker_id: str, cfg: JobConfig,
                 deadline: Optional[float] = None):
        super().__init__(daemon=True)
        self._db, self._run, self._wid, self._cfg = db_path, run_id, worker_id, cfg
        self._deadline = deadline
        self._stop = threading.Event()

    def run(self) -> None:
        conn = connect(self._db)
        q = JobQueue(conn)
        try:
            while not self._stop.wait(self._cfg.heartbeat_interval):
                # Stop RENEWING the lease once the job is past its deadline or a cancel was
                # requested. A non-cooperative stage (stuck in a native angr/unicorn/pypcode call
                # that never reaches a check) would otherwise have its lease extended forever, so
                # the reaper could never reclaim the row: the job sits 'running' indefinitely,
                # holding a worker and blocking the pipeline, and a UI cancel does nothing. Letting
                # the lease lapse lets reap() mark it failed/requeue so the case moves on; when the
                # stuck stage finally returns, complete() sees the lease lost and discards.
                if self._deadline is not None and time.time() > self._deadline:
                    _log.warning("run %s is past its deadline and unresponsive; letting its lease "
                                 "lapse so the reaper can reclaim it", self._run)
                    return
                try:
                    if q.is_cancel_requested(self._run):
                        _log.info("run %s cancel-requested but unresponsive; letting its lease "
                                  "lapse for the reaper", self._run)
                        return
                    q.heartbeat(self._run, self._wid, self._cfg.lease_seconds)
                except Exception:
                    # A transient failure (e.g. "database is locked") must not kill the heartbeat
                    # thread: if it dies the lease expires and a still-running job is requeued. Log
                    # and retry on the next tick instead.
                    _log.warning("heartbeat failed for run %s (worker %s); will retry",
                                 self._run, self._wid, exc_info=True)
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop.set()


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
            while not self._stopping.is_set():
                if not self._try_one(q, wid, idx):
                    time.sleep(self.cfg.poll_interval)
        finally:
            conn.close()

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

        timeout = sd.timeout if sd.timeout is not None else self.cfg.default_timeout
        deadline = (time.time() + timeout) if timeout else None
        # Register this execution so the supervisor can reclaim the slot if the stage wedges. Only
        # a stage WITH a deadline gets a hard deadline; an intentionally-unbounded stage does not.
        hard = (deadline + self.cfg.wedge_grace) if deadline else None
        active = _Active(slot, hard)
        with self._alock:
            self._active[idx] = active
        ctx = JobContext(q.conn, self.content, run, deadline=deadline, on_event=self.on_event)
        hb = _Heartbeat(self.db_path, run_id, wid, self.cfg, deadline=deadline)
        hb.start()
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
                q.reap()
                self._stopping.wait(interval)
        finally:
            conn.close()

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
                                _log.error("worker-%d wedged past its hard deadline; reclaimed its "
                                           "concurrency slot and spawned a replacement (the stuck "
                                           "thread is abandoned)", i)
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
        return None
    return None
