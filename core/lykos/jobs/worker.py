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


class _Heartbeat(threading.Thread):
    """Periodically extends a running job's lease from its OWN connection."""

    def __init__(self, db_path: Path, run_id: str, worker_id: str, cfg: JobConfig):
        super().__init__(daemon=True)
        self._db, self._run, self._wid, self._cfg = db_path, run_id, worker_id, cfg
        self._stop = threading.Event()

    def run(self) -> None:
        conn = connect(self._db)
        q = JobQueue(conn)
        try:
            while not self._stop.wait(self._cfg.heartbeat_interval):
                q.heartbeat(self._run, self._wid, self._cfg.lease_seconds)
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
        self._supervisor: Optional[threading.Thread] = None
        self._reaper: Optional[threading.Thread] = None
        # per-class concurrency caps shared across workers
        self._sems = {cls: threading.BoundedSemaphore(cap)
                      for cls, cap in self.cfg.class_caps.items()}
        self._classes = sorted(self.cfg.class_caps, key=lambda c: self.cfg.class_caps[c])
        self._metrics: dict[str, int] = defaultdict(int)
        self._mlock = threading.Lock()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        # JE-07 boot recovery
        conn = connect(self.db_path)
        try:
            JobQueue(conn, self.on_event).recover_orphans()
        finally:
            conn.close()
        self._stopping.clear()
        for i in range(self.cfg.workers):
            self._threads.append(self._spawn_worker(i))
        self._reaper = threading.Thread(target=self._reaper_loop, daemon=True, name="reaper")
        self._reaper.start()
        self._supervisor = threading.Thread(target=self._supervise, daemon=True, name="supervisor")
        self._supervisor.start()

    def stop(self, grace: Optional[float] = None) -> None:
        """JE-13 graceful shutdown: stop claiming, drain within grace."""
        grace = self.cfg.shutdown_grace if grace is None else grace
        self._stopping.set()
        deadline = time.time() + grace
        for t in self._threads:
            t.join(timeout=max(0.0, deadline - time.time()))
        self._threads.clear()

    # ------------------------------------------------------------------ workers
    def _spawn_worker(self, idx: int) -> threading.Thread:
        t = threading.Thread(target=self._worker_loop, args=(idx,), daemon=True,
                             name=f"worker-{idx}")
        t.start()
        return t

    def _worker_id(self, idx: int) -> str:
        return f"{os.getpid()}-w{idx}"

    def _worker_loop(self, idx: int) -> None:
        conn = connect(self.db_path)
        q = JobQueue(conn, self.on_event)
        wid = self._worker_id(idx)
        try:
            while not self._stopping.is_set():
                if not self._try_one(q, wid):
                    time.sleep(self.cfg.poll_interval)
        finally:
            conn.close()

    def _try_one(self, q: JobQueue, wid: str) -> bool:
        """Claim+run one job across allowed classes (honoring caps). True if one ran."""
        for cls in self._classes:
            sem = self._sems[cls]
            if not sem.acquire(blocking=False):
                continue
            try:
                if not self._admit(cls):
                    continue
                rid = q.claim(wid, [cls], self.cfg.lease_seconds)
                if rid is None:
                    continue
                self._bump("claimed")
                self._execute(q, wid, rid)
                return True
            finally:
                sem.release()
        return False

    def _admit(self, cls: str) -> bool:
        """JE-12 coarse memory admission for heavy classes."""
        if cls not in self.cfg.heavy_classes:
            return True
        avail = _mem_available_mb()
        return avail is None or avail >= self.cfg.mem_min_mb_for_heavy

    def _execute(self, q: JobQueue, wid: str, run_id: str) -> None:
        run = q.runs.get(run_id)
        if run is None:
            return
        try:
            sd = get_stage(run.stage)
        except KeyError as e:
            q.fail(run_id, f"{e}", retryable=False)
            self._bump("error")
            return

        timeout = sd.timeout if sd.timeout is not None else self.cfg.default_timeout
        deadline = (time.time() + timeout) if timeout else None
        ctx = JobContext(q.conn, self.content, run, deadline=deadline, on_event=self.on_event)
        hb = _Heartbeat(self.db_path, run_id, wid, self.cfg)
        hb.start()
        try:
            result = sd.fn(ctx)
            ctx.check_cancel()  # honor cancel/timeout requested during the stage
            outputs = [(sha, "output") for sha in (result or {}).get("output_shas", [])]
            q.complete(run_id, outputs or None)
            self._bump("done")
        except StageCancelled:
            q.set_cancelled(run_id)
            self._bump("cancelled")
        except StageTimeout:
            q.fail(run_id, "timeout", retryable=False)
            self._bump("timeout")
        except Exception as e:  # crashing stage: fail the job, keep the worker alive
            q.fail(run_id, repr(e))
            self._bump("error")
        finally:
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
        """JE-10 respawn dead worker threads."""
        while not self._stopping.is_set():
            for i, t in enumerate(list(self._threads)):
                if not t.is_alive():
                    self._threads[i] = self._spawn_worker(i)
                    self._bump("respawned")
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
