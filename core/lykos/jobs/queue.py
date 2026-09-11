"""JE-02..JE-08, JE-17/18 — SQLite-backed job queue.

One JobQueue is bound to ONE connection (each worker thread/process opens its own —
sqlite connections are not shared across threads). Atomic claim uses BEGIN IMMEDIATE +
a status-guarded UPDATE so no two workers claim the same job.
"""
from __future__ import annotations

import sqlite3
import time
from typing import Callable, Iterable, Optional

from ..db.dao import AnalysisRunDAO, EventDAO, RunArtifactDAO
from ..db.models import AnalysisRun
from ..hashing import compute_cache_key


def _now() -> int:
    return int(time.time())


class JobQueue:
    def __init__(self, conn: sqlite3.Connection,
                 on_event: Optional[Callable[[dict], None]] = None) -> None:
        self.conn = conn
        self.runs = AnalysisRunDAO(conn)
        self.events = EventDAO(conn)
        self.on_event = on_event
        self._pending: list[dict] = []

    # ------------------------------------------------------------------ events
    def _emit(self, type: str, *, run_id: Optional[str] = None,
              case_id: Optional[str] = None, level: str = "info",
              payload: Optional[dict] = None) -> None:
        """Record an event row now; deliver it to `on_event` only once the row is COMMITTED.

        Firing the callback inside the transaction let a live consumer -- the UI event stream
        tails this table -- observe a `job.done` that a rollback then erased.
        """
        ev = self.events.append(type, level, case_id=case_id, run_id=run_id, payload=payload)
        self._pending.append({"id": ev.id, "type": ev.type, "level": ev.level,
                              "case_id": ev.case_id, "run_id": ev.run_id, "ts": ev.ts,
                              "payload": ev.payload})
        if not self.conn.in_transaction:          # emitted outside a txn: already durable
            self._flush()

    def _flush(self) -> None:
        pending, self._pending = self._pending, []
        if self.on_event:
            for ev in pending:
                self.on_event(ev)

    def _commit(self) -> None:
        self.conn.execute("COMMIT")
        self._flush()

    def _rollback(self, mark: int) -> None:
        self.conn.execute("ROLLBACK")
        del self._pending[mark:]                  # the rows are gone; drop their callbacks

    # ------------------------------------------------------------ enqueue (JE-02/17/18)
    def enqueue(self, case_id: str, stage: str, *, target_id: Optional[str] = None,
                params: Optional[dict] = None, tool: Optional[str] = None,
                tool_version: Optional[str] = None, priority: int = 100,
                resource_class: str = "quick", max_attempts: int = 1,
                input_hashes: Optional[Iterable[str]] = None, force: bool = False,
                dedup: bool = True) -> AnalysisRun:
        ck = compute_cache_key(stage, list(input_hashes or []), params, tool_version)
        # The cache/dedup lookup and the insert that depends on it run under ONE write lock.
        # Read-then-insert let two workers both miss the same pending run and both enqueue it,
        # which is exactly the duplicate work `dedup` exists to prevent.
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if not force:
                cached = self.runs.find_cached(ck)
                if cached:
                    run = self._materialize_cache_hit(
                        case_id, stage, target_id, params, tool, tool_version, ck, cached,
                        priority, resource_class, max_attempts)
                    self._commit()
                    return self.runs.get(run.id)  # type: ignore[return-value]
                if dedup:
                    pending = self._find_pending(ck)
                    if pending:
                        self._rollback(mark)
                        return pending
            run = self.runs.create(case_id, stage, target_id=target_id, params=params,
                                   tool=tool, tool_version=tool_version, cache_key=ck,
                                   priority=priority, resource_class=resource_class,
                                   max_attempts=max_attempts)
            self._emit("job.queued", run_id=run.id, case_id=case_id)
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return run

    def _find_pending(self, cache_key: str) -> Optional[AnalysisRun]:
        r = self.conn.execute(
            "SELECT * FROM analysis_run WHERE cache_key=? AND status IN ('queued','running') "
            "ORDER BY created_at ASC LIMIT 1", (cache_key,)).fetchone()
        return AnalysisRunDAO._row(r) if r else None

    def _materialize_cache_hit(self, case_id: str, stage: str, target_id: Optional[str],
                               params: Optional[dict], tool: Optional[str],
                               tool_version: Optional[str], ck: str, cached: AnalysisRun,
                               priority: int, resource_class: str,
                               max_attempts: int) -> AnalysisRun:
        """Materialise a cache hit. The CALLER holds the write transaction (see enqueue), so
        the lookup that decided this was a hit and the rows written for it are atomic."""
        run = self.runs.create(case_id, stage, target_id=target_id, params=params,
                               tool=tool, tool_version=tool_version, cache_key=ck,
                               priority=priority, resource_class=resource_class,
                               max_attempts=max_attempts)
        now = _now()
        self.conn.execute(
            "UPDATE analysis_run SET status='done', started_at=?, ended_at=? WHERE id=?",
            (now, now, run.id))
        ra = RunArtifactDAO(self.conn)
        for link in ra.list_by_run(cached.id):
            ra.link(run.id, link.artifact_sha256, link.role)
        self._emit("job.cachehit", run_id=run.id, case_id=case_id,
                   payload={"source_run": cached.id})
        self._emit("job.done", run_id=run.id, case_id=case_id, payload={"cached": True})
        return run

    # ------------------------------------------------------------- claim (JE-03/08)
    def claim(self, worker_id: str, classes: Iterable[str], lease_seconds: int) -> Optional[str]:
        classes = list(classes)
        if not classes:
            return None
        ph = ",".join("?" for _ in classes)
        now = _now()
        mark = len(self._pending)
        try:
            self.conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            return None
        try:
            row = self.conn.execute(
                f"SELECT id FROM analysis_run WHERE status='queued' AND resource_class IN ({ph}) "
                "ORDER BY priority ASC, created_at ASC, id ASC LIMIT 1", classes).fetchone()
            if not row:
                self._rollback(mark); return None
            rid = row["id"]
            cur = self.conn.execute(
                "UPDATE analysis_run SET status='running', claimed_by=?, attempts=attempts+1, "
                "started_at=COALESCE(started_at,?), heartbeat_at=?, lease_expires_at=? "
                "WHERE id=? AND status='queued'", (worker_id, now, now, now + lease_seconds, rid))
            if cur.rowcount != 1:
                self._rollback(mark); return None
            self._commit()
        except Exception:
            self._rollback(mark); raise
        self._emit("job.started", run_id=rid)
        return rid

    def heartbeat(self, run_id: str, worker_id: str, lease_seconds: int) -> None:
        now = _now()
        self.conn.execute(
            "UPDATE analysis_run SET heartbeat_at=?, lease_expires_at=? "
            "WHERE id=? AND claimed_by=? AND status='running'",
            (now, now + lease_seconds, run_id, worker_id))

    # --------------------------------------------------------- terminal transitions
    def _lease_lost(self, run: Optional[AnalysisRun],
                    worker_id: Optional[str]) -> Optional[str]:
        """Why this worker may no longer report a result for `run`, or None if it may.

        The reaper requeues a 'running' job whose lease expired. If the worker was in fact
        still alive, it then finishes and tries to record its result against a row that has
        moved on -- and the result used to be dropped on the floor with no trace, while a
        second worker re-ran the same job. The drop is unavoidable (another worker may already
        own the row); the SILENCE is not.
        """
        if run is None:
            return "run no longer exists"
        if run.status != "running":
            return f"status moved to {run.status!r} (lease reaped or cancelled)"
        if worker_id is not None and run.claimed_by not in (None, worker_id):
            return f"claimed by {run.claimed_by!r} (re-claimed after a lease expiry)"
        return None

    def complete(self, run_id: str, outputs: Optional[list[tuple[str, str]]] = None,
                 worker_id: Optional[str] = None) -> bool:
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            lost = self._lease_lost(run, worker_id)
            if lost:
                self._emit("job.result_discarded", run_id=run_id,
                           case_id=run.case_id if run else None, level="warn",
                           payload={"reason": lost, "worker": worker_id,
                                    "outputs": len(outputs or [])})
                self._commit()                    # the warning itself must survive
                return False
            assert run is not None                # _lease_lost returns a reason when it is
            self.conn.execute("UPDATE analysis_run SET status='done', ended_at=? WHERE id=?",
                              (_now(), run_id))
            if outputs:
                ra = RunArtifactDAO(self.conn)
                for sha, role in outputs:
                    ra.link(run_id, sha, role)
            self._emit("job.done", run_id=run_id, case_id=run.case_id)
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return True

    def fail(self, run_id: str, error: str, retryable: bool = True,
             worker_id: Optional[str] = None) -> Optional[str]:
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            lost = self._lease_lost(run, worker_id)
            if lost:
                self._emit("job.result_discarded", run_id=run_id,
                           case_id=run.case_id if run else None, level="warn",
                           payload={"reason": lost, "worker": worker_id, "error": error})
                self._commit()
                return run.status if run else None
            assert run is not None                # _lease_lost returns a reason when it is
            if retryable and run.attempts < run.max_attempts:
                self.conn.execute(
                    "UPDATE analysis_run SET status='queued', claimed_by=NULL, "
                    "lease_expires_at=NULL, error=? WHERE id=?", (error, run_id))
                self._emit("job.requeued", run_id=run_id, case_id=run.case_id,
                           payload={"error": error, "attempt": run.attempts})
                result = "queued"
            else:
                self.conn.execute(
                    "UPDATE analysis_run SET status='error', ended_at=?, error=? WHERE id=?",
                    (_now(), error, run_id))
                self._emit("job.error", run_id=run_id, case_id=run.case_id, level="error",
                           payload={"error": error})
                result = "error"
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return result

    def set_cancelled(self, run_id: str) -> bool:
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            if not run or run.status != "running":
                self._rollback(mark); return False
            self.conn.execute("UPDATE analysis_run SET status='cancelled', ended_at=? WHERE id=?",
                              (_now(), run_id))
            self._emit("job.cancelled", run_id=run_id, case_id=run.case_id)
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return True

    # ----------------------------------------------------------------- cancel (JE-19)
    def cancel(self, run_id: str) -> bool:
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            if not run or run.status in ("done", "error", "cancelled"):
                self._rollback(mark); return False
            self.conn.execute("UPDATE analysis_run SET cancel_requested=1 WHERE id=?", (run_id,))
            if run.status == "queued":
                self.conn.execute(
                    "UPDATE analysis_run SET status='cancelled', ended_at=? WHERE id=?",
                    (_now(), run_id))
                self._emit("job.cancelled", run_id=run_id, case_id=run.case_id)
            else:
                self._emit("job.cancel_requested", run_id=run_id, case_id=run.case_id)
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return True

    # ------------------------------------------------------- reaper / recovery (JE-04/07)
    def _requeue_or_error(self, r: sqlite3.Row, error: str) -> None:
        rid, cid = r["id"], r["case_id"]
        if r["attempts"] < r["max_attempts"]:
            self.conn.execute(
                "UPDATE analysis_run SET status='queued', claimed_by=NULL, "
                "lease_expires_at=NULL, error=? WHERE id=?", (error, rid))
            self._emit("job.requeued", run_id=rid, case_id=cid, payload={"error": error})
        else:
            self.conn.execute(
                "UPDATE analysis_run SET status='error', ended_at=?, error=? WHERE id=?",
                (_now(), error, rid))
            self._emit("job.error", run_id=rid, case_id=cid, level="error",
                       payload={"error": error})

    def reap(self, now: Optional[int] = None) -> int:
        now = now or _now()
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                "SELECT * FROM analysis_run WHERE status='running' "
                "AND lease_expires_at IS NOT NULL AND lease_expires_at < ?", (now,)).fetchall()
            for r in rows:
                self._requeue_or_error(r, "lease expired")
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return len(rows)

    def recover_orphans(self) -> int:
        """Startup crash-recovery: all 'running' rows have no live worker (JE-07)."""
        mark = len(self._pending)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute("SELECT * FROM analysis_run WHERE status='running'").fetchall()
            for r in rows:
                self._requeue_or_error(r, "orphaned (service restart)")
            self._commit()
        except Exception:
            self._rollback(mark); raise
        return len(rows)

    # ------------------------------------------------------------------ counts (JE-28)
    def pending_count(self) -> int:
        r = self.conn.execute(
            "SELECT COUNT(*) AS c FROM analysis_run WHERE status IN ('queued','running')"
        ).fetchone()
        return int(r["c"])
