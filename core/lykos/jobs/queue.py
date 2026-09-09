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

    # ------------------------------------------------------------------ events
    def _emit(self, type: str, *, run_id: Optional[str] = None,
              case_id: Optional[str] = None, level: str = "info",
              payload: Optional[dict] = None) -> None:
        ev = self.events.append(type, level, case_id=case_id, run_id=run_id, payload=payload)
        if self.on_event:
            self.on_event({"id": ev.id, "type": ev.type, "level": ev.level,
                           "case_id": ev.case_id, "run_id": ev.run_id, "ts": ev.ts,
                           "payload": ev.payload})

    # ------------------------------------------------------------ enqueue (JE-02/17/18)
    def enqueue(self, case_id: str, stage: str, *, target_id: Optional[str] = None,
                params: Optional[dict] = None, tool: Optional[str] = None,
                tool_version: Optional[str] = None, priority: int = 100,
                resource_class: str = "quick", max_attempts: int = 1,
                input_hashes: Optional[Iterable[str]] = None, force: bool = False,
                dedup: bool = True) -> AnalysisRun:
        ck = compute_cache_key(stage, list(input_hashes or []), params, tool_version)
        if not force:
            cached = self.runs.find_cached(ck)
            if cached:
                return self._materialize_cache_hit(
                    case_id, stage, target_id, params, tool, tool_version, ck, cached,
                    priority, resource_class, max_attempts)
            if dedup:
                pending = self._find_pending(ck)
                if pending:
                    return pending
        run = self.runs.create(case_id, stage, target_id=target_id, params=params,
                               tool=tool, tool_version=tool_version, cache_key=ck,
                               priority=priority, resource_class=resource_class,
                               max_attempts=max_attempts)
        self._emit("job.queued", run_id=run.id, case_id=case_id)
        return run

    def _find_pending(self, cache_key: str) -> Optional[AnalysisRun]:
        r = self.conn.execute(
            "SELECT * FROM analysis_run WHERE cache_key=? AND status IN ('queued','running') "
            "ORDER BY created_at ASC LIMIT 1", (cache_key,)).fetchone()
        return AnalysisRunDAO._row(r) if r else None

    def _materialize_cache_hit(self, case_id, stage, target_id, params, tool, tool_version,
                               ck, cached, priority, resource_class, max_attempts) -> AnalysisRun:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
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
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return self.runs.get(run.id)  # type: ignore[return-value]

    # ------------------------------------------------------------- claim (JE-03/08)
    def claim(self, worker_id: str, classes: Iterable[str], lease_seconds: int) -> Optional[str]:
        classes = list(classes)
        if not classes:
            return None
        ph = ",".join("?" for _ in classes)
        now = _now()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError:
            return None
        try:
            row = self.conn.execute(
                f"SELECT id FROM analysis_run WHERE status='queued' AND resource_class IN ({ph}) "
                "ORDER BY priority ASC, created_at ASC, id ASC LIMIT 1", classes).fetchone()
            if not row:
                self.conn.execute("ROLLBACK"); return None
            rid = row["id"]
            cur = self.conn.execute(
                "UPDATE analysis_run SET status='running', claimed_by=?, attempts=attempts+1, "
                "started_at=COALESCE(started_at,?), heartbeat_at=?, lease_expires_at=? "
                "WHERE id=? AND status='queued'", (worker_id, now, now, now + lease_seconds, rid))
            if cur.rowcount != 1:
                self.conn.execute("ROLLBACK"); return None
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        self._emit("job.started", run_id=rid)
        return rid

    def heartbeat(self, run_id: str, worker_id: str, lease_seconds: int) -> None:
        now = _now()
        self.conn.execute(
            "UPDATE analysis_run SET heartbeat_at=?, lease_expires_at=? "
            "WHERE id=? AND claimed_by=? AND status='running'",
            (now, now + lease_seconds, run_id, worker_id))

    # --------------------------------------------------------- terminal transitions
    def complete(self, run_id: str, outputs: Optional[list[tuple[str, str]]] = None) -> bool:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            if not run or run.status != "running":
                self.conn.execute("ROLLBACK"); return False
            self.conn.execute("UPDATE analysis_run SET status='done', ended_at=? WHERE id=?",
                              (_now(), run_id))
            if outputs:
                ra = RunArtifactDAO(self.conn)
                for sha, role in outputs:
                    ra.link(run_id, sha, role)
            self._emit("job.done", run_id=run_id, case_id=run.case_id)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return True

    def fail(self, run_id: str, error: str, retryable: bool = True) -> Optional[str]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            if not run or run.status != "running":
                self.conn.execute("ROLLBACK")
                return run.status if run else None
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
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return result

    def set_cancelled(self, run_id: str) -> bool:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            if not run or run.status != "running":
                self.conn.execute("ROLLBACK"); return False
            self.conn.execute("UPDATE analysis_run SET status='cancelled', ended_at=? WHERE id=?",
                              (_now(), run_id))
            self._emit("job.cancelled", run_id=run_id, case_id=run.case_id)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return True

    # ----------------------------------------------------------------- cancel (JE-19)
    def cancel(self, run_id: str) -> bool:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            run = self.runs.get(run_id)
            if not run or run.status in ("done", "error", "cancelled"):
                self.conn.execute("ROLLBACK"); return False
            self.conn.execute("UPDATE analysis_run SET cancel_requested=1 WHERE id=?", (run_id,))
            if run.status == "queued":
                self.conn.execute(
                    "UPDATE analysis_run SET status='cancelled', ended_at=? WHERE id=?",
                    (_now(), run_id))
                self._emit("job.cancelled", run_id=run_id, case_id=run.case_id)
            else:
                self._emit("job.cancel_requested", run_id=run_id, case_id=run.case_id)
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return True

    # ------------------------------------------------------- reaper / recovery (JE-04/07)
    def _requeue_or_error(self, r, error: str) -> None:
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
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                "SELECT * FROM analysis_run WHERE status='running' "
                "AND lease_expires_at IS NOT NULL AND lease_expires_at < ?", (now,)).fetchall()
            for r in rows:
                self._requeue_or_error(r, "lease expired")
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return len(rows)

    def recover_orphans(self) -> int:
        """Startup crash-recovery: all 'running' rows have no live worker (JE-07)."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute("SELECT * FROM analysis_run WHERE status='running'").fetchall()
            for r in rows:
                self._requeue_or_error(r, "orphaned (service restart)")
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return len(rows)

    # ------------------------------------------------------------------ counts (JE-28)
    def pending_count(self) -> int:
        r = self.conn.execute(
            "SELECT COUNT(*) AS c FROM analysis_run WHERE status IN ('queued','running')"
        ).fetchone()
        return int(r["c"])
