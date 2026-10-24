"""Operator curation of findings (doc 47 P3): mark a finding false-positive / true-positive /
needs-review and annotate it, persisted per case.

EVENT-SOURCED on purpose. Each curation is one `finding.curation` row in the case's existing
`event` table, and the current verdict for a finding is its LATEST such event. That gives, with no
schema change and no migration:

  * persistence per case, across server restarts and reopens;
  * a full audit trail (who-changed-what-when is the event history, never overwritten);
  * portability -- `export_case` already archives a case's events, so a curated case exported from
    one laptop and imported on another keeps the operator's triage.

PRECISION INVARIANT: curation is the OPERATOR's judgement, kept strictly beside the tool's own
evidence. It never rewrites `finding.state`, severity, confidence or any PoC level -- a finding the
operator marks false-positive is still reported by the API exactly as the tool found it, with a
separate `curation` object. Consumers (GUI, report) decide how to present it; they must not fold
it into the tool's L-level. The stored status is `true_positive`, not "confirmed", so it can never
be mistaken for the tool's two-source `confirmed` state.

Hook for other consumers (e.g. the report builder): `current_for_case(conn, case_id)` returns
`{finding_id: {status, note, updated_at, ...}}` from a plain sqlite connection.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Optional

CURATION_EVENT = "finding.curation"
STATUSES = ("false_positive", "true_positive", "needs_review")
STATUS_LABEL = {"false_positive": "False positive", "true_positive": "True positive (operator)",
                "needs_review": "Needs review"}
MAX_NOTE = 4000


class CurationError(ValueError):
    """A curation request the server refuses (bad status / note); maps to HTTP 400."""


def validate(body: Any) -> tuple[Optional[str], str]:
    """(status, note) from a request body, or raise CurationError.

    `status` is one of STATUSES, or null/"" to clear the verdict. `note` is free text (trimmed,
    at most MAX_NOTE characters). Clearing both status and note removes the curation."""
    if not isinstance(body, dict):
        raise CurationError("body must be a JSON object")
    status = body.get("status")
    if status in ("", None):
        status = None
    elif not isinstance(status, str) or status not in STATUSES:
        raise CurationError(f"status must be one of {list(STATUSES)} or null")
    note = body.get("note", "")
    if note is None:
        note = ""
    if not isinstance(note, str):
        raise CurationError("note must be a string")
    note = note.strip()
    if len(note) > MAX_NOTE:
        raise CurationError(f"note is longer than {MAX_NOTE} characters")
    return status, note


def _entry(payload: dict, ts: Optional[int]) -> dict:
    return {"finding_id": payload.get("finding_id"), "status": payload.get("status"),
            "note": payload.get("note") or "", "updated_at": payload.get("at") or ts,
            "target_id": payload.get("target_id"), "dedup_key": payload.get("dedup_key")}


# Incremental per-(database, case) cache of the parsed curation events. The findings list attaches
# curation on every read, and the GUI re-reads findings every few seconds during a run; a long
# fuzzing case holds hundreds of thousands of events, and re-filtering all of them by type on each
# poll measured ~40 ms. Event ids are monotonic (AUTOINCREMENT, append-only), so after the first
# read only rows past the cached high-water id are scanned -- an index range on (case_id, id).
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()


def _db_key(conn) -> str:
    try:
        for row in conn.execute("PRAGMA database_list").fetchall():
            if row[1] == "main":
                return row[2] or f"mem:{id(conn)}"
    except Exception:                                    # noqa: BLE001 -- uncachable, still correct
        pass
    return f"conn:{id(conn)}"


def _rows(conn, case_id: str, finding_id: Optional[str] = None):
    """(payload, ts) for every curation event of a case, oldest first. Reads the event table
    directly so the event TIMESTAMP comes along (EventDAO.payloads_of_type returns payloads only)."""
    key = (_db_key(conn), case_id)
    with _CACHE_LOCK:
        ent = _CACHE.get(key)
        last, cached = (ent["last"], list(ent["rows"])) if ent else (0, [])
    if last:
        rows = conn.execute(
            "SELECT id, ts, type, payload_json FROM event WHERE case_id = ? AND id > ? "
            "ORDER BY id ASC", (case_id, last)).fetchall()
        hi = last
    else:
        # First read: fix the high-water mark (the case's newest event, curation or not) BEFORE
        # the type scan, and bound the scan by it -- a curation appended between the two queries
        # is then picked up by the next incremental read instead of being skipped forever.
        r = conn.execute("SELECT MAX(id) FROM event WHERE case_id = ?", (case_id,)).fetchone()
        hi = int(r[0] or 0)
        rows = conn.execute(
            "SELECT id, ts, type, payload_json FROM event WHERE case_id = ? AND type = ? "
            "AND id <= ? ORDER BY id ASC", (case_id, CURATION_EVENT, hi)).fetchall()
    for r in rows:
        hi = max(hi, int(r["id"]))
        if r["type"] != CURATION_EVENT:
            continue
        try:
            p = json.loads(r["payload_json"] or "null")
        except (TypeError, ValueError):
            continue
        if isinstance(p, dict) and p.get("finding_id"):
            cached.append((p, r["ts"]))
    with _CACHE_LOCK:
        if len(_CACHE) > 256:
            _CACHE.clear()
        _CACHE[key] = {"last": hi, "rows": cached}
    if finding_id is not None:
        return [(p, ts) for p, ts in cached if p.get("finding_id") == finding_id]
    return cached


def current_for_case(conn, case_id: str) -> dict:
    """{finding_id: curation} -- the latest verdict per finding; cleared ones are omitted."""
    cur: dict = {}
    for p, ts in _rows(conn, case_id=case_id):
        e = _entry(p, ts)
        if e["status"] is None and not e["note"]:
            cur.pop(e["finding_id"], None)
        else:
            cur[e["finding_id"]] = e
    return cur


def history_for_finding(conn, case_id: str, finding_id: str) -> list:
    """Every curation of one finding, oldest first (the audit trail)."""
    return [_entry(p, ts) for p, ts in _rows(conn, case_id=case_id, finding_id=finding_id)]


def record(store, finding, status: Optional[str], note: str) -> dict:
    """Append one curation event for `finding` and return the resulting entry."""
    prev = current_for_case(store.conn, finding.case_id).get(finding.id)
    now = int(time.time())
    payload = {"finding_id": finding.id, "target_id": finding.target_id,
               "dedup_key": getattr(finding, "dedup_key", None),
               "status": status, "note": note, "at": now,
               "previous_status": (prev or {}).get("status")}
    store.events.append(CURATION_EVENT, case_id=finding.case_id, payload=payload)
    e = _entry(payload, now)
    e["cleared"] = status is None and not note
    return e
