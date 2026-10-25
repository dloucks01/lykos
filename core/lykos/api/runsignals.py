"""The run's HONESTY SIGNALS, gathered from the case event log for the web GUI.

The engine reports, as events, every way a run can be weaker than it looks: a target whose
analysis aborted (`autopilot.target_error`, and `target_errors`/`failed_targets` on
`autopilot.done`), a fuzzer that ran without its sandbox (`coverage|net_fuzz|env_fuzz.isolation`),
data-flow that analysed only the ranked top-N of the reachable functions (`detect.taint_ranked`),
a large binary recovered at a shallower tier (`re.done` `analysis_tier`/`degradations`), a crash
corpus bigger than the prove loop will take (`autopilot.crashes_capped`), inputs that hang the
target (`<prefix>.hang`, CWE-835), a lease renewed under write contention
(`job.lease_renewed`), and what the target needed supplied to start -- or a startup gate nothing
could open (`runtime_env`).

The GUI's live tail only sees events that arrive WHILE it is polling, so a reopened case -- or a
tab opened after the event -- would show none of these and present the run as clean. This reads
them back from the event log instead, the way the scorecard endpoint does.

Two scopes, deliberately different:
  * RUN-SCOPED facts (a target failed, the sandbox was degraded, crashes were capped, a lease was
    renewed) describe ONE autopilot run, so they come from the latest run's window: events after
    the previous run's terminal event (`autopilot.done`/`autopilot.error`).
  * TARGET-SCOPED facts (how deep recovery went, how much of the program taint saw, which inputs
    hang it) describe the target's analysis, which a later run may reuse from cache without
    re-emitting -- so the LATEST such event per target over the whole case is used.

Reads are incremental: the relevant rows are cached per case and only events newer than the last
scan are queried, so the GUI can poll this during a long fuzzing run (whose event log grows by
thousands of progress rows) without rescanning the log.
"""
from __future__ import annotations

import threading
from typing import Any, Optional

from ..db.repository import loads

#: Event types that carry a signal (plus every `<prefix>.hang`, matched by suffix).
SIGNAL_TYPES = (
    "autopilot.target_error", "autopilot.done", "autopilot.error",
    "coverage.isolation", "net_fuzz.isolation", "env_fuzz.isolation",
    "detect.taint_ranked", "re.done", "autopilot.crashes_capped", "job.lease_renewed",
    "runtime_env",
)
_TERMINAL = ("autopilot.done", "autopilot.error")
#: Ceiling on cached rows per case. Only `job.lease_renewed` / `*.hang` can be numerous; the
#: oldest rows go first, and the run-scoped window only ever needs the newest.
_MAX_ROWS = 20000

_CACHE: dict = {}
_LOCK = threading.Lock()


def _scan(conn, case_id: str, after_id: int) -> list[dict]:
    marks = ",".join("?" for _ in SIGNAL_TYPES)
    rows = conn.execute(
        "SELECT e.id, e.type, e.level, e.ts, e.payload_json, r.target_id AS run_target "
        "FROM event e LEFT JOIN analysis_run r ON r.id = e.run_id "
        f"WHERE e.case_id = ? AND e.id > ? AND (e.type IN ({marks}) OR e.type LIKE '%.hang') "
        "ORDER BY e.id",
        (case_id, int(after_id), *SIGNAL_TYPES)).fetchall()
    out = []
    for r in rows:
        try:
            p = loads(r["payload_json"])
        except Exception:                                # noqa: BLE001 -- a bad row is skipped
            p = None
        out.append({"id": r["id"], "type": r["type"], "level": r["level"], "ts": r["ts"],
                    "payload": p if isinstance(p, dict) else {},
                    "run_target": r["run_target"]})
    return out


def signal_rows(conn, case_dir: str, case_id: str) -> list[dict]:
    """Every signal-bearing event of the case, oldest first (incrementally cached)."""
    key = (str(case_dir), case_id)
    top = conn.execute("SELECT MAX(id) FROM event WHERE case_id = ?", (case_id,)).fetchone()[0] or 0
    with _LOCK:
        ent = _CACHE.get(key)
        if ent is None or top < ent["scanned"]:          # first read, or the log was reset
            ent = {"scanned": 0, "rows": []}
            _CACHE[key] = ent
        after = ent["scanned"]
    new = _scan(conn, case_id, after) if top > after else []
    with _LOCK:
        if ent["scanned"] == after:                      # no concurrent reader got here first
            ent["rows"].extend(new)
            if len(ent["rows"]) > _MAX_ROWS:
                del ent["rows"][:len(ent["rows"]) - _MAX_ROWS]
            ent["scanned"] = max(after, top)
        return list(ent["rows"])


def _target_of(row: dict) -> Optional[str]:
    return (row.get("payload") or {}).get("target_id") or row.get("run_target")


def _renv_item(x) -> str:
    """One supplied runtime-environment item, as the operator reads it."""
    if not isinstance(x, dict):
        return str(x)[:200]
    if x.get("kind") == "env":
        return f"env {x.get('name')}={x.get('value')}"[:200]
    at = x.get("at") or x.get("path")
    return f"{x.get('kind')} {at}" + (f" ({x.get('why')})" if x.get("why") else "")[:200]


def _engine_of(etype: str) -> str:
    return etype.rsplit(".", 1)[0]


def summarize(rows: list[dict], *, running: bool = False,
              filenames: Optional[dict] = None) -> dict[str, Any]:
    """Fold the signal rows into the compact shape the GUI renders. Pure (testable)."""
    names = filenames or {}
    terminals = [r["id"] for r in rows if r["type"] in _TERMINAL]
    # The latest run's window. While a run is in flight it is everything after the last
    # terminal; once it finished, everything after the one BEFORE it (so the finished run's own
    # done event and everything it emitted are in).
    if running:
        after = terminals[-1] if terminals else 0
    else:
        after = terminals[-2] if len(terminals) >= 2 else 0
    win = [r for r in rows if r["id"] > after]

    def fname(tid):
        return names.get(tid) if tid else None

    out: dict[str, Any] = {"window": {"after_id": after, "running": bool(running),
                                      "runs_seen": len(terminals)},
                           "outcome": None, "target_errors": [], "failed_targets": [],
                           "isolation": [], "taint": [], "recovery": [], "crashes_capped": [],
                           "hangs": [], "lease_renewed": None, "runtime_env": []}
    # ---- run-scoped -------------------------------------------------------------------
    iso_seen: dict = {}
    capped: dict = {}
    leases = 0
    lease_ts = None
    for r in win:
        t, p = r["type"], r["payload"]
        if t == "autopilot.done":
            out["outcome"] = {"outcome": p.get("outcome"), "cancelled": bool(p.get("cancelled")),
                              "target_errors": int(p.get("target_errors") or 0),
                              "failed_targets": list(p.get("failed_targets") or [])}
        elif t == "autopilot.error":
            out["outcome"] = {"outcome": "error", "error": str(p.get("error") or "")[:500]}
        elif t == "autopilot.target_error":
            tid = p.get("target_id")
            out["target_errors"].append({
                "target_id": tid, "filename": fname(tid), "stage": p.get("stage"),
                "error": str(p.get("error") or "")[:500], "note": p.get("note"), "ts": r["ts"]})
        elif t.endswith(".isolation"):
            iso = p.get("isolation")
            degraded = iso == "rlimits-only" or r.get("level") in ("warn", "error")
            if not degraded:
                continue
            k = (_engine_of(t), iso)
            ent = iso_seen.get(k)
            if ent is None:
                ent = {"engine": _engine_of(t), "isolation": iso, "note": p.get("note"),
                       "targets": []}
                iso_seen[k] = ent
                out["isolation"].append(ent)
            tid = _target_of(r)
            if tid and tid not in ent["targets"]:
                ent["targets"].append(tid)
        elif t == "autopilot.crashes_capped":
            tid = p.get("target_id")
            capped[tid] = {"target_id": tid, "filename": fname(tid),
                           "distinct": p.get("distinct"), "proving": p.get("proving")}
        elif t == "job.lease_renewed":
            leases += 1
            lease_ts = r["ts"]
    out["crashes_capped"] = list(capped.values())
    if leases:
        out["lease_renewed"] = {"count": leases, "last_ts": lease_ts}
    # A done event is the authority on which targets failed; the per-target error events carry
    # the detail. Either alone still marks the target failed.
    failed = list((out["outcome"] or {}).get("failed_targets") or [])
    for e in out["target_errors"]:
        if e["target_id"] and e["target_id"] not in failed:
            failed.append(e["target_id"])
    out["failed_targets"] = failed
    # ---- target-scoped (latest per target over the whole case) ------------------------
    taint: dict = {}
    recov: dict = {}
    hangs: dict = {}
    renv: dict = {}
    for r in rows:
        t, p = r["type"], r["payload"]
        tid = _target_of(r)
        if t == "detect.taint_ranked":
            taint[tid] = {"target_id": tid, "filename": fname(tid),
                          **{k: p.get(k) for k in ("total", "cap", "analyzed", "skipped",
                                                   "unreachable", "skipped_reachable",
                                                   "exact", "note")}}
        elif t == "re.done":
            degr = [d for d in (p.get("degradations") or []) if d]
            tier = p.get("analysis_tier")
            issue = bool(degr or p.get("partial") or p.get("recovery_failed")
                         or (tier and tier != "aaa"))
            # A later CLEAN recovery of the same target supersedes an earlier degraded one.
            recov[tid] = ({"target_id": tid, "filename": fname(tid), "analysis_tier": tier,
                           "degradations": degr, "partial": bool(p.get("partial")),
                           "recovery_failed": bool(p.get("recovery_failed")),
                           "functions": p.get("functions"),
                           "total_functions": p.get("total_functions"),
                           "note": p.get("note")} if issue else None)
        elif t == "runtime_env":
            # What the target needed to START (a config file, a data dir, an env var) and was
            # given -- or a startup gate nothing could open, in which case every dynamic result
            # for this target measured the gate. A target that needed nothing is no signal.
            # (A reuse event carries the same record, so the latest one stands.)
            renv[tid] = ({"target_id": tid, "filename": fname(tid),
                          "applied": bool(p.get("applied")), "note": p.get("note"),
                          "supplied": [_renv_item(x) for x in (p.get("supplied") or [])][:12],
                          "degraded": [f"{d.get('path')}: {d.get('why')}"
                                       for d in (p.get("degraded") or [])
                                       if isinstance(d, dict)][:12]}
                         if (p.get("applied") or p.get("gated")) else None)
        elif t.endswith(".hang"):
            sha = p.get("input_sha")
            if sha and sha not in hangs:
                hangs[sha] = {"target_id": tid, "filename": fname(tid), "engine": _engine_of(t),
                              "input_sha": sha, "mode": p.get("mode"), "timeout": p.get("timeout")}
    out["taint"] = [v for v in taint.values() if v]
    out["recovery"] = [v for v in recov.values() if v]
    out["hangs"] = list(hangs.values())
    out["runtime_env"] = [v for v in renv.values() if v]
    # ---- overall tone -------------------------------------------------------------------
    bad = bool(out["target_errors"] or out["failed_targets"]
               or (out["outcome"] or {}).get("outcome") == "error"
               or any(x["recovery_failed"] for x in out["recovery"]))
    warn = bool(out["isolation"] or out["crashes_capped"] or out["lease_renewed"]
                or any((x.get("skipped_reachable") or 0) > 0 for x in out["taint"])
                or out["recovery"]
                or any(not x["applied"] or x["degraded"] for x in out["runtime_env"]))
    out["level"] = "bad" if bad else ("warn" if warn else "ok")
    return out
