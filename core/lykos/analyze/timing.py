"""Per-technique time + yield, and the overall analysis time.

The operator's question this answers: which techniques earned their time? A stage that spent the
most clock for zero findings and zero reproduced crashes is exactly what this surfaces. Durations
come from the DURABLE per-run timestamps (`analysis_run.started_at/ended_at`, set by the queue),
grouped by `stage` -- the run rows survive a server restart and are the one source the report and
the GUI both re-derive identically.

Read-only, stdlib-only. One source for the report's `timing` section and the GUI's timing panel.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from .. import observe
from ..db.dao import AnalysisRunDAO
from .stages import label_for

_log = logging.getLogger(__name__)


def format_duration(seconds: int) -> str:
    """`93` -> `1m 33s`, `3671` -> `1h 1m 11s`, `0` -> `0s`. Human, compact, no decimals."""
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    out = []
    if h:
        out.append(f"{h}h")
    if m or h:
        out.append(f"{m}m")
    out.append(f"{sec}s")
    return " ".join(out)


def _iso(ts: Optional[int]) -> Optional[str]:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def timing_model(all_runs, store, case_id: str) -> dict[str, Any]:
    """The timing dict from a pre-fetched run list (the report already has one).

    `overall.wall_seconds` is the real elapsed span (min start -> max end). `overall.compute_seconds`
    is the SUM of per-technique time, LARGER because the worker pool runs targets in parallel -- both
    are reported so the gap is explained. Yield counts are UNFILTERED (what the technique actually
    produced), so a demoted / zero-yield stage reads honestly.
    """
    by_stage: dict[str, dict] = {}
    starts: list[int] = []
    ends: list[int] = []
    for r in all_runs:
        st, en = r.started_at, r.ended_at
        if st is not None:
            starts.append(st)
        if en is not None:
            ends.append(en)
        stg = r.stage
        if not stg:
            continue
        slot = by_stage.setdefault(stg, {"seconds": 0, "runs": 0})
        slot["runs"] += 1
        if st is not None and en is not None and en >= st:
            slot["seconds"] += int(en - st)
    findings_by_stage: dict[str, int] = {}
    crashes_by_stage: dict[str, int] = {}
    try:
        for row in store.conn.execute(
                "SELECT stage, COUNT(*) FROM finding WHERE case_id=? GROUP BY stage", (case_id,)):
            if row[0]:
                findings_by_stage[row[0]] = int(row[1])
        for row in store.conn.execute(
                "SELECT ar.stage, COUNT(*) FROM dyn_result dr "
                "JOIN analysis_run ar ON dr.run_id = ar.id "
                "WHERE dr.case_id = ? AND dr.crashed = 1 GROUP BY ar.stage", (case_id,)):
            if row[0]:
                crashes_by_stage[row[0]] = int(row[1])
    except Exception:                                        # noqa: BLE001 -- must still render
        observe.absorbed(_log, "timing yield query failed")
    techniques: list[dict] = []
    for stg, slot in by_stage.items():
        techniques.append({
            "stage": stg,
            "label": label_for(stg) or stg,
            "seconds": slot["seconds"],
            "human": format_duration(slot["seconds"]),
            "runs": slot["runs"],
            "findings": findings_by_stage.get(stg, 0),
            "crashes": crashes_by_stage.get(stg, 0),
        })
    techniques.sort(key=lambda d: (-d["seconds"], d["label"]))   # dearest first, stable by name
    compute = sum(d["seconds"] for d in techniques)
    wall = (max(ends) - min(starts)) if starts and ends else 0
    return {
        "overall": {
            "wall_seconds": int(max(0, wall)),
            "wall_human": format_duration(max(0, wall)),
            "compute_seconds": int(compute),
            "compute_human": format_duration(compute),
            "runs": len(all_runs),
            "started_at": _iso(min(starts)) if starts else None,
            "ended_at": _iso(max(ends)) if ends else None,
        },
        "techniques": techniques,
    }


def build_timing(store, case_id: str) -> dict[str, Any]:
    """Case-level entry: fetch the run rows and derive the timing model (the GUI endpoint uses this)."""
    return timing_model(AnalysisRunDAO(store.conn).list_by_case(case_id), store, case_id)
