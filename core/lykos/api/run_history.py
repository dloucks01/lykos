"""Read-only endpoints over the durable autopilot run history (analyze.run_history).

    GET /cases/{id}/runs-history              the case's recorded runs, newest first, no snapshots,
                                              + a synthetic {run_id:"current:<case>", synthetic:true}
                                              "current state" entry built from the DB now
    GET /autopilot-runs/{run_id}              one record WITH its end-of-run findings snapshot
    GET /autopilot-runs/compare?a=<id>&b=<id> new / gone / changed findings A -> B, same_count,
                                              per-target deltas; A and B may be in different cases

(`/cases/{id}/runs` is the STAGE-run list and is unrelated.) Plain functions taking the request
handler, so server.py only adds dispatch lines -- the Handler's class bases are not touched.
Nothing here returns a server path: records are scrubbed when written (see analyze.run_history).
"""
from __future__ import annotations

from urllib.parse import unquote

from ..analyze import run_history as rh


def get_runs_history(h, cid: str):
    s = h._store()
    try:
        if not s.cases.get(cid):
            return h._json({"error": "no case"}, 404)
        return h._json({"case_id": cid, "runs": rh.list_runs(s, cid)})
    finally:
        s.close()


def get_autopilot_run(h, run_id: str):
    run_id = unquote(run_id)                    # `current%3A<case>` from an encoding client
    s = h._store()
    try:
        rec = rh.get_run(s, run_id)
        if rec is None:
            return h._json({"error": "no run"}, 404)
        return h._json(rec)
    finally:
        s.close()


def compare_autopilot_runs(h, qs: dict):
    a_id = (qs.get("a") or [""])[0]
    b_id = (qs.get("b") or [""])[0]
    if not a_id or not b_id:
        return h._json({"error": "compare needs ?a=<run_id>&b=<run_id>"}, 400)
    s = h._store()
    try:
        a = rh.get_run(s, a_id)
        b = rh.get_run(s, b_id)
        missing = [x for x, r in ((a_id, a), (b_id, b)) if r is None]
        if missing:
            return h._json({"error": "no run", "unknown": missing}, 404)
        return h._json(rh.compare(a, b))
    finally:
        s.close()
