"""Server-side Autopilot registry + endpoints, split out of `server.py` as a mixin.

`server.Handler` mixes this in, so the endpoint methods keep full access to the request/response
helpers (`self._json`, `self._store`, `self.server`) via the MRO while the ~1600-line server module
sheds one cohesive responsibility. Moving it changes nothing at runtime: the shared registry lives
on the mixin class exactly as it did on Handler (one dict, one lock, shared across request threads).

This is the pattern the rest of the Handler's endpoint groups (cases, targets, findings, report)
should follow to finish decomposing the God-object.
"""
from __future__ import annotations

import threading


class AutopilotMixin:
    # Server-side Autopilot runs, keyed by case. Each is {thread, status, stop}. In-memory (one
    # server process): a run survives the client tab closing, its results persist in the case DB,
    # and a reopened case shows them. Class-level so it is shared across request threads.
    _AUTOPILOTS: dict = {}
    _AUTOPILOTS_LOCK = threading.Lock()

    def _start_autopilot(self, cid):
        """Start (or restart) a server-side Autopilot for a case: a daemon thread that drives the
        pipeline to a PoC and keeps running after the client disconnects."""
        from ..analyze import orchestrate
        body = self._json_body() or {}
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            target_ids = body.get("target_ids") or [t.id for t in s.targets.list_by_case(cid)]
        finally:
            s.close()
        if not target_ids:
            return self._json({"error": "no targets to analyse"}, 400)
        with AutopilotMixin._AUTOPILOTS_LOCK:
            cur = AutopilotMixin._AUTOPILOTS.get(cid)
            if cur and cur["thread"].is_alive():
                return self._json({"error": "already running", "status": cur["status"]}, 409)
            status = {"state": "starting", "stage": None, "target": 0, "targets": len(target_ids)}
            stop = threading.Event()
            th = threading.Thread(
                target=orchestrate.run_case_autopilot,
                args=(self.server.case_dir, cid, target_ids, status, stop),
                name=f"autopilot-{cid[:8]}", daemon=True)
            AutopilotMixin._AUTOPILOTS[cid] = {"thread": th, "status": status, "stop": stop}
            th.start()
        return self._json({"started": True, "targets": len(target_ids)}, 202)

    def _get_autopilot(self, cid):
        """The status of a case's server-side Autopilot, for polling from the UI."""
        with AutopilotMixin._AUTOPILOTS_LOCK:
            rec = AutopilotMixin._AUTOPILOTS.get(cid)
            if not rec:
                return self._json({"state": "none"})
            st = dict(rec["status"])
            st["running"] = rec["thread"].is_alive()
        return self._json(st)

    def _cancel_autopilot(self, cid):
        with AutopilotMixin._AUTOPILOTS_LOCK:
            rec = AutopilotMixin._AUTOPILOTS.get(cid)
            if not rec:
                return self._json({"error": "no run"}, 404)
            rec["stop"].set()
        return self._json({"cancelling": True})
