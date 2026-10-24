"""Server-side Autopilot registry + endpoints, split out of `server.py` as a mixin.

`server.Handler` mixes this in, so the endpoint methods keep full access to the request/response
helpers (`self._json`, `self._store`, `self.server`) via the MRO while the ~1600-line server module
sheds one cohesive responsibility. Moving it changes nothing at runtime: the shared registry lives
on the mixin class exactly as it did on Handler (one dict, one lock, shared across request threads).

This is the pattern the rest of the Handler's endpoint groups (cases, targets, findings, report)
should follow to finish decomposing the God-object.
"""
from __future__ import annotations

import copy
import math
import threading
import time


class AutopilotMixin:
    # Server-side Autopilot runs, keyed by case. Each is {thread, status, stop}. In-memory (one
    # server process): a run survives the client tab closing, its results persist in the case DB,
    # and a reopened case shows them. Class-level so it is shared across request threads.
    _AUTOPILOTS: dict = {}
    _AUTOPILOTS_LOCK = threading.Lock()

    @staticmethod
    def _normalize_overrides(over: dict) -> dict:
        """Turn the web invocation controls into the autopilot's override dict. `argv` may arrive as
        a shell-quoted STRING (e.g. "-c @@") -- split it exactly as the CLI's --argv does, so the
        web GUI and the CLI accept the same thing. `input_mode` is validated against the channels
        the stages understand; anything else (incl. "auto") is dropped so discovery runs."""
        import shlex
        out = dict(over)
        av = out.get("argv")
        if isinstance(av, str):
            try:
                out["argv"] = shlex.split(av)
            except ValueError:
                out.pop("argv", None)                    # unbalanced quotes: ignore rather than 500
        im = out.get("input_mode")
        if im not in ("stdin", "arg", "file", "env", "none"):
            out.pop("input_mode", None)                  # "auto"/blank/garbage -> let discovery decide
        return out

    def _start_autopilot(self, cid):
        """Start (or restart) a server-side Autopilot for a case: a daemon thread that drives the
        pipeline to a PoC and keeps running after the client disconnects."""
        from ..analyze import orchestrate
        body = self._json_body()
        if body is None:
            return          # a malformed / over-size body: _json_body already sent the error.
                            # `or {}` would double-respond AND start an unwanted run over every target.
        s = self._store()
        try:
            if not s.cases.get(cid):
                return self._json({"error": "no case"}, 404)
            in_case = [t.id for t in s.targets.list_by_case(cid)]
        finally:
            s.close()
        target_ids = body.get("target_ids")
        if target_ids:
            # A string here was iterated per CHARACTER into "target ids", and an id from ANOTHER
            # case was run and its findings/events filed under this one. Both are refused.
            if not (isinstance(target_ids, list) and all(isinstance(t, str) for t in target_ids)):
                return self._json({"error": "target_ids must be a list of target ids"}, 400)
            foreign = [t for t in target_ids if t not in set(in_case)]
            if foreign:
                return self._json({"error": "target_ids not in this case",
                                   "unknown": foreign[:20]}, 400)
            target_ids = list(dict.fromkeys(target_ids))           # de-dupe, keep order
        else:
            target_ids = in_case
        if not target_ids:
            return self._json({"error": "no targets to analyse"}, 400)
        with AutopilotMixin._AUTOPILOTS_LOCK:
            cur = AutopilotMixin._AUTOPILOTS.get(cid)
            if cur and cur["thread"].is_alive():
                return self._json({"error": "already running", "status": cur["status"]}, 409)
            status = {"state": "starting", "stage": None, "target": 0, "targets": len(target_ids)}
            stop = threading.Event()
            # Per-target wall clock, divided among the phases by analyze.budget. Without one
            # a single stage registered at 3600s could outlast the whole run and everything
            # after it never executed -- measured on stock binaries, three runs in four.
            try:
                secs = float(body.get("budget_seconds")) if body.get("budget_seconds") else None
            except (TypeError, ValueError):
                secs = None
            # NaN / inf / <= 0 parse as floats but are not budgets: a NaN budget compares false
            # against every deadline, so the run never thought it was out of time.
            if secs is not None and not (math.isfinite(secs) and secs > 0):
                secs = None
            over = body.get("overrides") if isinstance(body.get("overrides"), dict) else None
            if over:
                over = self._normalize_overrides(over)
            converge = bool(body.get("converge"))
            # Stages the operator switched OFF for this run (GUI checkboxes). Restricted to a safe
            # allowlist so a malformed request cannot skip triage/disassembly and hollow out the run;
            # the search/prove stages can be dropped without breaking the rest (the ladder just has
            # fewer crash sources). `skip_stages: ["fuzz"]` is "uncheck black-box fuzzing".
            _skippable = {"fuzz", "coverage_fuzz", "directed_fuzz", "libfuzzer", "concolic"}
            raw_skip = body.get("skip_stages")
            skip_stages = (sorted(_skippable & {str(s) for s in raw_skip})
                           if isinstance(raw_skip, list) else [])
            status["budget_seconds"] = secs
            status["converge"] = converge
            status["skip_stages"] = skip_stages
            pause = threading.Event()
            th = threading.Thread(
                target=orchestrate.run_case_autopilot,
                args=(self.server.case_dir, cid, target_ids, status, stop, secs, over, converge,
                      skip_stages, pause),
                name=f"autopilot-{cid[:8]}", daemon=True)
            AutopilotMixin._AUTOPILOTS[cid] = {"thread": th, "status": status, "stop": stop,
                                               "pause": pause}
            th.start()
        return self._json({"started": True, "targets": len(target_ids)}, 202)

    def _get_autopilot(self, cid):
        """The status of a case's server-side Autopilot, for polling from the UI."""
        with AutopilotMixin._AUTOPILOTS_LOCK:
            rec = AutopilotMixin._AUTOPILOTS.get(cid)
            if not rec:
                return self._json({"state": "none"})
            # DEEP copy under the lock: the autopilot thread keeps mutating the nested `plan` entry
            # dicts (adding started/ended/elapsed keys via _plan_set), so a shallow dict() would let
            # json.dumps iterate them mid-mutation -> "dictionary changed size during iteration" 500.
            st = copy.deepcopy(rec["status"])
            st["running"] = rec["thread"].is_alive()
            st["paused"] = bool(rec.get("pause") and rec["pause"].is_set())
        # Server clock, so the UI can show each stage's elapsed time (now - plan[i].started) in the
        # server's own time base -- no client/server clock skew. The elapsed on a running stage is
        # the signal that tells slow-but-working apart from a hang.
        st["now"] = time.time()
        return self._json(st)

    def _cancel_autopilot(self, cid):
        with AutopilotMixin._AUTOPILOTS_LOCK:
            rec = AutopilotMixin._AUTOPILOTS.get(cid)
            if not rec:
                return self._json({"error": "no run"}, 404)
            rec["stop"].set()
            if rec.get("pause"):
                rec["pause"].clear()           # unblock a paused run so it can see the stop
        return self._json({"cancelling": True})

    def _pause_autopilot(self, cid, want_pause: bool):
        """Pause (suspend between stages) or resume a running Autopilot. A paused run finishes the
        stage in flight, then waits -- no work is lost -- until resumed or stopped."""
        with AutopilotMixin._AUTOPILOTS_LOCK:
            rec = AutopilotMixin._AUTOPILOTS.get(cid)
            if not rec or not rec.get("pause"):
                return self._json({"error": "no run"}, 404)
            if want_pause:
                rec["pause"].set()
            else:
                rec["pause"].clear()
        return self._json({"paused": want_pause})
