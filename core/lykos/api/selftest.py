"""Self-test from the GUI: the tool's own validation gates (`lykos archgate`, `realgate`, `eval`),
which were CLI-only. One runs at a time, in the background; the GUI polls GET /selftest for its
progress lines and, when done, the same table, verdict and reason the CLI prints.

These check LYKOS, not a target: archgate detonates its per-ISA PoC matrix, realgate runs the full
detect -> PoC -> attribution chain on real programs, eval scores detection on the bundled corpus.
They are minutes-long and cannot be cancelled mid-run (the gates have no cancel hook), so the GUI
says so. GET /selftest/history is the detection-quality dashboard (`lykos dashboard`).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Optional

from .. import observe

_log = logging.getLogger(__name__)

KINDS = ("archgate", "realgate", "eval")
_MAX_LINES = 400
_JOB: dict[str, Any] = {"state": "idle", "kind": None, "options": None, "started": None,
                        "ended": None, "lines": [], "result": None, "error": None, "thread": None}
_LOCK = threading.Lock()


def _line(msg) -> None:
    with _LOCK:
        _JOB["lines"].append(str(msg)[:400])
        del _JOB["lines"][:-_MAX_LINES]


def _only(matrix, only: Optional[list]):
    if not only:
        return matrix
    want = {str(x).strip() for x in only if str(x).strip()}
    picked = [c for c in matrix if c.label in want]
    if not picked:
        # An empty selection would "pass" vacuously (realgate reports PASS on zero cases).
        raise ValueError(f"no case matches {sorted(want)}; known: "
                         f"{', '.join(c.label for c in matrix)}")
    return picked


def _run(kind: str, opts: dict) -> dict:
    """Run one gate and return {passed, verdict, reason, table, report} -- what the CLI prints."""
    timeout = float(opts.get("timeout") or 30.0)
    if kind in ("archgate", "realgate"):
        from ..eval import archgate, realgate
        mod = archgate if kind == "archgate" else realgate
        rep = mod.run(_only(mod.MATRIX, opts.get("only")), timeout=timeout, progress=_line)
        passed, verdict, reason = mod.gate(rep)
        return {"passed": bool(passed), "verdict": verdict, "reason": reason,
                "table": mod.table(rep), "report": rep}
    from ..eval import harness
    from ..eval.metrics import gate
    stage = opts.get("stage") if opts.get("stage") in ("static", "dynamic") else "static"
    kw: dict[str, Any] = {"stage": stage, "workers": 2, "progress": _line}
    if stage == "static":
        kw["min_state"] = (opts.get("min_state")
                           if opts.get("min_state") in ("candidate", "corroborated", "confirmed")
                           else "candidate")
    rep = harness.run(None, **kw)
    passed, verdict, reason = gate(rep.metrics, rep.meta, stage=stage)
    return {"passed": bool(passed), "verdict": verdict, "reason": reason, "table": rep.table(),
            "report": rep.to_dict()}


def _worker(kind: str, opts: dict) -> None:
    try:
        res = json.loads(json.dumps(_run(kind, opts), default=str))   # JSON-safe for the API
        with _LOCK:
            _JOB.update(state="done", result=res, ended=time.time())
    except Exception as e:                               # noqa: BLE001 -- reported to the GUI
        observe.absorbed(_log, f"self-test {kind} failed")
        with _LOCK:
            _JOB.update(state="error", error=f"{type(e).__name__}: {e}"[:400], ended=time.time())


def status() -> dict:
    with _LOCK:
        busy = _JOB["thread"] is not None and _JOB["thread"].is_alive()
        out = {k: v for k, v in _JOB.items() if k not in ("thread", "lines")}
        out["running"] = busy
        out["lines"] = list(_JOB["lines"][-80:])
        out["kinds"] = list(KINDS)
    return out


def start(kind: str, opts: Optional[dict] = None) -> tuple:
    """(started, error). One self-test at a time."""
    if kind not in KINDS:
        return False, f"unknown self-test {kind!r}; one of {', '.join(KINDS)}"
    opts = dict(opts or {})
    with _LOCK:
        if _JOB["thread"] is not None and _JOB["thread"].is_alive():
            return False, f"a {_JOB['kind']} self-test is already running"
        th = threading.Thread(target=_worker, args=(kind, opts), name=f"lykos-selftest-{kind}",
                              daemon=True)
        _JOB.update(state="running", kind=kind, options=opts, started=time.time(), ended=None,
                    lines=[], result=None, error=None, thread=th)
        th.start()
    return True, None


def history() -> dict:
    """The detection-quality dashboard: the recorded eval history and any regression."""
    from ..eval import dashboard
    from ..eval import history as histmod
    hist = histmod.load(histmod.DEFAULT_PATH)
    return {"path": histmod.DEFAULT_PATH, "runs": len(hist),
            "text": dashboard.render_text(hist), "regressions": histmod.regressions(hist)}


class SelftestMixin:
    """GET /selftest, POST /selftest {kind, options}, GET /selftest/history."""

    def _get_selftest(self):
        return self._json(status())

    def _start_selftest(self):
        body = self._json_body()
        if body is None:
            return
        opts = body.get("options") if isinstance(body.get("options"), dict) else {}
        ok, err = start(str(body.get("kind") or ""), opts)
        if not ok:
            return self._json({"error": err}, 409 if "already running" in (err or "") else 400)
        return self._json({"started": True, "kind": body.get("kind")}, 202)

    def _get_selftest_history(self):
        try:
            return self._json(history())
        except Exception as e:                           # noqa: BLE001 -- never 500 a view
            observe.absorbed(_log, "eval history unavailable")
            return self._json({"error": f"{type(e).__name__}: {e}"[:300], "text": ""})
