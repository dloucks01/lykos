"""Server-side Autopilot: a background orchestrator that drives the analysis pipeline to a
proof-of-concept without a browser tab keeping it alive.

The interactive one-click Autopilot lives in the web UI and drives the FULL deep pipeline stage
by stage. That is perfect while someone is watching, but a deep run takes minutes and stops the
moment the tab closes. This runs the essential path -- recover, detect, search, prove each
distinct crash, review -- in a daemon thread inside the server, so it keeps going after the
client disconnects. Progress is written to the case event stream (the UI already tails it) and a
small in-memory status is exposed for polling; a reopened case shows the finished results.

It reuses the SAME stage enqueue functions and job queue as everything else; it only sequences
them and threads a crashing input into the PoC ladder. Each stage is guarded, and a stop flag
makes it cancellable.
"""
from __future__ import annotations

import importlib
import threading
import time
from typing import Optional

from ..casestore import CaseStore
from ..db.dao import DynResultDAO, FindingDAO, PocDAO
from ..jobs.queue import JobQueue

# stage -> (module, enqueue-fn). Target-scoped unless listed in _CASE.
_TARGET = {
    "disassemble": ("..analyze.disassemble", "enqueue_disassemble"),
    "detect_cwe": ("..analyze.detect", "enqueue_detect"),
    "cve_scan": ("..analyze.fingerprint", "enqueue_cve_scan"),
    "coverage_fuzz": ("..analyze.fuzz", "enqueue_coverage_fuzz"),
    "fuzz": ("..analyze.fuzz", "enqueue_fuzz"),
    "directed_fuzz": ("..analyze.fuzz", "enqueue_directed_fuzz"),
    "heap_check": ("..analyze.dynamic", "enqueue_heap_check"),
    "concolic": ("..analyze.symbolic", "enqueue_concolic"),
    "root_cause": ("..analyze.debug", "enqueue_root_cause"),
    "build_poc": ("..analyze.poc", "enqueue_build_poc"),
    "poc_primitive": ("..analyze.poc", "enqueue_primitive"),
    "build_exploit": ("..analyze.poc", "enqueue_exploit"),
    "synthesize_injection": ("..analyze.poc", "enqueue_inject"),
    "behavior_trace": ("..analyze.debug", "enqueue_behavior_trace"),
    "dynamic_taint": ("..analyze.debug", "enqueue_taint"),
}
_CASE = {
    "link_case": ("..analyze.link", "enqueue_link"),
    "ipc_model": ("..analyze.link", "enqueue_ipc"),
    "cross_taint": ("..analyze.link", "enqueue_cross_taint"),
    "whole_system": ("..analyze.link", "enqueue_whole_system"),
}
# Stages whose enqueue-fn takes NO params. root_cause/build_poc/poc_primitive are NOT here: they
# require params["input_sha"] (the crashing input), which the prove loop threads in -- listing
# them dropped that input and every one failed with "requires params.input_sha".
_NO_PARAMS = {"disassemble", "detect_cwe"}
_CASE_NO_PARAMS = {"link_case", "ipc_model", "cross_taint"}

_TERMINAL = {"done", "cancelled", "error"}


def _enqueue_fn(spec):
    mod = importlib.import_module("lykos" + spec[0].replace("..", ".", 1))
    return getattr(mod, spec[1])


def _wait(store, run_id: str, stop: threading.Event, timeout: float = 900.0) -> str:
    """Poll a run to a terminal state (the in-process workers execute it), or until cancelled."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if stop.is_set():
            try:
                JobQueue(store.conn).cancel(run_id)
            except Exception:
                pass
            return "cancelled"
        r = store.runs.get(run_id)
        if r and r.status in _TERMINAL:
            return r.status
        time.sleep(0.6)
    return "timeout"


def _best_block_pct(store, target_id) -> Optional[float]:
    """The best block-coverage percent the target's fuzz runs reached, or None. Lets the pipeline
    run concolic when the search left the binary UNDER-COVERED (guarded branches unreached), not
    only when it found no crash."""
    try:
        from ..report.model import _best_coverage
        t = store.targets.get(target_id)
        runs = [r for r in store.runs.list_by_case(t.case_id) if r.target_id == target_id]
        cov = _best_coverage(store, runs)
        return cov.get("pct") if cov and cov.get("kind") == "block" else None
    except Exception:
        return None


def _run_target_stage(store, target, stage, status, stop, params=None) -> Optional[str]:
    if stop.is_set():
        return None
    status["stage"] = stage
    status["updated"] = time.time()
    store.events.append("autopilot.stage", case_id=target.case_id,
                        payload={"stage": stage, "target_id": target.id})
    try:
        fn = _enqueue_fn(_TARGET[stage])
        q = JobQueue(store.conn)
        run = fn(q, target) if stage in _NO_PARAMS else fn(q, target, params=params or {})
    except Exception as e:
        store.events.append("autopilot.stage_error", level="warn", case_id=target.case_id,
                            payload={"stage": stage, "error": str(e)})
        return None
    if run.status == "done":
        # A content-addressed CACHE HIT clones the output artifacts but never re-runs the body,
        # so per-target rows the body writes -- disassembly's functions/edges/strings, triage's
        # columns -- are absent for this target. Re-project them, exactly as the HTTP run route
        # does; without this a cached disassemble leaves the target with zero functions, and the
        # fuzzer then runs blind with no block coverage.
        try:
            from ..jobs.registry import reproject_cache_hit
            reproject_cache_hit(store, stage, target.id, run.id)
        except Exception:
            pass
        return "done"
    return _wait(store, run.id, stop)


def _run_case_stage(store, case_id, stage, status, stop) -> None:
    if stop.is_set():
        return
    status["stage"] = stage
    status["updated"] = time.time()
    store.events.append("autopilot.stage", case_id=case_id, payload={"stage": stage})
    try:
        fn = _enqueue_fn(_CASE[stage])
        q = JobQueue(store.conn)
        run = fn(q, case_id) if stage in _CASE_NO_PARAMS else fn(q, case_id, params={})
    except Exception as e:
        store.events.append("autopilot.stage_error", level="warn", case_id=case_id,
                            payload={"stage": stage, "error": str(e)})
        return
    if run.status != "done":
        _wait(store, run.id, stop)


def _distinct_crashes(store, target_id):
    seen, out = set(), []
    for d in DynResultDAO(store.conn).list_by_target(target_id):
        if not (d.crashed and d.input_sha):
            continue
        # A SIGABRT is bucketed by signal alone (its PC is in the abort/check machinery, not the
        # defect), so one double-free is proved once, not 47 times -- EXCEPT a sanitizer abort,
        # which carries a defect_key (ASan class+source) separating two distinct defects that both
        # abort, so both reach the prove loop instead of collapsing. See crash_dedup_key.
        key = ((d.signal_name, d.defect_key) if d.signal_name == "SIGABRT"
               else (d.signal_name, d.fault_pc))
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out[:12]


def run_case_autopilot(case_dir, case_id: str, target_ids, status: dict, stop: threading.Event) -> None:
    """The background pipeline. Owns its OWN CaseStore connection (SQLite is per-thread)."""
    store = CaseStore(case_dir)
    try:
        status.update({"state": "running", "targets": len(target_ids), "started": time.time()})
        for i, tid in enumerate(target_ids):
            if stop.is_set():
                break
            status["target"] = i + 1
            t = store.targets.get(tid)
            if not t:
                continue
            mode = None
            # Recover + detect.
            _run_target_stage(store, t, "disassemble", status, stop)
            _run_target_stage(store, t, "detect_cwe", status, stop)
            _run_target_stage(store, t, "cve_scan", status, stop)
            # Demonstrate injection / format-string leaks by probing the binary's sinks directly
            # (no crash needed) -- a printf(user) leaks live memory, a system(user) runs a command.
            _run_target_stage(store, t, "synthesize_injection", status, stop)
            # Search. Coverage fuzz (falls back to blind if unavailable), then directed + heap.
            dyn = {"input_mode": mode} if mode else {}
            _run_target_stage(store, t, "coverage_fuzz", status, stop, dyn)
            _run_target_stage(store, t, "directed_fuzz", status, stop, dyn)
            _run_target_stage(store, t, "heap_check", status, stop, dyn)
            crashes = _distinct_crashes(store, tid)
            # Run concolic when the search found nothing OR left the binary under-covered: a low
            # block-coverage number means guarded branches (magic values, length checks) were
            # never reached -- exactly what concolic solves for.
            cov_pct = _best_block_pct(store, tid)
            if not crashes or (cov_pct is not None and cov_pct < 60):
                _run_target_stage(store, t, "concolic", status, stop, dyn)
                # Close the coverage loop: re-fuzz once more, now that directed_fuzz automatically
                # reuses concolic's solved inputs as seeds -- so the fuzzer explores AROUND the
                # guarded branches concolic just unlocked, instead of the run ending at them.
                _run_target_stage(store, t, "directed_fuzz", status, stop, {**dyn, "seed": 4242})
                crashes = _distinct_crashes(store, tid)
            # Prove each distinct crash.
            for cr in crashes:
                if stop.is_set():
                    break
                p = {"input_sha": cr.input_sha}
                _run_target_stage(store, t, "root_cause", status, stop, p)
                _run_target_stage(store, t, "build_poc", status, stop, p)
                _run_target_stage(store, t, "poc_primitive", status, stop, p)
            if crashes and not stop.is_set():
                rep = {"input_sha": crashes[0].input_sha}
                _run_target_stage(store, t, "build_exploit", status, stop, rep)
                _run_target_stage(store, t, "behavior_trace", status, stop, rep)
                _run_target_stage(store, t, "dynamic_taint", status, stop, rep)
            # Review each demonstrated finding: replay its input several times so a flaky crash is
            # flagged rather than trusted, and a reopened case carries the verdict. Verified-PoC
            # inputs come first (never dropped), then any distinct crash; capped so a target with
            # many faults cannot become hundreds of sandbox runs. This is the SAME false-positive
            # review the interactive Autopilot runs -- the background path shipped findings
            # unreviewed without it.
            if crashes and not stop.is_set():
                from . import review
                pocs = PocDAO(store.conn).list_by_target(tid)
                shas = list(dict.fromkeys(
                    [p.input_sha for p in pocs if getattr(p, "verified", False) and p.input_sha]
                    + [c.input_sha for c in crashes]))[:12]
                if shas:
                    status["stage"] = "verify"
                    store.events.append("autopilot.stage", case_id=t.case_id,
                                        payload={"stage": "verify", "target_id": t.id})
                    for sha in shas:
                        if stop.is_set():
                            break
                        try:
                            review.replay_verdict(store, t, sha, times=5)
                        except Exception:
                            pass
        # Case-level cross-binary analysis for a multi-binary case.
        if len(target_ids) > 1 and not stop.is_set():
            for stage in ("link_case", "ipc_model", "cross_taint", "whole_system"):
                _run_case_stage(store, case_id, stage, status, stop)
        # Outcome.
        pd, fd = PocDAO(store.conn), FindingDAO(store.conn)
        verified = any(p.verified for tid in target_ids for p in pd.list_by_target(tid))
        crashed = any(d.crashed for tid in target_ids for d in DynResultDAO(store.conn).list_by_target(tid))
        outcome = "poc" if verified else ("crash" if crashed else "static")
        status.update({"state": "cancelled" if stop.is_set() else "done",
                       "outcome": outcome, "stage": None, "updated": time.time()})
        store.events.append("autopilot.done", case_id=case_id,
                            payload={"outcome": outcome, "cancelled": stop.is_set()})
    except Exception as e:
        status.update({"state": "error", "error": str(e), "updated": time.time()})
        try:
            store.events.append("autopilot.error", level="error", case_id=case_id, payload={"error": str(e)})
        except Exception:
            pass
    finally:
        store.close()
