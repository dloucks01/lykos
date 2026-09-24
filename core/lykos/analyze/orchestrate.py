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
import logging
import threading
import time
from typing import Optional

_log = logging.getLogger(__name__)

from ..casestore import CaseStore
from ..db.dao import DynResultDAO, FindingDAO, FunctionDAO, PocDAO
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
    "heap_trace": ("..analyze.dynamic", "enqueue_heap_trace"),
    "oob_index": ("..analyze.dynamic", "enqueue_oob_index"),
    "chain_primitive": ("..analyze.poc", "enqueue_chain"),
    "concolic": ("..analyze.symbolic", "enqueue_concolic"),
    "root_cause": ("..analyze.debug", "enqueue_root_cause"),
    "build_poc": ("..analyze.poc", "enqueue_build_poc"),
    "poc_primitive": ("..analyze.poc", "enqueue_primitive"),
    "build_exploit": ("..analyze.poc", "enqueue_exploit"),
    "synthesize_poc": ("..analyze.poc", "enqueue_synthesize"),
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
_NO_PARAMS = {"disassemble", "detect_cwe", "heap_trace", "oob_index", "chain_primitive",
              "synthesize_poc"}
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
    # Deadline hit: CANCEL the run before giving up on it, exactly as the stop branch does. Without
    # this the run keeps executing in a worker (CPU/RAM) after the plan has already moved on and
    # marked the stage "error", and it later writes results into a target the plan called failed.
    try:
        JobQueue(store.conn).cancel(run_id)
    except Exception:
        pass
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
        _log.debug("best block-coverage lookup failed for target %s", target_id, exc_info=True)
        return None


# The pipeline PLAN: the ordered steps a target goes through, so the UI can show what is done,
# running, and still to come -- not just a live log. Conditional steps (concolic, the exploit
# ladder) start `pending` and become `skipped` if the run does not reach them. Repeats (directed
# fuzz runs twice; root_cause/build_poc run per crash) update the same entry.
_PLAN_STAGES = [
    ("disassemble", "Disassemble"), ("detect_cwe", "Static detectors"),
    ("cve_scan", "Known-CVE scan"), ("synthesize_injection", "Injection probes"),
    ("coverage_fuzz", "Coverage fuzzing"), ("directed_fuzz", "Directed fuzzing"),
    ("heap_check", "Heap checks"), ("heap_trace", "Heap primitives"),
    ("oob_index", "Array-index probes"), ("chain_primitive", "Primitive chaining"),
    ("concolic", "Concolic execution"), ("synthesize_poc", "Synthesize PoC"),
    ("root_cause", "Root-cause"), ("build_poc", "Build PoC"),
    ("poc_primitive", "PoC primitive"), ("build_exploit", "Build exploit"),
    ("behavior_trace", "Behaviour trace"), ("dynamic_taint", "Dynamic taint"),
    ("verify", "False-positive review"),
]
_PLAN_LABEL = dict(_PLAN_STAGES)
# how far along a phase is, so a repeat/cache cannot regress a finished one back to running
_PLAN_RANK = {"pending": 0, "running": 1, "skipped": 2, "cancelled": 3, "error": 4, "done": 5}


def _init_plan(status, target, idx, total) -> None:
    status["target_id"] = target.id
    status["target_name"] = getattr(target, "filename", None) or target.id[:12]
    status["target"] = idx
    status["targets"] = total
    status["plan"] = [{"stage": s, "label": lbl, "state": "pending", "detail": ""}
                      for s, lbl in _PLAN_STAGES]
    status["updated"] = time.time()


def _plan_set(status, stage, state, detail=None) -> None:
    for p in status.get("plan", []):
        if p["stage"] != stage:
            continue
        # never regress a finished phase (build_poc done -> running on the next crash)
        if state == "running" and _PLAN_RANK.get(p["state"], 0) >= _PLAN_RANK["running"] \
                and p["state"] != "running":
            if detail is not None:
                p["detail"] = detail
            return
        p["state"] = state
        if detail is not None:
            p["detail"] = detail
        status["updated"] = time.time()
        return


def _finalize_plan(status) -> None:
    for p in status.get("plan", []):
        if p["state"] == "pending":          # a conditional step the run never reached
            p["state"] = "skipped"
    status["updated"] = time.time()


def _stage_detail(store, target, stage) -> str:
    """A short 'what it found' summary for a COMPLETED step, shown inline in the plan so the
    progress view reads as results (`142 functions`, `58% cov · 2 crashes`, `CWE-122`), not just
    checkmarks. Best-effort: any query failure just yields no detail."""
    tid = target.id
    try:
        if stage == "disassemble":
            n = FunctionDAO(store.conn).count_by_target(tid)
            return f"{n} functions" if n else ""
        if stage == "detect_cwe":
            n = FindingDAO(store.conn).count_by_target(tid)
            return f"{n} finding{'s' if n != 1 else ''}" if n else ""
        if stage in ("coverage_fuzz", "directed_fuzz", "heap_check"):
            from ..report.model import _best_coverage
            t = store.targets.get(tid)
            runs = [r for r in store.runs.list_by_case(t.case_id) if r.target_id == tid]
            cov = _best_coverage(store, runs)
            ncr = sum(1 for d in DynResultDAO(store.conn).list_by_target(tid) if d.crashed)
            bits = []
            # Block coverage is a % of recovered code; edge coverage (AFL bitmap) has no honest %
            # -- its EDGE COUNT is the figure, so `coverage_fuzz` reads "19 edges", not an empty
            # cell that looks like it did nothing.
            if cov and cov.get("kind") == "block" and cov.get("pct") is not None:
                bits.append(f"{cov['pct']:.0f}% cov")
            elif cov and cov.get("kind") == "edge" and cov.get("edges"):
                bits.append(f"{int(cov['edges'])} edges")
            if ncr:
                bits.append(f"{ncr} crash{'es' if ncr != 1 else ''}")
            return " · ".join(bits)
        if stage == "root_cause":
            cwes = [f.cwe for f in FindingDAO(store.conn).list_by_target(tid) if f.cwe]
            return cwes[0] if cwes else ""
        if stage in ("build_poc", "poc_primitive", "build_exploit"):
            pocs = PocDAO(store.conn).list_by_target(tid)
            v = sum(1 for p in pocs if getattr(p, "verified", False))
            if v:
                return f"{v} verified PoC{'s' if v != 1 else ''}"
            return f"{len(pocs)} PoC" if pocs else ""
    except Exception:
        return ""
    return ""


def _emit_stage(store, case_id, stage, state, *, target_id=None, detail=None) -> None:
    """A structured per-stage event so the log reads as WHAT each step is doing, not just that a
    stage fired: `Directed fuzzing · running`, `Build PoC · done`, `Concolic · skipped`."""
    payload = {"stage": stage, "label": _PLAN_LABEL.get(stage, stage), "state": state}
    if target_id:
        payload["target_id"] = target_id
    if detail:
        payload["detail"] = detail
    lvl = "warn" if state in ("error",) else "info"
    store.events.append("autopilot.stage", level=lvl, case_id=case_id, payload=payload)


def _run_target_stage(store, target, stage, status, stop, params=None) -> Optional[str]:
    if stop.is_set():
        return None
    status["stage"] = stage
    status["updated"] = time.time()
    _plan_set(status, stage, "running")
    _emit_stage(store, target.case_id, stage, "running", target_id=target.id)
    try:
        fn = _enqueue_fn(_TARGET[stage])
        q = JobQueue(store.conn)
        run = fn(q, target) if stage in _NO_PARAMS else fn(q, target, params=params or {})
    except Exception as e:
        _plan_set(status, stage, "error", str(e)[:120])
        _emit_stage(store, target.case_id, stage, "error", target_id=target.id, detail=str(e)[:200])
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
            _log.debug("cache-hit reprojection failed for stage %s target %s", stage, target.id, exc_info=True)
            pass
        d = _stage_detail(store, target, stage) or "cached"
        _plan_set(status, stage, "done", d)
        _emit_stage(store, target.case_id, stage, "done", target_id=target.id, detail=d)
        return "done"
    outcome = _wait(store, run.id, stop)
    pstate = ({"done": "done", "cancelled": "cancelled", "timeout": "error",
               "error": "error"}).get(outcome, outcome or "error")
    d = _stage_detail(store, target, stage) if pstate == "done" else None
    _plan_set(status, stage, pstate, d)
    _emit_stage(store, target.case_id, stage, pstate, target_id=target.id, detail=d)
    return outcome


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


def _ranked_channels(store, target_id):
    """Input channels to try for a target, best-first (from the functions it imports), always
    ending with all channels attempted. Lets the autopilot fuzz the RIGHT channel and, on no crash,
    retry the others -- a file parser's overflow can live in the argv filename it was handed
    (ncompress), which a stdin-only campaign never reaches."""
    from ..db.dao import CallEdgeDAO
    from .poc.capture import modes_for
    try:
        chans = modes_for(CallEdgeDAO(store.conn).list_by_target(target_id))
        return chans or ["stdin", "arg", "file"]
    except Exception:
        _log.debug("channel inference failed for %s", target_id, exc_info=True)
        return ["stdin", "arg", "file"]


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
            _init_plan(status, t, i + 1, len(target_ids))
            # Recover + detect.
            _run_target_stage(store, t, "disassemble", status, stop)
            _run_target_stage(store, t, "detect_cwe", status, stop)
            _run_target_stage(store, t, "cve_scan", status, stop)
            # Demonstrate injection / format-string leaks by probing the binary's sinks directly
            # (no crash needed) -- a printf(user) leaks live memory, a system(user) runs a command.
            _run_target_stage(store, t, "synthesize_injection", status, stop)
            # Search. Fuzz the channel the binary most likely reads (its imports rank them); coverage
            # fuzz (AFL, falls back to blind if unavailable), then directed + heap on the same channel.
            channels = _ranked_channels(store, tid)
            primary = channels[0] if channels else None
            dyn = {"input_mode": primary} if primary else {}
            _run_target_stage(store, t, "coverage_fuzz", status, stop, dyn)
            _run_target_stage(store, t, "directed_fuzz", status, stop, dyn)
            _run_target_stage(store, t, "heap_check", status, stop, dyn)
            # Custom-allocator heap-primitive discovery (double-free / UAF / overflow) for a target
            # with its OWN allocator, which the libc guard-page check cannot see.
            _run_target_stage(store, t, "heap_trace", status, stop)
            # Out-of-bounds array-index discovery (a fixed-size object table selected by a
            # user id whose bound check is missing / off-by-one).
            _run_target_stage(store, t, "oob_index", status, stop)
            # Chain a discovered heap / OOB primitive into a demonstrated control-flow hijack
            # (or an L2 recipe) -- consumes the heap_trace / oob_index Findings, which otherwise
            # reach no exploit builder.
            _run_target_stage(store, t, "chain_primitive", status, stop)
            crashes = _distinct_crashes(store, tid)
            # Multi-channel retry: the best-guess channel is not always where the bug is (a file
            # parser's overflow can be in the argv filename). If nothing crashed, drive the fast
            # directed fuzzer at each of the OTHER channels before spending concolic's budget.
            if not crashes and not stop.is_set():
                for j, alt in enumerate([c for c in channels[1:] if c != primary]):
                    if stop.is_set():
                        break
                    _run_target_stage(store, t, "directed_fuzz", status, stop,
                                      {"input_mode": alt, "seed": 91 + j})
                    crashes = _distinct_crashes(store, tid)
                    if crashes:
                        store.events.append("autopilot.channel_hit", case_id=t.case_id,
                                            payload={"target_id": tid, "mode": alt})
                        break
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
            # Static-overflow synthesis: an unbounded stack overflow (gets(), a size-less strcpy,
            # scanf("%s")) needs a long, NEWLINE-FREE payload that blind mutation almost never
            # generates -- a stray 0x0a ends gets() before the frame is smashed -- so the fuzzer
            # reports full block coverage and zero crashes on a binary whose bug is glaringly
            # static. Derive the overflow straight from the recovered stack frame and detonate once
            # over the channel the binary reads; on a fault it files a verified L1 crash exactly
            # like a fuzzer-found one, which the exploit ladder below then builds into L2/L3. The
            # stage no-ops when no stack buffers were recovered, so it is safe to run generally.
            if not crashes and not stop.is_set():
                _run_target_stage(store, t, "synthesize_poc", status, stop)
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
                    _plan_set(status, "verify", "running", f"{len(shas)} to replay")
                    _emit_stage(store, t.case_id, "verify", "running", target_id=t.id,
                                detail=f"replaying {len(shas)} input(s)")
                    for sha in shas:
                        if stop.is_set():
                            break
                        try:
                            review.replay_verdict(store, t, sha, times=5)
                        except Exception:
                            _log.debug("replay verdict failed for %s", sha, exc_info=True)
                            pass
                    _plan_set(status, "verify", "cancelled" if stop.is_set() else "done")
                    _emit_stage(store, t.case_id, "verify",
                                "cancelled" if stop.is_set() else "done", target_id=t.id)
            _finalize_plan(status)          # any step never reached is marked skipped
        # Case-level cross-binary analysis for a multi-binary case.
        if len(target_ids) > 1 and not stop.is_set():
            for stage in ("link_case", "ipc_model", "cross_taint", "whole_system"):
                _run_case_stage(store, case_id, stage, status, stop)
        # Outcome.
        pd = PocDAO(store.conn)
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
