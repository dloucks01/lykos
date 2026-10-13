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
import re
import threading
import time
from typing import Optional

_log = logging.getLogger(__name__)

from ..casestore import CaseStore
from ..db.dao import DynResultDAO, FindingDAO, FunctionDAO, PocDAO
from ..db.models import STATIC_DETECTORS
from ..jobs.queue import JobQueue
from . import budget as budget_mod
from . import substrate

# stage -> (module, enqueue-fn). Target-scoped unless listed in _CASE.
_TARGET = {
    # The FLOOR: one execution, before any analysis. See the call site for why it was missing.
    "dynamic_run": ("..analyze.dynamic", "enqueue_dynamic"),
    "disassemble": ("..analyze.disassemble", "enqueue_disassemble"),
    "detect_cwe": ("..analyze.detect", "enqueue_detect"),
    "cve_scan": ("..analyze.fingerprint", "enqueue_cve_scan"),
    "source_cve_scan": ("..analyze.fingerprint", "enqueue_source_cve_scan"),
    "embedded_audit": ("..analyze.fingerprint", "enqueue_embedded_audit"),
    "int_overflow_scan": ("..analyze.fingerprint", "enqueue_int_overflow_scan"),
    "uaf_scan": ("..analyze.fingerprint", "enqueue_uaf_scan"),
    "source_sink_scan": ("..analyze.fingerprint", "enqueue_source_sink_scan"),
    "net_fuzz": ("..analyze.fuzz", "enqueue_net_fuzz"),
    "env_fuzz": ("..analyze.fuzz", "enqueue_env_fuzz"),
    "cve_corroborate": ("..analyze.fingerprint", "enqueue_cve_corroborate"),
    "cve_poc": ("..analyze.poc", "enqueue_cve_poc"),
    "coverage_fuzz": ("..analyze.fuzz", "enqueue_coverage_fuzz"),
    "fuzz": ("..analyze.fuzz", "enqueue_fuzz"),
    "directed_fuzz": ("..analyze.fuzz", "enqueue_directed_fuzz"),
    "heap_check": ("..analyze.dynamic", "enqueue_heap_check"),
    "heap_trace": ("..analyze.dynamic", "enqueue_heap_trace"),
    "oob_index": ("..analyze.dynamic", "enqueue_oob_index"),
    "mem_oracle": ("..analyze.dynamic", "enqueue_mem_oracle"),
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
    "unpack": ("..analyze.unpack", "enqueue_unpack"),
    "firmware_carve": ("..analyze.firmware", "enqueue_firmware"),
    "firmware_rehost": ("..analyze.firmware", "enqueue_rehost"),
    # These seven were REGISTERED and reachable only by a human clicking in the web UI --
    # nothing in the autopilot named them and no other stage chained to them, so for an
    # unattended run the capability did not exist. `multi_debug` in particular was the only
    # follow-fork/exec capture in the engine, which means a crash in a forked child or an
    # exec'd helper was never attributed to the input that caused it.
    "extract_secrets": ("..analyze.debug", "enqueue_extract"),
    "synthesize_secret": ("..analyze.poc", "enqueue_secret"),
    "debug_monitor": ("..analyze.debug", "enqueue_monitor"),
    "multi_debug": ("..analyze.debug", "enqueue_multi_debug"),
    "libfuzzer": ("..analyze.libfuzzer_stage", "enqueue_libfuzzer"),
    "boundary_fuzz": ("..analyze.link", "enqueue_boundary"),
    "poc_diff": ("..analyze.poc", "enqueue_poc_diff"),
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
              "synthesize_poc", "firmware_carve", "source_cve_scan", "embedded_audit",
              "int_overflow_scan", "uaf_scan", "source_sink_scan", "net_fuzz", "env_fuzz",
              "cve_corroborate", "cve_poc",
              # extract_secrets feeds itself a probe input when given none; synthesize_secret
              # reads static findings and never executes; libfuzzer builds its own harness from
              # source; boundary_fuzz discovers its own IPC channel. Each declines for itself
              # when it does not apply, which is why none of them needs a gate here.
              "extract_secrets", "synthesize_secret", "libfuzzer", "boundary_fuzz",
              # mem_oracle picks its own probe inputs (a recorded crash if there is one, else an
              # empty probe -- a default-path uninitialised read needs no input at all).
              "mem_oracle"}
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
    ("dynamic_run", "Baseline execution"),
    ("disassemble", "Disassemble"), ("detect_cwe", "Static detectors"),
    ("cve_scan", "Known-CVE scan"), ("source_cve_scan", "Dependency-CVE scan"),
    ("embedded_audit", "RTOS config audit"), ("int_overflow_scan", "Int-overflow allocs"),
    ("uaf_scan", "Use-after-free scan"), ("source_sink_scan", "Tainted-sink scan"),
    ("extract_secrets", "Recover gate values"), ("synthesize_secret", "Secret PoC"),
    ("net_fuzz", "Network fuzzing"), ("boundary_fuzz", "IPC boundary fuzzing"),
    ("libfuzzer", "libFuzzer harness"), ("env_fuzz", "Env-var fuzzing"),
    ("cve_poc", "CVE weaponization"),
    ("cve_corroborate", "CVE corroboration"), ("synthesize_injection", "Injection probes"),
    ("coverage_fuzz", "Coverage fuzzing"), ("directed_fuzz", "Directed fuzzing"),
    ("heap_check", "Heap checks"), ("heap_trace", "Heap primitives"),
    ("oob_index", "Array-index probes"), ("mem_oracle", "Uninitialised-memory oracle"),
    ("chain_primitive", "Primitive chaining"),
    ("concolic", "Concolic execution"), ("synthesize_poc", "Synthesize PoC"),
    ("root_cause", "Root-cause"), ("build_poc", "Build PoC"),
    ("poc_primitive", "PoC primitive"), ("build_exploit", "Build exploit"),
    ("behavior_trace", "Behaviour trace"), ("dynamic_taint", "Dynamic taint"),
    ("multi_debug", "Follow fork/exec"), ("debug_monitor", "Runtime monitor"),
    ("poc_diff", "Regression diff"),
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


def _looks_packed(store, target) -> bool:
    """True for an ELF/PE target whose bytes carry a runtime-packer (UPX) marker, so the orchestrator
    unpacks it into a child target before the machine-code stages run on the compressed stub."""
    if (target.file_type or "").lower() not in ("elf", "pe"):
        return False
    try:
        from .unpack import looks_packed
        return looks_packed(store, target)
    except Exception:                                        # noqa: BLE001 -- never block the pipeline
        return False


#: Operator-supplied invocation facts, and which stages may be handed each one.
#:
#: There was no channel for these at all: `run_case_autopilot` took no params, so a caller who
#: KNEW how the target is invoked -- the one thing that decides whether a campaign does any work
#: -- could not tell it. The UI's invocation box reaches the fuzz stage only when that stage is
#: launched by hand. `argv` and `input_mode` are safe everywhere (`dynamic_run` is the only stage
#: that validates its params, and it declares both); `seed_files`/`seed_dir` are read by the
#: fuzzers alone and `dynamic_run` would reject them.
_OVERRIDE_SCOPE: dict = {
    "argv": None,                                        # None = every stage
    "input_mode": None,
    "seed_files": frozenset({"fuzz", "coverage_fuzz", "directed_fuzz"}),
    "seed_dir": frozenset({"fuzz", "coverage_fuzz", "directed_fuzz"}),
}


def _apply_overrides(stage: str, params: Optional[dict], overrides: Optional[dict]) -> dict:
    """Operator facts win over the autopilot's inferences: they are knowledge, not a guess."""
    out = dict(params or {})
    for key, value in (overrides or {}).items():
        if value in (None, [], ""):
            continue
        scope = _OVERRIDE_SCOPE.get(key, frozenset())
        if scope is None or stage in scope:
            out[key] = value
    return out


#: What a blind / coverage-guided campaign is WORTH, declared like every other stage's `want`.
#: These two were the only stages that declared nothing, which in `budget.slice` means "give me
#: half of whatever this phase has left" -- so on a 600 s case `fuzz` took 211.4 s and the
#: solver after it got 19.2 s of the 120 s it asked for. A campaign's value also plateaus:
#: measured on /usr/bin/xxd, `coverage_fuzz` returned "done" after 22 s of a 97 s allowance.
_CAMPAIGN_WANT = 180.0

#: Mirrors jobs.worker._BUDGET_MARGIN: the orchestrator must outlast the worker's kill deadline,
#: or it stops waiting on a stage that was about to finish cleanly.
_WORKER_MARGIN = 1.25


#: Stages whose own default caps EXECUTIONS as well as time. The count is a runaway guard, not
#: a campaign size -- see budget.EXEC_CEILING.
_EXEC_BOUNDED = frozenset({"fuzz", "coverage_fuzz", "directed_fuzz", "net_fuzz", "env_fuzz"})


def _run_target_stage(store, target, stage, status, stop, params=None, *,
                      budget=None, want=None) -> Optional[str]:
    """Run one stage and wait for it, within the slice its phase can afford.

    `budget` is the case's divided wall clock (`analyze.budget.CaseBudget`). The slice is handed
    to the stage as `max_seconds`, which does three jobs at once: it caps the wait below, it
    becomes the worker's per-run deadline so a wedged stage stops blocking the pipeline, and for
    the four stages that read `max_seconds` themselves it IS the campaign length -- which is how
    a campaign stops being a 30-second smoke test on every target.

    With no budget the behaviour is exactly as before, so a stage launched on its own from the
    API still gets its registered timeout.
    """
    if stop.is_set():
        return None
    secs = None
    if budget is not None:
        secs = budget.slice(stage, want)
        if secs <= 0.0:
            # Saying this is the point: "we ran out of time before this stage" and "this stage
            # found nothing" are different outcomes that used to look identical in a report.
            why = f"no budget left in the {budget.current_phase} phase"
            budget.skipped(stage, why)
            _plan_set(status, stage, "skipped", why)
            _emit_stage(store, target.case_id, stage, "skipped", target_id=target.id, detail=why)
            return "skipped"
        params = dict(params or {})
        # MIN, never MAX: an explicit caller budget may tighten the slice but not exceed it.
        prior = params.get("max_seconds")
        params["max_seconds"] = min(float(prior), secs) if prior else secs
        if stage in _EXEC_BOUNDED and "max_execs" not in params:
            # Time is the bound that matters; the count is only a runaway guard. The stage
            # default of 3,000 turned a 200-second slice into a 17-second campaign.
            params["max_execs"] = budget_mod.EXEC_CEILING
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
    t_begin = time.time()
    # The grace is PROPORTIONAL, and small. The worker's deadline fires at the slice and marks
    # the run, but a stage that never polls `should_cancel()` cannot be interrupted -- all the
    # orchestrator can do is stop waiting and move on, leaving the stage to finish on its own
    # worker thread. A flat +30s grace made that generosity the dominant term: measured on a
    # 90-second budget, `build_exploit` was allowed 13.5s and held the pipeline for 42.1s, so
    # the search phase it was supposed to protect got nothing at all.
    # Beyond the worker's own kill deadline (jobs.worker._run_timeout), which already sits a
    # little past the stage's campaign length, plus a small proportional grace for the handover.
    grace = min(15.0, max(3.0, secs * 0.25)) if secs else None
    wait_for = (secs * _WORKER_MARGIN + grace) if secs else None
    outcome = _wait(store, run.id, stop, **({"timeout": wait_for} if wait_for else {}))
    if budget is not None:
        budget.record(stage, time.time() - t_begin)
    pstate = ({"done": "done", "cancelled": "cancelled", "timeout": "error",
               "error": "error"}).get(outcome, outcome or "error")
    d = _stage_detail(store, target, stage) if pstate == "done" else None
    _plan_set(status, stage, pstate, d)
    _emit_stage(store, target.case_id, stage, pstate, target_id=target.id, detail=d)
    return outcome


def _staged(budget, store, target, stage, status, stop, params=None, *, want=None,
            overrides=None):
    """`_run_target_stage` with the case budget in front, for the autopilot's own call sites.

    Spelled as its own name so that a stage added to the pipeline without a budget is visible in
    review: `_run_target_stage` still exists for the API's single-stage launches, where the
    stage's registered timeout is the right ceiling.
    """
    over = overrides if overrides is not None else getattr(budget, "overrides", None)
    return _run_target_stage(store, target, stage, status, stop,
                             _apply_overrides(stage, params, over),
                             budget=budget, want=want)


def _run_target_stages(store, target, specs, status, stop) -> dict:
    """Enqueue several INDEPENDENT target stages at once and wait for all of them, letting the worker
    pool run them concurrently under its per-class concurrency caps -- the single sandbox governor
    (quick/io/cpu/vm) that already bounds how many sandbox runs execute at once. An independent
    discovery group is thus no longer serialized one-at-a-time, with NO new concurrency primitive and
    no risk of oversubscribing the sandbox: the pool's caps decide the real parallelism (a 1-worker
    pool still runs them correctly, just serially).

    `specs` is a list of (stage, params). The caller GUARANTEES the stages do not consume each other's
    Findings/artifacts; a stage that reads another's output must stay a serial _run_target_stage after
    this batch. Per-stage plan/event/cache-hit handling mirrors _run_target_stage exactly. Returns
    {stage: outcome}."""
    from ..jobs.registry import reproject_cache_hit
    pending: dict = {}                                    # run_id -> stage
    outcomes: dict = {}
    for stage, params in specs:
        if stop.is_set():
            break
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
            outcomes[stage] = None
            continue
        if run.status == "done":                          # content-addressed cache hit (see _run_target_stage)
            try:
                reproject_cache_hit(store, stage, target.id, run.id)
            except Exception:
                _log.debug("cache-hit reprojection failed for stage %s target %s", stage, target.id,
                           exc_info=True)
            d = _stage_detail(store, target, stage) or "cached"
            _plan_set(status, stage, "done", d)
            _emit_stage(store, target.case_id, stage, "done", target_id=target.id, detail=d)
            outcomes[stage] = "done"
        else:
            pending[run.id] = stage
    # Poll every queued run to a terminal state; the pool's workers execute them in parallel, bounded
    # by the per-class caps. Finalize each stage the instant it finishes, exactly as the serial path.
    deadline = time.time() + 900.0
    while pending and time.time() < deadline:
        if stop.is_set():
            break
        for rid in list(pending):
            r = store.runs.get(rid)
            if r and r.status in _TERMINAL:
                stage = pending.pop(rid)
                pstate = ({"done": "done", "cancelled": "cancelled", "timeout": "error",
                           "error": "error"}).get(r.status, r.status or "error")
                d = _stage_detail(store, target, stage) if pstate == "done" else None
                _plan_set(status, stage, pstate, d)
                _emit_stage(store, target.case_id, stage, pstate, target_id=target.id, detail=d)
                outcomes[stage] = r.status
        if pending:
            time.sleep(0.6)
    # Anything still pending (cancelled or past the batch deadline) is cancelled so it cannot keep a
    # worker busy writing into a target the plan has moved past -- the same cleanup _wait does.
    for rid, stage in list(pending.items()):
        try:
            JobQueue(store.conn).cancel(rid)
        except Exception:
            pass
        timed_out = not stop.is_set()
        _plan_set(status, stage, "error" if timed_out else "cancelled")
        _emit_stage(store, target.case_id, stage, "error" if timed_out else "cancelled",
                    target_id=target.id)
        outcomes[stage] = "timeout" if timed_out else "cancelled"
    return outcomes


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
    from ..db.dao import CallEdgeDAO, TargetDAO
    from .ingest import triage_symbols
    from .poc.capture import modes_for
    try:
        # A MANAGED target owns no machine code, so it has no call edges and the ranking had
        # nothing to go on: `arg` came first for every jar, .pyc and .NET assembly. Triage
        # already recorded the names from its constant pool / metadata, which say which stream
        # the program reads -- so hand those over too.
        # Not only for a managed target. A native ELF's IMPORT TABLE names what it reads
        # (`read`, `fgets`, `fopen`) and triage recorded it at ingest, while `disassemble` may
        # not have run yet or may have returned nothing useful -- measured on quack_quack,
        # where an empty edge set left every channel without evidence and the concolic stage
        # ran against `arg` on a program whose input is `read(0, ...)`.
        syms = ()
        tgt = TargetDAO(store.conn).get(target_id)
        if tgt is not None:
            try:
                syms = triage_symbols(store.conn, store.content, tgt)
            except Exception:                            # best-effort: fewer signals, not none
                syms = ()
        chans = modes_for(CallEdgeDAO(store.conn).list_by_target(target_id), symbols=syms,
                          file_type=getattr(tgt, "file_type", None))
        return chans or ["stdin", "arg", "file"]
    except Exception:
        _log.debug("channel inference failed for %s", target_id, exc_info=True)
        return ["stdin", "arg", "file"]


_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _cve_crash_origins(store, target_id) -> dict:
    """input_sha -> CVE id for crashes the `cve_poc` stage reproduced (its DynResult note is
    '<label> trigger', the label carrying the matched CVE). Lets the autopilot attribute a crash the
    exploit ladder then weaponizes back to the known CVE it came from -- the CVE->exploit chain."""
    out = {}
    for d in DynResultDAO(store.conn).list_by_target(target_id):
        if d.crashed and d.input_sha and (d.note or "").endswith("trigger"):
            m = _CVE_ID_RE.search(d.note or "")
            if m:
                out.setdefault(d.input_sha, m.group(0))
    return out


# Detectors that report a defect from the CODE rather than from an observed effect. A finding from
# one of these is "detected", not "demonstrated", so it must never satisfy a check for whether a
# bug class has actually been proven -- `dangerous_api` files a strcpy() sighting as corroborated.
# Imported, not re-stated: three of the four names this used to hold ("detect_cwe",
# "cwe_scan", "source_sink_scan") are STAGE names and could never match a finding's
# detector column, so the "detected is not demonstrated" rule covered one detector of
# fourteen. See db.models.STATIC_DETECTORS.
_STATIC_DETECTORS = STATIC_DETECTORS
# The unbounded stack/buffer-copy family that synthesize_poc exists to demonstrate.
_OVERFLOW_CWES = frozenset({"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-193",
                            "CWE-242", "CWE-787"})


def _run_poc_diff(store, worklist, status, stop) -> None:
    """Replay a PoC-bearing target's crashing inputs against a REBUILD of the same program.

    This is the one stage that needs a PAIR, which is why nothing scheduled it: a single-target
    case has no baseline. When a case does hold two builds of one program -- ingest the patched
    binary beside the vulnerable one -- replaying the verified PoC across them turns "the static
    findings differ" into "the exploit no longer reproduces", which is the only claim worth
    making about a fix.

    Gated on the SAME FILENAME with a different content hash, because that is what a rebuild
    looks like. Without that gate a carved firmware's unrelated components would be compared to
    each other and poc_diff would report the bug "fixed" in a program that never had it.
    """
    pd = PocDAO(store.conn)
    builds: dict = {}
    for tid in worklist:
        t = store.targets.get(tid)
        if t is None or not t.filename:
            continue
        builds.setdefault(t.filename, []).append(t)
    for _name, group in builds.items():
        if len(group) < 2:
            continue
        proven = [t for t in group
                  if any(getattr(pc, "verified", False) for pc in pd.list_by_target(t.id))]
        if not proven:
            continue
        baseline = proven[0]
        for cand in group:
            if stop.is_set():
                return
            if cand.id == baseline.id or cand.sha256 == baseline.sha256:
                continue
            _run_target_stage(store, cand, "poc_diff", status, stop,
                              {"baseline_target_id": baseline.id})


def _nonnative_image(target) -> bool:
    """Is this target something AFL fundamentally cannot instrument?

    AFL rewrites/traces MACHINE CODE. Bytecode (.class/.jar/.pyc), a wasm module and a .NET
    assembly are not machine code -- the only machine code in the process belongs to the
    interpreter or the engine, so instrumenting it measures coverage of the JVM, of CPython, of
    V8 or of the CLR and tells you nothing about the target. A PE is machine code but runs under
    wine rather than as a host process, and a Mach-O or a bare-metal image does not run on this
    host at all. coverage_fuzz cannot apply to any of them; it has to be the blind campaign.

    Answered by the one substrate table because the hand-kept set this replaced missed `dotnet`
    and `macho`, so the autopilot started an AFL campaign against CIL bytecode and against an
    image the kernel refuses to exec.

    Distinct from _expensive_substrate, which includes a foreign ARCH: AFL++ qemu-mode
    genuinely does handle those, given afl-qemu-trace.
    """
    ft = getattr(target, "file_type", "") or ""
    if not substrate.known(ft):
        return False                     # not yet triaged: do not block AFL on no evidence
    sub = substrate.of(ft)
    return not (sub.machine_code and sub.backend in (substrate.NATIVE, substrate.QEMU))


def _expensive_substrate(target) -> bool:
    """Is one execution of this target orders of magnitude dearer than a native exec?

    True for wine / the JVM / qemu -- the substrates sandbox.run_batch refuses, so the fuzzers
    fall back to one process per input and pay the start-up every time. Stage ORDER has to differ
    there: a cheap, certain, single-detonation stage must not sit behind a campaign that will
    consume the entire budget.
    """
    try:
        if substrate.expensive(target.file_type):
            return True
        from .dynamic import sandbox
        return substrate.foreign_cpu(target.arch, target.file_type, sandbox.host_arch())
    except Exception:                                    # noqa: BLE001 -- ordering hint only
        _log.debug("substrate-cost check failed", exc_info=True)
        return False


def _has_demonstrated(store, target_id, cwes) -> bool:
    """Has any bug in `cwes` been DEMONSTRATED (not merely flagged statically) on this target?"""
    try:
        for f in FindingDAO(store.conn).list_by_target(target_id):
            if (f.detector not in _STATIC_DETECTORS
                    and f.state in ("poc-backed", "corroborated", "confirmed")
                    and (f.cwe or "") in cwes):
                return True
    except Exception:                                    # noqa: BLE001 -- advisory check only
        _log.debug("demonstrated-CWE check failed for %s", target_id, exc_info=True)
    return False


def _max_verified_poc_level(store, target_id) -> int:
    """Highest verified PoC level (L1->1, L2->2, L3->3) on the target, or 0 when none."""
    lv = 0
    for p in PocDAO(store.conn).list_by_target(target_id):
        if p.verified and (p.level or "").startswith("L") and p.level[1:].isdigit():
            lv = max(lv, int(p.level[1:]))
    return lv


def _record_cve_weaponized(store, target, cve: str, level: int) -> None:
    """Record that a version-matched CVE was reproduced AND its crash escalated by the exploit ladder
    to L{level} -- the explicit CVE->exploit link (otherwise the escalation reads as a generic
    control-flow finding disconnected from the CVE)."""
    note = (f"{cve} was version-matched on this target, its trigger reproduced a real fault, and the "
            f"exploit ladder weaponized that crash to L{level} -- a demonstrated CVE-to-exploit "
            f"chain (not just a version match).")
    store.events.append("cve.weaponized", case_id=target.case_id,
                        payload={"target_id": target.id, "cve": cve, "level": f"L{level}",
                                 "note": note})
    try:
        FindingDAO(store.conn).upsert(target.id, target.case_id, {
            "cwe": "CWE-1395", "title": f"{cve} weaponized to L{level} (CVE -> exploit chain)",
            "severity": "critical" if level >= 3 else "high", "detector": "cve_chain",
            "state": "poc-backed", "confidence": 0.95, "site_detail": cve,
            "dedup_key": f"cve-chain:{cve}:{target.id}",
            "evidence": [{"channel": "cve", "detail": note}]})
    except Exception:
        _log.debug("recording cve_chain finding failed", exc_info=True)


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


# CWE classes where a static finding SHOULD be reproducible but may not fault a non-instrumented
# binary (the overflow doesn't reach an unmapped page; the target has no canary/sanitizer).
_MEMCORRUPTION_CWES = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416",
                       "CWE-190", "CWE-131", "CWE-476", "CWE-824"}


def _note_static_memcorruption(store, target) -> None:
    """When a memory-corruption defect was found statically but NO crash was reproduced, record a
    note explaining why there is no dynamic PoC -- so a static-only outcome does not read as a
    clean bill of health. A sanitizer build / source would demonstrate it."""
    try:
        from ..db.dao import FindingDAO
        hits = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if (f.cwe in _MEMCORRUPTION_CWES
                    and f.state in ("corroborated", "confirmed", "poc-backed"))]
        if not hits:
            return
        cwes = sorted({f.cwe for f in hits})
        store.events.append("autopilot.note", case_id=target.case_id, payload={
            "target_id": target.id, "kind": "static_memcorruption_unreproduced",
            "cwes": cwes,
            "note": (f"A memory-corruption defect ({', '.join(cwes)}) was found statically but no "
                     f"runtime fault was reproduced on this binary. That is expected when the "
                     f"target has no stack canary or sanitizer and the overflow does not reach an "
                     f"unmapped page (e.g. the write stays within a large task/thread stack) -- "
                     f"the bug is real but not self-evidently crashing. Rebuild with "
                     f"-fsanitize=address, or provide source, to demonstrate it.")})
    except Exception:
        _log.debug("static-memcorruption note failed for %s", target.id, exc_info=True)


SCORECARD_EVENT = "autopilot.scorecard"


def _scorecard(store, target, bud, status) -> dict:
    """What this run actually DID to the target, recorded whether or not it found anything.

    The gap this closes, measured on four stock /usr/bin binaries: one of them
    (`/usr/bin/xxd`) completed the whole pipeline with 2,756 executions and no crash -- a
    legitimately clean result -- and another (`/usr/bin/jpegtran`) executed the program ZERO
    times because a stage upstream consumed the budget. Both produced a report with
    `corroborated` findings and no crashes, and nothing in either report distinguished them.

    A null result is only worth something next to the work behind it, so this records the work:
    did the program run at all, how many times, how fast, which stages were reached, and which
    were skipped for want of time. The report prints it beside the findings.
    """
    card: dict = {"target_id": target.id, "filename": target.filename}

    # One pass over the case's events: the baseline verdict and every campaign's own execution
    # count. `dynamic.done` already reports `ran`, which is the floor this whole card is about.
    by_stage: dict = {}
    try:
        events = store.events.list(case_id=target.case_id, limit=8000)
    except Exception:                                    # noqa: BLE001 -- advisory
        _log.debug("scorecard: event read failed", exc_info=True)
        events = []
    for e in events:
        pl = e.payload if isinstance(e.payload, dict) else {}
        if e.type == "dynamic.done" and "baseline" not in card:
            card["baseline"] = {"ran": bool(pl.get("ran")), "crashed": bool(pl.get("crashed")),
                                "isolation": pl.get("isolation"),
                                "note": str(pl.get("note") or "")[:200]}
        n = pl.get("execs")
        if isinstance(n, int) and n > 0 and "." in (e.type or ""):
            key = (e.type or "").split(".")[0]
            if n > by_stage.get(key, 0):
                by_stage[key] = n                        # a stage's last count, not a sum of ticks
    execs = sum(by_stage.values())
    card["executions"] = {"total": execs, "by_engine": by_stage}

    spent = bud.spent()
    search = max(1e-3, sum(v for k, v in spent["by_stage"].items() if k in _EXEC_BOUNDED))
    card["executions"]["per_second"] = round(execs / search, 1) if execs else 0.0
    card["budget"] = spent

    plan = status.get("plan") or []
    counts: dict = {}
    for step in plan:
        st = (step.get("state") or "pending") if isinstance(step, dict) else "pending"
        counts[st] = counts.get(st, 0) + 1
    card["stages"] = counts
    card["stages_skipped_for_budget"] = list(
        dict.fromkeys(x["stage"] for x in spent["skipped_for_budget"]))
    store.events.append(SCORECARD_EVENT, case_id=target.case_id, payload=card)
    return card


def run_case_autopilot(case_dir, case_id: str, target_ids, status: dict,
                       stop: threading.Event, budget_seconds: Optional[float] = None,
                       overrides: Optional[dict] = None) -> None:
    """The background pipeline. Owns its OWN CaseStore connection (SQLite is per-thread).

    `budget_seconds` is the wall clock EACH TARGET gets, divided among the phases by
    `budget.CaseBudget` (default `budget.DEFAULT_TARGET_BUDGET`). Before this the pipeline had no
    budget of its own: stage timeouts were absolute and generous (3600s for two of them), so a
    single stage could outlast the whole run and everything after it never executed. Measured on
    stock /usr/bin binaries, three runs out of four ended inside one stage with a third of the
    pipeline unreached -- see the table in `budget.py`.
    """
    store = CaseStore(case_dir)
    try:
        status.update({"state": "running", "targets": len(target_ids), "started": time.time()})
        # Worklist, not a fixed loop: a firmware image is a CONTAINER whose embedded binaries are
        # discovered mid-run (firmware_carve registers them as sub-targets). Those get appended and
        # analysed in the same pass.
        worklist = list(target_ids)
        done_tids: set = set()
        wi = 0
        while wi < len(worklist):
            tid = worklist[wi]
            wi += 1
            if stop.is_set():
                break
            if tid in done_tids:
                continue
            done_tids.add(tid)
            status["target"] = len(done_tids)
            t = store.targets.get(tid)
            if not t:
                continue
            _init_plan(status, t, len(done_tids), len(worklist))
            bud = budget_mod.CaseBudget(budget_seconds, overrides=overrides)
            status["budget"] = bud.spent()                # serializable; refreshed as we go
            # A firmware image is not a program: carve it into its embedded binaries (each registered
            # as a sub-target) and analyse THOSE. Running native recovery on the raw blob finds nothing
            # and misses every component + secret.
            if (t.file_type or "").lower() == "firmware":
                # CVE-fingerprint the image's OWN bytes first: a monolithic RTOS image (VxWorks,
                # bare-metal) statically links its libraries, so a vulnerable zlib/openssl/etc.
                # lives as a version banner in the container itself with no filesystem to carve
                # and no standalone ELF to extract. The byte-scan finds it either way.
                _staged(bud, store, t, "cve_scan", status, stop)
                _staged(bud, store, t, "firmware_carve", status, stop)
                # A bare-metal image (no filesystem, no embedded ELF) is a Cortex-M blob: rehost
                # it under Unicorn and fuzz its modelled MMIO inputs. The stage self-gates to a
                # detected Cortex-M reset-vector table, so it is a cheap no-op otherwise.
                _staged(bud, store, t, "firmware_rehost", status, stop)
                for sub in store.targets.list_by_case(case_id):
                    if sub.id not in done_tids and sub.id not in worklist:
                        worklist.append(sub.id)
                _finalize_plan(status)
                continue
            # A runtime-packed executable (UPX) is a compressed stub around the real program: the
            # machine-code stages would analyse the decompressor, not the code. Unpack it into a
            # child target and analyse THAT, exactly as a firmware image is carved into its binaries.
            if _looks_packed(store, t):
                _staged(bud, store, t, "unpack", status, stop)
                for sub in store.targets.list_by_case(case_id):
                    if sub.id not in done_tids and sub.id not in worklist:
                        worklist.append(sub.id)
                _finalize_plan(status)
                continue
            # THE FLOOR, before any analysis: can this image be executed here at all, and what
            # does it do with one input? Measured on stock /usr/bin binaries, this stage --
            # whose own capability description is "Run once, to see the target work" -- was
            # registered, wired to the API and offered in the UI, and the autopilot never called
            # it. So the pipeline's first execution of an arbitrary target happened inside a
            # fuzzer twenty stages later, and if anything upstream consumed the budget the
            # program was never run at all while the report still showed corroborated findings.
            #
            # It is also the cheapest honest signal there is: a target that cannot start (wrong
            # loader, missing runtime, needs an argument) is a different situation from one that
            # runs and survives, and every later stage's result is read in that light.
            bud.phase("recover")
            _staged(bud, store, t, "dynamic_run", status, stop, want=30.0)
            # Recover + detect.
            _staged(bud, store, t, "disassemble", status, stop)
            _staged(bud, store, t, "detect_cwe", status, stop)
            _staged(bud, store, t, "cve_scan", status, stop)
            # Known-CVE scan of a built-from-source project's declared dependencies + vendored
            # headers -- versions that never survive into the compiled binary's banners.
            _staged(bud, store, t, "source_cve_scan", status, stop)
            # Audit an embedded RTOS config header (FreeRTOSConfig.h) for disabled safety nets.
            _staged(bud, store, t, "embedded_audit", status, stop)
            # Unguarded size arithmetic feeding an allocator (integer-overflow allocation).
            _staged(bud, store, t, "int_overflow_scan", status, stop)
            # A freed pointer used or freed again on a path the fuzzer may never reach (UAF/dbl-free).
            _staged(bud, store, t, "uaf_scan", status, stop)
            # A dangerous sink (system/popen, printf-family) called with a non-literal arg (CWE-78/134).
            _staged(bud, store, t, "source_sink_scan", status, stop)
            # Recover the CONSTANTS the program checks input against -- a password, magic bytes,
            # an expected token, a menu command -- by breaking on its comparison functions. Those
            # are the values every later stage needs in order to get PAST a gate, so this belongs
            # before the campaigns, not after them. Native-arch + gdb only; self-gates.
            _staged(bud, store, t, "extract_secrets", status, stop, want=30.0)
            # Package any hard-coded credential detect_cwe found (CWE-798/321) into a verified,
            # self-contained PoC. It is the one demonstrated-effect class that needs NO crash --
            # deterministic, offline, and it never executes the target, so it costs nothing and
            # can never be starved by the fuzzing budget. It must follow detect_cwe, whose
            # findings it promotes rather than duplicates.
            _staged(bud, store, t, "synthesize_secret", status, stop, want=20.0)
            # A SOCKET SERVER has to be fuzzed before anything else touches it. Such a target
            # blocks in accept() and never reads stdin, so every stage that drives it that way --
            # the injection prober, the crashless exploit ladder, the OOB-index driver, the generic
            # fuzzers -- waits out its full timeout and finds nothing, draining the budget before
            # the one channel that works is ever tried. net_fuzz crashes such a server in about
            # three execs. It self-gates on bind/listen/recvfrom imports, so a non-server pays
            # nothing for being asked first.
            try:
                from ..db.dao import CallEdgeDAO as _CE  # imported here: the module-level name
                from .fuzz import netfuzz as _nf  # lives in _ranked_channels, not this scope
                _is_server = _nf.detect_server(_CE(store.conn).list_by_target(tid))[1]
            except Exception:
                _log.debug("server detection failed for %s", tid, exc_info=True)
                _is_server = False
            if _is_server:
                _staged(bud, store, t, "net_fuzz", status, stop, want=45.0)
            # An IPC/protocol boundary (a unix socket, a pipe, a datagram listener) is a channel
            # the generic fuzzers cannot reach at all: they drive stdin/argv/files. It discovers
            # its own channel and declines when there is none, so a plain binary pays nothing.
            _staged(bud, store, t, "boundary_fuzz", status, stop, want=45.0)
            # On a SOURCE target, an in-process libFuzzer harness under ASan+UBSan is the
            # strongest crash finder available -- thousands of executions a second with a
            # sanitizer oracle, against a few hundred for out-of-process mutation. It builds its
            # own harness and reports unsupported for a binary-only target.
            _staged(bud, store, t, "libfuzzer", status, stop, want=60.0)

            # Weaponize every version-matched CVE -- a bespoke per-CVE trigger where one is
            # authored, else the library's format attack (zlib bomb, XML billion-laughs) and its
            # CWE-class probes -- recording a verified reproduction only if the target faults.
            _staged(bud, store, t, "cve_poc", status, stop, want=45.0)
            # Demonstrate injection / format-string leaks by probing the binary's sinks directly
            # (no crash needed) -- a printf(user) leaks live memory, a system(user) runs a command.
            _staged(bud, store, t, "synthesize_injection", status, stop, want=30.0)
            # Leak-centric weaponization that needs NO crash -- run it BEFORE the budget-draining
            # fuzz/concolic below, so a modern-hardened target (PIE / stack canary / full RELRO) that
            # blind mutation can't crash still reaches its demonstrable effect within a time budget.
            # strategy="auto" provokes its own leak (a %p/%s over-read behind the input prompts, a
            # format sink, a heap UAF/menu) and drives the canary-bypass ret2win/ret2libc, the
            # format-%n saved-return overwrite, the heap FSOP chain, or files the demonstrated ASLR
            # info-leak (L2) when no shell is reachable. The overflow-based auto paths that DO need a
            # crash offset just no-op here and are covered by the crash-driven build_exploit later.
            # Self-gates per arch/mitigation and reports honest ceilings -- a bounded attempt, not a
            # false positive. (Placed early precisely because the old end-of-pass slot was never
            # reached once fuzz/concolic had spent the budget.)
            # Bounded by the PRE-SEARCH allowance on purpose. Running it early is itself an
            # earlier fix (the end-of-pass slot was never reached once fuzz had spent the
            # budget), and moving it back would undo that -- but unbounded it took its full
            # registered 300s on a jpegtran that had no crash yet and the run ended before any
            # fuzzer started. It keeps its early slot and can no longer spend the search's share.
            if not stop.is_set() and _max_verified_poc_level(store, tid) < 3:
                _staged(bud, store, t, "build_exploit", status, stop,
                        {"strategy": "auto"}, want=60.0)
            # SEARCH: everything from here actually executes the target with attacker input, so
            # it gets the largest share and the phase reserve stops an earlier stage spending it.
            bud.phase("search")
            # Channel ranking (from the imports) feeds both the heap check and the fuzzer below.
            channels = _ranked_channels(store, tid)
            primary = channels[0] if channels else None
            dyn = {"input_mode": primary} if primary else {}
            # DISCOVERY that needs NO fuzzer crash -- run it BEFORE the budget-draining fuzz/concolic,
            # for the same reason as the crashless weaponization above: a menu-driven heap / OOB target
            # rarely yields a blind-mutation crash, so with the old ordering heap_trace + oob_index +
            # chain_primitive were starved (the conformance harness caught a UAF-read heap failing here
            # for exactly this reason). heap_check (libc guard pages) + the custom-allocator UAF/
            # double-free trace + OOB-index discovery, then chain their primitives into a demonstrated
            # hijack / L2 recipe (chain_primitive consumes those Findings).
            # heap_check (libc guard pages), heap_trace (custom-allocator UAF/double-free) and
            # oob_index (OOB-index discovery) are three INDEPENDENT discovery passes -- none reads a
            # Finding or artifact another writes (heap_check -> detector "heap_monitor"; heap_trace ->
            # "heap_trace"; oob_index -> "oob_index"), so they run concurrently under the pool's
            # per-class caps (the single sandbox governor), halving this phase on a multi-core box
            # without oversubscribing the sandbox. chain_primitive then runs SERIALLY after them --
            # its _lead_finding consumes the heap_trace / oob_index Findings, so it must see them done.
            _run_target_stages(store, t, [("heap_check", dyn), ("heap_trace", None),
                                          ("oob_index", None)], status, stop)
            # A defect that never crashes is invisible to every stage above and below this one.
            # Shadow memory sees an uninitialised read as it happens, and tells a disclosure --
            # undefined bytes reaching a write syscall, which IS the effect -- from a merely
            # internal one. Native-ELF only and ~10-30x a bare run, so it is a bounded pass over
            # a few inputs here rather than anything inside a campaign.
            _staged(bud, store, t, "mem_oracle", status, stop, want=60.0)
            _staged(bud, store, t, "chain_primitive", status, stop, want=45.0)
            # Search. The CHANNEL-SPECIFIC fuzzers go first, because each one knows the channel its
            # target actually reads and both self-gate to the imports that prove it (bind/listen/
            # recvfrom; getenv), so a target they do not apply to pays nothing. Running them after
            # the generic sweeps starved them: a socket server BLOCKS in accept(), so every
            # stdin/argv/file exec runs to its timeout and drains the budget before net_fuzz is ever
            # reached -- while net_fuzz crashes the same server in about three execs. The generic
            # coverage/directed sweeps then follow for whatever the binary reads conventionally.
            _staged(bud, store, t, "env_fuzz", status, stop, want=45.0)
            # On an EXPENSIVE SUBSTRATE, synthesize the static overflow BEFORE the campaigns for
            # exactly the reason net_fuzz moved ahead of them. Wine, the JVM and qemu cannot be
            # batched (sandbox.run_batch returns None for them), so every execution pays a fresh
            # interpreter/emulator start-up -- seconds, not milliseconds. A coverage campaign then
            # eats the whole time budget and the run never reaches synthesize_poc at the end, even
            # though that stage demonstrates this bug class in ONE detonation from the recovered
            # stack frame. Measured on a mingw PE whose scanf("%s") overflow synthesize_poc proves
            # instantly: the full autopilot spent its entire budget fuzzing under wine and finished
            # at L0. Native targets keep the original order -- there, fuzzing is cheap and finds
            # strictly more. The stage no-ops without recovered stack buffers.
            if _expensive_substrate(t):
                _staged(bud, store, t, "synthesize_poc", status, stop, want=45.0)
            # coverage fuzz (AFL, falls back to blind if unavailable), then directed on the same
            # channel -- EXCEPT on a non-native image, where AFL cannot apply at all. AFL
            # instruments machine code: a .class/.jar is bytecode and a PE runs under wine, so
            # coverage_fuzz got as far as AFL++ qemu-mode and then ERRORED ("needs afl-qemu-trace"),
            # which is not the documented "falls back to blind". directed_fuzz then had no recovered
            # functions to direct at and synthesize_poc has no stack frame to work from, so a JVM
            # target reached the end of the ladder having executed the program ZERO times.
            #
            # The blind campaign is the right stage for these and already knows them -- it carries
            # the measured per-execution costs for wine (~1/s) and the JVM (~36/s) and reads a
            # defect as an uncaught exception rather than a signal -- but the autopilot never ran
            # it: "fuzz" appeared only in the stage registry. It splits its budget across every
            # channel, which is what this needs, since a bytecode target has no call edges and so
            # no channel ranking either.
            if _nonnative_image(t):
                _staged(bud, store, t, "fuzz", status, stop, dyn, want=_CAMPAIGN_WANT)
            elif _staged(bud, store, t, "coverage_fuzz", status, stop, dyn,
                         want=_CAMPAIGN_WANT) != "done" or \
                    bud.slice("fuzz") > 0:
                # The blind campaign is a SECOND campaign, not only a fallback. Measured on
                # /usr/bin/xxd with a 400s budget: coverage_fuzz returned "done" after 22s of a
                # 97s allowance -- AFL finishing early is not AFL having searched -- and because
                # `fuzz` was reached only when coverage_fuzz failed, the remaining 75 seconds of
                # the search phase went unspent. The two look for different things (one is
                # coverage-guided and single-channel, the other splits its budget across every
                # channel the target reads), so with budget left both are worth running.
                #
                # AFL can also abort for reasons that say nothing about the target: its dry run is
                # FATAL on a single seed that times out ("results in a timeout",
                # perform_dry_run()), a missing qemu tracer ends it, a forkserver handshake can
                # fail. Without a fallback the one campaign a native target gets simply does not
                # happen, and the run then reports only static findings -- "nothing was run"
                # wearing the face of "nothing was found", at campaign scale. The blind stage
                # carries none of those preconditions, so it runs the same corpus regardless.
                _staged(bud, store, t, "fuzz", status, stop, dyn, want=_CAMPAIGN_WANT)
            _staged(bud, store, t, "directed_fuzz", status, stop, dyn, want=120.0)
            crashes = _distinct_crashes(store, tid)
            # Multi-channel retry: the best-guess channel is not always where the bug is (a file
            # parser's overflow can be in the argv filename). If nothing crashed, drive the fast
            # directed fuzzer at each of the OTHER channels before spending concolic's budget.
            if not crashes and not stop.is_set():
                for j, alt in enumerate([c for c in channels[1:] if c != primary]):
                    if stop.is_set():
                        break
                    _staged(bud, store, t, "directed_fuzz", status, stop,
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
                _staged(bud, store, t, "concolic", status, stop, dyn, want=120.0)
                # Close the coverage loop: re-fuzz once more, now that directed_fuzz automatically
                # reuses concolic's solved inputs as seeds -- so the fuzzer explores AROUND the
                # guarded branches concolic just unlocked, instead of the run ending at them.
                _staged(bud, store, t, "directed_fuzz", status, stop,
                        {**dyn, "seed": 4242}, want=120.0)
                crashes = _distinct_crashes(store, tid)
            # Static-overflow synthesis: an unbounded stack overflow (gets(), a size-less strcpy,
            # scanf("%s")) needs a long, NEWLINE-FREE payload that blind mutation almost never
            # generates -- a stray 0x0a ends gets() before the frame is smashed -- so the fuzzer
            # reports full block coverage and zero crashes on a binary whose bug is glaringly
            # static. Derive the overflow straight from the recovered stack frame and detonate once
            # over the channel the binary reads; on a fault it files a verified L1 crash exactly
            # like a fuzzer-found one, which the exploit ladder below then builds into L2/L3. The
            # stage no-ops when no stack buffers were recovered, so it is safe to run generally.
            # Run it when the fuzzer found NOTHING, and also when it found crashes that do not
            # include an overflow: a binary with two defects (say a format sink on one menu branch
            # and a scanf("%s") overflow on another) gives the fuzzer the easy one, and gating on
            # `not crashes` then skipped the synthesis the hard one needs -- so "find every crash"
            # held for one defect per target but not for several in one binary. The stage no-ops
            # when no stack buffers were recovered, so the added cost is one detonation.
            if not stop.is_set() and (not crashes or not _has_demonstrated(store, tid, _OVERFLOW_CWES)):
                _staged(bud, store, t, "synthesize_poc", status, stop, want=45.0)
                crashes = _distinct_crashes(store, tid)
            # CVE -> exploit chain: which of these crashes were REPRODUCED by a matched-CVE trigger,
            # so if the ladder escalates one we can attribute the exploit back to the CVE. Accumulate
            # the BEST level reached per CVE and record once at the end (so an L3 is not masked by an
            # earlier L2 record that shares the finding's dedup key).
            cve_origin = _cve_crash_origins(store, tid)
            cve_best: dict = {}

            def _note_escalation(cve, before):
                after = _max_verified_poc_level(store, tid)
                if cve and after > before and after >= 2:    # the ladder raised THIS CVE crash to L2/L3
                    cve_best[cve] = max(cve_best.get(cve, 0), after)
            # PROVE what the search found. This phase keeps no reserve -- it is last, and every
            # crash it is given is already evidence that something is there. The reserve the
            # search phase held back exists for exactly this: a campaign that finds a crash in
            # its final seconds must still have time to root-cause and prove it.
            bud.phase("prove")
            # Prove each distinct crash.
            for cr in crashes:
                if stop.is_set():
                    break
                p = {"input_sha": cr.input_sha}
                cve = cve_origin.get(cr.input_sha)
                lvl0 = _max_verified_poc_level(store, tid) if cve else 0
                _staged(bud, store, t, "root_cause", status, stop, p, want=60.0)
                _staged(bud, store, t, "build_poc", status, stop, p, want=60.0)
                _staged(bud, store, t, "poc_primitive", status, stop, p, want=90.0)
                _note_escalation(cve, lvl0)              # these three ran on THIS CVE crash's input
            if crashes and not stop.is_set():
                rep = {"input_sha": crashes[0].input_sha}
                cve0 = cve_origin.get(crashes[0].input_sha)
                lvlb = _max_verified_poc_level(store, tid) if cve0 else 0
                _staged(bud, store, t, "build_exploit", status, stop, rep, want=60.0)
                _note_escalation(cve0, lvlb)             # build_exploit ran on this CVE crash's input
                _staged(bud, store, t, "behavior_trace", status, stop, rep, want=45.0)
                _staged(bud, store, t, "dynamic_taint", status, stop, rep, want=60.0)
                # Follow fork/exec and blame the CHILD. A forking server or a target that
                # execve()s a helper faults in a process the ordinary single-process capture
                # never sees, so without this the crash is attributed to the parent or missed
                # entirely. gdb-only and native-only; self-gates and says so.
                _staged(bud, store, t, "multi_debug", status, stop, rep, want=45.0)
                # Break on the dangerous calls live and record the arguments they were actually
                # reached with -- the runtime counterpart to the static sink findings.
                _staged(bud, store, t, "debug_monitor", status, stop, rep, want=45.0)
            for cve, lvl in cve_best.items():            # one CVE->exploit link per CVE, at its best
                _record_cve_weaponized(store, t, cve, lvl)
            # Format-string -> shell WITHOUT a crash. A reachable printf(user) sink is an L3
            # candidate on its own -- overwrite printf@GOT with system and send "/bin/sh" -- and
            # needs no crashing input, but build_exploit otherwise runs only for a crash (above),
            # so a crashless format bug topped out at the synthesize_injection L1 leak. When a
            # CWE-134 finding was corroborated and the ladder has not already reached L3, drive the
            # format strategy directly. The stage self-gates (x86-64, writable GOT, a looping sink)
            # and reports an honest ceiling (full-RELRO / PIE blocks the GOT overwrite) rather than
            # faking it -- so the demonstrated info-disclosure stands and RCE stays potential.
            if not stop.is_set() and _max_verified_poc_level(store, tid) < 3:
                fmt_hit = any(
                    f.cwe == "CWE-134" and f.state in ("corroborated", "confirmed", "poc-backed")
                    for f in FindingDAO(store.conn).list_by_target(tid))
                if fmt_hit:
                    _staged(bud, store, t, "build_exploit", status, stop,
                                      {"strategy": "format"})
            # Menu-driven glibc-heap -> shell WITHOUT a crash. A notebook/heap-menu target
            # (malloc/free pair + a numbered add/free/view/edit menu) is an L3 candidate via the
            # tcache-poison + House-of-Apple-2 chain, which needs no crashing input -- but
            # build_exploit's heap path runs only on a crash (above) or the `auto` strategy, which
            # the autopilot never reaches for a crashless target. Drive strategy="heap" directly
            # when the binary looks like a heap menu and the ladder has not reached L3. The stage
            # self-gates (confirms only by a spawned shell; a target whose primitive is not
            # discovered or whose menu does not match just returns an honest "not confirmed"), so
            # this is a bounded attempt, not a false positive.
            if not stop.is_set() and _max_verified_poc_level(store, tid) < 3:
                try:
                    from .poc.exploit_stage import _looks_like_heap_menu
                    tb = store.content.path(t.sha256).read_bytes()
                    heap_menu = _looks_like_heap_menu(None, t, tb)
                except Exception:
                    _log.debug("heap-menu gate check failed for %s", tid, exc_info=True)
                    heap_menu = False
                if heap_menu:
                    _staged(bud, store, t, "build_exploit", status, stop,
                                      {"strategy": "heap"})
            # (The crashless leak-centric build_exploit(strategy="auto") now runs EARLY, before
            # fuzz/concolic, so a time-boxed pass reaches it; see above. It is not repeated here.)
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
            # Link a matched CVE to a demonstrated crash of a matching class (soft corroboration),
            # now that crashes/PoCs for this target exist.
            if not stop.is_set():
                _staged(bud, store, t, "cve_corroborate", status, stop, want=30.0)
            # Explain a static-only outcome: a memory-corruption defect was found but no runtime
            # fault was reproduced -- say WHY (the binary carries no sanitizer), rather than
            # leaving a bare "static" that reads like "nothing to see".
            if not crashes and not stop.is_set():
                _note_static_memcorruption(store, t)
            _finalize_plan(status)          # any step never reached is marked skipped
            # Record what this run DID, not only what it found. See _scorecard.
            try:
                status["scorecard"] = _scorecard(store, t, bud, status)
            except Exception:                            # noqa: BLE001 -- never fail a run on this
                _log.debug("scorecard failed for %s", tid, exc_info=True)
        # Case-level cross-binary analysis for a multi-binary case (a carved firmware's extracted
        # components are exactly such a set).
        if len(worklist) > 1 and not stop.is_set():
            for stage in ("link_case", "ipc_model", "cross_taint", "whole_system"):
                _run_case_stage(store, case_id, stage, status, stop)
            # Two builds of the same program in one case: re-run the proven exploit against the
            # other one and say whether it still reproduces.
            _run_poc_diff(store, worklist, status, stop)
        # Outcome.
        pd = PocDAO(store.conn)
        verified = any(p.verified for tid in worklist for p in pd.list_by_target(tid))
        crashed = any(d.crashed for tid in worklist for d in DynResultDAO(store.conn).list_by_target(tid))
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
