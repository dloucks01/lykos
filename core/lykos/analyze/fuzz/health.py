"""Fuzzing-engine health: one honest per-engine verdict, so a run that produced static-only
findings always says WHY each dynamic engine contributed nothing.

The per-stage signals already exist and are rich -- `coverage.done{aborted,note}`,
`coverage.starved`, `coverage.noprogress`, `<prefix>.done{starved,coverage,did_not_run}`,
`<prefix>.noprogress` -- but they are scattered across events and the operator had no single place
that said "afl could not instrument this target (handshake failed: missing libfoo.so.1)" versus "the
target has no bug". On the air-gapped laptop the fuzzing "just didn't work" and the run looked like a
clean empty result; this is the layer that makes the failure visible.

`summarize` is a PURE function of the plan + the emitted events (no I/O), so it is unit-testable and
the orchestrator can emit its result as a `fuzz.health` event for the web GUI to render.
"""
from __future__ import annotations

from typing import Optional

#: Dynamic engines and their event-type prefix (the stage that produces `<prefix>.done` etc.).
#: Keyed by stage name; the coverage-guided stage emits under the bare "coverage" prefix.
ENGINES = {
    "coverage_fuzz": ("coverage", "coverage-guided fuzz (AFL)"),
    "fuzz": ("fuzz", "blind fuzz"),
    "directed_fuzz": ("directed_fuzz", "sink-directed fuzz"),
    "net_fuzz": ("net_fuzz", "network/socket fuzz"),
    "boundary_fuzz": ("boundary_fuzz", "IPC/boundary fuzz"),
    "env_fuzz": ("env_fuzz", "environment fuzz"),
    "libfuzzer": ("libfuzzer", "libFuzzer (source)"),
    "concolic": ("concolic", "concolic solver"),
}

# Status values, worst-first for the overall verdict.
FAILED = "failed"         # the engine tried and could not execute the target (handshake/loader/sandbox)
NOPROGRESS = "noprogress"  # ran, but never reached the parser (needs config/args/CWD -- see R2)
STARVED = "starved"       # executed almost nothing (seeds rejected, or per-exec timeout)
ERROR = "error"           # the stage raised
OK = "ok"                 # really executed the target (execs > 0, coverage where instrumented)
DECLINED = "declined"     # not applicable to this target (e.g. net_fuzz on a non-server) -- not a fault
SKIPPED = "skipped"       # no budget left / not reached
NOT_RUN = "not_run"       # in the plan but no state yet


def _int(v) -> Optional[int]:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None


def _engine_events(prefix: str, events: list) -> dict:
    """The last payload seen for each `<prefix>.<kind>` event type, keyed by <kind>."""
    out: dict = {}
    pfx = prefix + "."
    for ev in events:
        t = ev.get("type") or ""
        if t.startswith(pfx):
            out[t[len(pfx):]] = ev.get("payload") or {}
    return out


def _classify(stage: str, state: Optional[str], detail: str, evs: dict) -> dict:
    """One engine's verdict from its plan state and its events. `state`/`detail` come from the
    autopilot plan; `evs` is {kind: payload} for this engine's `<prefix>.<kind>` events."""
    done = evs.get("done") or {}
    harvest = evs.get("harvest") or {}
    progress = evs.get("progress") or {}
    execs = (_int(done.get("execs")) or _int(done.get("execs_done"))
             or _int(harvest.get("execs_done")) or _int(progress.get("execs")) or 0)
    # coverage, when the engine instruments: "<hit>/<known>" blocks or AFL edges.
    hit = _int(progress.get("blocks_hit"))
    known = _int(progress.get("blocks_known"))
    edges = _int(harvest.get("edges_found"))
    coverage = (f"{hit}/{known} blocks" if hit is not None and known
                else f"{edges} edges" if edges else None)

    def mk(status, reason):
        return {"engine": stage, "status": status, "reason": reason,
                "execs": execs, "coverage": coverage}

    # Plan-level outcomes that mean the engine never got to run its own logic.
    if state == "error":
        return mk(ERROR, detail or "the stage raised an error")
    if state in ("skipped", "cancelled"):
        return mk(SKIPPED, detail or "no budget left / not reached")
    if state == "declined":
        return mk(DECLINED, detail or "not applicable to this target")
    if state in (None, "pending", "running") and not evs:
        return mk(NOT_RUN, None)

    # The engine ran (or at least emitted): read its own signals, worst-first.
    #  * aborted / did_not_run -> it TRIED and could not execute the target (handshake, loader,
    #    sandbox). That is a FAILURE the operator must see.
    if done.get("aborted") or done.get("did_not_run"):
        reason = done.get("note") or done.get("reason") or "could not execute the target"
        return mk(FAILED, reason)
    #  * a bare `supported: false` (no abort) is "not applicable HERE" -- no source for libFuzzer,
    #    not a server for net_fuzz, wrong format -- a decline, not a broken engine. Keeping these
    #    apart is the whole point: "afl could not instrument this target" and "libFuzzer needs
    #    source" are different facts and only the first is a problem to fix.
    if done.get("supported") is False:
        return mk(DECLINED, done.get("note") or done.get("reason") or detail
                  or "not applicable to this target")
    if "noprogress" in evs:
        return mk(NOPROGRESS, (evs["noprogress"].get("note")
                               or "ran but reached almost no code -- likely needs a config/"
                                  "arguments/working directory (see auto-invocation)"))
    if "starved" in evs or done.get("starved"):
        reason = (evs.get("starved", {}).get("note")
                  or "executed almost nothing -- seeds rejected or per-exec timeout")
        return mk(STARVED, reason)
    if execs > 0:
        return mk(OK, None)
    # `done` with no abort/starved/noprogress signal and no recorded execs is AMBIGUOUS, not a
    # failure: a solver (concolic) reports no exec count by nature, and on a short or budget-cut run
    # a fuzzer's terminal `.done` (which carries its execs) may not have settled before this summary
    # was built. FAILED is deliberately reserved for a concrete execution failure (aborted /
    # did_not_run) so it stays a trustworthy "fix this" signal -- a real breakage always emits one
    # of those. So give a clean `done` the benefit of the doubt rather than a false alarm.
    if state == "done":
        return mk(OK, None)
    return mk(NOT_RUN, None)


def summarize(plan: list, events: list) -> dict:
    """A per-engine health report + one overall verdict, from the autopilot `plan`
    (list of {stage,state,detail}) and the emitted `events` (list of {type,payload}).

    Returns {"engines": [ {engine,status,reason,execs,coverage}, ... ],
             "verdict": "ok"|"degraded"|"none", "note": <one line>}.
    `verdict`: `ok` if any engine really executed the target; `none` if NOTHING dynamic ran (the
    alert that a static-only result is a tooling outcome, not a clean binary); `degraded` in between
    (something ran, but an engine that should have worked failed)."""
    by_stage = {p.get("stage"): p for p in (plan or []) if p.get("stage")}
    engines = []
    for stage, (prefix, _label) in ENGINES.items():
        p = by_stage.get(stage)
        evs = _engine_events(prefix, events or [])
        if p is None and not evs:
            continue                                     # engine not in this plan at all
        state = (p or {}).get("state")
        detail = ((p or {}).get("detail") or "").strip()
        engines.append(_classify(stage, state, detail, evs))

    ran_ok = [e for e in engines if e["status"] == OK]
    failed = [e for e in engines if e["status"] in (FAILED, ERROR)]
    reachable = [e for e in engines if e["status"] in (OK, NOPROGRESS, STARVED, FAILED, ERROR)]
    if ran_ok:
        verdict = "ok"
        note = f"{len(ran_ok)} engine(s) executed the target"
        if failed:
            note += f"; {len(failed)} failed to run ({failed[0]['reason']})"
    elif not reachable:
        verdict = "none"
        note = ("no dynamic engine ran here -- every fuzzer declined or was skipped; this run's "
                "dynamic coverage is zero (not a clean 'no bugs' result)")
    else:
        verdict = "none" if failed else "degraded"
        lead = (failed or reachable)[0]
        note = (f"no engine executed the target -- {lead['engine']}: {lead['reason']}. "
                "A static-only result here is a tooling outcome, not a clean binary.")
    return {"engines": engines, "verdict": verdict, "note": note}
