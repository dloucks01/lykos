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
    # The prefix is what the stage EMITS, not its name: directed fuzz runs the shared campaign under
    # `directed.*` and the boundary harness under `harness.*`. Keyed by stage name here, these two
    # never matched an event, so both always read "ran" off the plan state with 0 execs.
    "directed_fuzz": ("directed", "sink-directed fuzz"),
    "net_fuzz": ("net_fuzz", "network/socket fuzz"),
    "boundary_fuzz": ("harness", "IPC/boundary fuzz"),
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
NO_GAIN = "no_gain"       # ran fine, but reached nothing its seeds had not already reached, no crash
STALLED = "stalled"       # its executions stopped completing (every one timed out, nothing new) and it
                          # ended itself early -- a wedged target, not a finished campaign
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
    # The per-attempt log's summary (fuzz/attempts.py): every execution's outcome, the verdict they
    # add up to, and whether the campaign reached anything beyond its seeds.
    att = evs.get("attempts") or done.get("attempts") or {}
    if att.get("engine") not in (None, stage):
        att = {}                                         # a different engine sharing this prefix
    execs = (_int(done.get("execs")) or _int(done.get("execs_done"))
             or _int(harvest.get("execs_done")) or _int(progress.get("execs")) or 0)
    # coverage, when the engine instruments: "<hit>/<known>" blocks or AFL edges.
    hit = _int(progress.get("blocks_hit"))
    known = _int(progress.get("blocks_known"))
    edges = _int(harvest.get("edges_found"))
    coverage = (f"{hit}/{known} blocks" if hit is not None and known
                else f"{edges} edges" if edges else None)

    if not execs and att.get("attempts"):
        execs = int(att["attempts"])
    # Did the campaign END ITSELF before its budget (fuzz/stage.py's plateau / stall monitors)?
    # The terminal `.done` is authoritative -- a multi-channel stage emits one per channel and the
    # last one says how the engine finished; the bare event is the fallback while it is running.
    if done:
        stopped = done.get("stopped")
    else:
        stopped = ("stalled" if "stalled" in evs else "converged" if "converged" in evs else None)
    stop_ev = evs.get(stopped) if stopped else None
    stop_note = (done.get("stop_reason") or (stop_ev or {}).get("note")) if stopped else None
    returned = done.get("budget_returned_s")
    if returned is None and stop_ev:
        returned = stop_ev.get("budget_returned_s")

    def mk(status, reason):
        e = {"engine": stage, "status": status, "reason": reason,
             "execs": execs, "coverage": coverage}
        if stopped:
            e["stopped"] = stopped
            e["budget_returned_s"] = returned
        if att:
            e["outcomes"] = att.get("counts")
            e["attempt_verdict"] = att.get("verdict")
            e["value"] = att.get("value")
            e["log"] = att.get("log")
            if att.get("afl_execs"):
                e["afl_execs"] = att.get("afl_execs")
        return e

    # Plan-level outcomes that mean the engine never got to run its own logic.
    if state == "error":
        return mk(ERROR, detail or "the stage raised an error")
    # A plan state of skipped/cancelled is the PLAN's view; if the engine actually ran (it emitted a
    # terminal event or an attempt log -- a repeat pass, a directed re-run) its own record wins.
    # Measured: directed_fuzz ran three times, 2,000 attempts, and read "skipped / no budget".
    if state in ("skipped", "cancelled") and not (done or att):
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
    if done.get("supported") is False or done.get("applicable") is False:
        return mk(DECLINED, done.get("note") or done.get("reason") or detail
                  or "not applicable to this target")
    #  * the attempt log says it was an error loop: (almost) no attempt reached the program.
    if att.get("verdict") == "erroring":
        return mk(FAILED, att.get("verdict_note") or "no attempt reached the program")
    found = (_int(done.get("crashes")) or _int(done.get("unique")) or _int(done.get("confirmed"))
             or (1 if done.get("crashed") else 0)
             # a re-verified hang (CWE-835) is a finding too, not "found nothing"
             or (1 if done.get("hang_input") else 0) or 0)
    #  * it ended itself because its executions stopped completing. With a find before the stall
    #    the campaign did its job and then hit a wall; without one it is a wedged target, which is
    #    neither a clean pass nor a broken engine -- say which, with the evidence.
    if stopped == "stalled":
        why = stop_note or "every execution timed out with nothing new reached"
        if found:
            return mk(OK, f"found {found} crash(es)/hang(s) before it stalled: {why}")
        return mk(STALLED, why)
    if "noprogress" in evs:
        return mk(NOPROGRESS, (evs["noprogress"].get("note")
                               or "ran but reached almost no code -- likely needs a config/"
                                  "arguments/working directory (see auto-invocation)"))
    if "starved" in evs or done.get("starved"):
        reason = (evs.get("starved", {}).get("note")
                  or "executed almost nothing -- seeds rejected or per-exec timeout")
        return mk(STARVED, reason)
    if execs > 0:
        # Ran -- but did it EARN its time? A campaign that reached nothing its seeds had not
        # already reached and found no crash executed the target without testing anything new.
        val = att.get("value") or {}
        # A CONVERGED campaign is a finished one: it stopped because coverage plateaued, and
        # handed the rest of its ceiling back. Said in the reason either way, so "ran 40 minutes
        # of a 6-hour ceiling" reads as the plateau it was, not as a cut-short run.
        conv = (f"converged: {stop_note}" if stopped == "converged" and stop_note
                else "converged (coverage plateaued)" if stopped == "converged" else None)
        if val.get("unit") in ("blocks", "behaviours", "edges") and val.get("gained") == 0 \
                and not found:
            return mk(NO_GAIN, (f"ran {execs:,} attempts but reached nothing beyond what its "
                                f"seeds reached ({val.get('seed_coverage', 0)} {val['unit']}) and "
                                f"found no crash -- the mutations added no coverage"
                                + (f"; {conv}" if conv else "")))
        if att.get("verdict") == "crashing_all":
            return mk(OK, att.get("verdict_note"))
        return mk(OK, conv)
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
             "verdict": "ok"|"idle"|"degraded"|"none", "note": <one line>}.
    `idle`: engines executed the target but none reached anything beyond its seeds or crashed.
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

    # "Executed the target" needs executions: a solver that finished with zero (concolic on a
    # binary nothing could run) is OK as a stage but is not evidence the target ran.
    ran_ok = [e for e in engines if e["status"] == OK and (e.get("execs") or 0) > 0]
    no_gain = [e for e in engines if e["status"] == NO_GAIN]
    failed = [e for e in engines if e["status"] in (FAILED, ERROR)]
    reachable = [e for e in engines
                 if e["status"] in (OK, NO_GAIN, NOPROGRESS, STARVED, STALLED, FAILED, ERROR)]
    if not ran_ok and no_gain:
        verdict = "idle"
        note = (f"{len(no_gain)} engine(s) executed the target but none reached any code beyond "
                f"what their seeds reached, and none found a crash -- the fuzzing ran but did not "
                f"test anything new. Open an engine's attempt log to see how its inputs ended.")
        if failed:
            note += f" {len(failed)} engine(s) failed to run ({failed[0]['reason']})."
    elif ran_ok:
        verdict = "ok"
        note = f"{len(ran_ok)} engine(s) executed the target"
        if no_gain:
            note += f"; {len(no_gain)} ran without gaining anything"
        if failed:
            note += f"; {len(failed)} failed to run ({failed[0]['reason']})"
    elif not reachable:
        verdict = "none"
        note = ("No dynamic engine ran -- every fuzzer declined or was skipped -- so this run's "
                "dynamic coverage is zero and NOTHING could escalate past L0. Every verified rung "
                "(L1 crash, L2 primitive, L3 exploit) requires executing the target; a static-only "
                "result here is a tooling/setup outcome, not a clean 'no bugs' binary.")
    else:
        verdict = "none" if failed else "degraded"
        lead = (failed or reachable)[0]
        note = (f"No dynamic engine could execute the target, so nothing escalated past L0 "
                f"(static findings only). {lead['engine']}: {lead['reason']}")
    return {"engines": engines, "verdict": verdict, "note": note}
