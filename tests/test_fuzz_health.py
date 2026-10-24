"""R1 fuzzing-engine health summarizer (doc 47): turn the scattered per-stage failure signals into
one honest per-engine verdict, so a static-only run always says WHY the dynamic engines contributed
nothing. Pure function -> unit-testable without running a campaign."""
from __future__ import annotations

from lykos.analyze.fuzz import health


def _verdict(plan, events):
    r = health.summarize(plan, events)
    return r["verdict"], {e["engine"]: e["status"] for e in r["engines"]}, r


def test_afl_handshake_failure_is_failed_not_clean():
    # coverage_fuzz ran but afl aborted at the fork-server handshake (missing .so) -> FAILED.
    plan = [{"stage": "coverage_fuzz", "state": "done", "detail": ""},
            {"stage": "fuzz", "state": "done", "detail": ""}]
    events = [
        {"type": "coverage.done", "payload": {"supported": False, "aborted": True,
         "note": "the target could not start: missing shared library 'libfoo.so.1'"}},
        {"type": "fuzz.done", "payload": {"execs": 20000, "crashes": 0}},
    ]
    verdict, statuses, r = _verdict(plan, events)
    assert statuses["coverage_fuzz"] == health.FAILED
    assert "libfoo.so.1" in [e for e in r["engines"] if e["engine"] == "coverage_fuzz"][0]["reason"]
    assert statuses["fuzz"] == health.OK
    assert verdict == "ok"                         # blind fuzz still executed -> overall ok
    assert "failed to run" in r["note"]


def test_nothing_ran_is_verdict_none():
    # Every engine failed/declined -> the alert: dynamic coverage is zero, not a clean binary.
    plan = [{"stage": "coverage_fuzz", "state": "done", "detail": ""},
            {"stage": "fuzz", "state": "done", "detail": ""},
            {"stage": "net_fuzz", "state": "declined", "detail": "not a server"}]
    events = [
        {"type": "coverage.done", "payload": {"aborted": True, "note": "Fork server handshake failed"}},
        {"type": "fuzz.done", "payload": {"execs": 0, "crashes": 0, "did_not_run": True,
         "reason": "sandbox could not execute the target"}},
    ]
    verdict, statuses, r = _verdict(plan, events)
    assert statuses["coverage_fuzz"] == health.FAILED
    assert statuses["fuzz"] == health.FAILED
    assert statuses["net_fuzz"] == health.DECLINED
    assert verdict == "none"
    # The note must tie the zero-dynamic-coverage result to the thing the operator sees -- that
    # nothing could escalate past L0 -- not just report a failed engine.
    assert "past L0" in r["note"]


def test_noprogress_flags_invocation_need():
    plan = [{"stage": "directed_fuzz", "state": "done", "detail": ""}]
    events = [{"type": "directed.noprogress",
               "payload": {"execs": 40000, "edges_found": 3,
                           "note": "ran many executions but reached almost no new code -- most "
                                   "likely needs a config/data file or arguments"}}]
    verdict, statuses, r = _verdict(plan, events)
    assert statuses["directed_fuzz"] == health.NOPROGRESS
    assert verdict == "degraded"
    assert "config" in [e for e in r["engines"]][0]["reason"]


def test_ok_run_reports_execs_and_coverage():
    plan = [{"stage": "coverage_fuzz", "state": "done", "detail": ""}]
    events = [
        {"type": "coverage.progress", "payload": {"execs": 51000, "blocks_hit": 310,
                                                  "blocks_known": 540}},
        {"type": "coverage.harvest", "payload": {"execs_done": "51234", "edges_found": "812"}},
    ]
    verdict, statuses, r = _verdict(plan, events)
    assert statuses["coverage_fuzz"] == health.OK and verdict == "ok"
    eng = r["engines"][0]
    assert eng["execs"] >= 51000 and eng["coverage"] == "310/540 blocks"


def test_declined_and_skipped_are_not_failures():
    plan = [{"stage": "net_fuzz", "state": "declined", "detail": "no bind/listen imports"},
            {"stage": "concolic", "state": "skipped", "detail": "no budget left in the search phase"},
            {"stage": "fuzz", "state": "done", "detail": ""}]
    events = [{"type": "fuzz.done", "payload": {"execs": 12000, "crashes": 1}}]
    verdict, statuses, _ = _verdict(plan, events)
    assert statuses["net_fuzz"] == health.DECLINED
    assert statuses["concolic"] == health.SKIPPED
    assert statuses["fuzz"] == health.OK and verdict == "ok"


def test_engine_not_in_plan_is_omitted():
    r = health.summarize([{"stage": "fuzz", "state": "done"}],
                         [{"type": "fuzz.done", "payload": {"execs": 5000}}])
    assert [e["engine"] for e in r["engines"]] == ["fuzz"]
