"""Every registered stage is either scheduled by the autopilot or deliberately exempt.

Seven stages were registered, wired into the web UI, covered by tests -- and named nowhere in
`orchestrate`. Nothing chained to them either, so for an unattended run the capability simply
did not exist. `multi_debug` was the worst of them: it is the only follow-fork/exec capture in
the engine, so a crash in a forked child or an `execve()`d helper was never attributed to the
input that caused it, which is a MISSED CRASH and not merely a missing convenience.
`synthesize_secret` was the other costly one: the only demonstrated-effect class that needs no
crash at all, deterministic and offline, which the autopilot could never produce.

This test exists so that adding a stage and forgetting to schedule it fails here rather than
being discovered by auditing the registry a year later.
"""
import importlib
import pathlib
import pkgutil

import lykos.analyze as analyze_pkg
from lykos.analyze.orchestrate import _CASE, _PLAN_STAGES, _TARGET

#: Stages that are deliberately NOT part of an autopilot run, each with the reason.
_EXEMPT = {
    # Run by the ingest path itself, before any autopilot exists for the case.
    "ingest_triage",
    # A one-shot "run it once and see it work" convenience for the operator. Every autopilot
    # stage that needs an execution does its own, so scheduling this would only duplicate them.
    "dynamic_run",
}


def _registered():
    for m in pkgutil.walk_packages(analyze_pkg.__path__, "lykos.analyze."):
        try:
            importlib.import_module(m.name)
        except Exception:                 # noqa: BLE001 -- an optional dep, not our concern
            continue
    from lykos.jobs import registry
    return set(registry._STAGES)


def test_every_registered_stage_is_scheduled_or_exempt():
    unscheduled = _registered() - set(_TARGET) - set(_CASE) - _EXEMPT
    assert not unscheduled, (
        "registered but the autopilot never runs them: %s. Either schedule the stage in "
        "orchestrate or add it to _EXEMPT with the reason." % sorted(unscheduled))


def test_the_seven_formerly_unreachable_stages_are_scheduled():
    """Named explicitly so a refactor cannot quietly drop one back out."""
    for stage in ("boundary_fuzz", "debug_monitor", "extract_secrets", "libfuzzer",
                  "multi_debug", "poc_diff", "synthesize_secret"):
        assert stage in _TARGET, stage


def test_a_scheduled_stage_is_actually_called_in_the_pass():
    """Being in the enqueue map is not enough -- it has to be reached in the run body."""
    src = pathlib.Path(analyze_pkg.__path__[0], "orchestrate.py").read_text()
    body = src.split("def run_case_autopilot", 1)[1]
    for stage in ("boundary_fuzz", "debug_monitor", "extract_secrets", "libfuzzer",
                  "multi_debug", "synthesize_secret"):
        assert f'"{stage}"' in body, f"{stage} is in _TARGET but never run"
    # poc_diff is reached through its own helper, which needs a baseline/candidate PAIR.
    assert "_run_poc_diff" in body


def test_the_operator_sees_every_scheduled_stage_in_the_plan():
    """A stage that runs but is absent from the plan is invisible progress: the UI shows the
    run sitting on the previous step while something else is actually executing."""
    planned = {s for s, _ in _PLAN_STAGES}
    for stage in ("extract_secrets", "synthesize_secret", "boundary_fuzz", "libfuzzer",
                  "multi_debug", "debug_monitor", "poc_diff"):
        assert stage in planned, stage


def test_the_params_free_stages_really_take_no_required_params():
    """`_NO_PARAMS` drops params on the floor, so a stage listed there that REQUIRES one fails
    at runtime with "requires params.input_sha" -- which is how root_cause/build_poc were
    deliberately kept out of it."""
    from lykos.analyze.orchestrate import _NO_PARAMS
    # multi_debug needs the crashing input, so it must NOT be listed.
    assert "multi_debug" not in _NO_PARAMS
    for stage in ("extract_secrets", "synthesize_secret", "boundary_fuzz"):
        assert stage in _NO_PARAMS, stage
    # A stage that reads `max_seconds` must NOT be listed, even though it requires no params:
    # the list drops ALL params, so the budget's slice never arrives and the stage runs its own
    # default instead. `libfuzzer` was listed and ran its 30 s default on a 900 s case -- the
    # "30-second smoke test" defect, in the engine that is the most productive one there is on a
    # library. "Requires no params" and "wants no params" are different questions.
    for stage in ("libfuzzer", "fuzz", "coverage_fuzz", "concolic"):
        assert stage not in _NO_PARAMS, stage
