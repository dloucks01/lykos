"""Regression guard: a stage added to STAGES must also be SCHEDULED by the autopilot.

Adding coverage_sweep to stages.STAGES was not enough — the autopilot enqueues target stages by
explicit _staged(...) calls, so a registered stage with no such call silently never runs (the same
bug class that once dropped patch_diff from the schedule). This pins that the key source-analysis
stages, coverage_sweep included, appear in orchestrate's _staged sequence."""
import re
from pathlib import Path


def _staged_sequence() -> list:
    src = Path(__file__).resolve().parents[1] / "lykos" / "analyze" / "orchestrate.py"
    text = src.read_text()
    return re.findall(r'_staged\([^,]+,[^,]+,[^,]+,\s*"(\w+)"', text)


def test_coverage_sweep_is_scheduled():
    seq = _staged_sequence()
    assert "coverage_sweep" in seq, "coverage_sweep is registered but the autopilot never enqueues it"


def test_coverage_sweep_runs_after_grounding():
    seq = _staged_sequence()
    assert seq.index("coverage_sweep") > seq.index("grounding"), \
        "coverage_sweep must run after grounding (it reads the grounded source tree)"


def test_core_source_stages_all_scheduled():
    seq = set(_staged_sequence())
    for stage in ("detect_cwe", "wire_flow", "param_sink", "lifecycle_scan", "intwidth_scan", "dop_scan", "race_scan", "grounding", "coverage_sweep", "confirm", "drivable_confirm", "weaponize_plan", "triage", "attack_path"):
        assert stage in seq, f"{stage} fell out of the autopilot schedule"


def test_triage_runs_after_confirm():
    seq = _staged_sequence()
    assert seq.index("triage") > seq.index("confirm"), \
        "triage must run after confirm/weaponize so poc-backed states are final"


def test_weaponize_plan_is_always_run():
    """weaponize_plan is a cheap offline finalizer that composes already-confirmed primitives into
    TTP chains; like coverage_sweep/triage it must be budget-exempt so a late target never silently
    drops its weaponization analysis. (Regression: a fresh FreeRDP run starved it on late targets.)"""
    from lykos.analyze import orchestrate
    assert "weaponize_plan" in orchestrate._ALWAYS_RUN, "weaponize_plan is budget-exempt"


def test_attack_path_is_always_run():
    """attack_path composes the findings into a full path; a cheap offline finalizer like
    weaponize_plan/triage, it must be budget-exempt so late targets keep their path."""
    from lykos.analyze import orchestrate
    assert "attack_path" in orchestrate._ALWAYS_RUN
