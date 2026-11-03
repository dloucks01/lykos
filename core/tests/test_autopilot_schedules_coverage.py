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
    for stage in ("detect_cwe", "codeql", "grounding", "coverage_sweep", "confirm", "drivable_confirm", "triage"):
        assert stage in seq, f"{stage} fell out of the autopilot schedule"


def test_triage_runs_after_confirm():
    seq = _staged_sequence()
    assert seq.index("triage") > seq.index("confirm"), \
        "triage must run after confirm/weaponize so poc-backed states are final"
