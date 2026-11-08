"""F6 (doc 60): gap self-audit — no capability may sit in STAGES unwired from the autopilot.

The coverage_sweep bug (registered but never scheduled, so it silently never ran) is a whole class.
This test fails if ANY in-plan, per-target stage is neither scheduled via the autopilot's _staged
sequence nor in the explicit allowlist of stages enqueued through an alternate path. Adding a new
stage therefore forces a conscious decision: wire it, or allowlist it with a reason.
"""
import re
from pathlib import Path

from lykos.analyze import stages

# in-plan target stages enqueued through a path other than a literal _staged(bud,store,t,"name"):
# the dynamic-flow batch (heap_check/heap_trace/oob_index driven inside the crash/dynamic block) and
# the case-level poc_diff (_run_poc_diff). Each is genuinely wired, just not via the plain pattern.
_ALTERNATE_PATH = {"heap_check", "heap_trace", "oob_index", "poc_diff"}


def _staged_sequence() -> set:
    src = (Path(__file__).resolve().parents[1] / "lykos" / "analyze" / "orchestrate.py").read_text()
    return set(re.findall(r'_staged\([^,]+,[^,]+,[^,]+,\s*"(\w+)"', src))


def test_every_inplan_target_stage_is_wired():
    staged = _staged_sequence()
    inplan_target = [s.name for s in stages.STAGES
                     if s.in_plan and s.scope == "target" and not s.on_demand]
    unwired = [n for n in inplan_target if n not in staged and n not in _ALTERNATE_PATH]
    assert not unwired, (
        f"stages registered in STAGES but never scheduled by the autopilot (wire them in "
        f"orchestrate, or allowlist with a reason): {unwired}")


def test_alternate_path_stages_still_exist():
    # keep the allowlist honest: every allowlisted name must still be a real registered stage.
    names = {s.name for s in stages.STAGES}
    assert _ALTERNATE_PATH <= names, f"stale allowlist entries: {_ALTERNATE_PATH - names}"


def test_offline_finalizers_always_run():
    """coverage_sweep + triage must be budget-exempt finalizers (skipping them discards the run's
    accounting). Guards the _ALWAYS_RUN set."""
    from lykos.analyze import orchestrate
    assert {"coverage_sweep", "triage"} <= orchestrate._ALWAYS_RUN
