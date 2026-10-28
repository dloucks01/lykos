"""The stage registry is the single source of truth (doc 49, Theme 1a).

`stages.STAGES` declares each pipeline stage once; `orchestrate` derives `_TARGET`, `_CASE`,
`_ON_DEMAND`, `_NO_PARAMS`, `_CASE_NO_PARAMS`, and `_PLAN_STAGES` from it. These tests pin that the
derivation is faithful and that the registry cannot silently drift from the actual job dispatch --
the `patch_diff` regression (583f1fe) was a stage present in some of those lists and not others, and
a registry with one declaration point makes that un-expressible.
"""
import importlib
import pkgutil

import lykos.analyze as _analyze_pkg
from lykos.analyze import orchestrate as O
from lykos.analyze import stages


def _import_all_analyze():
    for m in pkgutil.walk_packages(_analyze_pkg.__path__, "lykos.analyze."):
        try:
            importlib.import_module(m.name)
        except Exception:                 # noqa: BLE001 -- optional dep, not our concern
            continue


def test_registry_is_internally_consistent():
    stages.check_consistency()            # raises on any inconsistent descriptor


def test_stage_names_are_unique():
    names = [s.name for s in stages.STAGES]
    assert len(names) == len(set(names)), "duplicate stage name in stages.STAGES"


def test_declared_dispatchable_set_equals_the_job_registry():
    """Every registered (dispatchable) stage has exactly one descriptor, and vice versa. This is
    the anti-drift pin: `register_stage` without a descriptor here -- or a descriptor for a stage
    nothing registers -- fails loudly, so 'add a stage' is a single append to stages.STAGES."""
    _import_all_analyze()
    from lykos.jobs import registry
    registered = set(registry._STAGES)
    declared = {s.name for s in stages.STAGES if s.scope in ("target", "case")}
    assert registered == declared, (
        "stage registry drifted from the job dispatch: "
        f"registered-only={sorted(registered - declared)}, "
        f"declared-only={sorted(declared - registered)}")


def test_only_plan_scope_has_no_enqueue():
    for s in stages.STAGES:
        if s.scope == "plan":
            assert s.module is None and s.enqueue is None
        else:
            assert s.module and s.enqueue, f"{s.name} should have an enqueue"
    planonly = [s.name for s in stages.STAGES if s.scope == "plan"]
    assert planonly == ["verify"], planonly


def test_on_demand_stages_are_dispatchable_but_out_of_plan():
    for s in stages.STAGES:
        if s.on_demand:
            assert not s.in_plan, f"{s.name}: on-demand must not be in the plan"
            assert s.scope in ("target", "case"), f"{s.name}: on-demand must be dispatchable"
        if s.in_plan:
            assert s.label, f"{s.name}: a planned stage needs a label"


# ---- the derivations in orchestrate must equal what the registry implies --------------------

def test_target_and_case_derivations_match_the_registry():
    assert O._TARGET == {s.name: (s.module, s.enqueue)
                         for s in stages.STAGES if s.scope == "target"}
    assert O._CASE == {s.name: (s.module, s.enqueue)
                       for s in stages.STAGES if s.scope == "case"}


def test_on_demand_derivation_matches_the_registry():
    assert O._ON_DEMAND == {s.name: s.on_demand for s in stages.STAGES if s.on_demand}
    # every on-demand stage is dispatchable (in _TARGET or _CASE) and absent from the plan
    planned = {name for name, _ in O._PLAN_STAGES}
    for name in O._ON_DEMAND:
        assert name in O._TARGET or name in O._CASE
        assert name not in planned


def test_no_params_derivations_match_the_registry():
    assert set(O._NO_PARAMS) == {s.name for s in stages.STAGES
                                 if s.no_params and s.scope == "target"}
    assert set(O._CASE_NO_PARAMS) == {s.name for s in stages.STAGES
                                      if s.no_params and s.scope == "case"}


def test_plan_is_the_in_plan_descriptors_in_declaration_order():
    assert O._PLAN_STAGES == [(s.name, s.label) for s in stages.STAGES if s.in_plan]
    assert O._PLAN_LABEL == dict(O._PLAN_STAGES)


def test_the_formerly_unreachable_stages_survive_the_registry():
    """A refactor must not drop the seven stages that were once registered-but-never-scheduled."""
    for stage in ("boundary_fuzz", "debug_monitor", "extract_secrets", "libfuzzer",
                  "multi_debug", "poc_diff", "synthesize_secret"):
        assert stage in O._TARGET, stage
        assert stage in {name for name, _ in O._PLAN_STAGES}, stage
