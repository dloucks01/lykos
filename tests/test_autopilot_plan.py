"""The Autopilot pipeline PLAN: the ordered steps a target goes through, tracked so the UI can
show what is done, running, and still to come -- not just a live log."""
from lykos.analyze import orchestrate as o


class _T:
    id = "t" * 32
    filename = "sample.bin"
    case_id = "c" * 32


def test_the_plan_starts_all_pending_and_names_the_target():
    st = {}
    o._init_plan(st, _T(), 1, 3)
    assert st["target"] == 1 and st["targets"] == 3 and st["target_name"] == "sample.bin"
    assert [p["stage"] for p in st["plan"]] == [s for s, _ in o._PLAN_STAGES]
    assert all(p["state"] == "pending" for p in st["plan"])


def _state(st, stage):
    return next(p["state"] for p in st["plan"] if p["stage"] == stage)


def test_a_stage_moves_pending_to_running_to_done():
    st = {}
    o._init_plan(st, _T(), 1, 1)
    o._plan_set(st, "disassemble", "running")
    assert _state(st, "disassemble") == "running"
    o._plan_set(st, "disassemble", "done", "42 functions")
    assert _state(st, "disassemble") == "done"
    assert next(p["detail"] for p in st["plan"] if p["stage"] == "disassemble") == "42 functions"


def test_a_finished_phase_does_not_regress_to_running_on_a_repeat():
    """root_cause/build_poc run once per crash; a second crash must not flip a done phase back."""
    st = {}
    o._init_plan(st, _T(), 1, 1)
    o._plan_set(st, "build_poc", "done")
    o._plan_set(st, "build_poc", "running")          # the next crash's iteration
    assert _state(st, "build_poc") == "done", "a completed phase regressed to running"


def test_finalize_marks_unreached_conditional_steps_skipped():
    st = {}
    o._init_plan(st, _T(), 1, 1)
    o._plan_set(st, "disassemble", "done")
    o._plan_set(st, "coverage_fuzz", "done")
    o._finalize_plan(st)
    # the exploit ladder / concolic were never reached -> skipped, not left pending
    assert _state(st, "concolic") == "skipped"
    assert _state(st, "build_exploit") == "skipped"
    assert _state(st, "disassemble") == "done"       # a real state is untouched


def test_an_error_state_is_preserved_and_not_downgraded():
    st = {}
    o._init_plan(st, _T(), 1, 1)
    o._plan_set(st, "concolic", "error", "backend missing")
    o._plan_set(st, "concolic", "running")           # a later touch must not hide the error
    assert _state(st, "concolic") == "error"
    o._finalize_plan(st)
    assert _state(st, "concolic") == "error"
