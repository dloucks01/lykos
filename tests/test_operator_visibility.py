"""What the OPERATOR sees, measured against what the gate asserts.

`tools/real_corpus_gate.py` checks ten things about a run. The operator running `lykos analyze`
was shown six of them. The four missing ones were not cosmetic:

  * **the verified PoC level** -- the thing the tool exists to produce. A run that reached L2 and
    a run that reached nothing printed the same scorecard, and the ladder appeared nowhere.
  * **where the bundle is.** A verified PoC is a self-contained tarball with the target, the
    input and a runner; the run never said it existed, so anyone who wanted it had to know that
    artifacts live in the case directory and which `kind` means "bundle".
  * **how many crashes were recorded.** A crash with no verified reproducer is the single outcome
    that most needs saying out loud, and it was visible only by reading the finding list.
  * **how long the search engines held.** "budget 134s of 180s" does not answer it, and a null
    result is worth exactly what the search behind it was worth: libtiff at a 200s budget showed
    six capabilities working and no crashes -- indistinguishable from a clean library -- while the
    same tarball with a real search slice found a heap overflow in six executions.

And one distinction the gate drew that the operator could not: these two printed identically.

    libfuzzer  no source for this target (libFuzzer needs C/C++ source to build a harness)
    libfuzzer  libFuzzer build failed: 'tiffio.h' file not found

The first is a fact about the target. The second is our defect, and it means the run is
INCOMPLETE for a reason that can be fixed.
"""
import pathlib

import lykos.analyze as analyze_pkg
import lykos.cli as C
from lykos.analyze.capabilities import classify_decline
from lykos.analyze.orchestrate import _CASE, _PLAN_STAGES, _TARGET


def _cli_src():
    return pathlib.Path(C.__file__).read_text()


def test_whose_fault_a_decline_is_has_one_definition():
    """It lived only in the gate, so the operator never saw the distinction the gate was built
    around. Both now read the same table."""
    gate = pathlib.Path(analyze_pkg.__path__[0]).parents[2] / "tools" / "real_corpus_gate.py"
    src = gate.read_text()
    assert "from lykos.analyze.capabilities import classify_decline" in src, \
        "the gate keeps its own copy of the classifier again"
    assert "_OUR_FAULT = (" not in src, "the gate restates the OURS list"
    assert "from .analyze.capabilities import classify_decline" in _cli_src(), \
        "the operator's output does not classify declines at all"


def test_the_classifier_separates_our_defects_from_the_targets_nature():
    assert classify_decline("no source for this target (libFuzzer needs C/C++ source)") == "target"
    assert classify_decline("libFuzzer build failed: 'tiffio.h' file not found") == "ours"
    assert classify_decline("undefined reference to `LLVMFuzzerTestOneInput'") == "ours"
    assert classify_decline("memcheck cannot run a non-host-architecture target") == "target"
    # Unclassified stays VISIBLE rather than being lumped in with the target's nature.
    assert classify_decline("the exploit did not confirm") == "unknown"


def test_the_operator_is_told_the_run_is_incomplete_when_a_defect_is_ours():
    src = _cli_src()
    assert "INCOMPLETE" in src, "a decline caused by our own defect prints like any other"
    assert "unclassified" in src


def test_the_ladder_and_the_crash_count_reach_the_operator():
    src = _cli_src()
    for needle in ("L1 (verified crash reproducer)", "L2 (confirmed exploitation primitive)",
                   "L3 (working exploit)", "crashes      "):
        assert needle in src, f"the operator's scorecard never prints {needle!r}"
    # the one outcome that most needs saying out loud
    assert "a crash was recorded but NOTHING was verified" in src


def test_the_search_time_reaches_the_operator():
    src = _cli_src()
    assert "search_seconds" in src and "in the engines" in src
    assert "little of this run was spent searching" in src, \
        "a run that barely searched reads like a run that found nothing"


def test_a_verified_poc_is_written_out_with_the_command_that_runs_it():
    src = _cli_src()
    assert "def _export_pocs(" in src
    assert "runner.sh" in src, "the operator is not told how to run the bundle"
    assert "SANDBOX" in src, "a PoC executes an untrusted binary and must say so"
    assert '"--out"' in src, "there is no way to choose where bundles land"


def test_every_scheduled_stage_appears_in_the_plan_the_operator_watches():
    """A stage absent from the plan is invisible progress. Nine were missing, `fuzz` among them --
    on /usr/bin/xxd it performed 4,513 of the run's 7,272 executions and never appeared, so the
    live view sat on another stage's name while the main campaign ran."""
    planned = {s for s, _ in _PLAN_STAGES}
    missing = sorted((set(_TARGET) | set(_CASE)) - planned)
    assert not missing, f"scheduled but never shown to the operator: {missing}"


def test_the_live_view_shows_what_each_stage_did_not_just_its_name():
    src = _cli_src()
    assert "def _tick_plan(" in src
    assert '"declined"' in src and '"error"' in src, \
        "the live view cannot distinguish a stage that refused from one that worked"
    # it reads the plan the autopilot writes, rather than only the current stage name
    assert 'status.get("plan")' in src


def test_a_decline_is_recorded_in_the_plan_as_it_happens():
    """It reached the operator only in the end-of-run table, because the live plan recorded a
    decline as `done` -- so while watching a run, "libfuzzer worked" and "libfuzzer cannot apply
    to a binary-only target" were the same line."""
    src = pathlib.Path(analyze_pkg.__path__[0], "orchestrate.py").read_text()
    assert "def _stage_decline(" in src
    assert '_plan_set(status, stage, "declined" if _why else "done", d)' in src
    from lykos.analyze.orchestrate import _PLAN_RANK
    assert _PLAN_RANK["declined"] == _PLAN_RANK["done"], \
        "a decline must rank as terminal, or a later running stage regresses it"
