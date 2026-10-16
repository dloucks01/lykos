"""A gate nothing runs is not a gate.

Two separate instances of this, both found by audit rather than by anything failing.

**lint and typecheck.** The Makefile has carried them since the repo's lint config landed, with a
comment calling them "gates, not suggestions" and making a missing tool FAIL rather than skip --
and `.github/workflows/ci.yml` never invoked either. Of `make ci`'s four gates only `test` ran on
a push. E501 drifted from 14 violations to 859 over two months, and four undefined names reached
`main` inside `except` handlers, every one of which `ruff --select F821` reports.

**The conformance harness.** `tools/pipeline_conformance.py` drives ~60 synthetic targets through
the real autopilot and is the only thing that exercises the JOINS between stages. It had no exit
status at all -- it printed a FAIL table and returned 0 -- and no Makefile target, so nothing
could gate on it and it ran by hand. The defect that escaped through that gap made L3 unreachable
on every structured-input target while both stages' own unit tests stayed green.

So these tests check the wiring, not the gates. They are cheap and they are the only thing that
notices a gate quietly becoming decorative again.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text()
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def _make_target(name: str) -> str:
    """The recipe lines of one Makefile target."""
    m = re.search(rf"^{re.escape(name)}:[^\n]*\n((?:\t[^\n]*\n|\n)*)", MAKEFILE, re.M)
    assert m, f"no `{name}` target in the Makefile"
    return m.group(1)


def test_ci_runs_the_lint_gate():
    assert re.search(r"ruff check\s+core", CI), "CI does not run ruff"


def test_the_lint_gate_covers_tools_too():
    """`tools/` holds every gate in the project and was the one directory nothing linted --
    `ruff check core tests` never looked at it. It had 17 violations, including an unused import
    and a file handle left to the GC, in the harness that decides whether a release ships."""
    for where, text in (("the Makefile", MAKEFILE), ("CI", CI)):
        m = re.search(r"ruff check ([a-z /]+)", text)
        assert m, f"{where} does not run ruff"
        scope = m.group(1).split()
        for d in ("core", "tests", "tools"):
            assert d in scope, f"{where} lints {scope}, missing {d}"


def test_ci_runs_the_type_gate():
    assert re.search(r"mypy core/lykos", CI), "CI does not run mypy"


def test_ci_runs_the_gui_harnesses():
    """Under pytest they SKIP when node is absent, and a skip is invisible in a green run --
    which is why they have to run somewhere with node installed, where a miss FAILS."""
    assert "make gui" in CI, "CI does not run the GUI harnesses"
    assert "setup-node" in CI, "...and would skip them anyway with no node installed"


def test_ci_runs_the_conformance_smoke_subset():
    """The joins. The full table is a release gate; this subset is ~5 minutes and runs per push."""
    assert "pipeline_conformance.py --smoke" in CI, \
        "CI does not exercise the stage-to-stage joins"


def test_make_ci_includes_every_static_gate():
    """`make ci` is what a developer runs before pushing, and it has to agree with CI."""
    line = re.search(r"^ci:([^\n]*)", MAKEFILE, re.M)
    assert line, "no `ci` target"
    deps = line.group(1).split()
    for want in ("lint", "typecheck", "gui", "test", "conformance-smoke"):
        assert want in deps, f"`make ci` does not include {want}: {deps}"


def test_make_release_runs_the_full_conformance_table():
    line = re.search(r"^release:([^\n]*)", MAKEFILE, re.M)
    assert line, "no `release` target"
    assert "conformance" in line.group(1).split(), \
        "`make release` does not run the full conformance table"


def test_the_conformance_harness_has_an_exit_status():
    """It printed a FAIL table and exited 0 for its whole life, so no caller could gate on it."""
    src = (ROOT / "tools" / "pipeline_conformance.py").read_text()
    assert "_s.exit(" in src, "the harness cannot fail"
    assert "any(not r.ok for r in _results)" in src, \
        "the exit status must be derived from the case results"
    assert "NO CASES RAN" in src, \
        "zero cases must not be a pass -- a bad filter used to print 0/0 and exit 0"


def test_the_smoke_subset_names_only_real_cases():
    """A renamed case must not silently shrink the subset. The harness checks this at runtime and
    exits 2; this catches it without paying for a run."""
    import importlib.util
    path = ROOT / "tools" / "pipeline_conformance.py"
    spec = importlib.util.spec_from_file_location("conf_gate", path)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules["conf_gate"] = mod
    spec.loader.exec_module(mod)
    known = {c.name for c in mod._CASES}
    missing = [n for n in mod.SMOKE if n not in known]
    assert not missing, f"SMOKE names cases that do not exist: {missing}"
    assert len(mod.SMOKE) >= 5, "the smoke subset is too small to cover the joins"


def test_the_smoke_subset_covers_the_full_ladder_and_a_precision_control():
    """The two things a join test must not omit: a case that has to reach the TOP of the ladder,
    and a case that has to demonstrate nothing at all. Without the first, a broken handoff looks
    like a target that merely was not exploitable; without the second, a detector that fires on
    everything passes."""
    import sys
    mod = sys.modules.get("conf_gate")
    if mod is None:                                       # test ordering independence
        import importlib.util
        path = ROOT / "tools" / "pipeline_conformance.py"
        spec = importlib.util.spec_from_file_location("conf_gate", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["conf_gate"] = mod
        spec.loader.exec_module(mod)
    by_name = {c.name: c for c in mod._CASES}
    smoke = [by_name[n] for n in mod.SMOKE if n in by_name]
    assert any(c.want_level >= 3 for c in smoke), \
        "no smoke case demands L3, so a broken ladder handoff passes"
    assert any(getattr(c, "clean", False) for c in smoke), \
        "no smoke case is a precision control"


def test_a_structured_input_case_demands_l3():
    """The case that would have caught the handoff bug. Every other L3 case feeds the target pure
    filler, so the ladder could reach a shell while being completely unable to inherit what L2
    had learned -- and it was: `_l2_offset` returned None on every real run for months. On a
    target whose sink is behind a `key=value` parse the fallback cannot work at all, so the only
    route to L3 is to inherit L2's offset, channel and framing."""
    import sys
    mod = sys.modules["conf_gate"]
    case = next((c for c in mod._CASES if c.name == "structured_l3_ret2win"), None)
    assert case is not None, "the structured-input L3 case is gone"
    assert case.want_level >= 3, "it must demand a demonstrated L3, not a crash"
    assert "strchr" in case.src and "=" in case.src, \
        "the sink must sit behind a key=value parse, or the bare cyclic probe would reach it"
