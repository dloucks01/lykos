"""The GUI harnesses, run under pytest.

These render the page's own script against a stubbed DOM and assert what comes OUT. Every
other GUI assertion in this suite checks that source text exists -- a function is named, a
label appears -- and none would notice a board that renders zero rows. One such bug got as far
as a commit: `t.open || ... || BOARD_OPEN[k]` short-circuits, so the chevron on a default-open
tier did nothing at all. Invisible to a grep; obvious the moment the thing is run.

Here they SKIP without node, because a developer without a JS runtime should still be able to
run the Python suite. `make gui` runs the same harnesses and FAILS instead -- that is the gate,
and it is wired into `make ci` so a green CI cannot mean "the GUI checks did not run".
"""
import pathlib
import shutil
import subprocess

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PAGE = _ROOT / "core/lykos/api/static/index.html"
_HARNESSES = sorted((_ROOT / "tests/js").glob("*.js"))


def test_there_are_harnesses_to_run():
    """A directory that quietly became empty would make every test below vacuously pass."""
    assert _HARNESSES, "tests/js/*.js is empty"
    names = {h.name for h in _HARNESSES}
    assert {"board_render.js", "runs_render.js", "syntax.js"} <= names, names


@pytest.mark.parametrize("harness", _HARNESSES, ids=lambda h: h.stem)
def test_gui_harness(harness):
    if not shutil.which("node"):
        pytest.skip("node not installed (`make gui` fails instead of skipping)")
    r = subprocess.run(["node", str(harness), str(_PAGE)], capture_output=True, timeout=180)
    out = (r.stdout or b"").decode() + (r.stderr or b"").decode()
    assert r.returncode == 0, out
    assert "FAIL" not in out, out
    assert "PASS" in out, "a harness that asserts nothing is not a test\n" + out


def test_resolving_links_goes_through_the_job_queue():
    """`GET /systemmap?resolve=1` calls resolve_case() -- the same function link_case_stage
    calls -- synchronously inside the HTTP request. So the one stage of twenty-nine the GUI
    "could not launch" was reachable all along, and doing it that way cost the run row, the
    progress, the cancel, the cached result and the event: nothing recorded that linking had
    happened."""
    h = _PAGE.read_text()
    assert "doResolveLinks" in h
    assert '"link_case"' in h, "the button has to enqueue the stage"
    assert 'if(v==="sysmap") loadSystemMap(false)' in h
