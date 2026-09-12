"""The Findings Board, rendered headlessly and asserted on what it actually produces.

Every other GUI assertion in this suite checks that source text exists -- a function is named,
a label appears. None would notice a board rendering zero rows, and one nearly shipped:
`t.open || ... || BOARD_OPEN[k]` short-circuits, so the chevron on a default-open tier did
nothing at all. Invisible to a grep; obvious the moment the thing is run.
"""
import pathlib
import shutil
import subprocess

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PAGE = _ROOT / "core/lykos/api/static/index.html"
_HARNESS = _ROOT / "tests/js/board_render.js"
_RUNS = _ROOT / "tests/js/runs_render.js"


def test_the_board_renders_evidence_tiers():
    if not shutil.which("node"):
        pytest.skip("node not installed")
    r = subprocess.run(["node", str(_HARNESS), str(_PAGE)], capture_output=True, timeout=120)
    out = (r.stdout or b"").decode() + (r.stderr or b"").decode()
    assert r.returncode == 0, out
    assert "FAIL" not in out, out


def test_the_run_list_groups_by_target_and_never_hides_a_failure():
    """The flat list truncated to 14 with no target name on any row: with four binaries you
    could not tell which run belonged to which, and everything past the cap -- including the
    only run that ERRORED -- was simply not drawn."""
    if not shutil.which("node"):
        pytest.skip("node not installed")
    r = subprocess.run(["node", str(_RUNS), str(_PAGE)], capture_output=True, timeout=120)
    out = (r.stdout or b"").decode() + (r.stderr or b"").decode()
    assert r.returncode == 0, out
    assert "FAIL" not in out, out


def test_resolving_links_goes_through_the_job_queue():
    """`GET /systemmap?resolve=1` calls resolve_case() -- the same function link_case_stage
    calls -- synchronously inside the HTTP request. So the one stage of twenty-nine the GUI
    "could not launch" was reachable all along, and doing it that way cost the run row, the
    progress, the cancel, the cached result and the event: nothing recorded that linking had
    happened."""
    h = _PAGE.read_text()
    assert "doResolveLinks" in h
    assert '"link_case"' in h, "the button has to enqueue the stage"
    # opening the tab must not silently re-resolve on every visit
    assert 'if(v==="sysmap") loadSystemMap(false)' in h


def test_the_page_script_parses():
    """A syntax error anywhere in 120 KB of inline script takes the whole GUI down, and
    nothing else in this suite would catch it."""
    if not shutil.which("node"):
        pytest.skip("node not installed")
    import re
    import tempfile
    src = re.search(r"<script[^>]*>(.*?)</script>", _PAGE.read_text(), re.S).group(1)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(src)
        p = f.name
    r = subprocess.run(["node", "--check", p], capture_output=True, timeout=60)
    assert r.returncode == 0, (r.stderr or b"").decode()[:800]
