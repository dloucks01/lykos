"""What the web UI runs, and what it shows.

`./start` opens the workbench, and for most users it IS the product. Two things were wrong with
it, both invisible from inside the UI.

**It ran a different, shorter autopilot.** There are two implementations of stage scheduling:
`analyze/orchestrate.py` (what the CLI, every gate and the background button use) and a
hand-maintained `PIPELINE` array in `api/static/app/autopilot.js`. The server one schedules all
45 registered stages; the browser one knew 28. The primary "▶ Run Autopilot" button ran the
browser one, so a user clicking the obvious button got 17 fewer capabilities than a CLI user --
including the whole heap chain (`heap_trace`, `oob_index`, `chain_primitive`), the uninitialised
memory oracle (`mem_oracle`), in-process harness fuzzing (`libfuzzer`) and the CVE->exploit
chain (`cve_poc`, `cve_corroborate`). The server-side autopilot arrived in the commit that added
"a wall clock it divides, a baseline execution, a scorecard and a front door"; the button was
never moved onto it.

**It showed no account of the work.** There was no scorecard endpoint at all. The CLI prints the
card and the HTML report renders it, but the UI could not fetch it, so findings appeared with no
executions, no declines, no never-scheduled list and no absorbed count. Of two targets with zero
crashes, one that executed 2,756 times and one that executed zero because a stage upstream ate
the budget looked identical.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
STATIC = ROOT / "core" / "lykos" / "api" / "static"
APP = (STATIC / "app" / "app.js").read_text()
APIJS = (STATIC / "app" / "api.js").read_text()
COMPONENTS = (STATIC / "app" / "components.js").read_text()
AUTOPILOT_JS = (STATIC / "app" / "autopilot.js").read_text()


def _code(fn):
    """A function's executable source only: no docstring, no comments.

    Every one of these functions documents the bug it fixes, so a text search over the whole
    source reads the explanation as the thing being explained.
    """
    import ast
    import inspect
    import textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    body = tree.body[0].body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return "\n".join(ast.unparse(n) for n in body)


def _registered():
    import lykos.analyze  # noqa: F401  -- registers every stage
    from lykos.jobs import registry
    return set(getattr(registry, "_STAGES", None) or registry.STAGES)


def _js_pipeline():
    """Every stage the browser-side file knows about.

    Not only the PIPELINE array: `synthesize_poc` is run explicitly before the prove phase and
    `dynamic_run` / `firmware_carve` are handled in switch arms, so matching the array alone
    undercounts by three and reports stages as missing that are not.
    """
    return set(re.findall(r'"([a-z_]+)"', AUTOPILOT_JS)) & _registered()


def test_the_primary_autopilot_button_runs_the_server_pipeline():
    """The obvious button has to be the complete one. `onBackground` is the server-side autopilot
    -- all 45 stages, the phase budget, the baseline execution and the scorecard."""
    # Anchored on the button's own label, not on how the label expression is written (it grew
    # cancelled/error branches ahead of the `ran ?` test, which broke the old anchor).
    m = re.search(r'class="btn primary"\s+onClick=\$\{(\w+)\}(?:(?!</button>).)*?Run Autopilot', APP, re.S)
    assert m, "could not find the primary Run Autopilot button"
    assert m.group(1) == "onBackground", (
        "the primary Autopilot button runs %s; it must run onBackground (the server pipeline), "
        "or GUI users silently get a shorter run than CLI users" % m.group(1))


def test_the_browser_pipeline_does_not_claim_to_be_complete():
    """Its own header opened "one click, every applicable capability" while knowing 28 of 45. A
    second copy of the schedule is tolerable behind a secondary button; a second copy that
    overstates itself is how the gap went unnoticed for as long as it did.

    Asserted on the OPENING line, not on a substring: the header now quotes the old claim in
    order to retract it, and a search of the whole block cannot tell a claim from its retraction.
    """
    first = AUTOPILOT_JS.splitlines()[0]
    assert "IN-TAB" in first or "in-tab" in first, \
        "autopilot.js does not open by saying it is the in-tab subset: %r" % first
    assert "every applicable capability" not in first, \
        "autopilot.js still opens by claiming every capability; it runs a subset"


def test_the_browser_pipeline_cannot_silently_fall_further_behind():
    """It is allowed to be a subset -- it is the in-tab fallback -- but the gap has to be
    DECLARED, so adding a stage to the engine and forgetting this file fails here instead of
    quietly shipping a shorter run."""
    reg = _registered()
    js = _js_pipeline()
    assert js <= reg, "the browser pipeline names stages that do not exist: %s" % sorted(js - reg)
    missing = sorted(reg - js)
    declared = set(re.findall(r"//\s*not-in-tab:\s*([a-z_, ]+)", AUTOPILOT_JS))
    declared = {n.strip() for group in declared for n in group.split(",") if n.strip()}
    undeclared = sorted(set(missing) - declared)
    assert not undeclared, (
        "%d stage(s) the server runs and the in-tab pipeline does not, and the file does not say "
        "so: %s -- add them to PIPELINE, or declare them with a `// not-in-tab:` comment"
        % (len(undeclared), undeclared))


def test_the_ui_can_fetch_the_scorecard():
    from lykos.api import routes
    assert hasattr(routes, "_CASE_SCORECARD"), "no scorecard route"
    assert routes._CASE_SCORECARD.match("/cases/abc/scorecard")
    assert "scorecard:" in APIJS, "api.js cannot fetch the scorecard"
    from lykos.api.endpoints import EndpointsMixin
    assert hasattr(EndpointsMixin, "_get_scorecard"), "no scorecard endpoint"


def test_the_scorecard_is_read_from_the_event_log_not_the_live_run():
    """So a reopened case, a restarted server and a case produced by `lykos analyze` all show it.
    The in-memory autopilot record has none of those."""

    from lykos.api.endpoints import EndpointsMixin
    code = _code(EndpointsMixin._get_scorecard)
    assert "payloads_of_type" in code, "the scorecard must come from the event log"
    assert "_AUTOPILOTS" not in code, "it must not depend on the live in-memory record"
    assert "limit" not in code, "the scorecard is a case's LAST event; a windowed read drops it"


def test_the_ui_renders_the_scorecard():
    assert "export function RunScorecard" in COMPONENTS, "no scorecard component"
    assert "RunScorecard" in APP and "api.scorecard(" in APP, \
        "the component exists but the app never fetches or renders it"
    # the fields that make a null result readable
    for field in ("executions", "capability", "never_scheduled", "absorbed", "declined",
                  "baseline"):
        assert field in COMPONENTS, f"the scorecard panel does not show {field}"


def test_the_scorecard_survives_a_case_reset():
    """A stale card from the previous case is worse than none: it describes work on a different
    binary."""
    assert "setScorecard([])" in APP, "the scorecard is not cleared when the case is reset"


def test_the_ui_can_fetch_the_coverage_ledger():
    """The "how close to 100%?" dashboard: a route, an api.js call, and an endpoint handler."""
    from lykos.api import routes
    assert hasattr(routes, "_CASE_COVERAGE"), "no coverage-ledger route"
    assert routes._CASE_COVERAGE.match("/cases/abc/coverage")
    assert "coverage:" in APIJS, "api.js cannot fetch the coverage ledger"
    from lykos.api.endpoints import EndpointsMixin
    assert hasattr(EndpointsMixin, "_get_coverage"), "no coverage endpoint"
    # a bad case id must be a 404, not a 200 with an empty ledger
    assert "404" in _code(EndpointsMixin._get_coverage), \
        "the coverage endpoint must 404 an unknown case"


def test_the_ui_renders_the_coverage_ledger():
    assert "export function LedgerPanel" in COMPONENTS, "no coverage-ledger component"
    assert "LedgerPanel" in APP and "api.coverage(" in APP, \
        "the component exists but the app never fetches or renders it"
    # the three axes + the worklist the panel must surface
    for token in ("Checks run", "weaponized", "Code exercised", "Gaps worklist"):
        assert token in COMPONENTS, f"the ledger panel does not show {token!r}"


def test_the_coverage_ledger_survives_a_case_reset():
    """A stale ledger from the previous case describes a different engagement."""
    assert "setLedger(null)" in APP, "the coverage ledger is not cleared when the case is reset"
