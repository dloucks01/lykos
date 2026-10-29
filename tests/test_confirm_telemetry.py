"""Honest per-rung telemetry: the ladder accounts for EVERY rung attempt, so a '0 confirmed' is never
silent about its cause. A rung that cannot run (no static explore build, no shared fuzz build, the
template rung unbuilt) is recorded as `skipped` WITH the reason; a rung that runs and finds nothing is
`no-confirm` with its execution count. This is the report-degradation-never-silent rule applied to the
confirmation ladder.
"""
from lykos.analyze.symbolic import directed_confirm as DC


def test_ladder_records_every_rung_skip_with_a_reason():
    # a harness descriptor with NO builds: every rung must skip, and say why -- no angr/clang needed.
    attempts = []
    proven = DC.confirm_ladder([{"name": "H"}], timeout_per=5, attempts_out=attempts)
    assert proven == []
    by_rung = {a["rung"]: a for a in attempts}
    assert set(by_rung) == {"template", "concolic", "smart-fuzz"}
    assert all(a["harness"] == "H" for a in attempts)
    assert by_rung["template"]["outcome"] == "skipped"
    assert by_rung["concolic"]["outcome"] == "skipped"
    assert "static" in (by_rung["concolic"]["reason"] or "")
    assert by_rung["smart-fuzz"]["outcome"] == "skipped"
    assert "fuzz" in (by_rung["smart-fuzz"]["reason"] or "")


def test_attempts_out_is_optional():
    # back-compat: without attempts_out the ladder still returns the proven list (here, empty).
    assert DC.confirm_ladder([{"name": "H"}], timeout_per=5) == []


def test_rung_wrappers_return_skip_dicts_not_none():
    # the rungs now always return a dict (so the ladder can account for them), never None.
    assert DC._rung_template({}, timeout=1, ctx=None)["skipped"] is True
    assert DC._rung_concolic({}, timeout=1, ctx=None)["skipped"] is True
    assert DC._rung_smartfuzz({}, timeout=1, ctx=None)["skipped"] is True
