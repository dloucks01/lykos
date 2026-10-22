"""Operator per-run stage skip (GUI 'black-box fuzzing' checkbox -> skip_stages=['fuzz']).

A stage named in CaseBudget.skip_stages must be dropped at the autopilot's scheduling chokepoint
(`_staged`) BEFORE any budget is spent, recorded as a `skipped` plan row with the operator reason --
and every other stage must still run."""
from __future__ import annotations

import types

from lykos.analyze import orchestrate
from lykos.analyze.budget import CaseBudget


def test_case_budget_normalizes_skip_stages():
    assert CaseBudget(600, skip_stages=["fuzz", "fuzz"]).skip_stages == {"fuzz"}
    assert CaseBudget(600).skip_stages == set()


def _fixture(monkeypatch):
    called = []
    monkeypatch.setattr(orchestrate, "_run_target_stage",
                        lambda *a, **k: (called.append(a[2]), "done")[1])  # a[2] = stage
    monkeypatch.setattr(orchestrate, "_emit_stage", lambda *a, **k: None)
    # the autopilot pre-seeds the plan with every stage; _plan_set updates the matching row
    status = {"plan": [{"stage": "fuzz", "state": "pending"},
                       {"stage": "directed_fuzz", "state": "pending"}]}
    stop = types.SimpleNamespace(is_set=lambda: False)
    target = types.SimpleNamespace(case_id="c", id="t")
    return called, status, stop, target


def test_staged_skips_the_disabled_stage(monkeypatch):
    called, status, stop, target = _fixture(monkeypatch)
    bud = CaseBudget(600, skip_stages={"fuzz"})
    out = orchestrate._staged(bud, object(), target, "fuzz", status, stop)
    assert out == "skipped"
    assert "fuzz" not in called                 # the stage never actually ran
    # recorded as a skip with the operator reason, not a silent omission
    row = next((r for r in status.get("plan", []) if r.get("stage") == "fuzz"), None)
    assert row and row.get("state") == "skipped" and "operator" in (row.get("detail") or "")


def test_staged_runs_a_non_disabled_stage(monkeypatch):
    called, status, stop, target = _fixture(monkeypatch)
    bud = CaseBudget(600, skip_stages={"fuzz"})
    out = orchestrate._staged(bud, object(), target, "directed_fuzz", status, stop)
    assert out == "done" and "directed_fuzz" in called
