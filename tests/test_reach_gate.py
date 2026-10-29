"""Reach-gated + plateau-bail fuzzing: the broad fuzz campaigns are demoted only when a harness
reaches almost no code AND a short probe makes zero progress -- fail-open otherwise, no tuning knob
for the bail decision (it is zero-vs-nonzero observed progress)."""
from __future__ import annotations

from lykos.analyze import orchestrate as O
from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO


def _undriven_target(store, case, name, sha):
    """A target whose harness entry statically reaches ~nothing (1 of 40 functions, <5%)."""
    t = TargetDAO(store.conn).upsert(case.id, name, sha, arch="x86-64", bits=64)
    fns = [{"addr": f"0x{0x1000 + i * 0x10:x}",
            "name": ("LLVMFuzzerTestOneInput" if i == 0 else f"f{i}")} for i in range(40)]
    FunctionDAO(store.conn).replace_for_target(t.id, fns)
    CallEdgeDAO(store.conn).replace_for_target(t.id, [])      # entry reaches only itself
    return t


def test_harness_reach_fraction(store, case):
    t = _undriven_target(store, case, "h", "a" * 64)
    reach = O._harness_reach_fraction(store, t.id)
    assert reach is not None and reach < O._REACH_GATE_FRACTION   # 1/40 = 0.025
    # a well-driven target: entry reaches both functions -> 1.0
    t2 = TargetDAO(store.conn).upsert(case.id, "h2", "b" * 64, arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t2.id, [
        {"addr": "0x2000", "name": "LLVMFuzzerTestOneInput"}, {"addr": "0x2100", "name": "p"}])
    CallEdgeDAO(store.conn).replace_for_target(t2.id, [{"src_addr": "0x2000", "dst_addr": "0x2100"}])
    assert O._harness_reach_fraction(store, t2.id) >= O._REACH_GATE_FRACTION


def test_well_driven_target_never_demotes_and_never_probes(monkeypatch, store, case):
    t2 = TargetDAO(store.conn).upsert(case.id, "h2", "b" * 64, arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t2.id, [
        {"addr": "0x2000", "name": "LLVMFuzzerTestOneInput"}, {"addr": "0x2100", "name": "p"}])
    CallEdgeDAO(store.conn).replace_for_target(t2.id, [{"src_addr": "0x2000", "dst_addr": "0x2100"}])
    staged = []
    monkeypatch.setattr(O, "_staged", lambda *a, **k: staged.append(a[3]) or "done")
    assert O._reach_gated_fuzz_demote(None, store, t2, t2.id, {}, None, None) is False
    assert staged == []                                          # fail-open: no probe ran


def test_undriven_demotes_only_when_probe_makes_no_progress(monkeypatch, store, case):
    t = _undriven_target(store, case, "h", "a" * 64)
    staged = []
    monkeypatch.setattr(O, "_staged", lambda *a, **k: staged.append(a[3]) or "done")

    # zero-progress probe (before == after) -> DEMOTE + an event explaining why
    monkeypatch.setattr(O, "_hybrid_progress", lambda s, tid: (0, -1.0, 0))
    assert O._reach_gated_fuzz_demote(None, store, t, t.id, {}, None, None) is True
    assert "fuzz" in staged                                      # a probe did run
    pls = store.events.payloads_of_type("autopilot.fuzz_demoted", case_id=case.id)
    assert pls and "reaches" in (pls[-1] or {}).get("note", "")

    # progress in the probe (coverage/crash/corpus up) -> NOT demoted (fail-open)
    seq = iter([(0, -1.0, 0), (1, 5.0, 3)])
    monkeypatch.setattr(O, "_hybrid_progress", lambda s, tid: next(seq))
    assert O._reach_gated_fuzz_demote(None, store, t, t.id, {}, None, None) is False
