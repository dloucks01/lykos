"""The shared confirmation-ladder / exploitability / attack-surface helpers, and the API
serializer enrichment that puts the same per-finding detail the report gives into the web GUI."""
from __future__ import annotations

from types import SimpleNamespace

from lykos.analyze.confirm_ladder import (
    attack_surface,
    finding_analysis,
    finding_exploitability,
)
from lykos.api.serializers import _finding


def _f(**kw):
    base = dict(id="x", target_id="t", case_id="c", cwe="CWE-190", title="t", severity="high",
                state="candidate", confidence=0.5, function_addr=None, site_addr=None,
                detector="int_overflow", evidence=[], stage=None, dedup_key="dk")
    base.update(kw)
    return SimpleNamespace(**base)


def test_ladder_states_and_next_rung():
    for state, nxt in [("candidate", "corroborated"), ("corroborated", "confirmed"),
                       ("confirmed", "poc-backed"), ("poc-backed", None)]:
        a = finding_analysis({"state": state, "evidence": []})
        assert a["state"] == state
        assert a["next_state"] == nxt
        assert (a["to_promote"] is None) == (nxt is None)
    # corroborated enriches the "why" with the channels present
    a = finding_analysis({"state": "corroborated",
                          "evidence": [{"channel": "dynamic", "detail": "x"}]})
    assert "dynamic" in a["why_state"]


def test_exploitability_ceiling_and_mitigations():
    f = {"cwe": "CWE-134", "evidence": [
        {"channel": "w", "detail": "weaponization reached L2 and stopped: PIE: no in-band leak"},
        {"channel": "r", "detail": "Targets L3 if run against the live target."}]}
    ex = finding_exploitability(f, {"nx": True, "pie": True, "relro": "partial"})
    assert "format string" in ex["class_primitive"]
    assert ex["ceiling"] == "L2" and "PIE" in ex["ceiling_reason"]
    assert ex["targets_live"] == "L3"
    joined = " ".join(ex["mitigations_in_way"])
    assert "NX" in joined and "PIE" in joined and "partial RELRO" in joined
    # no mitigations known -> still returns the class primitive + ceiling, just no "in the way"
    ex2 = finding_exploitability(f, None)
    assert ex2["class_primitive"] and "mitigations_in_way" not in ex2


def test_attack_surface_from_evidence():
    assert attack_surface({"evidence": [{"channel": "s",
                                         "detail": "on the fuzzed attack surface"}]}) == "on"
    assert attack_surface({"evidence": [{"channel": "s",
                                         "detail": "off the fuzzed attack surface"}]}) == "off"
    assert attack_surface({"evidence": []}) is None


def test_serializer_attaches_per_finding_detail():
    f = _f(cwe="CWE-134", state="corroborated", evidence=[
        {"channel": "w", "detail": "weaponization reached L2 and stopped: PIE no leak"},
        {"channel": "s", "detail": "on the fuzzed attack surface"}])
    d = _finding(f, mitigations={"nx": True, "pie": True})
    assert d["analysis"]["state"] == "corroborated"
    assert d["analysis"]["next_state"] == "confirmed"
    assert d["exploitability"]["ceiling"] == "L2"
    assert d["reachability"]["attack_surface"] == "on"
