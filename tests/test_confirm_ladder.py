"""The shared confirmation-ladder / exploitability / attack-surface helpers, and the API
serializer enrichment that puts the same per-finding detail the report gives into the web GUI."""
from __future__ import annotations

from types import SimpleNamespace

from lykos.analyze.confirm_ladder import (
    attack_surface,
    finding_analysis,
    finding_exploitability,
    finding_verification,
    instrumentation_noise,
    prove_out_plan,
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


def test_instrumentation_noise_is_conservative():
    # a sanitizer-runtime artifact is flagged
    n = instrumentation_noise({"title": "oob write _ZN11__sanitizerL24internal_allocator_cacheE[-9]",
                               "evidence": []})
    assert n["noise"] and "instrumentation" in n["reason"]
    # a real target finding is NOT flagged (no false "noise")
    assert instrumentation_noise({"title": "integer overflow in rdpsnd", "evidence": [
        {"channel": "static", "detail": "realloc sizes from overflow-prone arithmetic"}]})["noise"] \
        is False


def test_finding_verification_verdicts():
    # on attack surface + real -> prove-out shortlist
    v = finding_verification({"title": "ovf", "evidence": [
        {"channel": "s", "detail": "on the fuzzed attack surface (in an in-tree harness)"}]})
    assert v["verdict"] == "prove-out-shortlist" and v["shortlist"] is True and v["noise"] is False
    # off attack surface -> off-surface, not shortlist
    v = finding_verification({"title": "ovf", "evidence": [
        {"channel": "s", "detail": "off the fuzzed attack surface (a build tool)"}]})
    assert v["verdict"] == "off-surface" and v["shortlist"] is False
    # instrumentation artifact -> noise, regardless of surface
    v = finding_verification({"title": "oob _ZN11__sanitizer internal_allocator", "evidence": [
        {"channel": "s", "detail": "on the fuzzed attack surface"}]})
    assert v["verdict"] == "instrumentation-noise" and v["noise"] is True and v["shortlist"] is False
    # bonus reachable signal is carried through
    v = finding_verification({"title": "x", "evidence": [
        {"channel": "s", "detail": "on the fuzzed attack surface"}]}, reachable=True)
    assert v["reachable"] is True


def test_prove_out_plan_only_for_shortlist():
    on = {"cwe": "CWE-190", "function_addr": "0x401000", "site_addr": "0x401100",
          "evidence": [{"channel": "s", "detail": "on the fuzzed attack surface"}]}
    plan = prove_out_plan(on)
    assert plan and len(plan["steps"]) >= 3
    assert "heap-overflow" in plan["solver"]
    assert any("poc-backed" in s for s in plan["steps"])
    assert any("0x401000" in s for s in plan["steps"])          # names the finding's own function
    # off-surface and instrumentation-noise get NO plan
    assert prove_out_plan({"cwe": "CWE-190", "evidence": [
        {"channel": "s", "detail": "off the fuzzed attack surface"}]}) is None
    assert prove_out_plan({"cwe": "CWE-190", "title": "__sanitizer internal_allocator",
                           "evidence": [{"channel": "s", "detail": "on the fuzzed attack surface"}]}) \
        is None


def test_serializer_attaches_per_finding_detail():
    f = _f(cwe="CWE-134", state="corroborated", evidence=[
        {"channel": "w", "detail": "weaponization reached L2 and stopped: PIE no leak"},
        {"channel": "s", "detail": "on the fuzzed attack surface"}])
    d = _finding(f, mitigations={"nx": True, "pie": True})
    assert d["analysis"]["state"] == "corroborated"
    assert d["analysis"]["next_state"] == "confirmed"
    assert d["exploitability"]["ceiling"] == "L2"
    assert d["reachability"]["attack_surface"] == "on"
    assert d["verification"]["verdict"] == "prove-out-shortlist"
    assert d["verification"]["shortlist"] is True
