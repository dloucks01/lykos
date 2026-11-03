"""weaponize_plan router: per-finding TTP selection + whole-target RCE composition (integration 2)."""
from lykos.analyze import weaponize_plan as wp


def test_primitive_tag_maps_memory_classes():
    assert wp.primitive_tag("CWE-125") == "oob-read"
    assert wp.primitive_tag("CWE-787") == "oob-write"
    assert wp.primitive_tag("CWE-416") == "uaf"
    assert wp.primitive_tag("CWE-134") == "fmt"
    assert wp.primitive_tag("CWE-22") is None          # not a memory primitive


def test_plan_for_finding_selects_matching_ttp():
    assert wp.plan_for_finding("CWE-134")["ttp"] == "fmt-write-what-where"
    assert wp.plan_for_finding("CWE-416")["ttp"] == "uaf-reclaim"
    assert wp.plan_for_finding("CWE-787")["ttp"] == "heap-groom"
    assert wp.plan_for_finding("CWE-200") is None       # bare leak: target-level only


def test_plan_for_finding_heap_groom_feasible_on_heap_sizes():
    p = wp.plan_for_finding("CWE-122", overflow_size=64, victim_size=64)
    assert p["feasible"] is True and p["plan"]


def test_plan_target_reaches_rce_with_leak_and_write():
    findings = [{"cwe": "CWE-125", "function": "read_x"}, {"cwe": "CWE-787", "function": "write_y"}]
    out = wp.plan_target(findings)
    assert out["rce"]["reachable"] is True
    assert out["leak_write_chain"] is not None
    assert "ASLR" in " ".join(out["leak_write_chain"]["defeats"])


def test_plan_target_names_missing_technique_when_write_only():
    out = wp.plan_target([{"cwe": "CWE-787", "function": "w"}])
    assert out["rce"]["reachable"] is False
    assert any("leak" in n for n in out["rce"]["needs"])
    assert out["leak_write_chain"] is None
