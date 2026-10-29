"""CWE coverage matrix: the honest account of detection breadth and the per-class weaponization
ceiling. These tests pin the invariants that keep it honest -- the ceiling vocabulary is closed,
every ceiling key names a class the platform actually knows, a run's 'best state' only ever rises,
and the matrix never claims to detect a class it cannot name.
"""
from lykos.analyze import cwe_coverage as cc
from lykos.cwe import CWE_NAMES

_CEILINGS = {"rce", "primitive", "leak", "dos", "logic"}


def test_ceiling_vocabulary_is_closed():
    """Every declared ceiling is one of the five honest buckets -- no stray/typo'd impact word."""
    bad = {c for c in cc.CEILING.values() if c not in _CEILINGS}
    assert not bad, f"unknown ceiling values: {bad}"


def test_every_ceiling_key_is_a_well_formed_cwe_id():
    """The ceiling table is a weaponization lookup usable for ANY finding's CWE (broader than the
    name map), but every key must be a canonical 'CWE-<n>' id -- this catches typo'd keys like
    'CWE-787a' that would silently never match a real finding."""
    import re
    bad = [c for c in cc.CEILING if not re.fullmatch(r"CWE-\d+", c)]
    assert not bad, f"malformed ceiling keys (never match a real finding): {bad}"


def test_named_classes_with_a_ceiling_agree_with_the_matrix():
    """For classes the platform names, the matrix's ceiling is exactly the table's."""
    m = {e["cwe"]: e["ceiling"] for e in cc.capability_matrix()}
    for cwe, ceil in cc.CEILING.items():
        if cwe in CWE_NAMES:
            assert m[cwe] == ceil


def test_capability_matrix_covers_all_named_classes():
    m = cc.capability_matrix()
    assert len(m) == len(CWE_NAMES)
    assert all(e["detected"] for e in m)                 # a named class is a detectable class
    # rce_capable is exactly the 'rce' ceiling.
    assert all(e["rce_capable"] == (e["ceiling"] == "rce") for e in m)


def test_summary_distribution_sums_to_detected():
    s = cc.summary()
    assert s["detected_classes"] == len(CWE_NAMES)
    assert sum(s["ceiling_distribution"].values()) == s["detected_classes"]
    assert s["rce_capable"] == s["ceiling_distribution"].get("rce", 0)


def test_run_matrix_best_state_only_rises_and_dedups():
    """A class carried to poc-backed stays poc-backed even if a later candidate row arrives, and a
    repeated (cwe, dedup_key) is counted once."""
    findings = [
        {"cwe": "CWE-787", "state": "poc-backed", "dedup_key": "a"},
        {"cwe": "CWE-787", "state": "candidate", "dedup_key": "a"},   # dup -> ignored
        {"cwe": "CWE-787", "state": "candidate", "dedup_key": "b"},   # new site, lower state
        {"cwe": "CWE-476", "state": "candidate", "dedup_key": "c"},
    ]
    run = cc.run_matrix(findings)
    oob = next(r for r in run["rows"] if r["cwe"] == "CWE-787")
    assert oob["count"] == 2 and oob["best_state"] == "poc-backed"
    assert oob["ceiling"] == "rce"
    assert run["rce_capable_present"] == ["CWE-787"]
    assert run["demonstrated_classes"] == 1              # only the poc-backed class


def test_run_matrix_handles_missing_cwe_and_objects():
    class Row:
        def __init__(self, cwe, state, key):
            self.cwe, self.state, self.dedup_key = cwe, state, key
    run = cc.run_matrix([Row(None, "candidate", "x"), Row("CWE-125", "corroborated", "y")])
    cwes = {r["cwe"] for r in run["rows"]}
    assert "(none)" in cwes and "CWE-125" in cwes


def test_format_report_is_honest_text():
    txt = cc.format_report(cc.run_matrix([{"cwe": "CWE-78", "state": "corroborated", "dedup_key": "1"}]))
    assert "weaponization ceiling" in txt
    assert "DEPTH" in txt                                 # the honest framing is present
    assert "CWE-78" in txt
