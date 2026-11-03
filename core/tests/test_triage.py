"""Triage resolves every finding to exactly one honest disposition."""
from lykos.analyze import finding_triage
from lykos.analyze.finding_triage import (triage_finding, ledger, CONFIRMED, DRIVABLE, CEILING_,
                                  OFF_SURFACE, FALSE_POSITIVE, NEEDS_TECHNIQUE)


def test_confirmed_when_poc_exists():
    d = triage_finding(cwe="CWE-787", state="poc-backed", has_poc=True, grounded=True,
                       verdict="exploitable-candidate")
    assert d.status == CONFIRMED


def test_false_positive_when_grounding_disproves():
    d = triage_finding(cwe="CWE-190", state="candidate", has_poc=False, grounded=False,
                       verdict="arch-safe-mul")
    assert d.status == FALSE_POSITIVE and "arch-safe-mul" in d.reason


def test_memory_class_on_surface_is_drivable():
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="exploitable-candidate")
    assert d.status == DRIVABLE and d.action and "harness" in d.action


def test_memory_class_off_surface_is_off_surface():
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="off-surface-candidate")
    assert d.status == OFF_SURFACE


def test_oob_read_tops_out_at_ceiling_leak():
    d = triage_finding(cwe="CWE-125", state="candidate", has_poc=False, grounded=True,
                       verdict="exploitable-candidate")
    assert d.status == CEILING_ and "disclosure" in d.reason


def test_logic_class_is_ceiling():
    d = triage_finding(cwe="CWE-22", state="candidate", has_poc=False, grounded=True,
                       verdict="exploitable-candidate")
    assert d.status == CEILING_ and "impact" in d.reason


def test_dos_class_is_ceiling():
    d = triage_finding(cwe="CWE-617", state="candidate", has_poc=False, grounded=True,
                       verdict="exploitable-candidate")
    assert d.status == CEILING_ and "DoS" in d.reason


def test_no_reachability_verdict_is_not_drivable():
    # a memory-class finding with NO reachability verdict must NOT be called drivable (honesty).
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="undecided")
    assert d.status == NEEDS_TECHNIQUE and "reachability" in d.reason.lower()


def test_unknown_class_needs_technique():
    d = triage_finding(cwe="CWE-99999", state="candidate", has_poc=False, grounded=True,
                       verdict="reachability-unknown")
    assert d.status == NEEDS_TECHNIQUE


def test_ledger_resolves_everything():
    disp = [("a", triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                                 verdict="exploitable-candidate")),
            ("b", triage_finding(cwe="CWE-190", state="candidate", has_poc=False, grounded=False,
                                 verdict="arch-safe-mul"))]
    L = ledger(disp)
    assert L["total"] == 2 and L["resolved"] is True and L["drivable"] == ["a"]
