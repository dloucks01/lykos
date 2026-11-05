"""Triage resolves every finding to one honest disposition (PoC-as-script model)."""
from lykos.analyze.finding_triage import (triage_finding, ledger, CONFIRMED, DRIVABLE,
    OFF_SURFACE, FALSE_POSITIVE, NEEDS_TECHNIQUE, UNTAINTED)


def test_confirmed_when_poc_exists():
    d = triage_finding(cwe="CWE-787", state="poc-backed", has_poc=True, grounded=True,
                       verdict="exploitable-candidate", tainted=True)
    assert d.status == CONFIRMED


def test_false_positive_when_grounding_disproves():
    d = triage_finding(cwe="CWE-190", state="candidate", has_poc=False, grounded=False,
                       verdict="arch-safe-mul", tainted=None)
    assert d.status == FALSE_POSITIVE and "arch-safe-mul" in d.reason


def test_reachable_and_tainted_is_drivable_any_class():
    # memory class and logic/injection class alike: reachable+tainted -> a script PoC is constructible
    for cwe in ("CWE-787", "CWE-22", "CWE-78", "CWE-617", "CWE-125"):
        d = triage_finding(cwe=cwe, state="candidate", has_poc=False, grounded=True,
                           verdict="exploitable-candidate", tainted=True)
        assert d.status == DRIVABLE, cwe


def test_reachable_untainted_is_untainted_deadend():
    # the rfx case: reachable but the dangerous operand is a constant -> not exploitable
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="exploitable-candidate", tainted=False)
    assert d.status == UNTAINTED and "not attacker-controlled" in d.reason


def test_off_surface_when_unreachable():
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="off-surface-candidate", tainted=True)
    assert d.status == OFF_SURFACE


def test_no_reachability_verdict_needs_technique():
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="undecided", tainted=None)
    assert d.status == NEEDS_TECHNIQUE and "reachability" in d.reason.lower()


def test_taint_unknown_still_drivable():
    # reachable, taint undecided -> attempt (do not dead-end on unknown)
    d = triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                       verdict="exploitable-candidate", tainted=None)
    assert d.status == DRIVABLE and "taint-unknown" in d.reason


def test_ledger_resolves_everything():
    disp = [("a", triage_finding(cwe="CWE-787", state="candidate", has_poc=False, grounded=True,
                                 verdict="exploitable-candidate", tainted=True)),
            ("b", triage_finding(cwe="CWE-190", state="candidate", has_poc=False, grounded=False,
                                 verdict="arch-safe-mul", tainted=None))]
    L = ledger(disp)
    assert L["total"] == 2 and L["resolved"] is True and L["drivable"] == ["a"]
