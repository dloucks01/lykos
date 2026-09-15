"""Why cross-component taint found nothing.

A diagnosis is a claim needing the same evidence as a finding. This one exists because the
stage kept saying "nothing found" for six genuinely different reasons -- one component in the
case, no resolved links, a component too large to analyse, a caller that was never decompiled,
a boundary carrying no tainted argument, and a callee that genuinely does nothing dangerous
with the data. Only the last of those is a real negative. Reporting the other five as if they
were is how an operator concludes a target is clean when nothing was examined at all.

The ordering matters as much as the text: the reasons are not mutually exclusive, and the one
reported has to be the one that actually stopped the analysis. "Nothing was examined" must
outrank "we examined it and it was fine", or a run that analysed nothing reports a clean bill
of health.
"""
from __future__ import annotations

from lykos.analyze.detect import taint
from lykos.analyze.link.crosstaint import _why_nothing


def _why(**over):
    base = {"no_components": False, "no_links": False, "edges_without_tainted_symbol": 0,
            "edges_with_clean_callee": 0, "callers_without_ir": 0, "callees_without_ir": 0,
            "components_over_cap": 0}
    base.update(over)
    return base


def test_a_finding_needs_no_excuse():
    assert _why_nothing(_why(no_components=True), found=1) is None
    assert _why_nothing(_why(), found=3) is None


def test_a_single_component_case_says_so():
    msg = _why_nothing(_why(no_components=True), 0)
    assert "one component" in msg and "at least two" in msg


def test_no_resolved_links_tells_the_operator_what_to_run():
    msg = _why_nothing(_why(no_links=True), 0)
    assert "link_case" in msg, "the operator is not told how to fix it"


def test_a_component_over_the_ceiling_is_declared_NOT_a_negative_result():
    """The bug this text exists for: a component past the data-flow ceiling was skipped and
    the stage reported a clean result. Nothing was examined."""
    msg = _why_nothing(_why(components_over_cap=2), 0)
    assert "not a negative result" in msg
    assert "nothing was examined" in msg.lower()
    assert str(taint._MAX_FUNCS) in msg, "the ceiling is not named, so it cannot be raised"


def test_the_ceiling_message_agrees_with_itself_on_number():
    one = _why_nothing(_why(components_over_cap=1), 0)
    many = _why_nothing(_why(components_over_cap=3), 0)
    assert "boundary joins" in one and " it" in one
    assert "boundaries join" in many and "them" in many


def test_an_undecompiled_caller_names_the_stage_that_fixes_it():
    msg = _why_nothing(_why(callers_without_ir=1), 0)
    assert "disassemble" in msg
    assert "firmware" in msg, "carved firmware is the common cause and is worth naming"
    assert "has not been" in msg
    assert "have" in _why_nothing(_why(callers_without_ir=2), 0)


def test_an_undecompiled_callee_is_not_reported_as_a_real_negative():
    """The bug this text exists for, on the far side of the boundary: a callee with no IR was
    never searched for a sink, so 'no sink reached' is a MISSING analysis, not a clean callee.
    Reporting it as a real negative is a false all-clear about code that was never examined."""
    msg = _why_nothing(_why(callees_without_ir=1), 0)
    assert "not been decompiled" in msg
    assert "missing analysis" in msg and "not a real" in msg
    assert "disassemble" in msg
    assert "have" in _why_nothing(_why(callees_without_ir=2), 0)


def test_an_undecompiled_callee_outranks_a_clean_callee():
    """Both true at once: some callees were examined and were fine, another was never
    decompiled. The un-examined one must win, or 'we did not look' becomes 'we looked and it
    was fine'."""
    msg = _why_nothing(_why(callees_without_ir=1, edges_with_clean_callee=5), 0)
    assert "not been decompiled" in msg and "missing analysis" in msg
    # the clean-callee message (the real-negative one) must NOT be what is returned
    assert "does not carry it into a dangerous sink" not in msg


def test_a_boundary_with_no_tainted_argument_is_described_as_such():
    msg = _why_nothing(_why(edges_without_tainted_symbol=1), 0)
    assert "no tainted argument" in msg
    assert "boundary" in msg
    assert "boundaries" in _why_nothing(_why(edges_without_tainted_symbol=2), 0)


def test_a_clean_callee_is_the_one_reason_that_IS_a_real_negative():
    """The only one of the six that means the target was examined and found fine."""
    msg = _why_nothing(_why(edges_with_clean_callee=1), 0)
    assert "real negative" in msg
    assert "not a missing analysis" in msg


def test_nothing_to_examine_is_the_last_resort():
    assert _why_nothing(_why(), 0) == "nothing to examine."


# ---- the ordering, which is the part that carries the risk -------------------------------

def test_a_skipped_component_outranks_a_clean_callee():
    """Both true at once: some boundaries were examined and were fine, others were never
    examined at all. Reporting the clean one would turn "we did not look" into "we looked and
    it was fine" -- the exact false all-clear this diagnosis exists to prevent."""
    msg = _why_nothing(_why(components_over_cap=1, edges_with_clean_callee=5), 0)
    assert "not a negative result" in msg
    assert "real negative" not in msg


def test_a_missing_decompilation_outranks_a_clean_callee():
    msg = _why_nothing(_why(callers_without_ir=1, edges_with_clean_callee=5), 0)
    assert "disassemble" in msg


def test_a_skipped_component_outranks_a_missing_decompilation():
    msg = _why_nothing(_why(components_over_cap=1, callers_without_ir=1), 0)
    assert "not a negative result" in msg


def test_structural_reasons_outrank_every_per_edge_reason():
    """With no components there are no edges to say anything about."""
    every = _why(no_components=True, no_links=True, components_over_cap=1,
                 callers_without_ir=1, edges_without_tainted_symbol=1,
                 edges_with_clean_callee=1)
    assert "one component" in _why_nothing(every, 0)
    every["no_components"] = False
    assert "link_case" in _why_nothing(every, 0)


def test_every_reason_produces_a_sentence_an_operator_can_act_on():
    for key in ("no_components", "no_links"):
        msg = _why_nothing(_why(**{key: True}), 0)
        assert msg and msg[-1] == "." and len(msg) > 40
    for key in ("components_over_cap", "callers_without_ir",
                "edges_without_tainted_symbol", "edges_with_clean_callee"):
        msg = _why_nothing(_why(**{key: 1}), 0)
        assert msg and len(msg) > 40, key
