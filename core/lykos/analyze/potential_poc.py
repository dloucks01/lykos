"""Per-finding POTENTIAL-PoC generator (doc 60 F5 extension) — a PoC attempt for EVERY drivable /
untainted / needs-technique finding, not just the ones already confirmed.

The operator's bar: do not stop at the handful that happened to confirm. For each finding in those
dispositions, build out a concrete *potential* PoC (a trigger input + a harness recipe) and test it
where the sink is directly build-and-runnable; record the verified outcome. For an UNTAINTED finding
the same attempt is the PROOF of the verdict — if the constructed trigger cannot make it fault, the
"attacker doesn't control the value" call is demonstrated, not asserted; if it DOES fault, the
verdict was wrong and the finding is upgraded.

This module is the generator + a shape classifier (pure, testable). It produces, per finding:
  * trigger   -- the class-appropriate exploit input (payload for injection/traversal/format; an
                 oversized length/index / boundary input for memory classes);
  * recipe    -- how to drive the sink: a direct (buf,size) harness when the sink is exported and
                 parser-shaped, else expose_static(fn)+rebuild then call (proven on AUDIN);
  * testable_now -- whether the consuming stage can build+run it this run (exported + parser-shaped),
                 vs. requiring a per-sink rebuild (named explicitly, so it is a concrete next step).
The build+run itself is done by the consuming stage against the instrumented libraries.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# class -> a concrete exploit trigger for the potential PoC.
_PAYLOAD = {
    "CWE-22": "../../../../../../etc/passwd", "CWE-23": "../../../../../../etc/passwd",
    "CWE-78": "; id #", "CWE-77": "; id #", "CWE-88": "--output=/tmp/x",
    "CWE-134": "%n%n%n%n", "CWE-89": "' OR '1'='1",
}
_MEM = {"CWE-787", "CWE-125", "CWE-122", "CWE-120", "CWE-121", "CWE-416", "CWE-415",
        "CWE-190", "CWE-191", "CWE-124", "CWE-680", "CWE-131", "CWE-129"}
# exported parser/codec shapes we can drive directly with a (buf,size) or (ctx,buf,size) harness.
_PARSER_SHAPE = ("_decompress", "_decode", "_process_message", "_recv", "_read", "_parse")


@dataclass
class PotentialPoC:
    finding_id: str
    cwe: str
    fn: str
    disposition: str
    trigger: str
    recipe: str
    testable_now: bool
    reason: str = ""


def _trigger_for(cwe: str, disposition: str) -> str:
    if cwe in _PAYLOAD:
        return f"payload={_PAYLOAD[cwe]!r} (drive the tainted source with it)"
    if cwe in _MEM:
        if disposition == "untainted":
            return "attacker-max values for the flagged operand (verifies it is NOT attacker-controlled)"
        return "oversized length/index + truncated data for the flagged field (grammar-generated)"
    return "class-appropriate boundary input"


def generate(finding_id: str, cwe: "str|None", fn: "str|None", disposition: str,
             exported: bool) -> PotentialPoC:
    """Build the potential PoC for one finding. `exported` = the sink symbol is in the instrumented
    library (directly linkable). `testable_now` requires exported AND a parser/codec shape a generic
    harness can drive; otherwise the recipe names the per-sink rebuild needed."""
    cwe = cwe or "CWE-000"
    fn = fn or "<unresolved>"
    trigger = _trigger_for(cwe, disposition)
    parser_shaped = any(k in fn for k in _PARSER_SHAPE)
    if cwe in _PAYLOAD:
        recipe = (f"drive the CodeQL/ taint source that reaches {fn} with the payload; a script PoC "
                  f"(constructed) demonstrates the effect without a sanitizer")
        testable_now = False          # needs the dataflow source harnessed; recorded as constructed elsewhere
        reason = "injection/traversal: constructed script PoC (see drivable_confirm)"
    elif exported and parser_shaped:
        recipe = (f"direct libFuzzer/(buf,size) harness calling {fn} on the ASan-instrumented build; "
                  f"feed the trigger, confirm via the 0-FP gate")
        testable_now = True
        reason = "exported parser-shaped sink: build+run now"
    elif exported:
        recipe = (f"direct harness calling {fn} with scaffolded args on the instrumented build "
                  f"(signature-specific)")
        testable_now = False
        reason = "exported but not (buf,size)-shaped: needs per-signature arg scaffolding"
    else:
        recipe = (f"expose_static('{fn}') + rebuild the library, then call it with a built context "
                  f"(proven on AUDIN); confirm via the 0-FP gate")
        testable_now = False
        reason = "static sink: needs expose_static+rebuild"
    return PotentialPoC(finding_id=finding_id, cwe=cwe, fn=fn, disposition=disposition,
                        trigger=trigger, recipe=recipe, testable_now=testable_now, reason=reason)
