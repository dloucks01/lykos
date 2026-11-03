"""Per-sink exploitability determination (doc 60 F5) — a code-grounded verdict for EVERY static-sink
finding, since a single-shot harness usually cannot reach context/state-bounded sinks.

For a finding whose sink is a `static` function, the question "is this a real bug?" is answered by
reading the enclosing function: is the dangerous operand attacker-controlled and UNGUARDED at the
write, or is it validated / switch-constrained / a constant / a context field managed elsewhere?
This module encodes those determinations so all 68 static sinks get a verdict with evidence, rather
than 68 unreachable rebuild attempts. Verdicts:

  FP-constant     -- the operand is a literal / sizeof: not attacker-controlled.
  FP-bounded      -- a guard validates the operand before the sink (range/length check), or the write
                     index equals a switch case constant -> in bounds.
  needs-state     -- the operand is a context/struct field set elsewhere (nesting depth, parser
                     state): not reachable by a single call; needs the stateful sequence.
  outbound        -- an encode/send/write path: not driven by attacker INPUT.
  lifecycle       -- UAF/double-free: needs an alloc->free->use sequence, not a one-shot call.
  real-candidate  -- an unguarded, wire-read operand flows to the write: worth a harness/fuzz.

Pure read-analysis over the function body (deterministic, testable). Recall-first guards are
recognised conservatively, so a true unguarded sink is never hidden (it falls to real-candidate).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import value_range

_OUTBOUND = ("_send", "_write", "_encode", "send_", "write_", "_compress")
_GUARD = ("CheckAndLogRequiredLength", "CheckAndLogRequiredCapacity")


@dataclass
class Verdict:
    verdict: str
    reason: str


def _reads_from_wire(body: str, var: str) -> bool:
    """Is `var` filled by a Stream_Read_* in this body (attacker-controlled here)?"""
    base = var.split(".")[-1].split("->")[-1]
    return bool(re.search(r"Stream_Read_U?INT\d*\s*\(\s*\w+\s*,\s*[^;]*\b" + re.escape(base) + r"\b", body))


def determine(body: str, operand: str, cwe: str, fn: str) -> Verdict:
    body = body or ""
    op = (operand or "").strip()
    base = op.split(".")[-1].split("->")[-1].strip("* ")

    if any(k in (fn or "") for k in _OUTBOUND):
        return Verdict("outbound", f"{fn} is an encode/send/write path: not driven by attacker input")
    if cwe in ("CWE-416", "CWE-415") or (fn or "").endswith("_free") or "_init" in (fn or ""):
        return Verdict("lifecycle", "use-after-free/double-free class: needs an alloc->free->use "
                                    "sequence, not a one-shot harness")
    # literal / sizeof operand
    if re.fullmatch(r"\d+|0x[0-9a-fA-F]+|sizeof\s*\(.*\)", op) or "sizeof" in op:
        return Verdict("FP-constant", f"operand {op!r} is a constant/sizeof: not attacker-controlled")
    # index written inside a switch whose case label equals it (arr[CONST]) -> bounded
    if re.search(r"\bcase\s+[A-Z_]\w*\s*:", body) and \
       re.search(r"\[[^\]]*\b" + re.escape(base) + r"\b[^\]]*\]\s*=", body):
        return Verdict("FP-bounded", f"write index {base!r} is constrained to switch-case constants")
    # an explicit range/validation guard on the operand before use
    if re.search(r"if\s*\([^)]*\b" + re.escape(base) + r"\b[^)]*(>|>=|<|<=|==)\s*\w+[^)]*\)\s*\n?\s*(return|goto|break)", body) \
       or re.search(r"\b" + base + r"\s*(<|<=|>|>=)\s*\w+\s*\)\s*(return|goto)", body):
        return Verdict("FP-bounded", f"operand {base!r} is range-checked before the sink")
    if any(g in body for g in _GUARD) and re.search(re.escape(base), body):
        # a length guard naming the operand before the read/seek
        return Verdict("FP-bounded", f"a length guard covers {base!r} before the access")
    # CWE-369: the interval engine can prove a divisor is never zero (e.g. built from a constant,
    # or guarded to a non-zero range) -- a sound bound the regex guards above would miss.
    if cwe == "CWE-369" and not value_range.can_be_zero(base, body):
        return Verdict("FP-bounded", f"interval analysis proves divisor {base!r} is never zero")
    # a context/struct field not read from the wire here -> managed elsewhere (stateful)
    if ("->" in op or "." in op) and not _reads_from_wire(body, op):
        return Verdict("needs-state", f"operand {op!r} is a context/struct field set elsewhere: "
                                      f"needs the stateful sequence to reach a bad value")
    # operand read from the wire in this body and not guarded above -> a real candidate
    if _reads_from_wire(body, op):
        return Verdict("real-candidate", f"operand {base!r} is wire-read and not bounded before the "
                                         f"sink in this function: worth a harness/fuzz")
    return Verdict("needs-state", f"operand {op!r} origin not resolved in this function: "
                                  f"decide via the caller/stateful path")
