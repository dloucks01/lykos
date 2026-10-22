"""Deterministic, non-executed exploitation recipes -- the honest middle rung between a detected
defect (L0) and a demonstrated one (verified L1/L2/L3).

A synthesizer frequently COMPUTES a complete weaponization from the recovered program alone -- an
overflow offset + payload bytes, a command-injection string + delivery channel, a %n write plan +
GOT slot, an out-of-bounds index + write target, a ROP chain -- and can then only CONFIRM it by
RUNNING the target. In a real air-gapped engagement the target often cannot be executed (its own
shared libraries are absent), and a single detonation that does not fault is not proof of absence
either. Historically every such stage DISCARDED the computed artifact on that path and left the
finding at L0 with "no follow-up" -- the exact opposite of what the analysis actually produced.

`file_recipe` files that artifact as a first-class CANDIDATE: a `corroborated` finding carrying the
concrete steps/inputs, titled "Exploitation recipe: ...", explicitly marked "not executed here
(why)". It is the generalisation of the one stage that already did this right -- `chain_primitive`'s
`_file_recipe` / `_annotate_lead_ceiling` -- promoted so EVERY escalator uses one path.

Honesty contract (this module must never violate it -- precision is paramount):
  * A recipe is NEVER filed as `poc-backed` / `demonstrated` and NEVER carries `verified=True`.
    Those states are reserved for an artifact an execution actually confirmed. A recipe is
    `corroborated` at most -- "derived from the recovered program, not demonstrated here".
  * `target_level` is the rung the recipe TARGETS if finished (L1/L2/L3). It is recorded as a
    candidate CEILING ("reaches L2 and stops"), never asserted as achieved.
  * Everything in the recipe is computed from the binary; the row says plainly what was and was not
    proven and why confirmation did not happen. No step is invented to look complete.
  * A recipe does not overwrite or downgrade a stronger row: it uses its own `dedup_key` and, when a
    verified PoC for the same defect already exists, the caller should skip filing a recipe.
"""
from __future__ import annotations

import logging
from typing import Optional

from ... import observe
from ...db.dao import FindingDAO

_log = logging.getLogger(__name__)

#: The only state a non-executed recipe may claim. More than `candidate` (a flat pattern match):
#: the weaponization is concretely derived. Less than `poc-backed`: nothing ran to confirm it.
RECIPE_STATE = "corroborated"
RECIPE_CONFIDENCE = 0.5


def annotate_lead_ceiling(ctx, target, lead, *, target_level: str, why: str) -> None:
    """Record ON THE LEAD (the L0 detection) how far its weaponization got and why it stopped, in
    the lead's own evidence channel so the detected defect and its recipe are linked and the
    account survives a re-run of whichever detector owns the lead row. Generalised from
    `chain_primitive._annotate_lead_ceiling`. Best-effort: never fails the caller."""
    if lead is None:
        return
    try:
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": getattr(lead, "cwe", None), "title": getattr(lead, "title", None),
            "severity": getattr(lead, "severity", "medium"),
            "detector": getattr(lead, "detector", None), "state": getattr(lead, "state", None),
            "confidence": getattr(lead, "confidence", None),
            "dedup_key": getattr(lead, "dedup_key", None),
            "evidence": [{"channel": "recipe-ceiling",
                          "detail": f"weaponization reached {target_level} and stopped here: {why}"}]})
    except Exception:                                    # noqa: BLE001 -- never fail the filing
        observe.absorbed(_log, "leaving the lead alone")


def file_recipe(ctx, target, *, cwe: str, technique: str, target_level: str, summary: str,
                why_not_executed: str, severity: str = "high", steps: Optional[list] = None,
                detector: str = "recipe", dedup_key: Optional[str] = None,
                title: Optional[str] = None, confidence: float = RECIPE_CONFIDENCE,
                lead=None, extra_evidence: Optional[list] = None,
                input_bytes: Optional[bytes] = None, input_mode: Optional[str] = None,
                argv: Optional[list] = None) -> Optional[int]:
    """File a NON-EXECUTED exploitation recipe as a `corroborated` candidate finding, and annotate
    its originating lead with the ceiling. Returns the recipe finding's id, or None on failure.

    Parameters:
      cwe            the weakness class the recipe weaponizes (carried onto the row).
      technique      the concrete technique, e.g. "stack-overflow-ret-overwrite", "command-injection
                     via stdin", "oob-index-write", "format-string %n write-what-where".
      target_level   "L1" | "L2" | "L3" -- the rung this recipe would REACH if executed. Recorded as
                     a candidate ceiling, never as an achieved level.
      summary        one concrete line: what the recipe is + the key computed fact (offset, payload,
                     index, GOT slot). This is the deliverable the operator carries to the target.
      why_not_executed  why confirmation did not happen (no execution in this environment / the one
                     detonation did not fault / target could not be loaded). Stated plainly.
      steps          optional list of human-readable steps; joined into the evidence detail.
      dedup_key      defaults to "recipe:{cwe}:{technique}:{target.id}" so a recipe is its OWN row
                     and never collides with the lead or a verified PoC.
      lead           the originating L0 finding row, annotated with the ceiling when given.
      extra_evidence optional additional evidence dicts (e.g. a stored unverified-input artifact ref).
    """
    if target_level not in ("L1", "L2", "L3"):
        target_level = "L2"
    key = dedup_key or f"recipe:{cwe}:{technique}:{target.id}"
    detail = summary.strip()
    if steps:
        detail += "\nsteps: " + " | ".join(str(s) for s in steps)
    detail += (f"\nNOT executed here ({why_not_executed}) -- this is a synthesized recipe, "
               f"not a demonstrated exploit. Targets {target_level} if run against the live target.")
    ev = [{"channel": "recipe", "detail": detail}]
    # Hand over the ACTUAL computed bytes the operator carries to the live target. Stored as a plain
    # artifact, NOT a verified PoC bundle -- the report/GUI count only verified PoCs as demonstrated,
    # so this inflates nothing. It is the difference between "here is how" and "here is the input".
    if input_bytes is not None:
        try:
            sha = ctx.put_artifact("recipe-input", data=bytes(input_bytes))
            dmode = f" over {input_mode}" if input_mode else ""
            dargv = f" with argv {argv}" if argv else ""
            ev.append({"channel": "recipe-input",
                       "detail": (f"candidate input ({len(input_bytes)} bytes){dmode}{dargv}; "
                                  f"artifact {sha[:12]} -- deliver to the live target to confirm "
                                  f"(not executed here)")})
        except Exception:                                # noqa: BLE001 -- the prose recipe still stands
            observe.absorbed(_log, "recipe input not stored")
    if extra_evidence:
        ev.extend(extra_evidence)
    try:
        fd = FindingDAO(ctx.conn)
        fd.upsert(target.id, target.case_id, {
            "cwe": cwe, "title": title or f"Exploitation recipe: {technique} (targets {target_level})",
            "severity": severity, "detector": detector, "state": RECIPE_STATE,
            "confidence": confidence, "dedup_key": key, "site_detail": technique,
            "evidence": ev})
        fid = fd.id_for_dedup(target.id, key)
    except Exception:                                    # noqa: BLE001 -- advisory, never fatal
        observe.absorbed(_log, "recipe not filed")
        return None
    annotate_lead_ceiling(ctx, target, lead, target_level=target_level, why=why_not_executed)
    return fid
