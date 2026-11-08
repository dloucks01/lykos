"""Finding TRIAGE -- resolve every candidate to a disposition, so none sits as a bare "candidate".

The operator's standing bar (see validated-poc-or-nothing): a finding is either driven to a PoC or
given an honest, SPECIFIC dead-end -- "corroborated, nothing further" is banned. With hundreds of
detector candidates, that resolution has to be mechanical. This module assigns each finding exactly
one disposition from signals the pipeline already computes -- grounding's verdict (is it a real
defect, and is it on the attacker surface) and the CWE's weaponization ceiling (how far a sound
exploit of this class can go) -- so the backlog becomes a RESOLVED ledger:

  CONFIRMED       -- already has a validated PoC. Done.
  DRIVABLE        -- real, attacker-reachable, memory-corruption class (ceiling rce/primitive):
                     the actionable PoC worklist -- a harness-confirm attempt should run on it.
  CEILING         -- real + reachable, but the class tops out below a memory PoC BY NATURE (logic =
                     the finding itself is the impact; leak / dos). The recipe is the deliverable;
                     no memory PoC is achievable, and saying so is the honest result, not a failure.
  OFF_SURFACE     -- real code, but not on the attacker-reachable surface under the threat model
                     (e.g. a local config path in a client tool). Honest dead-end with the reason.
  FALSE_POSITIVE  -- grounding PROVED it is not an exploitable defect (safe arithmetic, a literal
                     format string, instrumentation noise, non-shipping/test code).
  NEEDS_TECHNIQUE -- real + reachable + memory class, but no harness path exists yet; names the
                     specific missing capability rather than calling it blocked.

Pure and deterministic (a finding's signals -> a Disposition); the stage wrapper computes the
signals once per case and writes each disposition back onto the finding. (Named finding_triage to
avoid the unrelated ingest `triage` module.)
"""
from __future__ import annotations

from dataclasses import dataclass

from .cwe_coverage import CEILING

# grounding verdicts that mean "proved not a real defect" (grounded=False).
_FP_VERDICTS = {"arch-safe-mul", "format-literal", "instrumentation-noise", "non-shipping-code"}

CONFIRMED = "confirmed"
DRIVABLE = "drivable"
CEILING_ = "ceiling"
OFF_SURFACE = "off-surface"
FALSE_POSITIVE = "false-positive"
NEEDS_TECHNIQUE = "needs-technique"
UNTAINTED = "untainted"            # reachable, but the attacker does not control the dangerous value


@dataclass
class Disposition:
    status: str
    reason: str
    action: str = ""               # the concrete next step for a DRIVABLE / NEEDS_TECHNIQUE item


def triage_finding(*, cwe: "str | None", state: "str | None", has_poc: bool,
                   grounded: bool, verdict: "str | None", tainted: "bool | None" = None) -> Disposition:
    """Resolve one finding to a disposition. A PoC is a small script/input that EXPLOITS the finding
    (a traversal that escapes the dir, a command that runs, an input that crashes or corrupts) -- it
    need not be an ASan detonation. So the CWE class sets the PoC's IMPACT (rce/dos/leak/logic), not
    whether a PoC exists: anything attacker-reachable with an attacker-controlled dangerous value is
    DRIVABLE (a script PoC is constructible). The only true dead-ends are not-a-bug, not-reachable,
    and attacker-doesn't-control-the-value.

    Inputs: the CWE, lifecycle state, whether a PoC exists, grounding's (grounded, verdict), and
    `tainted` -- whether the attacker controls the dangerous operand (True from a proven dataflow
    path / strong taint, False when it is a constant/bounded local, None when undecided)."""
    if has_poc or state == "poc-backed":
        return Disposition(CONFIRMED, "has a PoC")

    if not grounded:
        return Disposition(FALSE_POSITIVE,
                           f"grounding disproved it ({verdict or 'not a reachable defect'})")

    ceiling = CEILING.get(cwe or "", "unknown")
    impact = {"rce": "memory-corruption/RCE-capable", "primitive": "corruption primitive",
              "leak": "info-disclosure", "dos": "denial-of-service", "logic": "logic/traversal/injection",
              "unknown": "unknown-impact"}.get(ceiling, ceiling)

    # reachability not yet decided (a recipe/derived finding with no verdict) -> decide it first.
    if verdict in (None, "undecided"):
        return Disposition(NEEDS_TECHNIQUE,
                           f"no reachability verdict yet ({cwe}, {impact}): decide reachability first",
                           action="run call-graph reachability + taint on this sink (source_reach + "
                                  "CodeQL/srctaint); if reached+tainted it becomes drivable")

    # not on the attacker-reachable surface -> no remote PoC (honest dead-end with the reason).
    if verdict == "off-surface-candidate":
        return Disposition(OFF_SURFACE,
                           f"not on the attacker-reachable surface ({impact} class); reachable only "
                           f"if a caller exposes it (e.g. a local/CLI path)")

    # reachable, but the attacker does NOT control the dangerous value (constant/bounded local --
    # the rfx_differential case): genuinely not exploitable, not just 'no technique'.
    if tainted is False:
        return Disposition(UNTAINTED,
                           f"reachable but the dangerous operand is not attacker-controlled "
                           f"(constant/bounded local) -- no PoC exists for {cwe}")

    # reachable + (tainted True or taint-unknown): a script PoC is constructible. Impact = the class.
    tag = "attacker-tainted" if tainted else "taint-unknown"
    return Disposition(DRIVABLE,
                       f"reachable + {tag} ({cwe}, impact: {impact}): construct a PoC",
                       action="build a script/input that drives the attacker-controlled value to the "
                              "sink and demonstrates the effect (dataflow-guided; concolic/symbolic "
                              "solve first, bounded fuzz only as fallback)")


def ledger(dispositions: list) -> dict:
    """Summarise a list of (finding_id, Disposition) into counts per status + the drivable worklist."""
    by: dict = {}
    drivable: list = []
    for fid, d in dispositions:
        by[d.status] = by.get(d.status, 0) + 1
        if d.status == DRIVABLE:
            drivable.append(fid)
    return {"total": len(dispositions), "by_status": by, "drivable": drivable,
            "resolved": all(d.status for _f, d in dispositions)}
