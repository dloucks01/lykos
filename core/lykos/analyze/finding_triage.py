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


@dataclass
class Disposition:
    status: str
    reason: str
    action: str = ""               # the concrete next step for a DRIVABLE / NEEDS_TECHNIQUE item


def triage_finding(*, cwe: "str | None", state: "str | None", has_poc: bool,
                   grounded: bool, verdict: "str | None") -> Disposition:
    """Resolve one finding. Inputs: its CWE, lifecycle state, whether a PoC exists, and grounding's
    (grounded, verdict). Returns the single disposition, with a specific reason."""
    if has_poc or state == "poc-backed":
        return Disposition(CONFIRMED, "has a validated PoC")

    if not grounded:
        return Disposition(FALSE_POSITIVE,
                           f"grounding disproved it ({verdict or 'not a reachable defect'})")

    ceiling = CEILING.get(cwe or "", "unknown")

    # off the attacker surface: real code, but not reached under the malicious-peer threat model.
    if verdict == "off-surface-candidate":
        if ceiling in ("rce", "primitive"):
            return Disposition(OFF_SURFACE,
                               "memory-corruption class but its code is not on the attacker-reachable "
                               "surface (e.g. a local/CLI path); reachable only if a caller exposes it")
        return Disposition(OFF_SURFACE, f"not on the attacker surface; class ceiling is {ceiling}")

    # grounded + (on-surface or reachability-unknown): classify by the weaponization ceiling.
    if ceiling == "logic":
        return Disposition(CEILING_,
                           "logic/auth/crypto/traversal class: the finding IS the impact (reaching "
                           "the sink); no memory PoC exists by nature -- the recipe is the deliverable")
    if ceiling == "leak":
        return Disposition(CEILING_, "out-of-bounds READ class: tops out at information disclosure; "
                                     "an enabler for another bug's L3, not a memory-control PoC")
    if ceiling == "dos":
        return Disposition(CEILING_, "availability class (assert/abort/exhaustion): tops out at DoS; "
                                     "a reachable-assert PoC is the deliverable, not RCE")
    if ceiling in ("rce", "primitive"):
        tag = "reachable" if verdict == "exploitable-candidate" else "reachability-unknown"
        return Disposition(DRIVABLE,
                           f"memory-corruption class ({cwe}), {tag}: attempt a harness-confirm PoC",
                           action="synthesize a harness that reaches the sink on the "
                                  "ASan-instrumented build and drive it (exported entry, or "
                                  "expose_static+rebuild for a static/dispatcher-gated sink)")
    return Disposition(NEEDS_TECHNIQUE,
                       f"class {cwe} (ceiling {ceiling}) has no automated confirmation path yet",
                       action="name and build the missing detector/confirmation technique")


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
