"""doc 58: record a SOUNDLY-CONSTRUCTED PoC as a first-class result.

The confirmation model this fixes (see `recipe.py`'s old honesty contract): historically a payload
computed from the recovered program -- exact bytes, a complete reach+trigger argument -- was filed
as a `corroborated` RECIPE ("not executed here"), the same rung as a hand-wavy "find the offset with
a %p dump" note. That conflation is why real engagements produced "candidates and corroborations, no
PoCs": a target pulled off another system usually cannot be executed here (missing libraries /
configs / foreign CPU), so nothing ever reached the execution-only `confirmed`/`poc-backed` rungs.

This module splits the two. A construction whose soundness argument is COMPLETE -- every fact it
rests on is a literal fact of the binary (no PIE so the GOT slot is absolute, the format register is
fed by the stack buffer, the overflow offset is the recovered frame) with NO unproven assumption --
is a real PoC: the finding is raised to `confirmed` (doc: "verified by analysis as a real, reachable
defect"), provenance `constructed`, carrying the concrete payload and a lightweight few-line repro.
Detonation, WHEN the target can run (here or once the operator supplies the named deps), upgrades it
to `poc-backed`/`detonated`. 0-false-confirmation is preserved, not relaxed: the caller must only
pass a COMPLETE argument -- an incomplete one (needs a leak under PIE, offset needs a probe) still
goes to `recipe.file_recipe` as `corroborated`.
"""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from ... import observe
from ...db.dao import FindingDAO, PocDAO

_log = logging.getLogger(__name__)

#: A sound construction, not executed here -> "verified by analysis as a real, reachable defect".
CONSTRUCTED_STATE = "confirmed"
#: An execution fired the class oracle.
DETONATED_STATE = "poc-backed"
#: A construction is more than corroborated (a concrete, complete weaponization) and, undetonated,
#: just under a fired reproducer.
CONSTRUCTED_CONFIDENCE = 0.8
DETONATED_CONFIDENCE = 0.95


def record_constructed_poc(ctx, target, *, cwe: str, technique: str, level: str,
                           payload: bytes, soundness: Sequence[str], reproduce: str,
                           input_mode: str = "stdin", argv: Optional[list] = None,
                           severity: str = "high", detector: str = "construct",
                           dedup_key: Optional[str] = None, title: Optional[str] = None,
                           summary: Optional[str] = None, lead=None,
                           detonated: bool = False, signal_name: Optional[str] = None,
                           function_addr=None, site_addr=None,
                           extra_evidence: Optional[list] = None) -> Optional[str]:
    """File a soundly-constructed PoC. Returns the finding id, or None on failure.

    payload      the concrete triggering bytes, computed from the program.
    level        "L1" | "L2" | "L3" -- the rung this PoC reaches.
    soundness    the COMPLETE reach+trigger argument as a list of plain-fact lines (each a literal
                 fact of the binary). Non-empty and complete is the caller's contract; an incomplete
                 argument must use recipe.file_recipe instead (this never relaxes 0-false-confirm).
    reproduce    the lightweight deliverable: a few lines / one command an operator runs as-is.
    detonated    True once an execution fired the class oracle -> poc-backed/detonated; else the
                 construction stands on its soundness argument -> confirmed/constructed.
    signal_name  the oracle signal when detonated (e.g. "win-reached", "SIGSEGV").
    """
    if not payload or not soundness:
        return None
    if level not in ("L1", "L2", "L3"):
        level = "L2"
    key = dedup_key or f"poc:{cwe}:{technique}:{target.id}"
    prov = "detonated" if detonated else "constructed"
    state = DETONATED_STATE if detonated else CONSTRUCTED_STATE
    head = summary or f"{technique}: constructed {level} PoC"
    # the payload itself, stored once and referenced by both the evidence and the PoC row
    try:
        sha = ctx.put_artifact("poc-input", data=bytes(payload),
                               meta={"cwe": cwe, "technique": technique, "mode": input_mode})
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "constructed PoC payload not stored")
        return None
    dmode = f" over {input_mode}" if input_mode else ""
    dargv = f" with argv {argv}" if argv else ""
    ev = [
        {"channel": "soundness",
         "detail": (("DETONATED -- " if detonated else "CONSTRUCTED (sound, not executed here) -- ")
                    + head + "\n" + "\n".join(f"- {s}" for s in soundness))},
        {"channel": "poc-input",
         "detail": (f"PoC payload ({len(payload)} bytes){dmode}{dargv}; artifact {sha[:12]}"
                    + ("; detonated here, oracle fired" if detonated else
                       "; sound by construction -- deliver to the live target to detonate"))},
        {"channel": "reproduce", "detail": reproduce.strip()},
    ]
    if detonated and signal_name:
        ev.append({"channel": "detonation", "detail": f"oracle fired: {signal_name}"})
    if extra_evidence:
        ev.extend(extra_evidence)
    try:
        fd = FindingDAO(ctx.conn)
        row = {
            "cwe": cwe, "title": title or f"{technique} ({'detonated' if detonated else 'constructed'} {level} PoC)",
            "severity": severity, "detector": detector, "state": state,
            "confidence": DETONATED_CONFIDENCE if detonated else CONSTRUCTED_CONFIDENCE,
            "dedup_key": key, "site_detail": technique, "evidence": ev}
        # link the finding to its code so the UI can pull the function's disasm/frame/xrefs
        if function_addr is not None:
            row["function_addr"] = function_addr
        if site_addr is not None:
            row["site_addr"] = site_addr
        fd.upsert(target.id, target.case_id, row)
        fid = fd.id_for_dedup(target.id, key)
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "constructed PoC finding not filed")
        return None
    try:
        pd = PocDAO(ctx.conn)
        # dedup: this stage is reachable from more than one caller (inject + exploit), so guard
        # against inserting the same constructed PoC twice for one finding.
        dup = any(getattr(x, "finding_id", None) == fid and getattr(x, "input_sha", None) == sha
                  and getattr(x, "provenance", None) == prov
                  for x in pd.list_by_target(target.id))
        if not dup:
            pid = pd.insert(target.id, target.case_id, finding_id=fid, level=level,
                            verified=detonated, provenance=prov, input_sha=sha,
                            signal_name=signal_name)
            if fid:
                pd.set_finding(pid, fid)
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "constructed PoC row not inserted")
    try:
        ctx.emit("construct.poc", payload={"cwe": cwe, "technique": technique, "level": level,
                                           "provenance": prov, "finding_id": fid})
    except Exception:                                    # noqa: BLE001
        pass
    return fid
