"""`drivable_confirm` stage (F5, doc 60) -- confirm the DRIVABLE findings, NON-FUZZING FIRST.

The operator's standing priority: construct a PoC without blind execution where possible; fuzzing is
the additive fallback, not the default. A PoC here is a small script/input that EXPLOITS the finding
(doc 58 provenance "constructed" when built from analysis, "detonated" when a sanitizer confirmed it).

For each drivable finding this picks the first applicable strategy, in order:
  1. STATIC dataflow proof  -- a CodeQL source->sink path already proves the attacker reaches the
     sink; for an injection/traversal class the exploit is to send the malicious value, so we
     CONSTRUCT that payload input from the path. No execution.
  2. CONCOLIC / SYMBOLIC solve -- hand the sink to the directed solver (existing concolic/uc stages)
     to CONSTRUCT an input that drives a triggering value (recorded as the plan for that stage).
  3. CONSTRUCTED payload -- a class-specific crafted input (traversal/command/overflow length).
  4. BOUNDED FUZZ -- only as the fallback, on the reachable harnessable sink.

This module is the router + the payload constructor (pure, testable); it files a constructed-PoC
artifact for the classes it can build directly, and records the chosen strategy for the rest so the
downstream confirmers (and the operator) see a concrete non-fuzzing-first plan per finding.
"""
from __future__ import annotations

from ..db.dao import FindingDAO, PocDAO, TargetDAO
from ..jobs.registry import register_stage
from . import finding_triage, grounding
from .triage_stage import _finding_dict, _stored_grounding, _operand_tainted
from .grounding_stage import _source_root
from .source_lookup import source_project_for

DRIVABLE_CONFIRM_STAGE = "drivable_confirm"
TOOL = "lykos.drivable_confirm"
TOOL_VERSION = "1"

#: a class-appropriate exploit payload for a constructed script PoC. The value an attacker supplies
#: at the tainted source so the effect fires at the sink.
_PAYLOAD = {
    "CWE-22":  ("../../../../../../etc/passwd", "path traversal: escape the intended directory"),
    "CWE-23":  ("../../../../../../etc/passwd", "relative path traversal"),
    "CWE-78":  ("; id #", "OS command injection: append a command"),
    "CWE-77":  ("; id #", "command injection"),
    "CWE-88":  ("--output=/tmp/x", "argument injection"),
    "CWE-134": ("%n%n%n%n", "format string: attacker-controlled conversion specifiers"),
    "CWE-89":  ("' OR '1'='1", "SQL injection"),
}


def strategy_for(cwe: "str | None", has_dataflow: bool) -> str:
    """The non-fuzzing-first strategy for a drivable finding. Injection/traversal/format classes get
    a directly-constructed payload (strongest when a dataflow path proves reach); memory classes go
    to the concolic/symbolic solver; everything falls back to bounded fuzz last."""
    if cwe in _PAYLOAD:
        return "construct-payload"
    mem = cwe in {"CWE-787", "CWE-125", "CWE-122", "CWE-120", "CWE-121", "CWE-416", "CWE-415",
                  "CWE-190", "CWE-191", "CWE-124", "CWE-680", "CWE-131"}
    if mem:
        return "concolic-solve"
    return "bounded-fuzz"


def construct_payload(cwe: "str | None", dataflow: str = "") -> "dict | None":
    """A constructed script-PoC for an injection/traversal/format finding: the payload the attacker
    supplies and the effect it demonstrates. `dataflow` (CodeQL source->sink) is the reach proof.
    Returns None for a class with no direct payload (handed to the solver instead)."""
    p = _PAYLOAD.get(cwe or "")
    if not p:
        return None
    payload, effect = p
    return {"payload": payload, "effect": effect,
            "proof": f"dataflow: {dataflow}" if dataflow else "reach by call graph",
            "provenance": "constructed",
            "note": "analysis-constructed script PoC (dataflow-proven reach + exploit payload); "
                    "not detonated -- run against the built target to detonate"}


def _dataflow(fdict) -> str:
    for e in fdict.get("evidence") or []:
        if isinstance(e, dict) and e.get("channel") == "codeql-dataflow":
            return str(e.get("detail", ""))[:200]
    return ""


def drivable_confirm_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("drivable_confirm requires a target_id")
    fd = FindingDAO(ctx.conn)
    pd = PocDAO(ctx.conn)
    poc_fids = {p.finding_id for p in pd.list_by_target(target.id) if p.finding_id and p.verified}
    root = _source_root(ctx, target) if source_project_for(ctx.conn, target) else None
    lookup = grounding.make_source_lookup(root) if root else None
    textlookup = grounding.make_file_text_lookup(root) if root else None
    bits = target.bits or 64

    by_strategy: dict = {}
    constructed = 0
    for f in fd.list_by_target(target.id):
        if (f.detector or "") in ("grounding", "coverage_sweep", "triage"):
            continue
        fdict = _finding_dict(f)
        gm = _stored_grounding(fdict)
        if gm is not None:
            grounded, verdict = gm
        else:
            g = grounding.ground_finding(fdict, source_lookup=lookup, bits=bits)
            grounded = bool(g.get("grounded", True))
            verdict = g.get("verdict") if not grounded else "undecided"
        tainted = _operand_tainted(fdict, textlookup)
        disp = finding_triage.triage_finding(cwe=f.cwe, state=f.state, has_poc=(f.id in poc_fids),
                                             grounded=grounded, verdict=verdict, tainted=tainted)
        if disp.status != finding_triage.DRIVABLE:
            continue
        df = _dataflow(fdict)
        strat = strategy_for(f.cwe, bool(df))
        by_strategy[strat] = by_strategy.get(strat, 0) + 1
        if strat == "construct-payload":
            poc = construct_payload(f.cwe, df)
            if poc:
                # file the constructed script PoC as evidence + a PoC row (provenance constructed).
                fd.upsert(target.id, target.case_id, {
                    "cwe": f.cwe or "", "title": f.title, "detector": f.detector or "",
                    "dedup_key": f.dedup_key, "severity": f.severity, "state": f.state,
                    "evidence": [{"channel": "poc-constructed",
                                  "detail": f"payload={poc['payload']!r} -- {poc['effect']}; {poc['proof']}"}]})
                try:
                    pd.insert(target.id, target.case_id, finding_id=f.id, level="L1",
                              provenance="constructed", signal_name=f"constructed:{f.cwe}")
                    constructed += 1
                except Exception:                        # noqa: BLE001
                    pass
        else:
            # record the non-fuzzing-first plan so the downstream confirmer/operator sees it.
            fd.upsert(target.id, target.case_id, {
                "cwe": f.cwe or "", "title": f.title, "detector": f.detector or "",
                "dedup_key": f.dedup_key, "severity": f.severity, "state": f.state,
                "evidence": [{"channel": "confirm-plan",
                              "detail": f"strategy={strat} (non-fuzzing-first); "
                                        f"{'dataflow known' if df else 'reach by call graph'}"}]})
    return {"metrics": {"drivable_confirm_by_strategy": by_strategy,
                        "constructed_pocs": constructed}}


register_stage(DRIVABLE_CONFIRM_STAGE, drivable_confirm_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_drivable_confirm(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, DRIVABLE_CONFIRM_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
