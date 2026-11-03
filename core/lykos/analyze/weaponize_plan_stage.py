"""`weaponize_plan` stage -- attach a concrete TTP exploitation plan to the confirmed/drivable
memory-corruption findings, and a whole-target RCE plan, consuming the `weaponize_advanced` planners.

Runs AFTER build_exploit/drivable_confirm: the detonation stage tops out at an honest L3 ceiling, and
this stage answers "what technique carries it further". It never detonates; it records, per finding,
the heap-groom / UAF-reclaim / format-write TTP, and for the target the composed leak->write chain and
RCE primitive-graph verdict, so the report's weaponization section names the next technique to build
(the ceiling-is-a-limit-not-a-wall rule). Cheap, deterministic, defensive.
"""
from __future__ import annotations

from ..db.dao import FindingDAO, PocDAO, TargetDAO
from ..jobs.registry import register_stage
from . import weaponize_plan
from .triage_stage import _finding_dict

WEAPONIZE_PLAN_STAGE = "weaponize_plan"
TOOL = "lykos.weaponize_plan"
TOOL_VERSION = "1"

#: finding states / evidence channels that mark a finding as part of the real post-confirm worklist
#: (so we do not emit weaponization plans for triaged false positives / off-surface noise).
_LIVE_STATE = {"confirmed", "demonstrated"}
_LIVE_CHANNEL = {"poc-constructed", "confirm-plan", "primitive", "drivable"}


def _is_live(fdict: dict, has_poc: bool) -> bool:
    if has_poc or (fdict.get("state") or "") in _LIVE_STATE:
        return True
    for e in fdict.get("evidence") or []:
        if (e.get("channel") or "") in _LIVE_CHANNEL:
            return True
    return False


def weaponize_plan_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("weaponize_plan requires a target_id")
    fd = FindingDAO(ctx.conn)
    pd = PocDAO(ctx.conn)
    poc_fids = {p.finding_id for p in pd.list_by_target(target.id) if p.finding_id}

    live = []                                            # (finding, fdict) on the real worklist
    for f in fd.list_by_target(target.id):
        if (f.detector or "") in ("grounding", "coverage_sweep", "triage", "finding_triage"):
            continue
        if weaponize_plan.primitive_tag(f.cwe) is None:
            continue                                      # not a memory-corruption primitive class
        fdict = _finding_dict(f)
        if _is_live(fdict, f.id in poc_fids):
            live.append((f, fdict))

    planned = 0
    by_ttp: dict = {}
    for f, fdict in live:
        plan = weaponize_plan.plan_for_finding(f.cwe)
        if plan is None:
            continue
        verdict = "feasible" if plan.get("feasible") else "needs a prerequisite"
        steps = " | ".join(str(s) for s in (plan.get("plan") or []))[:400]
        detail = f"TTP {plan['ttp']} ({verdict}) -- {plan.get('note', '')}. steps: {steps}"
        fd.upsert(target.id, target.case_id, {
            "cwe": f.cwe or "", "title": f.title, "detector": f.detector or "",
            "dedup_key": f.dedup_key, "severity": f.severity, "state": f.state,
            "evidence": [{"channel": "weaponize-plan", "detail": detail}]})
        by_ttp[plan["ttp"]] = by_ttp.get(plan["ttp"], 0) + 1
        planned += 1

    # whole-target composition: can the confirmed primitive SET reach RCE, and if not, what is missing?
    tgt = weaponize_plan.plan_target([fd2 for _f, fd2 in live])
    rce = tgt["rce"]
    if live:
        lead = live[0][0]
        if rce["reachable"]:
            tdetail = ("RCE chain reachable from the confirmed primitives: " + " -> ".join(rce["chain"]))
        else:
            tdetail = ("RCE not yet reachable from the confirmed primitives " + str(tgt["primitives"]) +
                       "; missing: " + "; ".join(rce["needs"]))
        if tgt["leak_write_chain"]:
            tdetail += " || leak->write chain: " + " -> ".join(tgt["leak_write_chain"]["stages"])
        fd.upsert(target.id, target.case_id, {
            "cwe": lead.cwe or "", "title": lead.title, "detector": lead.detector or "",
            "dedup_key": lead.dedup_key, "severity": lead.severity, "state": lead.state,
            "evidence": [{"channel": "weaponize-target", "detail": tdetail}]})

    return {"metrics": {"weaponize_plans": planned, "by_ttp": by_ttp,
                        "target_primitives": tgt["primitives"], "rce_reachable": rce["reachable"],
                        "rce_needs": rce["needs"]}}


register_stage(WEAPONIZE_PLAN_STAGE, weaponize_plan_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_weaponize_plan(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, WEAPONIZE_PLAN_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
