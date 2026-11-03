"""`attack_path` stage -- compose the run's findings into a full attacker path and file it.

Runs after triage/weaponize: reads the target's findings (+ their PoC rungs), searches the capability
graph (attack_path.find_attack_path) for the deepest attacker path to an objective, and files it as a
first-class finding (channel "attack-path") the report renders as an entry->...->objective narrative.
This is the cross-linking spine over the flat finding list -- which vulnerabilities chain, in what
order, and what each step buys. Cheap, offline, deterministic.
"""
from __future__ import annotations

from ..db.dao import FindingDAO, PocDAO, TargetDAO
from ..jobs.registry import register_stage
from . import attack_path
from .triage_stage import _finding_dict

ATTACK_PATH_STAGE = "attack_path"
TOOL = "lykos.attack_path"
TOOL_VERSION = "1"

#: findings we don't treat as attack-graph edges (bookkeeping / meta rows).
_SKIP_DETECTORS = {"grounding", "coverage_sweep", "triage", "finding_triage", "chain_primitive"}


def attack_path_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("attack_path requires a target_id")
    fd = FindingDAO(ctx.conn)
    pd = PocDAO(ctx.conn)
    pocs = [{"finding_id": p.finding_id, "level": p.level} for p in pd.list_by_target(target.id)
            if p.finding_id]

    findings = []
    for f in fd.list_by_target(target.id):
        if (f.detector or "") in _SKIP_DETECTORS:
            continue
        fdict = _finding_dict(f)
        findings.append({"cwe": f.cwe, "id": f.id,
                         "function": fdict.get("site_detail") or (f.title or "")[:40]})

    path = attack_path.find_attack_path(findings, pocs=pocs)
    if not path.steps:
        return {"metrics": {"attack_path": "no composable path from the findings"}}

    # STAGED DETONATION: a reached-RCE memory path is not just a composition claim -- drive it to a
    # demonstrated end-to-end exploit. Reflect an existing detonation (chain_primitive's leak->groom
    # L3), or, when the leak and write edges were not composed upstream, detonate the path here via
    # the same leak->groom chain keyed off the path's write edge. Best-effort; never sinks the stage.
    deto = _detonate_rce_path(ctx, target, path)

    rendered = attack_path.format_path(path)
    rendered += f"\n[{deto['status'] or 'not detonated'}] end-to-end: {deto['detail']}"
    steps = [{"gained": list(s.gained), "label": s.label, "cwe": s.cwe,
              "function": s.function, "level": s.level, "technique": s.technique}
             for s in path.steps]
    # file the path on the deepest finding edge (or as a target-level row when the path is all
    # technique edges). poc-backed only reflects the edges; the path itself is a composition claim.
    lead_cwe = next((s.cwe for s in reversed(path.steps) if s.cwe), None) or "CWE-000"
    sev = "critical" if path.objective == attack_path.RCE else (
        "high" if path.reached else "medium")
    state = "poc-backed" if deto["status"] else "candidate"
    fd.upsert(target.id, target.case_id, {
        "cwe": lead_cwe, "title": f"Attack path: {'->'.join(s.gained[0] for s in path.steps)}"
                                   f" ({'reached ' + path.objective if path.reached else 'ceiling'})",
        "detector": "attack_path", "severity": sev, "state": state,
        "dedup_key": f"attack_path:{target.id}",
        "evidence": [{"channel": "attack-path",
                      "detail": rendered[:1600]},
                     {"channel": "attack-path-steps", "detail": _json_steps(steps)}]})
    return {"metrics": {"objective": path.objective, "reached": path.reached,
                        "steps": len(path.steps), "detonated": deto["status"],
                        "edges": [s.cwe for s in path.steps if s.cwe],
                        "capabilities": sorted(path.gained_caps)}}


#: memory-write CWE classes whose edge is the detonatable write of the leak->groom tail.
_WRITE_CWES = {"CWE-787", "CWE-122", "CWE-120", "CWE-121", "CWE-124", "CWE-131", "CWE-190",
               "CWE-129", "CWE-416", "CWE-415", "CWE-822", "CWE-823"}


def _detonate_rce_path(ctx, target, path) -> dict:
    """For a reached-RCE path, return its end-to-end demonstration status:
      {"status": "reflected"|"detonated"|None, "detail": str}.
    'reflected' when a verified L3 already exists (chain_primitive detonated the leak->groom tail);
    'detonated' when we drive it here (the cross-finding composition chain_primitive's single-lead
    logic may have missed); None when not a detonatable RCE path. Never raises."""
    if not (path.reached and path.objective == attack_path.RCE):
        return {"status": None, "detail": "not a reached-RCE path"}
    try:
        from ..db.dao import PocDAO
        if any(p.verified and (p.level or "") == "L3" for p in PocDAO(ctx.conn).list_by_target(target.id)):
            return {"status": "reflected", "detail": "leak->write->control detonated (verified L3 present)"}
    except Exception:                                        # noqa: BLE001
        pass
    # Attempt the detonation here, keyed off the path's write edge, on a detonatable PIE native target.
    if (target.mitigations or {}).get("pie") != "on":
        return {"status": None, "detail": "write primitive present but target is not PIE (leak-groom needs the base leak)"}
    try:
        from .dynamic import sandbox
        if sandbox.host_arch() != "x86-64" or (target.arch or "") not in ("x86-64", "x86_64", "amd64"):
            return {"status": None, "detail": "leak-groom detonation is x86-64 native only"}
        from ..db.dao import CallEdgeDAO, FindingDAO
        from .poc import chain_primitive, exploit
        # Detonate with the strongest CONCRETE write primitive on the target (a heap fptr-call /
        # overflow we can groom), independent of which logical write edge the path happened to pick
        # -- the path proves RCE is reachable; detonation uses the best real primitive.
        leads = [f for f in FindingDAO(ctx.conn).list_by_target(target.id)
                 if (f.cwe or "") in _WRITE_CWES or f.detector == "heap_fptr_call"]
        leads.sort(key=lambda f: (f.detector == "heap_fptr_call", (f.cwe or "") == "CWE-822",
                                  float(getattr(f, "confidence", 0.0) or 0.0)), reverse=True)
        if not leads:
            return {"status": None, "detail": "no concrete write primitive to detonate the path"}
        lead = leads[0]
        tb = ctx.content.path(target.sha256).read_bytes()
        functions = exploit.elf_functions(tb)
        edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        win = exploit.find_win(functions, call_edges=edges)
        win = win if win and win[0] else None
        res = chain_primitive._leak_groom_chain(ctx, target, tb, lead, win, dict(ctx.params))
        if res:
            return {"status": "detonated", "detail": "composed leak->groom->control across the path edges (L3)"}
    except Exception:                                        # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug("attack-path detonation skipped", exc_info=True)
    return {"status": None, "detail": "path reaches RCE but end-to-end detonation did not confirm "
                                      "here (needs the op-model / a live channel) -- recipe ceiling, "
                                      "names the technique to build next"}


def _json_steps(steps) -> str:
    import json
    return json.dumps(steps)[:2000]


register_stage(ATTACK_PATH_STAGE, attack_path_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_attack_path(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, ATTACK_PATH_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
