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

    rendered = attack_path.format_path(path)
    steps = [{"gained": list(s.gained), "label": s.label, "cwe": s.cwe,
              "function": s.function, "level": s.level, "technique": s.technique}
             for s in path.steps]
    # file the path on the deepest finding edge (or as a target-level row when the path is all
    # technique edges). poc-backed only reflects the edges; the path itself is a composition claim.
    lead_cwe = next((s.cwe for s in reversed(path.steps) if s.cwe), None) or "CWE-000"
    sev = "critical" if path.objective == attack_path.RCE else (
        "high" if path.reached else "medium")
    fd.upsert(target.id, target.case_id, {
        "cwe": lead_cwe, "title": f"Attack path: {'->'.join(s.gained[0] for s in path.steps)}"
                                   f" ({'reached ' + path.objective if path.reached else 'ceiling'})",
        "detector": "attack_path", "severity": sev, "state": "candidate",
        "dedup_key": f"attack_path:{target.id}",
        "evidence": [{"channel": "attack-path",
                      "detail": rendered[:1500]},
                     {"channel": "attack-path-steps", "detail": _json_steps(steps)}]})
    return {"metrics": {"objective": path.objective, "reached": path.reached,
                        "steps": len(path.steps),
                        "edges": [s.cwe for s in path.steps if s.cwe],
                        "capabilities": sorted(path.gained_caps)}}


def _json_steps(steps) -> str:
    import json
    return json.dumps(steps)[:2000]


register_stage(ATTACK_PATH_STAGE, attack_path_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_attack_path(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, ATTACK_PATH_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
