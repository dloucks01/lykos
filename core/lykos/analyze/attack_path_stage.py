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

    # STAGED DETONATION: a reached path is not just a composition claim -- drive it to a demonstrated
    # exploit. Dispatched by objective: a memory RCE path via the leak->groom chain (detonated L3); an
    # injection objective (cmd/sql/file) via a constructed payload (L1); a DoS by the crash finding it
    # already carries. Best-effort; never sinks the stage, and stays honest ("recipe ceiling") when
    # no detonator applies here.
    deto = _detonate_path(ctx, target, path)

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


def _detonate_path(ctx, target, path) -> dict:
    """Dispatch a reached path to the detonator for its objective and return the demonstration
    status {"status": "reflected"|"detonated"|"constructed"|None, "detail": str}. Extensible: each
    objective maps to the mechanism that proves THAT kind of attack (memory->chain, injection->
    payload, dos->the crash). Never raises."""
    if not path.reached:
        return {"status": None, "detail": "no objective reached from the attacker's entry"}
    # DATA-ONLY (DOP): if the path reaches its objective THROUGH a data-only write->auth edge, try to
    # demonstrate it directly on a binary target -- flip a security-decision variable so the program
    # takes the privileged path, discovered hands-off (no marker/distance). CFI-immune, leak-free.
    if any(s.technique and "data-only" in (s.label or "") for s in path.steps):
        d = _detonate_data_only(ctx, target)
        if d["status"]:
            return d
    obj = path.objective
    if obj == attack_path.RCE:
        return _detonate_memory_rce(ctx, target, path)
    if obj in (attack_path.CMD, attack_path.SQL, attack_path.FILE):
        return _construct_injection(ctx, target, path, obj)
    if obj == attack_path.DOS:
        return _reflect_dos(ctx, target)
    return {"status": None, "detail": f"no detonator wired for objective {obj}"}


#: CWE -> the injection objective it reaches directly (the last edge of a cmd/sql/file path).
_INJECTION_CWE = {attack_path.CMD: {"CWE-78", "CWE-77", "CWE-88"},
                  attack_path.SQL: {"CWE-89"}, attack_path.FILE: {"CWE-22", "CWE-23", "CWE-98"}}


def _construct_injection(ctx, target, path, obj) -> dict:
    """Injection/traversal objective: the exploit is a CONSTRUCTED payload (doc-58 provenance
    'constructed'), not a memory detonation. Reflect an existing PoC, else construct the class
    payload and file it at L1 so the path's objective edge is demonstrated by a concrete trigger."""
    try:
        from ..db.dao import FindingDAO, PocDAO
        from . import drivable_confirm
        want = _INJECTION_CWE.get(obj, set())
        edge = next((f for f in FindingDAO(ctx.conn).list_by_target(target.id)
                     if (f.cwe or "") in want), None)
        if edge is None:
            return {"status": None, "detail": f"{obj}: no injection finding to construct from"}
        if any(p.finding_id == edge.id and p.verified for p in PocDAO(ctx.conn).list_by_target(target.id)):
            return {"status": "reflected", "detail": f"{obj}: injection PoC already verified"}
        poc = drivable_confirm.construct_payload(edge.cwe)
        if not poc:
            return {"status": None, "detail": f"{obj}: no constructor for {edge.cwe}"}
        PocDAO(ctx.conn).insert(target.id, target.case_id, finding_id=edge.id, level="L1",
                                provenance="constructed", signal_name=f"attack_path:{obj}")
        return {"status": "constructed",
                "detail": f"{obj}: constructed payload {poc['payload']!r} -- {poc['effect']}"}
    except Exception:                                        # noqa: BLE001
        return {"status": None, "detail": f"{obj}: construction skipped"}


def _reflect_dos(ctx, target) -> dict:
    """A DoS path is demonstrated by the crash the run already has (a verified crash/abort PoC or a
    dyn_result fault). Reflect it; otherwise it is a static ceiling."""
    try:
        from ..db.dao import PocDAO
        if any(p.verified for p in PocDAO(ctx.conn).list_by_target(target.id)):
            return {"status": "reflected", "detail": "dos: a verified crash PoC demonstrates it"}
    except Exception:                                        # noqa: BLE001
        pass
    return {"status": None, "detail": "dos: no reproduced crash (static ceiling)"}


def _detonate_data_only(ctx, target) -> dict:
    """Demonstrate a data-only (DOP) privilege flip on a binary target: discover_data_only finds the
    security variable's distance and the privileged signal hands-off and detonates it. Native only;
    best-effort. 'detonated' when a flip takes the guarded path, else None (honest ceiling)."""
    try:
        from .dynamic import sandbox
        if sandbox.host_arch() != "x86-64" or (target.arch or "") not in ("x86-64", "x86_64", "amd64"):
            return {"status": None, "detail": "data-only detonation is x86-64 native only"}
        from . import dop
        wd = ctx.scratch() / "dop"
        wd.mkdir(parents=True, exist_ok=True)
        exe = wd / "target"
        ctx.content.stage_target(target, exe.parent, exe.name)
        import os as _os
        _os.chmod(exe, 0o755)
        plan, tok = dop.discover_data_only(str(exe), max_distance=256)
        if plan is not None and tok is not None:
            return {"status": "detonated",
                    "detail": f"data-only (DOP): flipping a decision variable at +{plan.distance} takes "
                              f"the privileged path (signal {tok[:24]!r}) -- no control-flow hijack"}
    except Exception:                                        # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug("data-only detonation skipped", exc_info=True)
    return {"status": None, "detail": "data-only path present but no flip took a privileged branch here"}


def _detonate_memory_rce(ctx, target, path) -> dict:
    """Memory RCE path: reflect chain_primitive's leak->groom L3, or detonate it here keyed off the
    strongest concrete write primitive. 'reflected' / 'detonated' / None. Never raises."""
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
