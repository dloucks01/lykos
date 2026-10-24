"""The `patch_diff` stage -- bring binary patch-diff (1-day / N-day) into the pipeline.

`patchdiff.diff()` localizes the functions whose body changed between two builds: a security patch
-- and therefore the vulnerability it fixes -- lives in the code that changed. Until now that was a
CLI print-only tool (`lykos bindiff`), invisible to the autopilot, the API and the GUI. This
registers it as a real stage that, given a BASELINE target to diff against, files each changed
function as a candidate LEAD carrying its address. Because `patch_diff` is in
`directed._TARGET_DETECTORS`, the directed/concolic search then STEERS at the changed functions --
the "diff -> drive" loop, instead of fuzzing the whole binary blind.

Honest: a changed function is a LEAD, not a proven weakness. Leads are filed candidate-tier with an
`NVD-CWE-noinfo` class (the weakness is unknown until the engines reach it) and assert nothing.
"""
from __future__ import annotations

from ..db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO
from ..jobs.registry import register_stage
from . import patchdiff

PATCH_DIFF_STAGE = "patch_diff"
TOOL = "patch-diff"
TOOL_VERSION = "patchdiff-1"


def _addr_str(a):
    return hex(a) if isinstance(a, int) else (str(a) if a is not None else None)


def _funcs_for_fingerprint(conn, target_id) -> list:
    """Build the function list `patchdiff.diff` expects (cfg.blocks + calls + name/addr) from the
    already-disassembled DB rows -- no re-disassembly. Callees come from the call-edge table, grouped
    by the calling function's address."""
    fdao = FunctionDAO(conn)
    callees: dict = {}
    for e in CallEdgeDAO(conn).list_by_target(target_id):
        if e.src_addr is not None and e.dst_name:
            callees.setdefault(e.src_addr, set()).add(e.dst_name)
    out = []
    for f in fdao.list_by_target(target_id):
        full = fdao.get(f.id)
        ir = (full.ir if full else None) or {}
        blocks = ir.get("blocks") or []
        if not blocks:
            continue
        edges = ir.get("edges")
        edges = len(edges) if isinstance(edges, list) else (edges or 0)
        out.append({"name": f.name, "addr": f.addr,
                    "cfg": {"blocks": blocks, "edges": edges},
                    "calls": [{"dst_name": n} for n in sorted(callees.get(f.addr, ()))]})
    return out


def patch_diff_stage(ctx) -> dict:
    tdao = TargetDAO(ctx.conn)
    b = tdao.get(ctx.target_id) if ctx.target_id else None
    if b is None:
        raise ValueError("patch_diff requires a target_id (the build to analyse)")
    p = ctx.params or {}
    a_id = p.get("baseline_target_id") or p.get("baseline")
    a = tdao.get(a_id) if a_id else None
    if a is None or a.id == b.id:
        ctx.emit("patch_diff.done", payload={"applicable": False,
                 "note": "need a DISTINCT baseline target (the other build) in this case to diff against"})
        ctx.progress(pct=100, msg="patch_diff: pick a baseline build to diff against")
        return {}

    funcs_a = _funcs_for_fingerprint(ctx.conn, a.id)      # the OTHER build (old/vuln or patched ref)
    funcs_b = _funcs_for_fingerprint(ctx.conn, b.id)      # THIS target
    if not funcs_a or not funcs_b:
        ctx.emit("patch_diff.done", payload={"applicable": False,
                 "note": "both builds must be disassembled first (no recovered functions on one side)"})
        ctx.progress(pct=100, msg="patch_diff: disassemble both builds first")
        return {}

    # a = the baseline, b = this target. diff(a, b) ranks the functions whose body changed.
    result = patchdiff.diff(funcs_a, funcs_b)
    changed = result.get("changed") or []
    fd = FindingDAO(ctx.conn)
    top = int(p.get("max_leads", 12))
    filed = 0
    for c in changed[:top]:
        addr = _addr_str(c.get("new_addr"))
        if addr is None:
            continue
        nc = c.get("new_callees") or []
        kc, dc = c.get("new_consts") or [], c.get("dropped_consts") or []
        detail = (f"function '{c['name']}' changed between the baseline '{a.filename}' and this "
                  f"build: blocks {c['blocks'][0]}->{c['blocks'][1]}, instructions "
                  f"{c['insns'][0]}->{c['insns'][1]}, moved-score {c['moved']}"
                  + (f", new callees {', '.join(nc[:6])}" if nc else "")
                  # an immediate-only edit (a bounds constant) is the classic silent fix: name it
                  + (f", immediates {', '.join(dc[:6]) or '-'} -> {', '.join(kc[:6]) or '-'}"
                     if (kc or dc) else "")
                  + ". A security patch -- and the vulnerability it fixes -- lives in the code that "
                    "changed between builds, so analysis is STEERED here (directed fuzzing / concolic "
                    "drive at this function). This is a LEAD, not a proven weakness.")
        fd.upsert(b.id, b.case_id, {
            "cwe": "NVD-CWE-noinfo", "severity": "medium",
            "title": f"Patch-diff lead: '{c['name']}' changed vs baseline"[:200],
            "detector": "patch_diff", "state": "candidate", "confidence": 0.4,
            "function_addr": addr,
            "dedup_key": f"patch_diff:{c['name']}:{addr}",
            "evidence": [{"channel": "patch-diff", "detail": detail}]})
        filed += 1

    ctx.emit("patch_diff.done", payload={
        "applicable": True, "baseline": a.filename, "target": b.filename,
        "changed": len(changed), "leads": filed, "added": len(result.get("added") or []),
        "removed": len(result.get("removed") or []), "symbols": bool(result.get("symbols"))})
    tail = (f"patch_diff: {filed} changed-function lead(s) from {len(changed)} changed "
            f"(vs {a.filename}); analysis steers at them")
    if not changed and not result.get("symbols"):
        tail += " -- NOTE: both builds are stripped; only structural inventory was compared"
    ctx.progress(pct=100, msg=tail)
    return {"changed": len(changed), "leads": filed}


def register() -> None:
    register_stage(PATCH_DIFF_STAGE, patch_diff_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=600)


def enqueue_patch_diff(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, PATCH_DIFF_STAGE, target_id=target.id,
                         params=params or {}, force=force)
