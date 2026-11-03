"""`triage` stage -- resolve every finding to a disposition and write it back, so a run ends with a
RESOLVED ledger (no bare candidates) instead of a backlog.

Runs after confirm/weaponize: by then findings carry their final state (poc-backed where a PoC was
built), grounding has tagged real-vs-FP + on/off-surface, and the CWE ceiling is known. For each
finding it calls `finding_triage.triage_finding`, records the disposition in the finding's evidence (channel
"triage", so the report and UI show WHY each is where it is), and returns the ledger (counts per
disposition + the DRIVABLE worklist -- the findings a harness-confirm attempt should target next).

Pure bookkeeping over existing signals; it confirms nothing itself (the DRIVABLE set names what to
drive). stdlib + grounding/triage modules only.
"""
from __future__ import annotations

from ..db.dao import FindingDAO, PocDAO, TargetDAO
from ..jobs.registry import register_stage
from . import grounding, finding_triage
from .grounding_stage import _source_root
from .source_lookup import source_project_for

TRIAGE_STAGE = "triage"
TOOL = "lykos.triage"
TOOL_VERSION = "1"


def _stored_grounding(fdict) -> "tuple | None":
    """The authoritative (grounded, verdict) the grounding STAGE already computed for this finding,
    read from its `grounding-map` evidence (which carries grounded/reachable/verdict with the full
    run context). Returns None when absent (then the caller recomputes). Maps the stored flags into
    the verdict vocabulary `finding_triage.triage_finding` expects: a disproved finding keeps its
    FP verdict; a real one becomes exploitable- vs off-surface-candidate by its `reachable` flag."""
    import json
    for e in (fdict.get("evidence") or []):
        if not isinstance(e, dict) or e.get("channel") != "grounding-map":
            continue
        try:
            gm = json.loads(e["detail"]) if isinstance(e.get("detail"), str) else e.get("detail")
        except Exception:                                # noqa: BLE001
            return None
        if not isinstance(gm, dict):
            return None
        grounded = bool(gm.get("grounded", True))
        if not grounded:
            return (False, gm.get("verdict") or "disproved")
        return (True, "exploitable-candidate" if gm.get("reachable") else "off-surface-candidate")
    return None


def _finding_dict(f) -> dict:
    # Finding.evidence is the already-parsed list (dao._row loads evidence_json into it); fall back
    # to a raw evidence_json attribute only if some caller passes one.
    ev = getattr(f, "evidence", None)
    if not ev:
        import json
        raw = getattr(f, "evidence_json", None)
        try:
            ev = json.loads(raw) if raw else []
        except Exception:                                # noqa: BLE001
            ev = []
    return {"cwe": f.cwe, "title": f.title, "detector": f.detector, "evidence": ev or [],
            "function_addr": f.function_addr, "site_addr": f.site_addr}


_LOC = __import__("re").compile(r'([A-Za-z0-9_./-]+\.[ch]):(\d+)')
_OP = __import__("re").compile(r"index '([^']+)'|arithmetic \(([^)]+)\)|'([^']+)'")


def _operand_tainted(fdict, textlookup) -> "bool | None":
    """Whether the attacker controls the dangerous operand at the sink. True when a CodeQL
    source->sink dataflow path reaches it (proven taint). Else, srctaint on the operand at the cited
    line: strong -> True, weak/none -> False, unparseable -> None (undecided)."""
    ev = fdict.get("evidence") or []
    # CodeQL proved a source->sink dataflow path -> attacker-tainted.
    if any(isinstance(e, dict) and e.get("channel") == "codeql-dataflow" for e in ev):
        return True
    if textlookup is None:
        return None
    src = next((str(e.get("detail")) for e in ev
                if isinstance(e, dict) and e.get("channel") == "source"), "")
    m = _LOC.search(src)
    op = _OP.search(src)
    if not m or not op:
        return None
    operand = op.group(1) or op.group(2) or op.group(3)
    txt = textlookup(m.group(1))
    if not txt:
        return None
    try:
        from .fingerprint import srctaint
        lines = txt.splitlines()
        st, _link = srctaint.any_untrusted_strength(
            lines, int(m.group(2)) - 1, [srctaint.base_ident(operand) or operand, operand])
        if st == "strong":
            return True
        if st == "weak" or st is None:
            return False
    except Exception:                                    # noqa: BLE001
        return None
    return None


def triage_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("triage requires a target_id")
    fd = FindingDAO(ctx.conn)
    pd = PocDAO(ctx.conn)
    findings = fd.list_by_target(target.id)

    # the PoC set (finding_ids with a verified PoC) + grounding's source lookup as a FALLBACK only.
    poc_fids = {p.finding_id for p in pd.list_by_target(target.id) if p.finding_id and p.verified}
    root = _source_root(ctx, target) if source_project_for(ctx.conn, target) else None
    lookup = grounding.make_source_lookup(root) if root else None
    textlookup = grounding.make_file_text_lookup(root) if root else None
    bits = target.bits or 64

    dispositions = []
    reasons: dict = {}
    for f in findings:
        if (f.detector or "") in ("grounding", "coverage_sweep"):
            continue
        fdict = _finding_dict(f)
        # AUTHORITATIVE verdict: the grounding STAGE already decided real-vs-FP + reachability for
        # this run (with the full taint/call-graph context) and stored it in the `grounding-map`
        # evidence channel. Read that; only recompute (context-free) if it is absent.
        gm = _stored_grounding(fdict)
        if gm is not None:
            grounded, verdict = gm
        else:
            # No authoritative verdict (recipe/derived finding grounding did not process). Try a
            # context-free recompute; if it still can't decide a surface, mark the verdict UNDECIDED
            # so triage does NOT optimistically call it drivable (honesty: a drivable claim needs a
            # reachability basis). A recompute that proves it FP still wins.
            g = grounding.ground_finding(fdict, source_lookup=lookup, bits=bits)
            grounded = bool(g.get("grounded", True))
            verdict = g.get("verdict") if not grounded else "undecided"
        tainted = _operand_tainted(fdict, textlookup)
        d = finding_triage.triage_finding(cwe=f.cwe, state=f.state, has_poc=(f.id in poc_fids),
                                  grounded=grounded, verdict=verdict, tainted=tainted)
        dispositions.append((f.id, d))
        reasons.setdefault(d.status, 0)
        reasons[d.status] += 1
        # write the disposition back onto the finding (idempotent: replace a prior triage note).
        fd.upsert(target.id, target.case_id, {
            "cwe": f.cwe or "", "title": f.title, "detector": f.detector or "",
            "dedup_key": f.dedup_key, "severity": f.severity, "state": f.state,
            "evidence": [{"channel": "triage",
                          "detail": f"{d.status}: {d.reason}" + (f" | next: {d.action}" if d.action else "")}]})

    led = finding_triage.ledger(dispositions)
    return {"metrics": {
        "findings_triaged": led["total"],
        "by_disposition": led["by_status"],
        "drivable_worklist": len(led["drivable"]),
        "resolved_every_finding": led["resolved"],
    }}


register_stage(TRIAGE_STAGE, triage_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_triage(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, TRIAGE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
