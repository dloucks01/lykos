"""The `grounding` stage -- apply the precision layer (grounding + malicious-peer reachability) to
every finding on a live run, as an ANNOTATION, never a mutation.

grounding.py and taint_reach.py decide whether a reported finding is a real, reachable,
arch-relevant defect or a pattern match that cannot be an exploit. Until now they were a standalone
module + a one-off analysis; this runs them in the pipeline and writes the verdict back onto each
finding as a `grounding` evidence channel (prose) plus a `grounding-map` channel (structured, for
the ledger/report to read numbers, not re-parse prose).

It does NOT demote: the finding's own state/confidence are set by the detectors and the
monotonic-confidence lifecycle (doc 05), and upsert only ever raises them. Grounding is a VIEW laid
on top -- the ledger/report/GUI read the annotation to present a GROUNDED shortlist (a real,
attacker-reachable candidate) and to set provable false positives aside WITH their reason, exactly
as the honest-filter design requires. Nothing real is hidden; every set-aside carries its basis.
"""
from __future__ import annotations

import io
import json
import logging
import tarfile

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from . import grounding, taint_reach
from .source_lookup import source_project_for

_log = logging.getLogger(__name__)

GROUNDING_STAGE = "grounding"
TOOL = "grounding"
TOOL_VERSION = "grounding-1"


def _finding_dict(f) -> dict:
    ev = getattr(f, "evidence", None) or []
    if isinstance(ev, str):                              # tolerate a raw json string
        try:
            ev = json.loads(ev)
        except Exception:                                # noqa: BLE001
            ev = []
    return {"cwe": f.cwe, "title": f.title, "detector": f.detector, "evidence": ev,
            "function_addr": f.function_addr, "target_id": f.target_id, "dedup_key": f.dedup_key,
            "severity": f.severity, "state": f.state, "confidence": f.confidence}


def _source_lookup(ctx, target):
    """A source_lookup over the case's archived source tree (for grounding's source-text checks),
    or None when there is no source project."""
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    root = ctx.scratch() / "grounding-src"
    if not root.exists():
        root.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                              mode="r:gz") as tf:
                for mem in tf.getmembers():
                    if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                        tf.extract(mem, root)
        except Exception:                                # noqa: BLE001
            return None
    return grounding.make_source_lookup(root)


def grounding_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("grounding requires a target_id")
    bits = target.bits or 64
    # Case-wide attacker-reachable set: the malicious-peer surface (parsers + what they reach),
    # not just the fuzz-harness slice. A function with no call graph yet yields an empty set, in
    # which case reachability stays "undecided" (never a false drop).
    try:
        reachable = taint_reach.attacker_reachable_names(ctx.conn, target.case_id)
    except Exception:                                    # noqa: BLE001
        reachable = set()
    lookup = _source_lookup(ctx, target)   # (path, line) -> source line context, for grounding

    fd = FindingDAO(ctx.conn)
    findings = fd.list_by_target(target.id)
    tally: dict = {}
    grounded = reach_hits = 0
    for f in findings:
        if (f.detector or "") == "grounding":
            continue
        fdict = _finding_dict(f)
        g = grounding.ground_finding(fdict, source_lookup=lookup, bits=bits)
        # taint_reach resolves the finding's function from its binary addr (via conn) and its
        # evidence prose; it wants whole-file text, which our line-lookup does not provide, so pass
        # None and let it fall back (the common path uses function_addr / the "in X" prose).
        r = taint_reach.ground_reach(fdict, reachable, conn=ctx.conn, source_lookup=None)
        is_real = bool(g["grounded"])          # grounding kept it (not a PROVABLE false positive)
        reach = r.get("reachable")             # taint_reach: True / False / None
        # COMBINED verdict: grounding decides real-vs-FP; taint_reach decides attacker-reachability,
        # which OVERRIDES grounding's tag-only surface guess (grounding sees only the detector's
        # "on/off the fuzzed surface" string; taint_reach walks the real peer call graph). A provable
        # FP keeps grounding's verdict and is set aside; a real + reachable finding is the shortlist.
        if not is_real:
            verdict = g["verdict"]             # instrumentation-noise / non-shipping / arch-safe / format-literal
        elif reach is True:
            verdict = "exploitable-candidate"
        elif reach is False:
            verdict = "unreached"              # kept, low priority (indirect dispatch may hide a path)
        else:
            verdict = g["verdict"]             # reachability undecided -> grounding's own tier
        on_shortlist = is_real and reach is True
        tally[verdict] = tally.get(verdict, 0) + 1
        if reach is True:
            reach_hits += 1
        if on_shortlist:
            grounded += 1
        prose = (f"grounding: {verdict} -- {g['reason']}. reachability: {r['reason']}")
        mapv = {"verdict": verdict, "grounded": is_real, "reachable": reach,
                "reach_basis": r.get("basis"), "cwe": g.get("cwe"),
                "surface": g.get("surface"), "role": g.get("role"), "shortlist": bool(on_shortlist)}
        # annotate by MERGE on the finding's own dedup_key -- adds the channels, raises nothing.
        fd.upsert(target.id, target.case_id, {
            "cwe": f.cwe, "title": f.title, "severity": f.severity, "detector": f.detector,
            "state": "candidate", "confidence": 0.0, "dedup_key": f.dedup_key,
            "function_addr": f.function_addr, "site_addr": f.site_addr,
            "evidence": [{"channel": "grounding", "detail": prose},
                         {"channel": "grounding-map", "detail": json.dumps(mapv, sort_keys=True)}]})

    ctx.emit("grounding.done", payload={"findings": len(findings), "grounded_shortlist": grounded,
             "attacker_reachable": reach_hits, "by_verdict": tally,
             "peer_surface_names": len(reachable)})
    ctx.progress(pct=100, msg=f"grounded {len(findings)} finding(s): {grounded} on the "
                             f"attacker-reachable shortlist; set-aside verdicts {tally}")
    return {"metrics": {"grounded_shortlist": grounded, "attacker_reachable": reach_hits,
                        "findings": len(findings)}}


def register() -> None:
    register_stage(GROUNDING_STAGE, grounding_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_grounding(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, GROUNDING_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="quick", force=force)
