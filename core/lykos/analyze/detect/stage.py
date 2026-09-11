"""Phase 3 — the `detect_cwe` stage: run detectors over IR/call-graph/strings -> findings."""
from __future__ import annotations

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from . import bounds, taint
from .catalog import entry_seed_params
from .detectors import DETECTORS, DetectContext, correlate

DETECT_STAGE = "detect_cwe"
TOOL = "detect"
TOOL_VERSION = "detect-1"


def detect_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("detect_cwe requires a target_id")

    fdao = FunctionDAO(ctx.conn)
    functions = fdao.list_by_target(target.id)
    # hydrate decompiler stack frames (heavy; omitted from the list view) for size-aware detection
    frames = {}
    for f in functions:
        if not f.blocks:
            continue
        full = fdao.get(f.id)
        if full and full.frame and (full.frame.get("vars") or full.frame.get("params")):
            frames[f.addr] = full.frame

    dctx = DetectContext(
        target_id=target.id, case_id=target.case_id,
        call_edges=CallEdgeDAO(ctx.conn).list_by_target(target.id),
        strings=StringDAO(ctx.conn).list_by_target(target.id),
        functions=functions,
        mitigations=target.mitigations or {}, frames=frames)

    ctx.progress(msg="running CWE detectors")
    cands = []
    for det in DETECTORS:
        cands += det(dctx)
    cands = correlate(cands, dctx)

    # inter-procedural data-flow taint over P-Code: flag sink sites whose argument
    # registers carry tainted data (across function boundaries), and upgrade findings.
    ctx.progress(msg="data-flow taint analysis (inter-procedural)")
    func_irs = {}
    for f in dctx.functions:
        if not f.blocks:
            continue
        full = fdao.get(f.id)
        if full and full.ir:
            func_irs[f.addr] = full.ir
    entry_seeds = entry_seed_params(dctx.functions, dctx.frames)   # argv/envp at main
    tainted_sites = taint.analyze_program(func_irs, dctx.call_edges, target.arch,
                                          entry_seeds=entry_seeds)
    for c in cands:
        if c["detector"] == "dangerous_api" and c.get("site_addr") in tainted_sites:
            c["state"] = "corroborated"
            c["confidence"] = max(c["confidence"], 0.8)
            c["evidence"].append({"channel": "taint-dataflow",
                                  "detail": "tainted value reaches a sink argument "
                                            "(intra-procedural P-Code taint)"})

    # Bounds channel: can this copy actually exceed its destination? The rule channel flags
    # every memcpy/strncpy and the taint channel confirms "attacker data reaches it", which on
    # a parser is true of nearly everything -- on jhead that was 20 LOW findings amounting to
    # "this program calls memcpy". A copy whose length is a compile-time constant that FITS
    # the recovered destination is not a defect, and saying so turns that noise into inventory.
    ctx.progress(msg="bounds analysis on copy sinks")
    verdicts = bounds.classify_program(func_irs, dctx.call_edges, frames, target.arch,
                                       bits=target.bits or 64)
    for c in cands:
        v = verdicts.get(c.get("site_addr"))
        if not v or c.get("detector") != "dangerous_api":
            continue
        if v["verdict"] == bounds.SAFE:
            # provably bounded: demote out of the headline, keep as inventory with the reason
            c["severity"] = "info"
            c["state"] = "candidate"
            c["confidence"] = min(c.get("confidence", 0.4), 0.15)
            c["evidence"].append({"channel": "bounds", "detail": v["why"]})
            c["site_detail"] = v["why"]
        elif v["verdict"] == bounds.SUSPECT:
            # surfaced for review -- NOT promoted, because a recovered frame can name the
            # wrong variable for a reused stack slot (see bounds.py)
            c["evidence"].append({"channel": "bounds", "detail": v["why"]})
            c["site_detail"] = v["why"]

    fd = FindingDAO(ctx.conn)
    for c in cands:
        fd.upsert(target.id, target.case_id, c)
    counts = fd.counts_by_state(target.id)
    ctx.emit("findings.done", payload={"candidates": len(cands), "states": counts})
    ctx.progress(pct=100, msg="%d candidate findings" % len(cands))
    return {}


def register() -> None:
    register_stage(DETECT_STAGE, detect_stage, resource_class="quick",
                   tool=TOOL, tool_version=TOOL_VERSION)


def enqueue_detect(queue, target, *, force: bool = True):
    # force by default: re-detect after re-analysis should re-run rather than cache-hit
    return queue.enqueue(target.case_id, DETECT_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         force=force)
