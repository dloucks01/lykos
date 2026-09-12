"""Cross-binary taint (doc 17.2) — a source in component A reaching a sink in component B
becomes ONE cross-component finding.

For each resolved `dynamic-link` edge A -> B over an imported symbol S:
  * A-side: does untrusted input in A flow into the call to S?  (caller_tainted_imports)
  * B-side: does tainting S's exported-function parameter reach a dangerous sink in B?
    (callee_sink_exports)
If both hold, the boundary call is the bridge: emit a corroborated cross-component finding
on B (where it manifests), with an evidence trail naming the source component and sink.

Deterministic, zero-AI, register-granularity (same honest limits as intra-binary taint).
Requires both components to have been disassembled (Ghidra); degrades to nothing otherwise.
"""
from __future__ import annotations

from collections import defaultdict

from ...db.dao import (
    CallEdgeDAO,
    ComponentEdgeDAO,
    FindingDAO,
    FunctionDAO,
    TargetDAO,
)
from ...db.models import SEVERITIES
from ..detect import taint
from ..detect.catalog import DANGEROUS
from .resolve import edge_symbols, resolve_case


def _load_component(conn, target):
    fdao = FunctionDAO(conn)
    func_irs: dict = {}
    name_to_addr: dict = {}
    for f in fdao.list_by_target(target.id):
        if f.name and f.name not in name_to_addr:
            name_to_addr[f.name] = f.addr
        if not f.blocks:
            continue
        full = fdao.get(f.id)
        if full and full.ir:
            func_irs[f.addr] = full.ir
    call_edges = CallEdgeDAO(conn).list_by_target(target.id)
    return func_irs, name_to_addr, call_edges


def _sev_rank(sev):
    try:
        return SEVERITIES.index(sev)
    except ValueError:
        return 0


def _cross_finding(a, b, sym, cwe, sink_name, severity, export_addr):
    return {
        "cwe": cwe,
        "title": (f"Cross-component taint: untrusted input in {a.filename} reaches "
                  f"{sink_name}() in {b.filename} via {sym}()"),
        "severity": severity,
        "state": "corroborated",
        "confidence": 0.62,
        "detector": "cross_binary_taint",
        "function_addr": export_addr,
        "site_addr": None,
        "dedup_key": f"xtaint:{a.id}:{b.id}:{sym}",
        "evidence": [
            {"channel": "cross-binary",
             "detail": (f"untrusted input in {a.filename} taints the call to {sym}() -> "
                        f"parameter of exported {sym}() in {b.filename}")},
            {"channel": "taint",
             "detail": (f"{sym}() parameter reaches {sink_name}() in {b.filename} "
                        f"(inter-procedural P-Code taint)")},
        ],
    }


def cross_taint_case(conn, content, case_id: str, *, persist: bool = True,
                     resolve: bool = True) -> dict:
    """Resolve the component graph, then propagate taint across each resolved edge.

    `resolve=False` reuses the already-persisted `dynamic-link` edges instead of
    recomputing them (re-runs / tests).
    """
    if resolve:
        resolve_case(conn, content, case_id, persist=True)
    dyn = [e for e in ComponentEdgeDAO(conn).list_by_case(case_id)
           if e.kind == "dynamic-link"]
    targets = {t.id: t for t in TargetDAO(conn).list_by_case(case_id)}

    incoming: dict = defaultdict(set)          # dst_target -> {imported symbols}
    for e in dyn:
        for s in edge_symbols(e.detail):
            incoming[e.dst_target].add(s)

    comps: dict = {}
    imps_cache: dict = {}
    sink_cache: dict = {}

    def comp(tid):
        if tid not in comps:
            comps[tid] = _load_component(conn, targets[tid])
        return comps[tid]

    def imports(tid):
        if tid not in imps_cache:
            fi, _n, ce = comp(tid)
            imps_cache[tid] = taint.caller_tainted_imports(fi, ce, targets[tid].arch)
        return imps_cache[tid]

    def sinks(tid):
        if tid not in sink_cache:
            fi, n2a, ce = comp(tid)
            sink_cache[tid] = taint.callee_sink_exports(
                fi, ce, targets[tid].arch, n2a, incoming.get(tid, set()))
        return sink_cache[tid]

    fd = FindingDAO(conn)
    ce_dao = ComponentEdgeDAO(conn)
    if persist:
        ce_dao.clear_case(case_id, kind="taint")
    findings = []
    # Why a run found nothing. "cross_findings: 0" is the same answer whether there were no
    # components, no resolved links, no tainted data reaching the boundary, or a boundary the
    # callee simply does not misuse -- and those call for four different next actions. The
    # only clue used to be `components_analyzed`, which reads as a count rather than a
    # diagnosis: on a program/library pair with a resolved edge it said 1, because the loop
    # stopped before ever loading the callee.
    why: dict = {"no_components": len(targets) < 2, "no_links": not dyn,
                 "edges_without_tainted_symbol": 0, "edges_with_clean_callee": 0,
                 "callers_without_ir": 0}
    for e in dyn:
        a, b = targets.get(e.src_target), targets.get(e.dst_target)
        if not a or not b:
            continue
        # No decompilation on the caller means no IR to trace, which is a different problem
        # from "the data does not reach the boundary" -- and only one of the two is something
        # the operator can act on. Carved firmware components arrive with neither.
        if not comp(e.src_target)[0]:
            why["callers_without_ir"] += 1
            continue
        syms = set(edge_symbols(e.detail)) & imports(e.src_target)
        if not syms:
            why["edges_without_tainted_symbol"] += 1
            continue
        b_sinks = sinks(e.dst_target)
        _fi, n2a, _ce = comp(e.dst_target)
        clean = True
        for sym in sorted(syms):
            hit = b_sinks.get(sym)
            if not hit:
                continue
            clean = False
            # pick the highest-severity sink reached, deterministically
            cwe, sink_name = max(sorted(hit),
                                 key=lambda cs: _sev_rank(DANGEROUS.get(cs[1], (0, "info"))[1]))
            severity = DANGEROUS.get(sink_name, ("", "high"))[1]
            cand = _cross_finding(a, b, sym, cwe, sink_name, severity, n2a.get(sym))
            findings.append(cand)
            if persist:
                fd.upsert(b.id, case_id, cand)
                ce_dao.upsert(case_id, a.id, b.id, kind="taint", symbol=sym,
                              detail=f"{sink_name} via {sym}")
        # per EDGE, at the end of its own iteration -- not after the loop, where `clean`
        # belongs to whichever edge happened to be last, and does not exist at all if every
        # edge took a `continue` above
        why["edges_with_clean_callee"] += int(clean)
    if persist:
        conn.commit()
    return {"edges_examined": len(dyn), "cross_findings": len(findings),
            "components_analyzed": len(comps), "note": _why_nothing(why, len(findings))}


def _why_nothing(why: dict, found: int):
    """One sentence naming what stopped this, or None when something was found."""
    if found:
        return None
    if why["no_components"]:
        return ("only one component in this case -- cross-component taint needs at least two "
                "(a program and a library it calls, or a client and a server).")
    if why["no_links"]:
        return ("no dynamic-link edges are resolved, so there is no boundary to chase taint "
                "across. Run link_case first.")
    if why["callers_without_ir"]:
        return (f"{why['callers_without_ir']} caller component"
                f"{'s have' if why['callers_without_ir'] != 1 else ' has'} not been "
                f"decompiled, so there is no data flow to trace across the boundary. Run "
                f"disassemble on the components first -- carved firmware components arrive "
                f"without it.")
    if why["edges_without_tainted_symbol"]:
        return (f"{why['edges_without_tainted_symbol']} linked boundar"
                f"{'ies' if why['edges_without_tainted_symbol'] != 1 else 'y'} carried no "
                f"tainted argument: the caller does not reach the imported symbol with data "
                f"this analysis can trace from an input source.")
    if why["edges_with_clean_callee"]:
        return (f"the caller does pass untrusted data across "
                f"{why['edges_with_clean_callee']} boundar"
                f"{'ies' if why['edges_with_clean_callee'] != 1 else 'y'}, but the callee "
                f"does not carry it into a dangerous sink -- which is a real negative, not a "
                f"missing analysis.")
    return "nothing to examine."
