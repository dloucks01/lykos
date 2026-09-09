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
    for e in dyn:
        a, b = targets.get(e.src_target), targets.get(e.dst_target)
        if not a or not b:
            continue
        syms = set(edge_symbols(e.detail)) & imports(e.src_target)
        if not syms:
            continue
        b_sinks = sinks(e.dst_target)
        _fi, n2a, _ce = comp(e.dst_target)
        for sym in sorted(syms):
            hit = b_sinks.get(sym)
            if not hit:
                continue
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
    if persist:
        conn.commit()
    return {"edges_examined": len(dyn), "cross_findings": len(findings),
            "components_analyzed": len(comps)}
