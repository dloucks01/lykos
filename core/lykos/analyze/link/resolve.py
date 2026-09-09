"""Cross-binary import/export resolution (doc 17.2).

Reads each target's triage record (dynamic-symbol import/export names captured at ingest),
then links a component that *imports* a symbol to the component(s) that *export* it. The
result is one merged component graph: aggregate `dynamic-link` edges (one per ordered
target pair) for the System Map, and a per-symbol resolution table that cross-binary taint
(doc 17.2) consumes. Also links by shared-object name (A `NEEDED` B) even when B is stripped
of exported names.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from ...db.dao import (
    AnalysisRunDAO,
    ArtifactDAO,
    ComponentEdgeDAO,
    RunArtifactDAO,
    TargetDAO,
)

_MAX_DETAIL_SYMS = 60


def _triage_records(conn, content, case_id: str) -> dict[str, dict]:
    """target_id -> latest done ingest_triage record (parsed JSON), or {}."""
    runs = [r for r in AnalysisRunDAO(conn).list_by_case(case_id)
            if r.stage == "ingest_triage" and r.status == "done" and r.target_id]
    latest: dict[str, Any] = {}
    for r in runs:
        cur = latest.get(r.target_id)
        if cur is None or (r.ended_at or 0) >= (cur.ended_at or 0):
            latest[r.target_id] = r
    ra, art = RunArtifactDAO(conn), ArtifactDAO(conn)
    out: dict[str, dict] = {}
    for tid, r in latest.items():
        rec: dict = {}
        for link in ra.list_by_run(r.id):
            a = art.get(link.artifact_sha256)
            if a and a.kind == "triage-json":
                try:
                    rec = json.loads(content.get_bytes(a.sha256))
                except Exception:
                    rec = {}
                break
        out[tid] = rec
    return out


def _norm_soname(name: str) -> str:
    """libcfg.so.1.2 / libcfg-1.0.so -> a coarse stem for NEEDED<->filename matching."""
    n = (name or "").strip().lower()
    for _ in range(4):  # strip trailing .so / version suffixes
        base = n
        if n.endswith(".so"):
            n = n[:-3]
        else:
            head, _, tail = n.rpartition(".")
            if head and (tail.isdigit() or tail == "so"):
                n = head
        if n == base:
            break
    return n


def symbol_resolution(conn, content, case_id: str) -> dict[str, Any]:
    """Compute (without persisting) the cross-binary resolution for a case.

    Returns {"targets": {tid: {filename, imports:set, exports:set, needed:[...]}},
             "pairs": {(src,dst): sorted[symbols]}, "needed": {(src,dst): [sonames]}}.
    """
    tdao = TargetDAO(conn)
    targets = {t.id: t for t in tdao.list_by_case(case_id)}
    recs = _triage_records(conn, content, case_id)

    tinfo: dict[str, dict] = {}
    export_map: dict[str, set] = {}
    stem_to_target: dict[str, set] = {}
    for tid, t in targets.items():
        rec = recs.get(tid, {}) or {}
        imps = set((rec.get("imports", {}) or {}).get("symbols", []) or [])
        exps = set((rec.get("exports", {}) or {}).get("symbols", []) or [])
        needed = list((rec.get("imports", {}) or {}).get("libraries", []) or [])
        tinfo[tid] = {"filename": t.filename, "imports": imps, "exports": exps,
                      "needed": needed}
        for nm in exps:
            export_map.setdefault(nm, set()).add(tid)
        stem_to_target.setdefault(_norm_soname(t.filename), set()).add(tid)

    pairs: dict[tuple, set] = {}
    for tid, info in tinfo.items():
        for nm in info["imports"]:
            for dst in export_map.get(nm, ()):
                if dst != tid:
                    pairs.setdefault((tid, dst), set()).add(nm)

    needed: dict[tuple, set] = {}
    for tid, info in tinfo.items():
        for lib in info["needed"]:
            for dst in stem_to_target.get(_norm_soname(lib), ()):
                if dst != tid:
                    needed.setdefault((tid, dst), set()).add(lib)

    return {"targets": tinfo, "pairs": {k: sorted(v) for k, v in pairs.items()},
            "needed": {k: sorted(v) for k, v in needed.items()}}


def resolve_case(conn, content, case_id: str, *, persist: bool = True) -> dict[str, Any]:
    """Resolve and (optionally) persist aggregate `dynamic-link` component edges.

    One edge per ordered (importer, exporter) pair; `detail` carries the resolved symbol
    count + a sample, `symbol=""` (aggregate). Returns a summary for the event/API.
    """
    res = symbol_resolution(conn, content, case_id)
    pairs, need = res["pairs"], res["needed"]
    all_pairs = set(pairs) | set(need)

    edges = []
    for (src, dst) in sorted(all_pairs):
        syms = pairs.get((src, dst), [])
        libs = need.get((src, dst), [])
        detail = json.dumps({"symbols": syms[:_MAX_DETAIL_SYMS], "count": len(syms),
                             "via": libs[:8]}, sort_keys=True)
        edges.append({"src": src, "dst": dst, "kind": "dynamic-link",
                      "symbol": "", "detail": detail, "sym_count": len(syms)})

    if persist:
        ce = ComponentEdgeDAO(conn)
        ce.clear_case(case_id, kind="dynamic-link")
        for e in edges:
            ce.upsert(case_id, e["src"], e["dst"], kind="dynamic-link",
                      symbol="", detail=e["detail"])
        conn.commit()

    return {"components": len(res["targets"]), "edges": len(edges),
            "resolved_symbols": sum(e["sym_count"] for e in edges),
            "pairs": [{"src": e["src"], "dst": e["dst"], "symbols": e["sym_count"]}
                      for e in edges]}


def edge_symbols(detail: Optional[str]) -> list[str]:
    """Decode the symbol sample stored on an aggregate edge's detail."""
    if not detail:
        return []
    try:
        return json.loads(detail).get("symbols", []) or []
    except Exception:
        return []
