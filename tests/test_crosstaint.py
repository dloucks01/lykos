"""Phase 8 (doc 17.2) — cross-binary taint: source in A -> sink in B = one finding."""
from __future__ import annotations

import json

from lykos.analyze.detect import taint
from lykos.analyze.link.crosstaint import cross_taint_case
from lykos.db.dao import CallEdgeDAO, ComponentEdgeDAO, FindingDAO, FunctionDAO
from factories import make_target


def _i(addr, pcode):
    return {"addr": addr, "text": "", "pcode": pcode}


# --- caller side: main() taints the imported handle() with untrusted input ------------
_A_IR = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
    _i("0x1000", ["CALL ram:0x8000:8"]),                 # getenv() -> RAX tainted (SOURCE)
    _i("0x1004", ["COPY reg:RAX:8 -> reg:RDI:8"]),       # into arg0
    _i("0x1008", ["CALL ram:0x8100:8"]),                 # handle(RDI) -- imported, tainted
]}]}
_A_EDGES = [
    {"src_addr": "0x1000", "site_addr": "0x1000", "dst_addr": "0x8000",
     "dst_name": "getenv", "external": True},
    {"src_addr": "0x1000", "site_addr": "0x1008", "dst_addr": "0x8100",
     "dst_name": "handle", "external": True},
]
# --- callee side: exported handle(s) does strcpy(b, s) -- s (param) reaches the sink ---
_B_IR = {"blocks": [{"addr": "0x2000", "succ": [], "instructions": [
    _i("0x2000", ["COPY reg:RDI:8 -> reg:RSI:8"]),       # param s -> strcpy src (arg2)
    _i("0x2004", ["CALL ram:0x9100:8"]),                 # strcpy() sink, RSI tainted
]}]}
_B_EDGES = [
    {"src_addr": "0x2000", "site_addr": "0x2004", "dst_addr": "0x9100",
     "dst_name": "strcpy", "external": True},
]


class _E:
    """Minimal CallEdge stand-in for the pure taint-summary unit tests."""
    def __init__(self, site, dst_name, dst_addr=None, src_addr=None, external=True):
        self.site_addr, self.dst_name, self.dst_addr = site, dst_name, dst_addr
        self.src_addr, self.external = src_addr, external


def test_caller_tainted_imports_summary():
    edges = [_E("0x1000", "getenv", "0x8000", "0x1000"),
             _E("0x1008", "handle", "0x8100", "0x1000")]
    imps = taint.caller_tainted_imports({"0x1000": _A_IR}, edges, "x86-64")
    assert "handle" in imps          # untrusted input flows into the handle() call
    assert "getenv" not in imps       # getenv's own args are not tainted


def test_callee_sink_export_summary():
    edges = [_E("0x2004", "strcpy", "0x9100", "0x2000")]
    res = taint.callee_sink_exports({"0x2000": _B_IR}, edges, "x86-64",
                                    {"handle": "0x2000"}, {"handle"})
    assert "handle" in res
    assert ("CWE-120", "strcpy") in res["handle"]


def test_no_sink_export_when_no_sink_reached():
    # exported getlen() just returns its param; it reaches no dangerous sink
    ir = {"blocks": [{"addr": "0x2000", "succ": [], "instructions": [
        _i("0x2000", ["COPY reg:RDI:8 -> reg:RAX:8"]),     # return param, no sink call
    ]}]}
    res = taint.callee_sink_exports({"0x2000": ir}, [], "x86-64",
                                    {"getlen": "0x2000"}, {"getlen"})
    assert res == {}


def _seed_component(store, case_id, content, funcs, edges, filename="c.bin"):
    t = make_target(store, case_id, content=content, arch="x86-64")
    store.targets.update_triage(t.id, filename=filename)
    FunctionDAO(store.conn).replace_for_target(t.id, funcs)
    CallEdgeDAO(store.conn).replace_for_target(t.id, edges)
    return store.targets.get(t.id)


def test_cross_taint_case_emits_cross_component_finding(store, case):
    a = _seed_component(store, case.id, b"AAAA-app", [
        {"addr": "0x1000", "name": "main", "blocks": 1, "edges": 0, "cfg": _A_IR}], _A_EDGES,
        filename="app")
    b = _seed_component(store, case.id, b"BBBB-lib", [
        {"addr": "0x2000", "name": "handle", "blocks": 1, "edges": 0, "cfg": _B_IR}], _B_EDGES,
        filename="libhandle.so")
    # component graph edge a -> b over the imported symbol handle
    ComponentEdgeDAO(store.conn).upsert(case.id, a.id, b.id, kind="dynamic-link", symbol="",
                                        detail=json.dumps({"symbols": ["handle"], "count": 1}))
    store.conn.commit()

    summary = cross_taint_case(store.conn, store.content, case.id, persist=True,
                               resolve=False)
    assert summary["cross_findings"] == 1

    findings = FindingDAO(store.conn).list_by_target(b.id)
    xf = [f for f in findings if f.detector == "cross_binary_taint"]
    assert xf, "expected a cross_binary_taint finding on the sink component"
    f = xf[0]
    assert f.cwe == "CWE-120" and f.state == "corroborated"
    assert "app" in f.title and "libhandle.so" in f.title and "handle" in f.title
    channels = {e["channel"] for e in f.evidence}
    assert {"cross-binary", "taint"} <= channels
    # a taint edge was added to the component graph
    taint_edges = [e for e in ComponentEdgeDAO(store.conn).list_by_case(case.id)
                   if e.kind == "taint"]
    assert taint_edges and taint_edges[0].symbol == "handle"


def test_cross_taint_no_finding_without_source(store, case):
    # app calls handle() but with a CONSTANT arg (no untrusted input) -> no cross finding
    a_ir = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["COPY const:0x1:8 -> reg:RDI:8"]),
        _i("0x1008", ["CALL ram:0x8100:8"]),
    ]}]}
    a = _seed_component(store, case.id, b"AAAA-app2", [
        {"addr": "0x1000", "name": "main", "blocks": 1, "edges": 0, "cfg": a_ir}],
        [{"src_addr": "0x1000", "site_addr": "0x1008", "dst_addr": "0x8100",
          "dst_name": "handle", "external": True}])
    b = _seed_component(store, case.id, b"BBBB-lib2", [
        {"addr": "0x2000", "name": "handle", "blocks": 1, "edges": 0, "cfg": _B_IR}], _B_EDGES)
    ComponentEdgeDAO(store.conn).upsert(case.id, a.id, b.id, kind="dynamic-link", symbol="",
                                        detail=json.dumps({"symbols": ["handle"], "count": 1}))
    store.conn.commit()
    summary = cross_taint_case(store.conn, store.content, case.id, persist=True, resolve=False)
    assert summary["cross_findings"] == 0
