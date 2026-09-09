"""Phase 3 — true intra-procedural data-flow taint over P-Code."""
import pytest
from factories import make_target
from lykos.analyze import register
from lykos.analyze.detect.stage import enqueue_detect
from lykos.analyze.detect.taint import analyze_function
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _i(addr, pcode):
    return {"addr": addr, "text": "", "pcode": pcode}


def test_taint_flows_source_to_sink_arg():
    ir = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["CALL ram:0x9000:8"]),                 # read() -> taints RAX
        _i("0x1004", ["COPY reg:RAX:8 -> reg:RSI:8"]),       # RAX -> RSI (arg2)
        _i("0x1008", ["CALL ram:0x9100:8"]),                 # strcpy() sink, RSI tainted
    ]}]}
    callmap = {"0x1000": "read", "0x1008": "strcpy"}
    assert analyze_function(ir, callmap, "x86-64") == {"0x1008"}


def test_taint_killed_by_redefinition():
    ir = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["CALL ram:0x9000:8"]),                 # taints RAX
        _i("0x1004", ["COPY const:0x0:8 -> reg:RSI:8"]),     # RSI := const (untainted)
        _i("0x1008", ["CALL ram:0x9100:8"]),                 # sink: no arg tainted
    ]}]}
    callmap = {"0x1000": "read", "0x1008": "strcpy"}
    assert analyze_function(ir, callmap, "x86-64") == set()


def test_no_source_no_flag():
    ir = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["COPY const:0x1:8 -> reg:RSI:8"]),
        _i("0x1008", ["CALL ram:0x9100:8"]),
    ]}]}
    assert analyze_function(ir, {"0x1008": "strcpy"}, "x86-64") == set()


def test_taint_propagates_across_blocks():
    ir = {"blocks": [
        {"addr": "0x1000", "succ": ["0x2000"], "instructions": [
            _i("0x1000", ["CALL ram:0x9000:8"]),             # read -> RAX
            _i("0x1004", ["COPY reg:RAX:8 -> reg:RDI:8"]),   # RAX -> RDI (arg1)
        ]},
        {"addr": "0x2000", "succ": [], "instructions": [
            _i("0x2000", ["CALL ram:0x9100:8"]),             # system() sink, RDI tainted
        ]},
    ]}
    callmap = {"0x1000": "read", "0x2000": "system"}
    assert analyze_function(ir, callmap, "x86-64") == {"0x2000"}


def test_unknown_arch_skips():
    ir = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["CALL ram:0x9000:8"]),
        _i("0x1004", ["COPY reg:RAX:8 -> reg:RSI:8"]),
        _i("0x1008", ["CALL ram:0x9100:8"]),
    ]}]}
    assert analyze_function(ir, {"0x1000": "read", "0x1008": "strcpy"}, "sparc") == set()


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=8, poll_interval=0.02,
                             heartbeat_interval=2.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_detect_stage_uses_dataflow_taint(store, case, pool):
    t = make_target(store, case.id, arch="x86-64")
    cfg = {"blocks": [{"addr": "0x2000", "succ": [], "instructions": [
        _i("0x2000", ["CALL ram:0x9000:8"]),                 # read source
        _i("0x2004", ["COPY reg:RAX:8 -> reg:RSI:8"]),       # into arg2
        _i("0x2008", ["CALL ram:0x9100:8"]),                 # strcpy sink
    ]}]}
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x2000", "name": "parse", "blocks": 1, "edges": 0, "cfg": cfg}])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x2000", "site_addr": "0x2000", "dst_addr": "0x9000",
         "dst_name": "read", "external": True},
        {"src_addr": "0x2000", "site_addr": "0x2008", "dst_addr": "0x9100",
         "dst_name": "strcpy", "external": True},
    ])
    q = JobQueue(store.conn)
    run = enqueue_detect(q, t)
    assert pool.wait_idle(10) and q.runs.get(run.id).status == "done"

    finding = next(f for f in FindingDAO(store.conn).list_by_target(t.id) if f.cwe == "CWE-120")
    assert finding.state == "corroborated"
    channels = {e["channel"] for e in finding.evidence}
    assert "taint-dataflow" in channels          # the precise channel fired
    assert finding.confidence >= 0.8


from lykos.analyze.detect.taint import analyze_program
from lykos.db.models import CallEdge


def _edge(src, site, dst, name, ext):
    return CallEdge(id="x", target_id="t", created_at=0, src_addr=src, site_addr=site,
                    dst_addr=dst, dst_name=name, external=ext)


def test_interproc_taint_into_callee():
    caller = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["CALL ram:0x9000:8"]),                 # read -> RAX
        _i("0x1004", ["COPY reg:RAX:8 -> reg:RDI:8"]),       # RAX -> RDI (arg1)
        _i("0x1008", ["CALL ram:0x2000:8"]),                 # call sub() (internal)
    ]}]}
    callee = {"blocks": [{"addr": "0x2000", "succ": [], "instructions": [
        _i("0x2000", ["COPY reg:RDI:8 -> reg:RSI:8"]),       # param1 -> RSI
        _i("0x2004", ["CALL ram:0x9100:8"]),                 # strcpy sink
    ]}]}
    edges = [
        _edge("0x1000", "0x1000", "0x9000", "read", True),
        _edge("0x1000", "0x1008", "0x2000", "sub", False),   # internal call
        _edge("0x2000", "0x2004", "0x9100", "strcpy", True),
    ]
    flagged = analyze_program({"0x1000": caller, "0x2000": callee}, edges, "x86-64")
    assert "0x2004" in flagged                               # taint crossed into the callee


def test_interproc_return_from_source_wrapper():
    wrapper = {"blocks": [{"addr": "0x3000", "succ": [], "instructions": [
        _i("0x3000", ["CALL ram:0x9000:8"]),                 # read -> RAX (returns tainted)
    ]}]}
    caller = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["CALL ram:0x3000:8"]),                 # x = getinput() (internal)
        _i("0x1004", ["COPY reg:RAX:8 -> reg:RSI:8"]),       # x -> RSI
        _i("0x1008", ["CALL ram:0x9100:8"]),                 # strcpy sink
    ]}]}
    edges = [
        _edge("0x3000", "0x3000", "0x9000", "read", True),
        _edge("0x1000", "0x1000", "0x3000", "getinput", False),
        _edge("0x1000", "0x1008", "0x9100", "strcpy", True),
    ]
    flagged = analyze_program({"0x3000": wrapper, "0x1000": caller}, edges, "x86-64")
    assert "0x1008" in flagged                               # tainted return flowed to sink


def test_detect_stage_interprocedural(store, case, pool):
    from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO
    t = make_target(store, case.id, arch="x86-64")
    caller = {"blocks": [{"addr": "0x1000", "succ": [], "instructions": [
        _i("0x1000", ["CALL ram:0x9000:8"]),
        _i("0x1004", ["COPY reg:RAX:8 -> reg:RDI:8"]),
        _i("0x1008", ["CALL ram:0x2000:8"]),
    ]}]}
    callee = {"blocks": [{"addr": "0x2000", "succ": [], "instructions": [
        _i("0x2000", ["COPY reg:RDI:8 -> reg:RSI:8"]),
        _i("0x2004", ["CALL ram:0x9100:8"]),
    ]}]}
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "main", "blocks": 1, "cfg": caller},
        {"addr": "0x2000", "name": "sub", "blocks": 1, "cfg": callee}])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "site_addr": "0x1000", "dst_addr": "0x9000",
         "dst_name": "read", "external": True},
        {"src_addr": "0x1000", "site_addr": "0x1008", "dst_addr": "0x2000",
         "dst_name": "sub", "external": False},
        {"src_addr": "0x2000", "site_addr": "0x2004", "dst_addr": "0x9100",
         "dst_name": "strcpy", "external": True}])
    q = JobQueue(store.conn)
    run = enqueue_detect(q, t)
    assert pool.wait_idle(10) and q.runs.get(run.id).status == "done"
    f = next(x for x in FindingDAO(store.conn).list_by_target(t.id) if x.cwe == "CWE-120")
    assert f.state == "corroborated"
    assert "taint-dataflow" in {e["channel"] for e in f.evidence}   # via inter-proc taint
