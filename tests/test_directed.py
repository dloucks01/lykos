"""Phase 5 (directed) — steering fuzzing toward statically-flagged sinks.

The distance/target-selection/dictionary-mining logic is pure and deterministic, so it is
unit-tested without any external tool. An undirected-fallback campaign (no static graph, e.g.
Ghidra absent) is exercised end-to-end; the fully-directed end-to-end run needs Ghidra and is
skipped when it is not installed."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.fuzz import enqueue_directed_fuzz
from lykos.analyze.fuzz.directed import (
    callgraph_distance,
    mine_targeted_dictionary,
    plan_directed_campaign,
    select_targets,
)
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, EventDAO, FindingDAO
from lykos.db.models import CallEdge, Finding, Function, StringRef
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")


def _edge(src, dst=None, name=None):
    return CallEdge(id="e", target_id="t", created_at=0, src_addr=src, dst_addr=dst,
                    dst_name=name, site_addr=src)


def _finding(**kw):
    base = {"id": "f", "target_id": "t", "case_id": "c", "dedup_key": "k",
            "created_at": 0, "updated_at": 0}
    base.update(kw)
    return Finding(**base)


def _func(addr, instr_addrs=(), size=None):
    ir = {"blocks": [{"instructions": [{"addr": a} for a in instr_addrs]}]} if instr_addrs \
        else None
    return Function(id=f"fn{addr}", target_id="t", addr=addr, created_at=0,
                    blocks=1 if instr_addrs else None, size=size, ir=ir)


def _str(value, xrefs):
    return StringRef(id="s", target_id="t", addr="0x0", created_at=0, value=value, xrefs=xrefs)


# ------------------------------------------------------------------- unit: callgraph distance
def test_callgraph_distance_backward_bfs():
    edges = [_edge("0x1000", "0x2000"), _edge("0x2000", "0x3000")]
    dist = callgraph_distance(edges, ["0x3000"])
    assert dist == {0x3000: 0, 0x2000: 1, 0x1000: 2}


def test_callgraph_distance_unreachable_absent():
    edges = [_edge("0x1000", "0x2000")]           # 0x4000 not connected to target
    dist = callgraph_distance(edges, ["0x2000"])
    assert 0x4000 not in dist and dist[0x2000] == 0 and dist[0x1000] == 1


# ------------------------------------------------------------------- unit: target selection
def test_select_targets_prefers_taint_corroborated_sink():
    taint = [{"channel": "taint-dataflow", "detail": "x"}]
    findings = [
        _finding(detector="dangerous_api", function_addr="0x1169", site_addr="0x1180",
                 cwe="CWE-120", state="corroborated", severity="high", confidence=0.8,
                 evidence=taint),
        _finding(detector="weak_crypto", function_addr="0x1200", cwe="CWE-328",
                 state="candidate", severity="medium", confidence=0.5),
        _finding(detector="dynamic", function_addr=None, cwe="CWE-119",
                 state="confirmed", severity="critical", confidence=0.9),   # no addr -> skip
    ]
    ts = select_targets(findings)
    assert [t["cwe"] for t in ts] == ["CWE-120", "CWE-328"]     # dynamic (no addr) dropped
    assert ts[0]["has_taint"] and ts[0]["score"] > ts[1]["score"]


# ------------------------------------------------------------------- unit: targeted dictionary
def test_mine_targeted_dictionary_via_xrefs():
    funcs = [_func("0x1000", instr_addrs=["0x1010", "0x1014"]),   # ancestor, dist 1
             _func("0x2000", instr_addrs=["0x2010"])]             # target, dist 0
    dist = {0x2000: 0, 0x1000: 1}
    strings = [_str("MAGIC", ["0x1010"]),          # referenced by ancestor -> included
               _str("target-tok", ["0x2010"]),     # referenced by target   -> included
               _str("faraway", ["0x9999"])]        # referenced by nothing  -> excluded
    toks = mine_targeted_dictionary(funcs, strings, dist)
    assert b"target-tok" in toks and b"MAGIC" in toks and b"faraway" not in toks
    assert toks[0] == b"target-tok"                # closest (distance 0) ranked first


def test_mine_targeted_dictionary_uses_size_ranges_without_ir():
    funcs = [_func("0x1000", size=0x100)]          # covers [0x1000, 0x1100)
    dist = {0x1000: 0}
    toks = mine_targeted_dictionary(funcs, [_str("HIT", ["0x1050"])], dist)
    assert toks == [b"HIT"]


# ------------------------------------------------------------------- unit: plan fallback
def test_plan_falls_back_to_undirected_without_targets():
    plan = plan_directed_campaign([], [], [], [_str("dictword", [])])
    assert plan["directed"] is False and b"dictword" in plan["dictionary"]


def test_plan_directed_builds_targeted_corpus():
    findings = [_finding(detector="dangerous_api", function_addr="0x2000", site_addr="0x2010",
                         cwe="CWE-120", state="corroborated", severity="high", confidence=0.8)]
    funcs = [_func("0x1000", instr_addrs=["0x1010"]), _func("0x2000", instr_addrs=["0x2010"])]
    edges = [_edge("0x1000", "0x2000"), _edge("0x1000", None, "read")]
    strings = [_str("SECRETCMD", ["0x1010"])]
    plan = plan_directed_campaign(findings, funcs, edges, strings)
    assert plan["directed"] and b"SECRETCMD" in plan["dictionary"]
    assert b"SECRETCMD" in plan["seeds"]           # tokens seeded into the corpus
    assert "read" in plan["sources"]               # input source reaching the target


# ------------------------------------------------------------------- integration: fallback run
@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_directed_fuzz_undirected_fallback_finds_crash(store, case, pool, gcc, tmp_path):
    """With no static graph (no findings/functions), directed_fuzz degrades to an undirected
    campaign and still confirms a crash, tagged with the directed_fuzz detector."""
    import base64
    c = tmp_path / "t.c"; c.write_text(_CRASH_ON_A)
    b = tmp_path / "t"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_directed_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 500, "max_seconds": 20, "exec_timeout": 1,
        "seeds": [base64.b64encode(b"AAAA").decode()]})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "directed_fuzz"]
    assert confirmed and confirmed[0].cwe == "CWE-119"
    assert [d for d in DynResultDAO(store.conn).list_by_target(target.id) if d.crashed]


def test_directed_start_event_reports_undirected(store, case, pool, gcc, tmp_path):
    """The directed.start event announces undirected mode when there are no static targets."""
    c = tmp_path / "t.c"; c.write_text(_CRASH_ON_A)
    b = tmp_path / "t"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    q = JobQueue(store.conn)
    run = enqueue_directed_fuzz(q, target, params={
        "input_mode": "stdin", "max_execs": 60, "max_seconds": 8, "exec_timeout": 1})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    starts = [e for e in EventDAO(store.conn).list(run_id=run.id, limit=500)
              if e.type == "directed.start"]
    assert starts and starts[0].payload["directed"] is False
