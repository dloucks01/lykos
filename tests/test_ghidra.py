"""Phase 1 — Ghidra integration: DAO, locator, parser, graceful absence, real run (skipped
if Ghidra is not installed)."""
import json

import pytest

from lykos.analyze import ingest, register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.ghidra import locate_ghidra, parse_result
from lykos.db.dao import CallEdgeDAO, FunctionDAO, StringDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool
from factories import make_target


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=8, poll_interval=0.02, heartbeat_interval=2.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_migration_function_table_with_ir(store):
    cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(function)").fetchall()}
    assert {"id", "target_id", "addr", "name", "size", "decompiled",
            "blocks", "edges", "ir_json"}.issubset(cols)


def test_function_dao_with_cfg_ir(store, case):
    t = make_target(store, case.id)
    fd = FunctionDAO(store.conn)
    cfg = {"blocks": [
        {"addr": "0x1000", "succ": ["0x1010"],
         "instructions": [{"addr": "0x1000", "text": "MOV EAX,1",
                           "pcode": ["COPY const:0x1:4 -> register:0x0:4"]}]},
        {"addr": "0x1010", "succ": [], "instructions": []},
    ]}
    fd.replace_for_target(t.id, [
        {"addr": "0x1000", "name": "main", "size": 50, "decompiled": "int main(){}",
         "blocks": 2, "edges": 1, "cfg": cfg},
        {"addr": "0x2000", "name": "helper", "size": 20, "decompiled": "void helper(){}",
         "blocks": 1, "edges": 0, "cfg": {"blocks": []}},
    ])
    lst = fd.list_by_target(t.id)
    assert len(lst) == 2
    assert lst[0].decompiled is None and lst[0].ir is None       # list omits code + IR
    assert lst[0].blocks == 2 and lst[0].edges == 1              # counts present in list
    full = fd.get(lst[0].id)
    assert full.decompiled and full.ir                           # detail includes code + IR
    assert full.ir["blocks"][0]["instructions"][0]["pcode"][0].startswith("COPY")  # P-Code round-tripped
    assert full.blocks == 2 and full.edges == 1
    fd.replace_for_target(t.id, [{"addr": "0x1000", "name": "main", "size": 50}])
    assert fd.count_by_target(t.id) == 1                         # replace overwrites


def test_migration_v5_callgraph_xref_tables(store):
    tables = {r["name"] for r in
              store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"call_edge", "string_ref"}.issubset(tables)


def test_call_edge_dao(store, case):
    t = make_target(store, case.id)
    ce = CallEdgeDAO(store.conn)
    ce.replace_for_target(t.id, [
        {"src_addr": "0x1000", "site_addr": "0x1008", "dst_addr": "0x4000",
         "dst_name": "parse", "external": False},
        {"src_addr": "0x1000", "site_addr": "0x1010", "dst_addr": "0x9000",
         "dst_name": "strcpy", "external": True},
        {"src_addr": "0x2000", "site_addr": "0x2004", "dst_addr": "0x4000",
         "dst_name": "parse", "external": False},
    ])
    assert ce.count_by_target(t.id) == 3
    callees = ce.callees_of(t.id, "0x1000")
    assert {c.dst_name for c in callees} == {"parse", "strcpy"}
    assert any(c.external for c in callees)                       # strcpy flagged external
    callers = ce.callers_of(t.id, "0x4000")
    assert {c.src_addr for c in callers} == {"0x1000", "0x2000"}  # both callers of parse
    sinks = ce.calls_to_name(t.id, "strcpy")
    assert len(sinks) == 1 and sinks[0].site_addr == "0x1010"     # dangerous-API sink site
    ce.replace_for_target(t.id, [])                              # re-disassembly overwrites
    assert ce.count_by_target(t.id) == 0


def test_string_dao(store, case):
    t = make_target(store, case.id)
    sd = StringDAO(store.conn)
    sd.replace_for_target(t.id, [
        {"addr": "0x3000", "value": "admin:password", "xrefs": ["0x1200", "0x1300"]},
        {"addr": "0x3010", "value": "%s", "xrefs": []},
    ])
    lst = sd.list_by_target(t.id)
    assert len(lst) == 2
    hit = next(s for s in lst if s.addr == "0x3000")
    assert hit.value == "admin:password" and hit.xrefs == ["0x1200", "0x1300"]
    assert sd.count_by_target(t.id) == 2


def test_locator_env_dir(tmp_path, monkeypatch):
    support = tmp_path / "support"; support.mkdir()
    hl = support / "analyzeHeadless"; hl.write_text("#!/bin/sh\n")
    monkeypatch.setenv("LYKOS_GHIDRA", str(tmp_path))
    assert locate_ghidra() == hl


def test_locator_absent(monkeypatch):
    monkeypatch.delenv("LYKOS_GHIDRA", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setattr("lykos.analyze.ghidra.glob", lambda p: [])
    monkeypatch.setattr("lykos.analyze.ghidra.shutil.which", lambda x: None)
    assert locate_ghidra() is None


def test_parse_result(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"program": {"language": "AARCH64:LE:64:v8A"},
                             "functions": [{"addr": "0x640", "name": "main", "size": 40,
                                            "decompiled": "int main(void){return 0;}"}]}))
    res = parse_result(p)
    assert res["functions"][0]["name"] == "main"
    with pytest.raises(ValueError):
        bad = tmp_path / "b.json"; bad.write_text("{}")
        parse_result(bad)


def test_disassemble_without_ghidra_errors(store, case, pool, sample_elf, monkeypatch):
    # force "Ghidra absent" deterministically regardless of host
    monkeypatch.setattr("lykos.analyze.ghidra.locate_ghidra", lambda *a, **k: None)
    target = ingest(store, case.id, sample_elf)
    q = JobQueue(store.conn)
    run = enqueue_disassemble(q, target)
    assert pool.wait_idle(10)
    r = q.runs.get(run.id)
    assert r.status == "error" and "Ghidra" in (r.error or "")


@pytest.mark.skipif(locate_ghidra() is None, reason="Ghidra not installed")
def test_real_disassemble(store, case, pool, sample_elf):
    target = ingest(store, case.id, sample_elf)
    q = JobQueue(store.conn)
    run = enqueue_disassemble(q, target)
    assert pool.wait_idle(600)                    # Ghidra headless is slow
    assert q.runs.get(run.id).status == "done"
    assert FunctionDAO(store.conn).count_by_target(target.id) > 0
    assert CallEdgeDAO(store.conn).count_by_target(target.id) > 0   # call graph extracted
