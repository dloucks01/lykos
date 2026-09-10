"""A content-addressed cache hit clones a stage's output artifacts to the new run but never
re-runs the body, so per-target DB rows the body writes are missing for a freshly uploaded copy
of the same bytes (e.g. the same binary in a second case). The stage's on_cache_hit hook rebuilds
them from the cloned output artifact. These tests cover the disassemble reprojection and the
generic registry dispatcher; triage's backfill is covered in test_ingest_stage.py.
"""
from lykos.analyze import disassemble
from lykos.analyze.disassemble import reproject_disassemble
from lykos.hashing import canonical_json
from lykos.jobs.registry import reproject_cache_hit

_ANALYSIS = {
    "program": {"language": "x86:LE:64:default"},
    "functions": [
        {"addr": "0x1149", "name": "handle", "size": 80,
         "calls": [{"site_addr": "0x1160", "dst_addr": "0x1050",
                    "dst_name": "strcpy", "external": True},
                   {"site_addr": "0x1180", "dst_addr": "0x1040",
                    "dst_name": "system", "external": True}]},
        {"addr": "0x11b0", "name": "main", "size": 60,
         "calls": [{"site_addr": "0x11c0", "dst_addr": "0x1149",
                    "dst_name": "handle", "external": False}]},
    ],
    "strings": [{"addr": "0x2004", "value": "echo unlocked", "section": ".rodata"}],
}


def _target_with_cached_disasm(store, case):
    """A target row plus a done disassemble run whose only output is the analysis artifact
    (mirrors the cache-hit clone: artifact linked, but no function/edge/string rows written)."""
    target = store.targets.upsert(case.id, "vuln", "deadbeef" * 8, size=100)
    run = store.runs.create(case.id, disassemble.DISASSEMBLE_STAGE, target_id=target.id,
                            tool=disassemble.TOOL, tool_version=disassemble.TOOL_VERSION,
                            cache_key="ck-disasm")
    art = store.put_artifact(case.id, "ghidra-analysis", data=canonical_json(_ANALYSIS))
    store.run_artifacts.link(run.id, art.sha256, "output")
    return target, run


def test_reproject_disassemble_rebuilds_rows(store, case):
    target, run = _target_with_cached_disasm(store, case)
    # nothing derived yet -- exactly the cache-hit state
    assert store.targets and not disassemble.FunctionDAO(store.conn).list_by_target(target.id)

    assert reproject_disassemble(store, target.id, run.id) is True

    funcs = disassemble.FunctionDAO(store.conn).list_by_target(target.id)
    edges = disassemble.CallEdgeDAO(store.conn).list_by_target(target.id)
    strings = disassemble.StringDAO(store.conn).list_by_target(target.id)
    assert {f.name for f in funcs} == {"handle", "main"}
    assert {e.dst_name for e in edges} == {"strcpy", "system", "handle"}
    assert any(s.value == "echo unlocked" for s in strings)

    # idempotent: rows already present -> no-op
    assert reproject_disassemble(store, target.id, run.id) is False


def test_registry_dispatch_routes_to_disassemble_hook(store, case):
    """reproject_cache_hit looks the stage up in the registry and calls its on_cache_hit."""
    disassemble.register()
    target, run = _target_with_cached_disasm(store, case)
    assert reproject_cache_hit(store, disassemble.DISASSEMBLE_STAGE, target.id, run.id) is True
    assert disassemble.CallEdgeDAO(store.conn).list_by_target(target.id)


def test_registry_dispatch_noop_for_stage_without_hook(store, case):
    target, _ = _target_with_cached_disasm(store, case)
    # a stage that denormalizes nothing (or isn't registered) is a safe no-op
    assert reproject_cache_hit(store, "no_such_stage", target.id, "whatever") is False
