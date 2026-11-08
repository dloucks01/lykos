from lykos.analyze.weaponize_advanced import (heap_groom_plan, leak_to_write_chain, plan_rce,
    fmt_write_what_where, uaf_reclaim_plan)

def test_heap_groom_feasible_small():
    g=heap_groom_plan(64, 64); assert g.feasible and len(g.steps)>=4

def test_heap_groom_mmap_infeasible():
    g=heap_groom_plan(2*1024*1024, 64); assert not g.feasible and "mmap" in g.reason

def test_leak_to_write_chain():
    c=leak_to_write_chain({"cwe":"CWE-125","function":"planar_decompress"},
                          {"cwe":"CWE-787","function":"clear_decompress"})
    assert len(c.stages)==3 and "ASLR/PIE (via the leak)" in c.defeats

def test_leak_to_write_needs_both():
    c=leak_to_write_chain({"cwe":"CWE-617"},{"cwe":"CWE-787"})
    assert c.stages==[]

def test_plan_rce_reachable():
    r=plan_rce(["oob-read","oob-write"]); assert r["reachable"] and r["target"]

def test_plan_rce_missing_leak():
    r=plan_rce(["oob-write"]); assert not r["reachable"] and any("leak" in m for m in r["needs"])

def test_fmt_write_what_where():
    p=fmt_write_what_where(0x601018, 0xdeadbeef); assert len(p["writes"])==4 and "hhn" in p["writes"][0]["spec"]

def test_uaf_reclaim_feasible():
    assert uaf_reclaim_plan(64, 128)["feasible"]
    assert not uaf_reclaim_plan(256, 16)["feasible"]
