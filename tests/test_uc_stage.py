"""The UC stage's selection + lead-filing logic (the angr scan itself is covered by test_uc_symbolic).

It scans UNDRIVEN, project-named functions and files a CANDIDATE control-hijack lead -- always with
the under-constrained caveat, never a proven bug.
"""
from lykos.analyze.symbolic import uc_stage as U
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO


def test_project_name_filter():
    assert U._project_name("freerdp_parse_pdu")
    assert not U._project_name("_Exit")                 # reserved / mangled
    assert not U._project_name("__libc_start_main")
    assert not U._project_name("__sanitizer_cov")       # runtime
    assert not U._project_name("fuzzer_internal")       # libFuzzer
    assert not U._project_name("")


def test_undriven_scan_names_picks_undriven_project_functions(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "h.bin", "c" * 64, arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "LLVMFuzzerTestOneInput", "blocks": 1},
        {"addr": "0x1100", "name": "driven_parser", "blocks": 5},        # reachable -> driven
        {"addr": "0x2000", "name": "orphan_project", "blocks": 9},       # undriven project -> pick
        {"addr": "0x2100", "name": "small_orphan", "blocks": 1},         # undriven project -> pick
        {"addr": "0x3000", "name": "__libc_helper", "blocks": 3},        # undriven but runtime -> skip
    ])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "dst_addr": "0x1100"},                    # entry -> driven_parser
    ])
    names = U._undriven_scan_names(store.conn, t.id, limit=10)
    assert names == ["orphan_project", "small_orphan"]                  # block-count order, runtime out
    assert "driven_parser" not in names and "__libc_helper" not in names


def test_undriven_scan_names_empty_without_entry(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "x", "d" * 64, arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t.id, [{"addr": "0x1", "name": "foo", "blocks": 2}])
    # no LLVMFuzzer*/main entry -> reachability undefined -> nothing to scan (not a false worklist)
    assert U._undriven_scan_names(store.conn, t.id, limit=10) == []


class _Ctx:
    def __init__(self, conn):
        self.conn = conn


def test_file_uc_lead_is_a_candidate_with_the_caveat(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "h", "e" * 64, arch="x86-64", bits=64)
    U._file_uc_lead(_Ctx(store.conn), t, "freerdp_dispatch",
                    {"data_to_pc": 1, "hijackable": True})
    f = next(x for x in FindingDAO(store.conn).list_by_target(t.id) if x.detector == "uc_symbolic")
    assert f.state == "candidate" and f.cwe == "CWE-94"                 # never 'confirmed'
    ev = " ".join(str(e.get("detail", "")) for e in (f.evidence or []))
    assert "under-constrained" in ev and "NOT a proven bug" in ev and "freerdp_dispatch" in ev
