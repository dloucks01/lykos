"""A source build's sibling products are not primaries and do not repeat the tree's analysis.

FreeRDP 3.20.0 uploaded in the web GUI registered 9 targets from one tree (its own binary, 6
libFuzzer harnesses, 3 shared libraries). Both GUIs hand the autopilot every target, so a 600 s
run gave each ~70 s, libraries first; the detectors, libFuzzer and the confirmation ladder were
skipped for budget on all nine, and source_confirm rebuilt the harnesses on every one."""
from types import SimpleNamespace

from lykos.analyze import orchestrate as O
from lykos.analyze.source_lookup import TREE_SCOPED_STAGES, tree_owner


def _setup(store, case):
    store.put_artifact(case.id, "source-project", data=b"tree", meta={"binary_sha": "OWN"})
    ids = {}
    for fn, sha in [("libwinpr3.so.3.20.0", "L1"), ("TestFuzzCoreClient", "H1"),
                    ("freerdp-3.20.0", "OWN"), ("libfreerdp3.so.3.20.0", "L2"),
                    ("TestFuzzCoreServer", "H2")]:
        ids[fn] = store.targets.upsert(case.id, fn, sha).id
    return ids


def test_tree_owner_names_the_owner_for_siblings_only(store, case):
    ids = _setup(store, case)
    own = tree_owner(store.conn, store.targets.get(ids["TestFuzzCoreClient"]))
    assert own is not None and own.filename == "freerdp-3.20.0"
    assert tree_owner(store.conn, store.targets.get(ids["freerdp-3.20.0"])) is None


def test_no_owner_in_the_case_means_no_siblings(store, case):
    store.put_artifact(case.id, "source-project", data=b"tree", meta={"binary_sha": "ABSENT"})
    t = store.targets.upsert(case.id, "a.out", "X")
    assert tree_owner(store.conn, t) is None


def test_siblings_order_after_the_owner_and_libraries_last(store, case):
    ids = _setup(store, case)
    wl = list(ids.values())
    owners = O._tree_owners(store, wl)
    assert set(owners) == set(wl) - {ids["freerdp-3.20.0"]}
    wl.sort(key=lambda x: (0 if x not in owners else 2 if O._is_shared_lib_name(store, x) else 1))
    names = [store.targets.get(x).filename for x in wl]
    assert names[0] == "freerdp-3.20.0"
    assert names[-2:] == ["libwinpr3.so.3.20.0", "libfreerdp3.so.3.20.0"]


def test_tree_scoped_stages_are_real_stages():
    assert TREE_SCOPED_STAGES <= set(O._TARGET), sorted(TREE_SCOPED_STAGES - set(O._TARGET))
    # the sibling's OWN binary analysis is never in the set
    assert not ({"dynamic_run", "disassemble", "detect_cwe", "heap_check", "fuzz",
                 "coverage_fuzz", "harness", "triage", "finding_resolve"} & TREE_SCOPED_STAGES)


def test_a_tree_owner_runs_the_tree_scanners_before_disassembly():
    """FreeRDP: disassembling the owner's ASan harness took 77 s of a 126 s recover phase and every
    tree detector (guard_gap, oob_write, cpg, sinks) was skipped for budget."""
    import inspect
    src = inspect.getsource(O.run_case_autopilot)
    i_first = src.index("if _tree_first:\n")
    i_dis = src.index('_staged(bud, store, t, "disassemble"')
    assert i_first < i_dis
    assert "_tree_scans()" in src[i_first:i_dis]
    body = src[src.index("def _tree_scans():"):i_first]
    for st in ("guard_gap", "oob_write_scan", "source_sink_scan", "cpg_scan", "wire_flow"):
        assert f'"{st}"' in body, st
    assert '"cve_scan"' not in body          # the binary banner scan is not a tree scan


def test_a_libfuzzer_harness_is_fed_by_file_argument_only(store, case):
    """A libFuzzer harness runs the one input FILE named on its command line; it ignores stdin
    and, run bare, fuzzes forever. FreeRDP's TestFuzz* import read/fread, so they were ranked
    stdin and every black-box execution waited out its timeout."""
    blob = b"\x7fELF" + b"\0" * 64 + b"LLVMFuzzerTestOneInput\0read\0fread\0"
    sha = store.content.put_bytes(blob)[0]
    t = store.targets.upsert(case.id, "TestFuzzCoreClient", sha, file_type="elf")
    assert O._ranked_channels(store, t.id) == ["file"]
    plain = store.content.put_bytes(b"\x7fELF" + b"\0" * 64 + b"read\0")[0]
    t2 = store.targets.upsert(case.id, "cat", plain, file_type="elf")
    assert O._ranked_channels(store, t2.id) != ["file"]


def test_hypo_hunt_is_handed_the_autopilots_channel():
    import inspect
    src = inspect.getsource(O.run_case_autopilot)
    call = src[src.index('_staged(bud, store, t, "hypo_hunt"'):][:120]
    assert "_hp" in call, call
    assert '_hp = {"input_mode": primary}' in src
