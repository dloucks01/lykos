"""The coverage ledger: the account of the gap along three axes (classes checked, findings
weaponized, code exercised) + the gaps worklist. It is read-only and must stay honest -- a check
never drifts out of the real stage registry, an un-weaponized finding lands on the worklist, and a
weaponized one does not.
"""
from lykos.analyze import coverage_ledger as CL
from lykos.analyze import stages as S
from lykos.db.dao import FindingDAO, TargetDAO


def test_every_ledger_check_is_a_real_registered_stage():
    """The ledger's 'what we can check' inventory must not drift from the pipeline."""
    registered = {sp.name for sp in S.STAGES}
    bad = [c["stage"] for c in CL._CHECKS if c["stage"] not in registered]
    assert not bad, f"ledger references stages that are not registered: {bad}"


def test_ledger_class_and_weaponization_accounting(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "t", "a" * 64, arch="source", bits=0)
    fd = FindingDAO(store.conn)
    # a confirmed finding (weaponized), a corroborated recipe (weaponized), a bare candidate (not)
    fd.upsert(t.id, t.case_id, {"cwe": "CWE-416", "title": "uaf", "severity": "high",
              "detector": "uaf", "state": "confirmed", "confidence": 0.9, "dedup_key": "k1",
              "evidence": []})
    fd.upsert(t.id, t.case_id, {"cwe": "CWE-190", "title": "recipe", "severity": "high",
              "detector": "source_recipe", "state": "corroborated", "confidence": 0.5,
              "dedup_key": "k2", "evidence": []})
    fd.upsert(t.id, t.case_id, {"cwe": "CWE-78", "title": "cand", "severity": "high",
              "detector": "source_sink", "state": "candidate", "confidence": 0.4,
              "dedup_key": "k3", "evidence": []})

    led = CL.build_ledger(store, case.id)
    assert led["schema"] == "lykos.coverage-ledger/1"
    wp = led["weaponization"]
    assert wp["findings"] == 3 and wp["weaponized"] == 2 and wp["pct"] == round(200 / 3, 1)
    # the bare candidate is on the worklist; the confirmed/corroborated are not
    titles = {u["title"] for u in wp["unweaponized"]}
    assert titles == {"cand"}
    # checks: nothing ran on this case -> all checks not_run, and that is the top gap
    assert led["checks"]["ran"] == 0 and led["checks"]["not_run"]
    assert any("did not run" in g for g in led["gaps"])
    assert any("weaponization worklist" in g for g in led["gaps"])


def test_ledger_distinct_dedup_across_targets(store, case):
    """The same source bug built into two targets is ONE distinct issue in the ledger, not two."""
    fd = FindingDAO(store.conn)
    for name, sha in (("libA", "a" * 64), ("libB", "b" * 64)):
        t = TargetDAO(store.conn).upsert(case.id, name, sha, arch="source", bits=0)
        fd.upsert(t.id, case.id, {"cwe": "CWE-190", "title": "ovf", "severity": "high",
                  "detector": "source_recipe", "state": "corroborated", "confidence": 0.5,
                  "dedup_key": "shared", "evidence": []})
        fd.upsert(t.id, case.id, {"cwe": "CWE-78", "title": f"cand-{name}", "severity": "high",
                  "detector": "source_sink", "state": "candidate", "confidence": 0.3,
                  "dedup_key": f"uniq-{name}", "evidence": []})
    wp = CL.build_ledger(store, case.id)["weaponization"]
    assert wp["findings"] == 4                         # raw rows: shared x2 + 2 uniques
    d = wp["distinct"]
    assert d["raw"] == 4
    assert d["issues"] == 3                            # shared + uniq-libA + uniq-libB
    assert d["weaponized"] == 1                        # only the shared (corroborated) issue


def test_ledger_verification_rollup_over_distinct_issues(store, case):
    """The ledger triages distinct issues into prove-out shortlist / off-surface / noise -- the
    case-level entry the GUI links into the findings board."""
    t = TargetDAO(store.conn).upsert(case.id, "x", "e" * 64, arch="source", bits=0)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, {"cwe": "CWE-190", "title": "ovf", "severity": "high",
              "state": "corroborated", "detector": "source_recipe", "dedup_key": "on",
              "evidence": [{"channel": "s", "detail": "on the fuzzed attack surface"}]})
    fd.upsert(t.id, case.id, {"cwe": "CWE-416", "title": "uaf", "severity": "high",
              "state": "corroborated", "detector": "uaf", "dedup_key": "off",
              "evidence": [{"channel": "s", "detail": "off the fuzzed attack surface"}]})
    fd.upsert(t.id, case.id, {"cwe": "CWE-129", "title": "oob _ZN11__sanitizer internal_allocator",
              "severity": "high", "state": "corroborated", "detector": "oob_index",
              "dedup_key": "noise",
              "evidence": [{"channel": "s", "detail": "on the fuzzed attack surface"}]})
    v = CL.build_ledger(store, case.id)["weaponization"]["verification"]
    assert v["shortlist"] == 1 and v["off_surface"] == 1 and v["noise"] == 1


def test_undriven_reachability_from_harness_entry(store, case):
    """A harness entry's forward call-graph reach vs total recovered functions -- the honest
    'how much code does a harness drive' measure (undriven = the rest)."""
    from lykos.db.dao import CallEdgeDAO, FunctionDAO
    t = TargetDAO(store.conn).upsert(case.id, "h.bin", "c" * 64, arch="x86-64", bits=64)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "LLVMFuzzerTestOneInput"},
        {"addr": "0x1100", "name": "parse"},
        {"addr": "0x1200", "name": "helper"},
        {"addr": "0x9000", "name": "orphan_never_called"},   # undriven
    ])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "dst_addr": "0x1100"},        # entry -> parse
        {"src_addr": "0x1100", "dst_addr": "0x1200"},        # parse -> helper
    ])
    und = CL._undriven_functions(store.conn, t.id)
    assert und["total"] == 4 and und["reachable"] == 3 and und["count"] == 1
    assert und["pct"] == 75.0


def test_ledger_renders_in_html():
    from lykos.report.html import _coverage_ledger_html
    led = {"checks": {"total": 10, "ran": 4, "classes_checked": ["CWE-190", "CWE-416"],
                      "not_run": [{"label": "Uninitialised-memory oracle (MSan)", "status": "not_run",
                                   "classes": ["CWE-457"]}]},
           "weaponization": {"findings": 5, "weaponized": 3, "pct": 60.0,
                             "unweaponized": [{"title": "x"}]},
           "code": [{"target": "libx.so", "block_pct": 12, "functions_recovered": 40}],
           "gaps": ["1 analysis check(s) did not run on this case"]}
    h = _coverage_ledger_html(led)
    assert "Coverage ledger" in h and "4/10" in h and "60%" in h
    assert "Uninitialised-memory oracle" in h and "Gaps" in h and "libx.so" in h


def test_ledger_surfaces_a_failed_build_as_a_coverage_caveat(store, case):
    """A source case whose build produced no binaries is the loudest coverage caveat: static-source
    only, with the failure reason, as the TOP gap -- the whole binary/dynamic capability did not run."""
    store.put_artifact(case.id, "source-project", data=b"tree",
                       meta={"filename": "proj", "build_failed": True,
                             "build_log": "cmake configuring\nfatal error: openssl/ssl.h: "
                                          "No such file or directory\nbuild aborted"})
    led = CL.build_ledger(store, case.id)
    b = led["build"]
    assert b and b["built"] is False
    assert "openssl/ssl.h" in (b["reason"] or "")
    assert "STATIC-SOURCE" in b["caveat"]
    assert led["gaps"] and "BUILD PRODUCED NO BINARIES" in led["gaps"][0]   # the top gap


def test_ledger_build_caveat_carries_preflight_stage_list(store, case):
    """A failed build whose ingest pre-flight found missing deps surfaces the exact stage-these
    checklist in the build caveat -- the actionable half of the coverage caveat."""
    store.put_artifact(case.id, "source-project", data=b"tree",
                       meta={"filename": "proj", "build_failed": True,
                             "build_log": "fatal error: openssl/ssl.h: No such file or directory",
                             "preflight": {"build_system": "cmake",
                                           "toolchain_missing": ["cmake"],
                                           "missing": [{"kind": "cmake-package", "name": "OpenSSL",
                                                        "hint": {"apt": "libssl-dev",
                                                                 "dnf": "openssl-devel"}}],
                                           "tokens": ["cmake", "OpenSSL (libssl-dev)"],
                                           "summary": {"missing": 1}}})
    b = CL.build_ledger(store, case.id)["build"]
    assert b["built"] is False
    assert b["stage"] == ["cmake", "OpenSSL (libssl-dev)"]
    assert b["toolchain_missing"] == ["cmake"]
    assert b["missing_deps"][0]["name"] == "OpenSSL"


def test_ledger_failed_build_without_preflight_still_renders(store, case):
    """The pre-flight is best-effort; a failed build with no preflight meta still yields a caveat
    (no stage list), never an error."""
    store.put_artifact(case.id, "source-project", data=b"tree",
                       meta={"filename": "proj", "build_failed": True, "build_log": "boom"})
    b = CL.build_ledger(store, case.id)["build"]
    assert b["built"] is False and "stage" not in b


def test_failed_build_stage_list_renders_in_html():
    from lykos.report.html import _coverage_ledger_html
    led = {"checks": {"total": 5, "ran": 0, "classes_checked": [], "not_run": []},
           "weaponization": {"findings": 0, "weaponized": 0, "pct": None, "unweaponized": []},
           "code": [], "gaps": [],
           "build": {"built": False, "system": "cmake",
                     "reason": "fatal error: openssl/ssl.h: No such file or directory",
                     "caveat": "static-source only", "stage": ["cmake", "OpenSSL (libssl-dev)"]}}
    h = _coverage_ledger_html(led)
    assert "Stage these before re-ingesting" in h
    assert "OpenSSL (libssl-dev)" in h and "lykos deps" in h


def test_ledger_notes_a_harness_only_build(store, case):
    store.put_artifact(case.id, "source-project", data=b"tree",
                       meta={"filename": "proj", "build_system": "cmake-fuzzers"})
    b = CL.build_ledger(store, case.id)["build"]
    assert b["built"] is True and "harness" in (b.get("caveat") or "")


def test_ledger_build_is_none_for_a_non_source_case(store, case):
    assert CL.build_ledger(store, case.id)["build"] is None   # no source-project artifact
