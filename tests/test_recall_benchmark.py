"""Regression gate for the known-vulnerable recall benchmark (tools/recall_benchmark.py).

Two layers:
  * score-logic unit tests -- always run, pin the recall/precision scoring (a positive must reach
    its level AND surface its CWE to PASS; a negative PASSES only when NO crash-backed PoC appears,
    so a fabricated bug on clean code is a FALSE-POSITIVE, not a pass).
  * an end-to-end gate on the flagship x86-64 CVE -- skipped unless the corpus is built -- that
    locks in "lykos drives CVE-2001-1413 to a demonstrated L2 control-flow hijack" so the catch
    can never silently regress.
"""
import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("recall_benchmark", ROOT / "tools" / "recall_benchmark.py")
rb = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rb)


def test_level_ordering():
    assert rb._lvl("none") < rb._lvl("L0") < rb._lvl("L1") < rb._lvl("L2") < rb._lvl("L3")
    assert rb._lvl("bogus") == 0


def test_positive_scoring_requires_cwe_and_level():
    spec = {"cwe": {"CWE-121"}, "min_level": "L2", "negative": False}
    # reached L2 and surfaced the CWE -> PASS
    assert rb.score({"cwes": ["CWE-121", "CWE-120"], "max_level": "L2",
                     "crash_confirmed": True}, spec)["verdict"] == "PASS"
    # reached only L1 -> MISS (under-exploited)
    assert rb.score({"cwes": ["CWE-121"], "max_level": "L1",
                     "crash_confirmed": True}, spec)["verdict"] == "MISS"
    # reached L2 but never surfaced the CWE -> MISS (detection gap)
    assert rb.score({"cwes": ["CWE-787"], "max_level": "L2",
                     "crash_confirmed": True}, spec)["verdict"] == "MISS"


def test_negative_scoring_flags_false_positives():
    spec = {"cwe": set(), "min_level": None, "negative": True}
    # clean: no crash-backed PoC -> PASS
    assert rb.score({"cwes": ["CWE-789"], "max_level": "none",
                     "crash_confirmed": False}, spec)["verdict"] == "PASS"
    # a crash-backed PoC on a target with no known bug is a FALSE POSITIVE, not a pass
    assert rb.score({"cwes": [], "max_level": "L1",
                     "crash_confirmed": True}, spec)["verdict"] == "FALSE-POSITIVE"
    assert rb.score({"cwes": [], "max_level": "none",
                     "crash_confirmed": True}, spec)["verdict"] == "FALSE-POSITIVE"


def test_known_gap_is_xfail_not_miss():
    """A documented recall gap that does not catch is XFAIL (tracked, does not fail the gate), not a
    silent pass and not a surprise MISS. If it starts catching, it becomes PASS (drop the flag)."""
    spec = {"cwe": {"CWE-125"}, "min_level": "L1", "negative": False, "known_gap": True}
    assert rb.score({"cwes": ["CWE-125"], "max_level": "none",
                     "crash_confirmed": False}, spec)["verdict"] == "XFAIL"
    # same spec, now actually caught -> PASS (the gap closed)
    assert rb.score({"cwes": ["CWE-125"], "max_level": "L1",
                     "crash_confirmed": True}, spec)["verdict"] == "PASS"
    # without the flag it would be a real MISS
    spec2 = dict(spec); spec2.pop("known_gap")
    assert rb.score({"cwes": ["CWE-125"], "max_level": "none",
                     "crash_confirmed": False}, spec2)["verdict"] == "MISS"


def test_cross_arch_scoring_is_crash_driven():
    # cross-arch stripped binaries: detection is advisory, the reproduced crash is authoritative
    spec = {"cwe": {"CWE-125"}, "min_level": "L1", "negative": False, "cross": True}
    assert rb.score({"cwes": [], "max_level": "L1", "crash_confirmed": True},
                    spec)["verdict"] == "PASS"
    assert rb.score({"cwes": [], "max_level": "none", "crash_confirmed": False},
                    spec)["verdict"] == "MISS"


def test_ground_truth_is_well_formed():
    for name, spec in rb.GROUND_TRUTH.items():
        assert "negative" in spec and "mode" in spec
        if spec["negative"]:
            assert spec["min_level"] is None
        else:
            assert spec["min_level"] in rb.LEVELS


# --- end-to-end gate (skipped unless the corpus is built) -----------------------------------------
_NCOMPRESS = rb.BIN / "ncompress_x86-64_cve"
_HAVE_TOOLS = shutil.which("gcc") is not None


@pytest.mark.skipif(not _NCOMPRESS.exists(),
                    reason="vuln-targets corpus not built (examples/vuln-targets/fetch_build.sh)")
def test_ncompress_cve_reaches_l2(tmp_path):
    """CVE-2001-1413: the full chain must reach a verified L2 control-flow hijack AND the static
    detectors must surface the stack-overflow CWE. Locks the catch against regression."""
    spec = rb.GROUND_TRUTH["ncompress_x86-64_cve"]
    res = rb.run_target(_NCOMPRESS, spec, fuzz_timeout=60, log=lambda *_: None)
    assert res["arch"] == "x86-64"
    assert rb._lvl(res["max_level"]) >= rb._lvl("L2"), f"only reached {res['max_level']}: {res}"
    assert {"CWE-121", "CWE-120"} & set(res["cwes"]), f"stack-overflow CWE not detected: {res['cwes']}"
    assert rb.score(res, spec)["verdict"] == "PASS"


_JHEAD = rb.BIN / "jhead_x86-64"


_JHEAD_SEED = rb.INPUTS / "jhead-crash.jpg"


@pytest.mark.skipif(not (_JHEAD.exists() and _JHEAD_SEED.exists()),
                    reason="vuln-targets corpus not built (examples/vuln-targets/fetch_build.sh)")
def test_jhead_file_arg_seeding_reproduces_crash(tmp_path):
    """jhead CWE-125 reads a file named on argv; the campaign must be seeded from the crashing
    example via `seed_files` to reproduce it. Locks the file-argument seeding fix with a FAST chain
    (triage -> fuzz(seed_files) -> build_poc; no disassembly): a verified L1 crash PoC. Regresses if
    external file seeding breaks again."""
    from lykos.analyze import register
    from lykos.analyze.ingest import ingest, enqueue_triage
    from lykos.analyze.fuzz.stage import enqueue_fuzz
    from lykos.analyze.poc.stage import enqueue_build_poc
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    register()
    store = CaseStore.open(tmp_path / "store")
    t = ingest(store, store.cases.create("jh").id, _JHEAD, filename="jhead_x86-64")
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=4, poll_interval=0.02))
    pool.start()
    try:
        q = JobQueue(store.conn)
        enqueue_triage(q, store.targets.get(t.id), force=True)
        assert pool.wait_idle(300)
        enqueue_fuzz(q, store.targets.get(t.id),
                     params={"timeout": 40, "input_mode": "file", "seed_files": [str(_JHEAD_SEED)]},
                     force=True)
        assert pool.wait_idle(300)
        crashes = [r for r in DynResultDAO(store.conn).list_by_target(t.id)
                   if r.crashed and r.input_sha]
        assert crashes, "seed_files did not reproduce the jhead crash (file-arg seeding regressed)"
        c0 = crashes[0]
        enqueue_build_poc(q, store.targets.get(t.id),
                          params={"input_sha": c0.input_sha, "input_mode": c0.input_mode or "file"},
                          force=True)
        assert pool.wait_idle(300)
    finally:
        pool.stop(grace=3.0)
    l1 = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified and p.level == "L1"]
    assert l1, "no verified L1 PoC from the reproduced jhead crash"
