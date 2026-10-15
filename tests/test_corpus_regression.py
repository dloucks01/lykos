"""Regression gate for the real-corpus regression benchmark (tools/corpus_regression.py).

The benchmark itself needs a 600s campaign per library and a corpus that is not in the repo, so
what is pinned here is its SCORING -- which is where the judgement lives, and where a mistake
would be invisible: a scorer that counts "identified" as "demonstrated", or passes a precision
control whose harness builder has stopped working, prints a clean table either way.

Every case below is a real failure this project has had, or a real one it must not start having.
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod                       # @dataclass resolves annotations via sys.modules
    spec.loader.exec_module(mod)
    return mod


cr = _load("corpus_run", "tools/corpus_run.py")
cb = _load("corpus_regression", "tools/corpus_regression.py")


# --- evidence builders ------------------------------------------------------------------------

def _ev(tmp_path, *, defects=(), crashes=(), pocs=(), doors_built=4, doors_planned=6,
        search=400.0, execs=100_000, budget=600.0, src=None):
    """An Evidence object shaped like a real source-project campaign."""
    ev = cr.Evidence(name="lib-1.0.tar.gz", src=src or Path("lib-1.0.tar.gz"), budget=budget,
                     workdir=tmp_path)
    ev.defects = list(defects)
    ev.crashes = list(crashes)
    ev.pocs = list(pocs)
    ev.scorecard = {
        "baseline": {"ran": True},
        "executions": {"total": execs, "per_second": 3780.0},
        "budget": {"by_stage": {"libfuzzer": search}},
        "in_process": {"entry_points": doors_built, "planned": doors_planned,
                       "doors": [{"entry": f"f{i}", "built": True} for i in range(doors_built)]},
    }
    return ev


def _defect(cwe, site, *, state="confirmed", detector="libfuzzer", through="XML_Parse",
            fid="f1"):
    return cr.Defect(finding_id=fid, target_id="t1", cwe=cwe, title=f"{cwe} thing",
                     state=state, severity="high", detector=detector, sites=[site],
                     evidence=[f"libFuzzer + AddressSanitizer reproduced x at {site} "
                               f"through {through} (crashing input abcdef)"])


_SPEC_ONE = {"archive": "lib.tar.gz", "min_doors": 2,
             "defects": [{"id": "the-bug", "cwe": "CWE-125", "site": "tif_getimage.c",
                          "through": "TIFFReadRGBAImageOriented", "min_level": 1}]}
_SPEC_CLEAN = {"archive": "lib.tar.gz", "clean": True, "min_doors": 2, "note": "n/a"}


# --- the characteristic failure: found, not proven ---------------------------------------------



def test_a_demonstrated_defect_passes(tmp_path):
    d = _defect("CWE-125", "tif_getimage.c", state="poc-backed",
                through="TIFFReadRGBAImageOriented")
    ev = _ev(tmp_path, defects=[d],
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("tiff", _SPEC_ONE, ev)
    assert r.verdict == "PASS"
    assert [x.verdict for x in r.defects] == ["DEMONSTRATED"]
    assert r.defects[0].through == "TIFFReadRGBAImageOriented"


def test_identified_but_not_demonstrated_is_not_a_catch(tmp_path):
    """`we identify, we don't demonstrate` is in the notes of three separate rounds. A scorer
    that read the finding list and stopped would call this a pass -- and the one thing the tool
    exists to produce, a reproducer, would be gone with the table still green."""
    ev = _ev(tmp_path, defects=[_defect("CWE-125", "tif_getimage.c")], pocs=[])
    r = cb.score_library("tiff", _SPEC_ONE, ev)
    assert r.defects[0].verdict == "IDENTIFIED"
    assert r.verdict == "IDENTIFIED-ONLY", "a found-but-unproven defect scored as caught"
    assert "no verified PoC" in r.problems[0]


def test_an_unverified_poc_does_not_count(tmp_path):
    ev = _ev(tmp_path, defects=[_defect("CWE-125", "tif_getimage.c")],
             pocs=[cr.PocRow(level=2, verified=False, input_sha="aa", finding_id="f1")])
    assert cb.score_library("tiff", _SPEC_ONE, ev).defects[0].verdict == "IDENTIFIED"


def test_a_missing_defect_is_a_miss(tmp_path):
    ev = _ev(tmp_path, defects=[_defect("CWE-400", "deflate.c")])
    r = cb.score_library("tiff", _SPEC_ONE, ev)
    assert r.defects[0].verdict == "MISS" and r.verdict == "MISS"


def test_a_known_gap_is_xfail_not_miss(tmp_path):
    spec = {"archive": "l", "min_doors": 2,
            "defects": [dict(_SPEC_ONE["defects"][0], known_gap=True)]}
    ev = _ev(tmp_path, defects=[])
    r = cb.score_library("tiff", spec, ev)
    assert r.defects[0].verdict == "XFAIL" and r.verdict == "PASS"


# --- attribution ------------------------------------------------------------------------------



def test_a_poc_is_attributed_through_the_crashing_input(tmp_path):
    """One defect wears two finding rows: libFuzzer files it under the sanitizer SITE, and the
    verified replay promotes the CRASH finding (signal + fault pc). `poc.finding_id` therefore
    points at the other row, and joining on it alone would score every in-process library
    finding as unproven."""
    d = _defect("CWE-125", "tif_getimage.c", fid="site-row")
    ev = _ev(tmp_path, defects=[d],
             crashes=[cr.Crash(input_sha="deadbeef", defect_key="libfuzzer:tif_getimage.c",
                               crashed=True)],
             pocs=[cr.PocRow(level=1, verified=True, input_sha="deadbeef",
                             finding_id="crash-row")])
    assert cb.demonstrated_level(ev, d) == 1
    assert cb.score_library("tiff", _SPEC_ONE, ev).verdict == "PASS"


def test_the_second_row_of_a_counted_defect_is_not_a_new_defect(tmp_path):
    """A verified PoC files a CRASH finding beside the libFuzzer one -- keyed on signal and fault
    pc, classed from the signal (CWE-119), with no site. Reporting that as a defect ground truth
    missed would put a NEW line under every library that passed."""
    site_row = _defect("CWE-125", "tif_getimage.c", state="poc-backed",
                       through="TIFFReadRGBAImageOriented")
    crash_row = cr.Defect(finding_id="f2", target_id="t1", cwe="CWE-119", title="SIGABRT",
                          state="poc-backed", detector="poc", sites=[], evidence=[])
    ev = _ev(tmp_path, defects=[site_row, crash_row],
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("tiff", _SPEC_ONE, ev)
    assert r.verdict == "PASS" and r.unexpected == []


def test_a_version_match_is_not_a_reproduced_bug(tmp_path):
    """`cve_fingerprint` files 108 candidate CVEs on libtiff 4.0.3 from a version match, none of
    them reached. Scoring one of those as the catch would make the benchmark pass on a library
    the campaign never entered."""
    static = cr.Defect(finding_id="s1", target_id="t1", cwe="CWE-125", title="CVE-2016-x",
                       state="candidate", detector="cve_fingerprint",
                       sites=["tif_getimage.c:100"])
    r = cb.score_library("tiff", _SPEC_ONE, _ev(tmp_path, defects=[static]))
    assert r.defects[0].verdict == "MISS"


# --- precision controls -----------------------------------------------------------------------



def test_a_fabricated_crash_on_a_clean_library_fails(tmp_path):
    """The scar this exists for: the planner read K&R C while `fn_params` kept an ANSI-only copy
    of the same regex, the harness called zlib's two-parameter `gzopen` with one argument, and
    the campaign reported an ASan SEGV in zlib on execution one."""
    ev = _ev(tmp_path, defects=[_defect("CWE-787", "gzlib.c:250", state="poc-backed")],
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("zlib", _SPEC_CLEAN, ev)
    assert r.verdict == "FALSE-POSITIVE"
    assert "baseline runs clean" in r.problems[0]


def test_a_site_less_crash_on_a_clean_library_is_still_reported(tmp_path):
    """The same suppression must not hide a fabricated crash: on a control nothing is counted,
    and the crash row is the only row a native (non-sanitizer) fault produces."""
    crash_row = cr.Defect(finding_id="f2", target_id="t1", cwe="CWE-119", title="SIGSEGV",
                          state="poc-backed", detector="poc", sites=[], evidence=[])
    r = cb.score_library("zlib", _SPEC_CLEAN, _ev(tmp_path, defects=[crash_row]))
    assert r.verdict == "FALSE-POSITIVE"


def test_an_oom_on_a_clean_library_is_reported_not_failed(tmp_path):
    """libFuzzer's `oom-` artifact is a real resource-exhaustion observation about a real
    library (libtiff has CVEs for exactly it), not a fabricated memory fault. Failing on it
    would train whoever runs this to ignore the result."""
    ev = _ev(tmp_path, defects=[_defect("CWE-400", "inflate.c:600", state="confirmed")])
    r = cb.score_library("zlib", _SPEC_CLEAN, ev)
    assert r.verdict == "PASS"
    assert r.unexpected and r.unexpected[0]["cwe"] == "CWE-400"


def test_a_clean_control_with_no_reach_is_invalid_not_a_pass(tmp_path):
    """The whole reason a findings-only benchmark could not do this job. zlib and bzip2 are
    expected to run clean, so a harness builder that stopped working entirely passes them --
    0 doors, 0 executions, 0 findings, green table."""
    ev = _ev(tmp_path, doors_built=0, doors_planned=6, execs=0)
    r = cb.score_library("zlib", _SPEC_CLEAN, ev)
    assert r.verdict == "INVALID"
    assert "REACH" in r.problems[0] and "0 of the 2 doors" in r.problems[0]


def test_reach_is_asserted_on_a_positive_library_too(tmp_path):
    """A run that opens one door is the single-harness pipeline again, whatever it finds -- and
    three of libtiff's four known defects are behind doors it never opened."""
    d = _defect("CWE-125", "tif_getimage.c", state="poc-backed")
    ev = _ev(tmp_path, defects=[d], doors_built=1,
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("tiff", _SPEC_ONE, ev)
    assert r.verdict == "INVALID" and r.defects[0].verdict == "DEMONSTRATED"


def test_a_starved_search_is_invalid(tmp_path):
    """Same floor the plumbing gate uses, and one definition of it: libtiff at a 200s budget
    reported six capabilities working and no crashes, and the same tarball with a real search
    slice found a heap overflow."""
    ev = _ev(tmp_path, search=12.0, budget=200.0, src=Path("lib-1.0.tar.gz"))
    r = cb.score_library("zlib", _SPEC_CLEAN, ev)
    assert r.verdict == "INVALID" and "starved" in r.problems[0]


# --- tiers: what a miss costs ------------------------------------------------------------------



_SPEC_TIERED = {"archive": "lib.tar.gz", "min_doors": 2, "defects": [
    dict(_SPEC_ONE["defects"][0]),
    {"id": "second-pass-bug", "cwe": "CWE-758", "site": "tif_read.c:460",
     "tier": "reach", "min_level": 1, "note": "behind a door a second pass opens"},
]}


def test_a_reach_tier_miss_is_watched_not_failed(tmp_path):
    """Three of libtiff's four known defects sit behind doors a SECOND pass opens, so whether
    they appear is the budget's decision. Failing the run on them would make the instrument red
    on every short budget, and an instrument that is always red gets ignored."""
    d = _defect("CWE-125", "tif_getimage.c", state="poc-backed",
                through="TIFFReadRGBAImageOriented")
    ev = _ev(tmp_path, defects=[d],
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("tiff", _SPEC_TIERED, ev)
    assert r.verdict == "PASS"
    assert r.watch and "second-pass-bug" in r.watch[0]
    assert r.problems == []


def test_an_anchor_miss_still_fails_when_a_reach_defect_is_present(tmp_path):
    ev = _ev(tmp_path, defects=[])
    r = cb.score_library("tiff", _SPEC_TIERED, ev)
    assert r.verdict == "MISS"
    assert any("the-bug" in p for p in r.problems)
    assert all("second-pass-bug" not in p for p in r.problems)


def test_a_site_may_be_any_of_several_measured_locations(tmp_path):
    """expat's namingBitmap shift reported `xmltok_impl.c:694` one day and `xmltok.c:147` the
    next -- the same macro family reached by a different input. The exact line is a fact about
    which input arrived first, so ground truth holds both and the match takes either."""
    spec = {"archive": "l", "min_doors": 1, "defects": [
        {"id": "expat-shift", "cwe": "CWE-758",
         "site": ["xmltok_impl.c:694", "xmltok.c:147"], "min_level": 1, "note": "measured"}]}
    for site in ("xmltok_impl.c:694", "xmltok.c:147"):
        d = _defect("CWE-758", site, state="poc-backed")
        ev = _ev(tmp_path, defects=[d], doors_built=1, doors_planned=1,
                 pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
        assert cb.score_library("expat", spec, ev).verdict == "PASS", site
    # a third, unmeasured site is not silently accepted
    d = _defect("CWE-758", "xmlparse.c:99", state="poc-backed")
    ev = _ev(tmp_path, defects=[d], doors_built=1, doors_planned=1,
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("expat", spec, ev)
    assert r.verdict == "MISS" and r.unexpected and r.unexpected[0]["cwe"] == "CWE-758"


def test_a_ground_truth_entry_without_a_cwe_matches_on_its_site(tmp_path):
    """Two of libtiff's UBSan entries record a site and no class, because the round that found
    them recorded a site and no class. Matching on the site alone is the honest reading; writing
    down a guessed CWE is how `tif_read.c:460` was recorded as a bad shift and turned out to be a
    null pointer use."""
    spec = {"archive": "l", "min_doors": 1, "defects": [
        {"id": "sited-only", "cwe": "", "site": "tif_read.c:545", "min_level": 1,
         "note": "site measured, class not"}]}
    d = _defect("CWE-476", "tif_read.c:545", state="poc-backed")
    ev = _ev(tmp_path, defects=[d], doors_built=1, doors_planned=1,
             pocs=[cr.PocRow(level=1, verified=True, input_sha="aa", finding_id="f1")])
    r = cb.score_library("tiff", spec, ev)
    assert r.verdict == "PASS" and r.defects[0].verdict == "DEMONSTRATED"


# --- ground truth and plumbing ----------------------------------------------------------------



def test_ground_truth_is_well_formed():
    for name, spec in cb.GROUND_TRUTH.items():
        assert spec.get("archive"), name
        assert spec.get("min_doors", 0) >= 1, f"{name} has no REACH floor"
        if spec.get("clean"):
            assert not spec.get("defects"), f"{name} is a control AND has expected defects"
            continue
        assert spec.get("defects"), f"{name} expects nothing and is not a control"
        for d in spec["defects"]:
            assert d["id"] and d["site"], d
            # A site with no CWE is legitimate (the class was never measured); a WRONG one is
            # not, so the field is either empty or a real identifier.
            assert d["cwe"] == "" or d["cwe"].startswith("CWE-"), d
            assert int(d.get("min_level") or 1) >= 1
            assert d.get("note") or d.get("known_gap"), f"{d['id']} has no provenance"


def test_the_corpus_is_scored_not_assumed():
    """An absent tarball must be a SKIP, never a pass: the corpus is upstream releases that are
    not in the repo, and a benchmark that counts a missing library as clean is worse than none.
    """
    r = cb.run_library("nope-9.9", {"archive": "nope-9.9.tar.gz"}, 10.0)
    assert r.verdict == "SKIP" and "not present" in r.problems[0]


def test_an_unscoreable_run_fails_the_exit_status():
    """Printing INVALID and exiting 0 is the same false clean one layer up: whatever runs this
    reads the exit status, not the table."""
    src = (ROOT / "tools" / "corpus_regression.py").read_text()
    assert "return 1 if bad else 0" in src
    assert 'r.verdict not in ("PASS", "SKIP")' in src, \
        "an INVALID or FALSE-POSITIVE library no longer fails the run"


def test_one_runner_two_scorers():
    """The campaign is shared with the plumbing gate. Two copies of this would drift the way the
    definition-scanner regex drifted -- and that drift synthesized a crash in a real library."""
    gate = (ROOT / "tools" / "real_corpus_gate.py").read_text()
    bench = (ROOT / "tools" / "corpus_regression.py").read_text()
    assert "from corpus_run import" in gate and "run_campaign" in gate
    assert "from corpus_run import" in bench and "run_campaign" in bench
    assert "def run_campaign" not in gate and "def run_campaign" not in bench


def test_a_clean_run_leaves_nothing_behind(tmp_path):
    """Two sweeps 0.5s apart were enough for a 90s target and not for zlib after a 449s campaign:
    a worker that outlives `pool.stop` recreates the content store's directory, and
    `/tmp/corpus-hcy408m7/case/artifacts` survived a passing run. The retry has to outlast the
    worker, and a directory that keeps coming back must not block the next library either."""
    wd = tmp_path / "case-store"
    (wd / "case" / "artifacts").mkdir(parents=True)
    ev = cr.Evidence(name="x", src=tmp_path / "x.tar.gz", budget=1.0, workdir=wd)
    ev.discard()
    assert not wd.exists()
