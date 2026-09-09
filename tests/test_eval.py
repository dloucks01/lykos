"""Phase 10 — validation & benchmark harness (doc 14): metrics, corpus, and a live run."""
import shutil

import pytest
from lykos.analyze.detect.catalog import CWE
from lykos.eval import corpus, harness
from lykos.eval.metrics import Outcome, Report, gate, matches, same_family, score

# ---- a faithful miniature NIST Juliet C drop (real conventions) ----
_STD_H = ("#ifndef STD_TESTCASE_H\n#define STD_TESTCASE_H\n#include <stdio.h>\n"
          "#include <stdlib.h>\n#include <string.h>\nvoid printLine(const char*);\n#endif\n")
_IO_C = ('#include "std_testcase.h"\nvoid printLine(const char*l){ if(l) puts(l); }\n')
_CWE121 = r"""#include "std_testcase.h"
#ifndef OMITBAD
void CWE121_Stack_Based_Buffer_Overflow__char_environment_cpy_01_bad(){
    char * data = getenv("ADD"); char dest[16];
    if(data){ strcpy(dest, data); printLine(dest); } }
#endif
#ifndef OMITGOOD
static void goodG2B(){ char * data = "fixed"; char dest[16]; strcpy(dest, data); printLine(dest); }
void CWE121_Stack_Based_Buffer_Overflow__char_environment_cpy_01_good(){ goodG2B(); }
#endif
#ifdef INCLUDEMAIN
int main(int c,char**v){ (void)c;(void)v;
#ifndef OMITGOOD
  CWE121_Stack_Based_Buffer_Overflow__char_environment_cpy_01_good();
#endif
#ifndef OMITBAD
  CWE121_Stack_Based_Buffer_Overflow__char_environment_cpy_01_bad();
#endif
  return 0; }
#endif
"""
_CWE134 = r"""#include "std_testcase.h"
#ifndef OMITBAD
void CWE134_Uncontrolled_Format_String__char_environment_printf_01_bad(){
    char * data = getenv("ADD"); if(data) printf(data); }
#endif
#ifndef OMITGOOD
static void goodG2B(){ printf("%s", "fixed"); }
void CWE134_Uncontrolled_Format_String__char_environment_printf_01_good(){ goodG2B(); }
#endif
#ifdef INCLUDEMAIN
int main(int c,char**v){ (void)c;(void)v;
#ifndef OMITGOOD
  CWE134_Uncontrolled_Format_String__char_environment_printf_01_good();
#endif
#ifndef OMITBAD
  CWE134_Uncontrolled_Format_String__char_environment_printf_01_bad();
#endif
  return 0; }
#endif
"""


def _mini_juliet(root):
    sup = root / "C" / "testcasesupport"; sup.mkdir(parents=True)
    (sup / "std_testcase.h").write_text(_STD_H)
    (sup / "io.c").write_text(_IO_C)
    d1 = root / "C" / "testcases" / "CWE121_x" / "s01"; d1.mkdir(parents=True)
    (d1 / "CWE121_Stack_Based_Buffer_Overflow__char_environment_cpy_01.c").write_text(_CWE121)
    d2 = root / "C" / "testcases" / "CWE134_x" / "s01"; d2.mkdir(parents=True)
    (d2 / "CWE134_Uncontrolled_Format_String__char_environment_printf_01.c").write_text(_CWE134)
    return root


# ---------------------------------------------------------------- metrics (pure, fast)
def _outs(spec):
    """spec: list of (cwe, verdict, flagged) -> Outcomes."""
    return [Outcome(f"c{i}", cwe, verdict, {cwe} if flagged else set())
            for i, (cwe, verdict, flagged) in enumerate(spec)]


def test_perfect_detector_scores_1():
    m = score(_outs([("CWE-120", "bad", True), ("CWE-120", "good", False),
                     ("CWE-78", "bad", True), ("CWE-78", "good", False)]))
    for c in m["per_cwe"].values():
        assert c["precision"] == 1.0 and c["recall"] == 1.0 and c["fp_rate"] == 0.0
    assert m["overall"]["precision"] == 1.0 and m["overall"]["fp_rate"] == 0.0


def test_false_positive_lowers_precision_and_raises_fp_rate():
    # one bad detected (TP), one good wrongly flagged (FP): precision .5, recall 1, fpr 1
    m = score(_outs([("CWE-798", "bad", True), ("CWE-798", "good", True)]))
    c = m["per_cwe"]["CWE-798"]
    assert c["tp"] == 1 and c["fp"] == 1 and c["fn"] == 0 and c["tn"] == 0
    assert c["precision"] == 0.5 and c["recall"] == 1.0 and c["fp_rate"] == 1.0


def test_missed_bug_lowers_recall():
    m = score(_outs([("CWE-120", "bad", False), ("CWE-120", "good", False)]))
    c = m["per_cwe"]["CWE-120"]
    assert c["fn"] == 1 and c["recall"] == 0.0 and c["fp_rate"] == 0.0
    assert c["precision"] is None                          # no positive predictions


def test_micro_average_aggregates_across_classes():
    m = score(_outs([("CWE-120", "bad", True), ("CWE-120", "good", False),
                     ("CWE-78", "bad", True), ("CWE-78", "good", True)]))
    o = m["overall"]
    assert o["tp"] == 2 and o["fp"] == 1 and o["tn"] == 1 and o["fn"] == 0
    assert m["n_cwe_classes"] == 2 and m["n_cases"] == 4


def test_release_gate_pass_fail_skip():
    clean = score(_outs([("CWE-120", "bad", True), ("CWE-120", "good", False)]))
    ok, verdict, _ = gate(clean, {"ghidra": "/x"})
    assert ok and verdict == "PASS"
    # a missed bug (recall 0.5) fails the default gate
    regressed = score(_outs([("CWE-120", "bad", False), ("CWE-120", "bad", True)]))
    ok, verdict, _ = gate(regressed, {"ghidra": "/x"})
    assert not ok and verdict == "FAIL"
    # a false positive fails when max_fp_rate is 0
    fp = score(_outs([("CWE-120", "bad", True), ("CWE-120", "good", True)]))
    assert gate(fp, {"ghidra": "/x"})[0] is False
    # static run with no Ghidra and nothing scored SKIPs (not a false regression)...
    empty = score([])
    ok, verdict, _ = gate(empty, {"ghidra": None}, stage="static")
    assert ok and verdict == "SKIP"
    # ...unless the backend is required
    ok, verdict, _ = gate(empty, {"ghidra": None}, stage="static", require_backend=True)
    assert not ok and verdict == "FAIL"
    # thresholds are configurable
    assert gate(regressed, {"ghidra": "/x"}, min_recall=0.5)[0] is True


def _report(recall, fp_rate, *, ghidra="/x"):
    return Report(outcomes=[], meta={"ghidra": ghidra, "max_execs": 2500}, metrics={
        "n_cases": 4, "n_cwe_classes": 2,
        "overall": {"tp": 2, "fp": 0, "fn": 0, "tn": 2, "recall": recall,
                    "precision": 1.0, "f1": 1.0, "fp_rate": fp_rate}})


def test_history_record_load_and_series(tmp_path):
    from lykos.eval import history
    h = tmp_path / "hist.jsonl"
    history.record(h, _report(1.0, 0.0), stage="static", min_state="candidate", ts=100)
    history.record(h, _report(1.0, 0.0), stage="dynamic", ts=101)
    history.record(h, _report(0.5, 0.0), stage="static", min_state="candidate", ts=102)
    hist = history.load(h)
    assert len(hist) == 3
    ser = history.series(hist)
    assert set(ser) == {"static/candidate", "dynamic"}
    # series are ordered by timestamp
    assert [r["ts"] for r in ser["static/candidate"]] == [100, 102]
    assert history.load(tmp_path / "nope.jsonl") == []      # missing file -> []


def test_history_detects_recall_and_fp_regressions(tmp_path):
    from lykos.eval import history
    h = tmp_path / "hist.jsonl"
    history.record(h, _report(1.0, 0.0), stage="static", min_state="candidate", ts=1)
    history.record(h, _report(0.7, 0.0), stage="static", min_state="candidate", ts=2)  # recall drop
    history.record(h, _report(1.0, 0.0), stage="dynamic", ts=1)
    history.record(h, _report(1.0, 0.5), stage="dynamic", ts=2)                         # fp rise
    regs = {r["series"]: r for r in history.regressions(h and history.load(h))}
    assert set(regs) == {"static/candidate", "dynamic"}
    assert regs["static/candidate"]["recall_delta"] == -0.3
    assert regs["dynamic"]["fp_rate_delta"] == 0.5
    # a single run per series cannot regress; a stable series doesn't flag
    stable = [_recj(1.0, 0.0, "static", 1), _recj(1.0, 0.0, "static", 2)]
    assert history.regressions(stable) == []


def _recj(recall, fp, stage, ts):
    return {"ts": ts, "stage": stage, "min_state": None, "git": "abc",
            "overall": {"recall": recall, "fp_rate": fp}}


def test_dashboard_renders_text_and_offline_html(tmp_path):
    from lykos.eval import dashboard, history
    h = tmp_path / "hist.jsonl"
    for ts, rec in ((1, 1.0), (2, 1.0), (3, 0.6)):        # last run regresses
        history.record(h, _report(rec, 0.0), stage="static", min_state="candidate", ts=ts)
    hist = history.load(h)
    txt = dashboard.render_text(hist)
    assert "static/candidate" in txt and "REGRESSION" in txt.upper()
    html = dashboard.render_html(hist)
    assert html.startswith("<!doctype html>") and "</html>" in html
    assert "regression" in html.lower() and "<svg" in html        # sparkline present
    assert "http://" not in html.split("</style>")[0]             # no external assets in CSS
    assert dashboard.render_text([]).startswith("no benchmark history")


def test_report_table_and_dict_roundtrip():
    outs = _outs([("CWE-120", "bad", True), ("CWE-120", "good", False)])
    rep = Report(outcomes=outs, metrics=score(outs), meta={"ghidra": None})
    d = rep.to_dict()
    assert d["metrics"]["overall"]["recall"] == 1.0
    assert len(d["outcomes"]) == 2 and d["outcomes"][0]["flagged"] is True
    assert "OVERALL" in rep.table() and "CWE-120" in rep.table()


# ---------------------------------------------------------------- corpus
def test_bundled_corpus_is_labeled_good_bad_pairs():
    cs = corpus.bundled()
    assert len(cs) >= 8
    for c in cs:
        assert c.verdict in ("good", "bad")
        assert c.cwe in CWE                                # a known catalog CWE
        assert c.source.strip() and c.cflags
    # every CWE class has at least one bad and one good sample (FP measurement needs both)
    by = {}
    for c in cs:
        by.setdefault(c.cwe, set()).add(c.verdict)
    for cwe, verds in by.items():
        assert verds == {"good", "bad"}, f"{cwe} lacks a good/bad pair"


def test_cwe_family_matching():
    # a sink's generic CWE credits a case labeled with a sibling (Juliet uses specific labels)
    assert same_family("CWE-121", "CWE-120") and same_family("CWE-787", "CWE-119")
    assert not same_family("CWE-121", "CWE-78")
    assert matches("CWE-121", {"CWE-120", "CWE-693"})     # strcpy(CWE-120) detects CWE-121
    assert not matches("CWE-134", {"CWE-120"})


def test_load_juliet_parses_and_pairs(tmp_path):
    _mini_juliet(tmp_path)
    cases = corpus.load_juliet(tmp_path)
    assert len(cases) == 4                                # 2 testcases x good/bad
    by = {(c.cwe, c.verdict): c for c in cases}
    assert set(by) == {("CWE-121", "bad"), ("CWE-121", "good"),
                       ("CWE-134", "bad"), ("CWE-134", "good")}
    bad = by[("CWE-121", "bad")]
    assert any(f.endswith("io.c") for f in bad.files)     # links Juliet support
    assert "-DOMITGOOD" in bad.cflags and "-DINCLUDEMAIN" in bad.cflags
    assert "-DOMITBAD" in by[("CWE-121", "good")].cflags
    # a CWE filter narrows the drop
    only134 = corpus.load_juliet(tmp_path, cwes={"CWE-134"})
    assert {c.cwe for c in only134} == {"CWE-134"}


def test_juliet_taint_channel_lifts_precision_end_to_end(tmp_path):
    """Score a Juliet testcase whose good variant calls the same API safely: the rule channel
    (candidate) false-positives on it, but the taint channel (corroborated) does not -- the
    confidence pipeline's precision lever, measured end to end. Needs gcc + Ghidra."""
    from lykos.analyze.ghidra import locate_ghidra
    if not shutil.which("gcc") or not locate_ghidra():
        pytest.skip("needs gcc + Ghidra")
    cases = corpus.load_juliet(_mini_juliet(tmp_path), cwes={"CWE-121"})  # 1 testcase, 2 bins
    cand = harness.run_corpus(cases, min_state="candidate", stage_timeout=180)
    corr = harness.run_corpus(cases, min_state="corroborated", stage_timeout=180)
    cbad = {o.verdict: o for o in cand.outcomes}
    assert cbad["bad"].flagged and cbad["good"].flagged        # rule flags BOTH (both strcpy)
    assert cand.metrics["overall"]["fp_rate"] == 1.0          # ...so precision suffers
    rbad = {o.verdict: o for o in corr.outcomes}
    assert rbad["bad"].flagged and not rbad["good"].flagged   # taint flags only the real flaw
    assert corr.metrics["overall"]["recall"] == 1.0 and corr.metrics["overall"]["fp_rate"] == 0.0


def test_load_dir_parses_named_cases(tmp_path):
    (tmp_path / "CWE-120__demo__bad.c").write_text("int main(){return 0;}")
    (tmp_path / "CWE-120__demo__good.c").write_text("int main(){return 0;}")
    (tmp_path / "ignoreme.txt").write_text("nope")
    cs = corpus.load_dir(tmp_path)
    assert len(cs) == 2 and {c.verdict for c in cs} == {"good", "bad"}
    assert all(c.cwe == "CWE-120" for c in cs)


def test_compile_uses_neutral_source_name(tmp_path):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    c = next(x for x in corpus.bundled() if x.name == "env_secret")
    exe = harness.compile_case(c, tmp_path, gcc)
    assert exe is not None
    # the descriptive label (which contains "secret") must NOT be embedded in the binary,
    # or it would leak the ground-truth CWE into the strings and cause a false positive.
    assert b"env_secret" not in exe.read_bytes()
    assert b"src.c" not in exe.read_bytes() and exe.name == "prog"


# ---------------------------------------------------------------- dynamic (confirmed) corpus
def test_dynamic_corpus_is_labeled_crash_pairs():
    cs = corpus.bundled_dynamic()
    assert len(cs) >= 4
    by = {}
    for c in cs:
        assert c.verdict in ("good", "bad") and c.cwe in CWE
        by.setdefault(c.cwe, set()).add(c.verdict)
    for cwe, verds in by.items():
        assert verds == {"good", "bad"}, f"{cwe} lacks a crash/safe pair"


# ---------------------------------------------------------------- live end-to-end (Ghidra)
def test_harness_scores_a_real_pair_end_to_end():
    """Compile + analyze a bad/good pair through the real pipeline; the bad case is flagged
    for its CWE and the good case is not (Juliet-style). Needs gcc + Ghidra."""
    from lykos.analyze.ghidra import locate_ghidra
    if not shutil.which("gcc") or not locate_ghidra():
        pytest.skip("needs gcc + Ghidra for the end-to-end benchmark")
    pair = [c for c in corpus.bundled() if c.name in ("system_inject", "system_none")]
    rep = harness.run_corpus(pair, stage_timeout=180)
    by = {o.name: o for o in rep.outcomes}
    assert by["system_inject"].flagged and "CWE-78" in by["system_inject"].found_cwes
    assert not by["system_none"].flagged             # safe variant -> no false positive
    assert rep.metrics["per_cwe"]["CWE-78"]["recall"] == 1.0
    assert rep.metrics["per_cwe"]["CWE-78"]["fp_rate"] == 0.0


def test_confirmed_stage_reproduces_a_crash_via_fuzzing():
    """The dynamic harness fuzzes a crash/safe pair: the bug is reproduced as a CONFIRMED
    finding (recall) and the safe variant is not (~0 FP-rate). Needs gcc; no Ghidra."""
    if not shutil.which("gcc"):
        pytest.skip("needs gcc for the confirmed-stage benchmark")
    pair = [c for c in corpus.bundled_dynamic()
            if c.name in ("nullderef_crash", "nullderef_safe")]
    rep = harness.run_dynamic_corpus(pair, max_execs=1200, max_seconds=20, stage_timeout=60)
    by = {o.name: o for o in rep.outcomes}
    assert by["nullderef_crash"].flagged                 # reproduced -> Confirmed
    assert by["nullderef_crash"].state in ("confirmed", "poc-backed")
    assert not by["nullderef_safe"].flagged              # safe variant -> no confirmed crash
    assert rep.metrics["per_cwe"]["CWE-476"]["recall"] == 1.0
    assert rep.metrics["per_cwe"]["CWE-476"]["fp_rate"] == 0.0
