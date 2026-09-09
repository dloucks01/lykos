"""Phase 10 — validation & benchmark harness (doc 14): metrics, corpus, and a live run."""
import shutil

import pytest
from lykos.analyze.detect.catalog import CWE
from lykos.eval import corpus, harness
from lykos.eval.metrics import Outcome, Report, score


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
