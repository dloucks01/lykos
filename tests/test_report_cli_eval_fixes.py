"""CLI exit codes, the offline `report` subcommand, and eval/dashboard math fixes."""
from __future__ import annotations

import json
import logging

from lykos import cli, observe
from lykos.casestore import CaseStore
from lykos.db.dao import FindingDAO
from lykos.eval import dashboard
from lykos.eval.metrics import Outcome, score
from lykos.hashing import hash_bytes


def _kept_case(tmp_path):
    d = tmp_path / "kept"
    s = CaseStore.open(d)
    c = s.cases.create("kept case")
    t = s.targets.upsert(c.id, filename="bin", sha256=hash_bytes(b"b"), size=1, arch="x86_64",
                         bits=64, file_type="ELF", mitigations={})
    FindingDAO(s.conn).upsert(t.id, c.id, {"dedup_key": "k", "cwe": "CWE-134",
                                           "title": "fmt", "severity": "medium",
                                           "state": "candidate", "confidence": 0.3,
                                           "detector": "rule", "evidence": []})
    s.close()
    return d, c.id


def test_report_subcommand_writes_every_format(tmp_path):
    d, cid = _kept_case(tmp_path)
    for suffix, check in ((".sarif", lambda b: json.loads(b)["version"] == "2.1.0"),
                          (".json", lambda b: json.loads(b)["schema"] == "lykos.case-export/1"),
                          (".pdf", lambda b: b[:5] == b"%PDF-"),
                          (".html", lambda b: b.startswith(b"<!doctype html>"))):
        out = tmp_path / f"r{suffix}"
        assert cli.main(["report", "--case-store", str(d), "--out", str(out)]) == 0
        assert check(out.read_bytes()), suffix
    # explicit case prefix + a filter
    out = tmp_path / "x.sarif"
    assert cli.main(["report", "--case-store", str(d), "--case", cid[:6],
                     "--min-severity", "high", "--out", str(out)]) == 0
    assert json.loads(out.read_bytes())["runs"][0]["results"] == []


def test_report_subcommand_refuses_a_missing_store_and_bad_states(tmp_path, capsys):
    missing = tmp_path / "nope"
    assert cli.main(["report", "--case-store", str(missing)]) == 2
    assert not missing.exists(), "the report command created an empty store"
    d, _ = _kept_case(tmp_path)
    assert cli.main(["report", "--case-store", str(d), "--states", "bogus",
                     "--out", str(tmp_path / "a.html")]) == 2
    assert cli.main(["report", "--case-store", str(d), "--case", "zzzz-none"]) == 2


def test_serve_rejects_a_malformed_http_bind(tmp_path, capsys):
    assert cli.main(["serve", "--case-store", str(tmp_path / "s"), "--http", "localhost"]) == 2
    assert "HOST:PORT" in capsys.readouterr().err


def test_weggli_json_reports_an_unsupported_scan_as_a_failure(tmp_path, monkeypatch, capsys):
    from lykos.analyze import weggli
    monkeypatch.setattr(weggli, "scan", lambda *a, **k: {"supported": False, "note": "no weggli",
                                                         "findings": [], "queries_run": 0})
    assert cli.main(["weggli-scan", str(tmp_path), "--json"]) == 3


def test_print_findings_survives_null_fields(capsys):
    class F:
        state = None
        severity = None
        cwe = None
        title = None
        detector = None
    cli._print_findings([F()])
    assert "detected only" in capsys.readouterr().out


def test_print_scorecard_survives_null_counts(capsys):
    cli._print_scorecard({"baseline": {"ran": True}, "executions": {"total": None,
                                                                    "by_engine": {"afl": None}},
                          "budget": {"total": 60, "elapsed": None}})
    assert "executions   0" in capsys.readouterr().out


def test_benchmark_with_lava_does_not_score_lava_programs_as_static_cases(monkeypatch):
    from lykos.eval import corpus as corpusmod
    from lykos.eval import harness
    from lykos.eval import history as histmod
    from lykos.eval.metrics import Report
    seen = []
    monkeypatch.setattr(corpusmod, "benchmark", lambda: ["STATIC"])
    monkeypatch.setattr(corpusmod, "load_lava", lambda *a, **k: ["LAVAPROG"])
    monkeypatch.setattr(harness, "run", lambda cases, **k: (seen.append(cases),
                                                            Report(metrics=score([])))[1])
    monkeypatch.setattr(harness, "run_lava_corpus", lambda progs, **k: Report(metrics=score([])))
    monkeypatch.setattr(histmod, "record", lambda *a, **k: {})
    assert cli.main(["eval", "--benchmark", "--lava", "/x"]) == 0
    assert seen and all(c == ["STATIC"] for c in seen), seen


def test_an_unscored_case_is_counted_conservatively():
    outs = [Outcome("g", "CWE-121", "good", set(), scored=False),     # never ran: NOT a TN
            Outcome("b", "CWE-121", "bad", set(), scored=False),      # never ran: a miss
            Outcome("g2", "CWE-121", "good", set()),
            Outcome("b2", "CWE-121", "bad", {"CWE-121"})]
    m = score(outs)
    o = m["overall"]
    assert (o["tp"], o["fn"], o["fp"], o["tn"]) == (1, 1, 0, 1)
    assert m["n_unscored"] == 2
    assert o["recall"] == 0.5


def test_dashboard_diffs_identical_runs_against_their_own_predecessor():
    run = {"ts": 1, "stage": "static", "min_state": "candidate", "git": "a",
           "overall": {"recall": 0.5, "fp_rate": 0.0}}
    hist = [dict(run, overall={"recall": 1.0, "fp_rate": 0.0}), dict(run), dict(run)]
    txt = dashboard.render_text(hist)
    rows = txt.splitlines()[-3:]
    assert "0.50!" in rows[1], rows          # second run: recall fell 1.0 -> 0.5
    # the third equals the second, so it diffs to "=", not to the drop from the FIRST run
    assert "0.50!" not in rows[2] and "=" in rows[2], rows


def test_numeric_log_level_is_honoured(monkeypatch):
    monkeypatch.setenv(observe.LEVEL_VAR, "10")
    observe.configure(force=True)
    assert logging.getLogger("lykos").level == logging.DEBUG
    observe.configure("warning", force=True)
