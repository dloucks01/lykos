"""The `lykos` command line itself.

`cli.py` is what the operator actually types, and it was the largest wholly untested module
in the tree: every command was reachable only by running the real gate behind it, so the
argument wiring -- which case list a `--only` filter selects, whether `--out` is written,
which exit code a failing gate produces -- had no test at all. These drive `main()` in
process and stub the expensive gate bodies, because the thing under test here is the wiring,
not the gate.
"""
from __future__ import annotations

import json

import pytest
from lykos import cli
from lykos.db.migrations import current_version


def test_db_init_then_version(tmp_path, capsys):
    d = tmp_path / "case"
    assert cli.main(["db", "init", "--case-store", str(d)]) == 0
    out = capsys.readouterr().out
    assert "initialized" in out and str(d) in out
    assert cli.main(["db", "version", "--case-store", str(d)]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed.isdigit() and int(printed) > 0


def test_db_upgrade_is_idempotent_and_reports_head(tmp_path, capsys):
    d = tmp_path / "case"
    cli.main(["db", "init", "--case-store", str(d)])
    capsys.readouterr()
    assert cli.main(["db", "upgrade", "--case-store", str(d)]) == 0
    out = capsys.readouterr().out
    assert "upgraded" in out
    from lykos.casestore import CaseStore
    s = CaseStore.open(d)
    try:
        assert f"v{current_version(s.conn)}" in out
    finally:
        s.close()


def test_db_rejects_an_unknown_subcommand():
    # argparse `choices` catches this at parse time -- exit 2, not a traceback.
    with pytest.raises(SystemExit) as e:
        cli.main(["db", "reticulate", "--case-store", "/tmp/x"])
    assert e.value.code == 2


def test_serve_without_a_bind_is_an_error(tmp_path, capsys):
    rc = cli.main(["serve", "--case-store", str(tmp_path)])
    assert rc == 2
    assert "needs --socket" in capsys.readouterr().err


def test_version_flag():
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0


def _rec(stage, ts, recall, fp, *, min_state=None):
    return {"ts": ts, "git": "abc1234", "stage": stage, "min_state": min_state,
            "label": None, "backend": {"fuzz_execs": 2500}, "n_cases": 6,
            "overall": {"recall": recall, "fp_rate": fp, "precision": 1.0, "f1": 1.0,
                        "tp": 3, "fp": 0, "fn": 0, "tn": 3},
            "per_cwe": {}}


def _history(tmp_path, records):
    p = tmp_path / "hist.jsonl"
    p.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    return p


def test_dashboard_renders_and_writes_html(tmp_path, capsys):
    p = _history(tmp_path, [_rec("dynamic", 1000, 1.0, 0.0),
                            _rec("dynamic", 2000, 1.0, 0.0)])
    html = tmp_path / "dash.html"
    rc = cli.main(["dashboard", "--history", str(p), "--html", str(html)])
    assert rc == 0
    assert "dynamic" in capsys.readouterr().out
    body = html.read_text()
    assert body.startswith("<") and "dynamic" in body


def test_dashboard_fails_on_a_regression_only_when_asked(tmp_path, capsys):
    # recall fell 1.0 -> 0.5 between two runs of the same series
    p = _history(tmp_path, [_rec("dynamic", 1000, 1.0, 0.0),
                            _rec("dynamic", 2000, 0.5, 0.0)])
    assert cli.main(["dashboard", "--history", str(p)]) == 0
    capsys.readouterr()
    assert cli.main(["dashboard", "--history", str(p), "--fail-on-regression"]) == 1
    assert "REGRESSION" in capsys.readouterr().err


def test_dashboard_on_a_missing_history_is_empty_not_a_crash(tmp_path, capsys):
    rc = cli.main(["dashboard", "--history", str(tmp_path / "nope.jsonl"),
                   "--fail-on-regression"])
    assert rc == 0
    capsys.readouterr()


@pytest.mark.parametrize("cmd,mod", [("archgate", "archgate"), ("realgate", "realgate")])
def test_gate_only_filters_the_matrix_and_writes_a_report(cmd, mod, tmp_path, capsys,
                                                          monkeypatch):
    """`--only` selects by label and `--out` gets the JSON -- the wiring, without the gate."""
    from lykos.eval import archgate, realgate
    target = {"archgate": archgate, "realgate": realgate}[mod]
    seen = {}

    def fake_run(cases, *, timeout=30.0, progress=None):
        seen["labels"] = [c.label for c in cases]
        seen["timeout"] = timeout
        return {"results": [{"label": lbl, "ok": True} for lbl in seen["labels"]]}

    monkeypatch.setattr(target, "run", fake_run)
    monkeypatch.setattr(target, "table", lambda rep: "TABLE")
    monkeypatch.setattr(target, "gate", lambda rep: (True, "PASS", "ok"))

    want = target.MATRIX[0].label
    out = tmp_path / "rep.json"
    rc = cli.main([cmd, "--only", want, "--timeout", "3", "--out", str(out)])
    assert rc == 0
    assert seen["labels"] == [want]
    assert seen["timeout"] == 3.0
    assert json.loads(out.read_text())["results"][0]["label"] == want
    err = capsys.readouterr().err
    assert "GATE: PASS" in err


@pytest.mark.parametrize("cmd,mod", [("archgate", "archgate"), ("realgate", "realgate")])
def test_a_failing_gate_exits_nonzero(cmd, mod, monkeypatch, capsys):
    from lykos.eval import archgate, realgate
    target = {"archgate": archgate, "realgate": realgate}[mod]
    monkeypatch.setattr(target, "run", lambda cases, **kw: {"results": []})
    monkeypatch.setattr(target, "table", lambda rep: "TABLE")
    monkeypatch.setattr(target, "gate", lambda rep: (False, "FAIL", "1 case regressed"))
    assert cli.main([cmd]) == 1
    assert "GATE: FAIL -- 1 case regressed" in capsys.readouterr().err


def test_eval_wiring_records_history_and_honours_the_gate(tmp_path, capsys, monkeypatch):
    """The `eval` command's own logic: stage selection, the summary line, --out, --record,
    and the exit code coming from the gate rather than from the run."""
    from lykos.eval import harness

    class Rep:
        meta = {"max_execs": 2500, "max_seconds": 25, "elapsed_s": 12.5,
                "gcc": True, "warnings": ["short budget"]}
        metrics = {"n_cases": 6, "n_cwe_classes": 3, "per_cwe": {},
                   "overall": {"recall": 1.0, "fp_rate": 0.0, "tp": 3, "fn": 0}}

        def table(self):
            return "TABLE"

        def to_dict(self):
            return {"metrics": self.metrics}

    seen = {}

    def fake_run(cases, **kw):
        seen.update(kw)
        return Rep()

    monkeypatch.setattr(harness, "run", fake_run)
    hist = tmp_path / "h.jsonl"
    out = tmp_path / "r.json"
    rc = cli.main(["eval", "--stage", "dynamic", "--record", "--history", str(hist),
                   "--out", str(out), "--min-recall", "1.0", "--max-fp-rate", "0.0"])
    assert rc == 0
    assert seen["stage"] == "dynamic"
    cap = capsys.readouterr()
    assert "warning: short budget" in cap.err
    assert "dynamic-stage: 6 cases, 3 CWE classes" in cap.out
    assert "fuzz budget=2500 execs/25s" in cap.out
    assert json.loads(out.read_text())["metrics"]["n_cases"] == 6
    rows = [json.loads(x) for x in hist.read_text().splitlines() if x.strip()]
    assert len(rows) == 1 and rows[0]["stage"] == "dynamic"
    assert "GATE: PASS" in cap.err


def test_eval_static_stage_passes_min_state_and_says_which_backend(capsys, monkeypatch):
    from lykos.eval import harness

    class Rep:
        meta = {"ghidra": True, "elapsed_s": 106.0, "warnings": []}
        metrics = {"n_cases": 20, "n_cwe_classes": 4, "per_cwe": {},
                   "overall": {"recall": 1.0, "fp_rate": 0.2, "tp": 6, "fn": 0}}

        def table(self):
            return "TABLE"

        def to_dict(self):
            return {}

    seen = {}
    monkeypatch.setattr(harness, "run", lambda cases, **kw: (seen.update(kw), Rep())[1])
    rc = cli.main(["eval", "--stage", "static", "--min-state", "corroborated",
                   "--min-recall", "1.0", "--max-fp-rate", "0.25"])
    assert rc == 0
    assert seen["min_state"] == "corroborated"
    out = capsys.readouterr().out
    # the backend line names which RE backend produced the scores (ghidra | native | NONE), so a
    # native-backend eval can't masquerade as a ghidra one -- see the --require-backend gate (P0.2).
    assert "backend=ghidra, min_state=corroborated" in out


def test_eval_exit_code_follows_the_gate_not_the_run(capsys, monkeypatch):
    from lykos.eval import harness

    class Rep:
        meta = {"max_execs": 100, "max_seconds": 5, "elapsed_s": 5.0, "gcc": True, "warnings": []}
        metrics = {"n_cases": 6, "n_cwe_classes": 3, "per_cwe": {},
                   "overall": {"recall": 0.5, "fp_rate": 0.0, "tp": 3, "fn": 3}}

        def table(self):
            return "TABLE"

        def to_dict(self):
            return {}

    monkeypatch.setattr(harness, "run", lambda cases, **kw: Rep())
    # recall 0.5 under a 1.0 floor is a FAIL, and the process must say so
    assert cli.main(["eval", "--stage", "dynamic", "--min-recall", "1.0"]) == 1
    assert "GATE: FAIL" in capsys.readouterr().err


# ---- doctor ------------------------------------------------------------------------------

def test_doctor_reports_the_host_and_exits_zero(capsys):
    """It must succeed even where nothing is installed -- reporting a bare host IS the job."""
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "REQUIRED" in out and "present." in out


def test_doctor_json_is_machine_readable(capsys):
    assert cli.main(["doctor", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tools"] and all("present" in t for t in data["tools"])


def test_doctor_strict_fails_only_on_a_missing_REQUIRED_tool(capsys, monkeypatch):
    """`--strict` is what a provisioning script keys on, so it must not fire for an optional
    engine that is simply not installed."""
    from lykos import toolchain
    real = toolchain.TOOLS

    def only(keys):
        return tuple(t for t in real if t.key in keys)

    monkeypatch.setattr(toolchain, "TOOLS", only({"python"}))       # required, always present
    assert cli.main(["doctor", "--strict"]) == 0
    capsys.readouterr()

    missing_req = toolchain.Tool("ghost", "Ghost Tool", "nothing at all",
                                 "nothing is lost", "cannot be installed",
                                 lambda: None, tier="required")
    monkeypatch.setattr(toolchain, "TOOLS", only({"python"}) + (missing_req,))
    assert cli.main(["doctor", "--strict"]) == 1
    out = capsys.readouterr().out
    assert "Ghost Tool" in out and "cannot be installed" in out


def test_doctor_without_strict_is_a_report_not_a_gate(capsys, monkeypatch):
    from lykos import toolchain
    missing_req = toolchain.Tool("ghost", "Ghost Tool", "nothing", "nothing lost",
                                 "cannot be installed", lambda: None, tier="required")
    monkeypatch.setattr(toolchain, "TOOLS", (missing_req,))
    assert cli.main(["doctor"]) == 0, "a plain report must not fail the shell"
    capsys.readouterr()
