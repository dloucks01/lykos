"""Bounded fuzz campaigns (deep_decoder_fuzz concurrency + memory-capped libFuzzer launch) and
run_and_verify judging only THIS run's rows in a reused case store."""
import importlib.util
import sqlite3
import subprocess
from pathlib import Path

from lykos.analyze import libfuzzer as LF

_TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _tool(name):
    spec = importlib.util.spec_from_file_location(f"lykos_tool_{name}", _TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_run_libfuzzer_prepends_launcher_and_rss_limit(monkeypatch, tmp_path):
    seen = {}

    def fake_group(argv, *, timeout, cwd=None, env=None):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(LF, "_run_group", fake_group)
    launcher = ["systemd-run", "--user", "--scope", "-q", "-p", "MemoryMax=4096M"]
    LF.run_libfuzzer("/bin/true", tmp_path, seconds=1, rss_limit_mb=777, launcher=launcher)
    assert seen["argv"][:len(launcher)] == launcher
    assert seen["argv"][len(launcher)] == "/bin/true"
    assert "-rss_limit_mb=777" in seen["argv"]


def test_deep_decoder_fuzz_concurrency_is_bounded(monkeypatch):
    d = _tool("deep_decoder_fuzz")
    monkeypatch.setattr(d.os, "cpu_count", lambda: 16)
    assert d._concurrency(30) == 4 and d._concurrency(2) == 2
    monkeypatch.setattr(d.os, "cpu_count", lambda: None)
    assert d._concurrency(30) == 4
    monkeypatch.setattr(d.shutil, "which", lambda _n: None)
    assert d._memcap_launcher(2048) == []                   # graceful fallback: rss-limit only


def test_run_and_verify_ignores_a_reused_store_prior_run(tmp_path):
    rv = _tool("run_and_verify")
    db = str(tmp_path / "case.db")
    c = sqlite3.connect(db)
    c.execute("create table analysis_run(id, case_id, stage, status, created_at)")
    c.execute("create table finding(case_id, updated_at)")
    c.execute("create table poc(case_id, created_at)")
    c.execute("insert into analysis_run values('old', 'c1', 'triage', 'done', 100)")
    c.execute("insert into finding values('c1', 100)")
    c.commit()
    runs, done, findings, _ = rv.this_run_rows(db, {"old"}, 200)   # this run crashed: no rows
    assert runs == [] and not ({"triage", "attack_path"} & done) and findings == 0
    c.execute("insert into analysis_run values('n1', 'c2', 'attack_path', 'done', 210)")
    c.execute("insert into finding values('c2', 211)")
    c.commit()
    runs, done, findings, _ = rv.this_run_rows(db, {"old"}, 200)
    assert "attack_path" in done and findings == 1
