"""U1-engine (doc 47): run-to-convergence makes the coverage campaign stop on AFL's own
coverage-plateau signal (AFL_EXIT_WHEN_DONE) rather than burning the full `-V` ceiling. The flag is
set ONLY when converge=True, so a normal (time-boxed) run is byte-for-byte unchanged."""
from __future__ import annotations

import subprocess
from pathlib import Path

from lykos.analyze.fuzz import aflpp


class _FakeProc:
    returncode = 0

    def wait(self, timeout=None):
        return 0


def _env_for(monkeypatch, tmp_path, *, converge):
    captured = {}

    def _fake_popen(cmd, env=None, **kw):
        captured["env"] = env
        return _FakeProc()

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    seeds = tmp_path / "seeds"
    seeds.mkdir(exist_ok=True)
    (seeds / "s").write_bytes(b"x")
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    afl = tmp_path / "afl-fuzz"
    afl.write_text("#!/bin/sh\n")
    exe = tmp_path / "t"
    exe.write_bytes(b"\x7fELF")
    aflpp.run_campaign(afl, exe, seeds, out, seconds=5, qemu=True, converge=converge)
    return captured["env"]


def test_converge_sets_afl_exit_when_done(monkeypatch, tmp_path):
    env = _env_for(monkeypatch, tmp_path, converge=True)
    assert env.get("AFL_EXIT_WHEN_DONE") == "1"


def test_timeboxed_run_does_not_set_exit_when_done(monkeypatch, tmp_path):
    env = _env_for(monkeypatch, tmp_path, converge=False)
    assert "AFL_EXIT_WHEN_DONE" not in env
