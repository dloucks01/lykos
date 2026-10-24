"""Audit regressions for analyze/libfuzzer.py: bounded process trees, temp cleanup, and a
sanitizer report always bound to the input that produced it."""
import os
import subprocess
import time
from pathlib import Path

import pytest
from lykos.analyze import libfuzzer as LF


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split()[2] != "Z"
    except OSError:
        return False


def test_run_group_timeout_takes_grandchildren_and_does_not_hang(tmp_path):
    pidf = tmp_path / "pid"
    t0 = time.time()
    with pytest.raises(subprocess.TimeoutExpired):
        LF._run_group(["sh", "-c", f"sleep 60 & echo $! > {pidf}; sleep 60"], timeout=0.5)
    assert time.time() - t0 < 10
    pid = int(pidf.read_text())
    for _ in range(100):
        if not _alive(pid):
            break
        time.sleep(0.02)
    assert not _alive(pid), "the forked grandchild outlived the timeout"


def test_run_group_returns_output_and_rc():
    r = LF._run_group(["sh", "-c", "echo out; echo err >&2; exit 3"], timeout=10)
    assert r.returncode == 3 and r.stdout.strip() == "out" and r.stderr.strip() == "err"


_REPORT = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2\n"
           "READ of size 1 at 0x1 thread T0\n    #0 0x2 in parse /src/lib.c:7:3\n")


def test_replayed_report_is_bound_to_the_input_that_produced_it(tmp_path, monkeypatch):
    # the loop printed a sanitizer report but wrote no artifact and no "Running:" line
    monkeypatch.setattr(LF, "_run_group", lambda *a, **k: subprocess.CompletedProcess(
        a, 1, "", "==1==ERROR: AddressSanitizer: SEGV on unknown address\n"))
    monkeypatch.setattr(LF, "_replay_report",
                        lambda _b, _w, data: _REPORT if data == b"B" else "")
    r = LF.run_libfuzzer(tmp_path / "bin", tmp_path, seconds=1,
                         corpus=[b"AAAAAAAA", b"B"])          # largest seed is NOT the culprit
    assert len(r["crashes"]) == 1
    c = r["crashes"][0]
    assert c["input"] == b"B" and c["reproduced"] is True
    assert "lib.c:7" in c["report"]


def test_an_unreproduced_stand_in_is_marked(tmp_path, monkeypatch):
    monkeypatch.setattr(LF, "_run_group", lambda *a, **k: subprocess.CompletedProcess(
        a, 1, "", "==1==ERROR: AddressSanitizer: SEGV on unknown address\n"))
    monkeypatch.setattr(LF, "_replay_report", lambda *_a: "")
    r = LF.run_libfuzzer(tmp_path / "bin", tmp_path, seconds=1, corpus=[b"AAAA"])
    assert r["crashes"] and r["crashes"][0]["reproduced"] is False


def test_an_unrunnable_binary_is_reported_not_raised(tmp_path):
    r = LF.run_libfuzzer(tmp_path / "missing-binary", tmp_path, seconds=1)
    assert r["crashes"] == [] and "could not be run" in r["log"]


def test_build_tmp_is_removed_when_the_build_raises(tmp_path, monkeypatch):
    made = tmp_path / "lf-tmp"

    def fake_mkdtemp(prefix=""):
        made.mkdir()
        return str(made)
    monkeypatch.setattr(LF.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(LF, "_clang", lambda _cxx: "clang")
    monkeypatch.setattr(LF, "ensure_configured", lambda *_a, **_k: False)

    def boom(*_a, **_k):
        raise RuntimeError("synth failed")
    monkeypatch.setattr(LF, "_build_in", boom)
    with pytest.raises(RuntimeError):
        LF.build_libfuzzer(tmp_path, tmp_path / "out", spec={"kind": "fn", "fn": "f", "id": "x"})
    assert not Path(made).exists()
