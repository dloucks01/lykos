"""The live run console (jobs/runlog): every stage, target execution, tool command and fuzz
campaign an analysis performs, tailed by the GUI. Before it, a whole 7.5-minute autopilot run on
jhead produced 13 console lines while the target was executed thousands of times."""
from __future__ import annotations

import base64
import json
import subprocess

import pytest
from lykos.jobs import runlog


def _lines(tmp_path, case="c1"):
    p = runlog.console_path(tmp_path, case)
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_executions_are_full_then_sampled_and_crashes_always_full(tmp_path, monkeypatch):
    monkeypatch.setattr(runlog, "_FULL_PER_STAGE", 3)
    log = runlog.RunLog(tmp_path, "c1", run_id="r" * 16, stage="fuzz")
    for i in range(10):
        log.target_run(["t", "-x"], rc=0, ms=5)
    log.target_run(["t", "-x"], signal="SIGSEGV", crashed=True, ms=7, fault_pc=0x401000)
    log.target_run(["t", "-x"], rc=1, ms=5)
    log.flush()
    recs = _lines(tmp_path)
    assert [r["k"] for r in recs[:3]] == ["run"] * 3                  # the first N in full
    crash = [r for r in recs if r["k"] == "crash"]
    assert crash and crash[0]["sig"] == "SIGSEGV" and crash[0]["pc"] == "0x401000"
    summ = [r for r in recs if r["k"] == "runs"]
    assert sum(r["n"] for r in summ) == 8                              # 7 x rc0 + 1 x rc1 folded
    assert all(r["stage"] == "fuzz" for r in recs)


def test_fuzz_telemetry_is_throttled_but_final_always_lands(tmp_path):
    log = runlog.RunLog(tmp_path, "c1", stage="coverage_fuzz")
    for i in range(50):
        log.fuzz("AFL++", execs=i, eps=100)
    log.fuzz("AFL++", final=True, execs=50, status="exited 0")
    recs = [r for r in _lines(tmp_path) if r["k"] == "fuzz"]
    assert len(recs) == 2 and recs[-1]["final"] is True and recs[-1]["execs"] == 50


def test_read_by_offset_and_partial_lines(tmp_path):
    log = runlog.RunLog(tmp_path, "c1", stage="s")
    log.note("one")
    log.note("two")
    first = runlog.read(tmp_path, "c1", after=0, limit=1)
    assert [r["text"] for r in first["lines"]] == ["one"]
    rest = runlog.read(tmp_path, "c1", after=first["next"])
    assert [r["text"] for r in rest["lines"]] == ["two"] and rest["next"] == rest["size"]
    with open(runlog.console_path(tmp_path, "c1"), "a") as fh:
        fh.write('{"k":"note","text":"half')                          # a write in flight
    again = runlog.read(tmp_path, "c1", after=rest["next"])
    assert again["lines"] == [] and again["next"] == rest["next"]
    assert runlog.read(tmp_path, "nope")["lines"] == []


def test_size_cap_keeps_only_essential_records(tmp_path, monkeypatch):
    monkeypatch.setattr(runlog, "_CAP_BYTES", 200)
    log = runlog.RunLog(tmp_path, "c1", stage="s")
    for i in range(20):
        log.note("x" * 40)
    log.stage_event("end", outcome="done")
    recs = _lines(tmp_path)
    assert any("size cap" in (r.get("text") or "") for r in recs)
    assert recs[-1]["k"] == "stage" and recs[-1]["state"] == "end"   # essential: still written
    assert len(recs) < 12


def test_no_sink_is_a_no_op():
    assert runlog.current() is None
    runlog.target_run(["t"], rc=0)                                   # must not raise
    runlog.fuzz("x", execs=1)


_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")


def test_a_real_fuzz_stage_fills_the_console(store, case, gcc, tmp_path):
    from lykos.analyze import register
    from lykos.analyze.fuzz.stage import enqueue_fuzz
    from lykos.analyze.ingest import ingest
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    c = tmp_path / "c.c"
    c.write_text(_CRASH_ON_A)
    b = tmp_path / "crash"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    pool.start()
    try:
        target = ingest(store, case.id, b)
        q = JobQueue(store.conn)
        enqueue_fuzz(q, target, params={"input_mode": "stdin", "max_execs": 400, "max_seconds": 20,
                                        "exec_timeout": 1,
                                        "seeds": [base64.b64encode(b"zzzz").decode()]})
        assert pool.wait_idle(60)
    finally:
        pool.stop(grace=3.0)
    out = runlog.read(store.content.root, case.id)
    recs = out["lines"]
    kinds = {r["k"] for r in recs}
    stages = [r for r in recs if r["k"] == "stage"]
    assert any(r["state"] == "start" for r in stages) and any(r["state"] == "end" for r in stages)
    assert {"run", "crash"} <= kinds, kinds                           # executions + the crash
    assert any(r["k"] == "fuzz" for r in recs) or any(r["k"] == "done" for r in recs)
    assert all(r.get("target") == target.id for r in recs if r["k"] in ("run", "crash"))
