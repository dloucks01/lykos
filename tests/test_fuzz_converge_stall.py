"""Blind / directed campaigns end themselves when they have nothing left to give (doc 47 U1/U2):

  * CONVERGED -- under run-to-convergence, coverage stopped moving for a window scaled to the run,
    so the rest of the (six-hour) ceiling goes back to the run instead of being burned;
  * STALLED   -- every execution runs into the per-exec limit with nothing new reached: a wedged
    target, ended after a grace window instead of spending the whole slice on more of the same.

Neither may fire on a campaign that is still producing, and a time-boxed run keeps its slice."""
import base64
import subprocess
import time

import pytest
from lykos.analyze import register
from lykos.analyze.fuzz import health
from lykos.analyze.fuzz import stage as FS
from lykos.analyze.fuzz.stage import enqueue_fuzz
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, EventDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


# ----------------------------------------------------------------------------- pure window maths
def test_plateau_window_scales_with_the_run():
    # early in a run the floors govern ...
    assert FS._plateau_window(100, 5.0) == (FS._PLATEAU_MIN_EXECS, FS._PLATEAU_MIN_S)
    # ... later the idle tail must match half of everything done so far
    assert FS._plateau_window(100_000, 3600.0) == (50_000, 1800.0)


def test_plateaued_needs_both_executions_and_time():
    # last find at exec 1000 / 100 s; plenty of executions since but not enough time
    assert not FS._plateaued(50_000, 150.0, 1000, 100.0)
    # enough time, too few executions (a slow target)
    assert not FS._plateaued(1500, 10_000.0, 1000, 100.0)
    # both
    assert FS._plateaued(50_000, 10_000.0, 1000, 100.0)
    # a find late in the run resets it
    assert not FS._plateaued(50_000, 10_000.0, 49_000, 9_900.0)


def test_stall_grace_window():
    # floors: 32 attempts AND max(30 s, 15 x timeout, 5% of the slice capped at 300 s)
    assert FS._stall_grace_s(2.0, 30.0) == 30.0
    assert FS._stall_grace_s(4.0, 30.0) == 60.0
    assert FS._stall_grace_s(1.0, 21600.0) == 300.0
    assert not FS._stalled(31, 1000.0, 1.0, 30.0)      # too few attempts, however long
    assert not FS._stalled(500, 29.0, 1.0, 30.0)       # too short, however many
    assert FS._stalled(32, 30.0, 1.0, 30.0)


# ------------------------------------------------------------------------------- health verdicts
def _fh(done, extra=()):
    evs = [{"type": "fuzz.done", "payload": done}] + list(extra)
    return health.summarize([{"stage": "fuzz", "state": "done", "detail": ""}], evs)["engines"][0]


def test_health_stalled_without_a_find_is_stalled():
    e = _fh({"execs": 64, "crashes": 0, "stopped": "stalled",
             "stop_reason": "the last 64 executions all ran into the 1s limit",
             "budget_returned_s": 500.0})
    assert e["status"] == health.STALLED
    assert "1s limit" in e["reason"] and e["budget_returned_s"] == 500.0


def test_health_stalled_after_a_crash_is_ok_and_says_so():
    e = _fh({"execs": 64, "crashes": 2, "stopped": "stalled", "stop_reason": "wedged"})
    assert e["status"] == health.OK and "stalled" in e["reason"]


def test_health_converged_is_ok_with_the_plateau_reason():
    e = _fh({"execs": 9000, "crashes": 0, "stopped": "converged",
             "stop_reason": "coverage plateaued at 40 behaviours",
             "attempts": {"engine": "fuzz", "value": {"unit": "behaviours", "gained": 12}}})
    assert e["status"] == health.OK and e["reason"].startswith("converged")
    assert e["stopped"] == "converged"


def test_health_converged_with_no_gain_stays_no_gain():
    e = _fh({"execs": 9000, "crashes": 0, "stopped": "converged", "stop_reason": "plateau",
             "attempts": {"engine": "fuzz", "value": {"unit": "behaviours", "gained": 0,
                                                      "seed_coverage": 3}}})
    assert e["status"] == health.NO_GAIN and "converged" in e["reason"]


def test_health_stalled_only_run_is_degraded_not_ok():
    fh = health.summarize([{"stage": "fuzz", "state": "done", "detail": ""}],
                          [{"type": "fuzz.done", "payload": {"execs": 40, "stopped": "stalled",
                                                             "stop_reason": "wedged"}}])
    assert fh["verdict"] == "degraded" and "wedged" in fh["note"]


# ------------------------------------------------------------------------- real campaigns, e2e
_FAST = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
         "if(n>2&&b[0]=='x')return 2;return 0;}\n")
_WEDGED = "#include <unistd.h>\nint main(){for(;;)pause();}\n"
# Half the inputs hang, half exit: slow and timing out a lot, but PROGRESSING.
_HALF = ("#include <unistd.h>\nint main(){unsigned char b[4]={0};read(0,b,1);"
         "if(b[0]&1)for(;;)pause();return 0;}\n")


@pytest.fixture(scope="module")
def progs(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("conv_bins")
    out = {}
    for name, src in (("fast", _FAST), ("wedged", _WEDGED), ("half", _HALF)):
        c = d / f"{name}.c"
        c.write_text(src)
        if subprocess.run([gcc, "-O0", str(c), "-o", str(d / name)],
                          capture_output=True).returncode == 0:
            out[name] = d / name
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _events(store, case_id, typ):
    return [e.payload for e in EventDAO(store.conn).walk(case_id=case_id) if e.type == typ]


def _run(store, case, pool, path, wait=120, pre=None, **params):
    target = ingest(store, case.id, path)
    if pre:
        pre(target)
    q = JobQueue(store.conn)
    p = {"input_mode": "stdin", "discover_argv": False,
         "seeds": [base64.b64encode(b"hello").decode()]}
    p.update(params)
    t0 = time.monotonic()
    run = enqueue_fuzz(q, target, params=p)
    assert pool.wait_idle(wait) and q.runs.get(run.id).status == "done"
    return time.monotonic() - t0


def _shrink_plateau(monkeypatch):
    monkeypatch.setattr(FS, "_PLATEAU_MIN_EXECS", 300)
    monkeypatch.setattr(FS, "_PLATEAU_MIN_S", 1.0)


def test_converge_stops_at_the_plateau_and_returns_the_budget(store, case, pool, progs,
                                                              monkeypatch):
    if "fast" not in progs:
        pytest.skip("build failed")
    _shrink_plateau(monkeypatch)
    took = _run(store, case, pool, progs["fast"], converge=True, max_seconds=90,
                max_execs=10**7, exec_timeout=1)
    conv = _events(store, case.id, "fuzz.converged")
    assert conv, "no fuzz.converged event"
    c = conv[-1]
    assert c["reason"] == "plateau" and c["unit"] in ("blocks", "behaviours")
    assert c["idle_execs"] >= c["window_execs"] and c["idle_s"] >= c["window_s"]
    assert c["budget_returned_s"] > 30
    done = _events(store, case.id, "fuzz.done")[-1]
    assert done["stopped"] == "converged" and done["budget_returned_s"] > 30
    assert took < 75
    fh = health.summarize([{"stage": "fuzz", "state": "done", "detail": ""}],
                          [{"type": f"fuzz.{k}", "payload": p}
                           for k in ("converged", "attempts", "done")
                           for p in _events(store, case.id, f"fuzz.{k}")])
    eng = fh["engines"][0]
    assert eng["stopped"] == "converged" and "converged" in (eng["reason"] or "")


def test_time_boxed_run_keeps_its_slice(store, case, pool, progs, monkeypatch):
    if "fast" not in progs:
        pytest.skip("build failed")
    _shrink_plateau(monkeypatch)                    # would converge quickly IF it applied
    took = _run(store, case, pool, progs["fast"], max_seconds=5, max_execs=10**7,
                exec_timeout=1)
    assert not _events(store, case.id, "fuzz.converged")
    done = _events(store, case.id, "fuzz.done")[-1]
    assert done["stopped"] is None
    assert took >= 4.5


def _shrink_stall(monkeypatch):
    monkeypatch.setattr(FS, "_STALL_MIN_ATTEMPTS", 8)
    monkeypatch.setattr(FS, "_STALL_MIN_S", 1.0)
    monkeypatch.setattr(FS, "_STALL_TIMEOUT_MULT", 1)


def test_a_wedged_target_stalls_out(store, case, pool, progs, monkeypatch):
    if "wedged" not in progs:
        pytest.skip("build failed")
    _shrink_stall(monkeypatch)
    took = _run(store, case, pool, progs["wedged"], max_seconds=90, max_execs=10**6,
                exec_timeout=0.2)
    st = _events(store, case.id, "fuzz.stalled")
    assert st, "no fuzz.stalled event"
    assert st[-1]["streak"] >= 8 and st[-1]["budget_returned_s"] > 60
    done = _events(store, case.id, "fuzz.done")[-1]
    assert done["stopped"] == "stalled" and "per-execution limit" in done["stop_reason"]
    assert took < 40
    fh = health.summarize([{"stage": "fuzz", "state": "done", "detail": ""}],
                          [{"type": "fuzz.done", "payload": done}])
    assert fh["engines"][0]["status"] == health.STALLED


def test_a_progressing_target_with_many_timeouts_never_stalls(store, case, pool, progs,
                                                              monkeypatch):
    if "half" not in progs:
        pytest.skip("build failed")
    # the real attempt floor (32 in a row), short time floors: half the inputs complete, so a
    # run of 32 consecutive timeouts is a 1-in-4-billion event
    monkeypatch.setattr(FS, "_STALL_MIN_S", 0.5)
    monkeypatch.setattr(FS, "_STALL_TIMEOUT_MULT", 1)
    _run(store, case, pool, progs["half"], max_seconds=8, max_execs=10**6, exec_timeout=0.1)
    assert not _events(store, case.id, "fuzz.stalled")
    assert _events(store, case.id, "fuzz.done")[-1]["stopped"] is None


def test_stall_check_is_off_for_a_target_that_never_terminates(store, case, pool, progs,
                                                               monkeypatch):
    if "wedged" not in progs:
        pytest.skip("build failed")
    _shrink_stall(monkeypatch)

    def baseline_hung(target):
        DynResultDAO(store.conn).insert(target.id, target.case_id, input_mode="none",
                                        crashed=False, timed_out=True, isolation="bwrap")
    _run(store, case, pool, progs["wedged"], pre=baseline_hung, max_seconds=8,
         max_execs=10**6, exec_timeout=0.2)
    assert not _events(store, case.id, "fuzz.stalled")
    off = _events(store, case.id, "fuzz.stall_check")
    assert off and off[-1]["enabled"] is False
