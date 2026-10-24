"""Orchestration + job-system robustness (doc 48 "Robustness" follow-ups, doc 47 P7).

* one target raising must not abort the rest of the worklist, and must be recorded, not hidden;
* `_recover_missing_fault_pcs` must not leak its staged full-binary copy;
* `_distinct_crashes` must not silently drop the 13th distinct crash, nor fold an unresolvable
  second defect (another channel; a wine/qemu target with no fault PC) into the first;
* a worker abandoned as wedged must retire when its stage returns, not run on as a surplus;
* the reaper must not reap a run whose owning worker thread is alive (heartbeat starvation);
* a reproducible hang is filed as a CWE-835 finding -- and a target that hangs on EVERY input
  is not.
"""
import pathlib
import sqlite3
import tempfile
import threading
import time

import pytest
from lykos.analyze import orchestrate as O
from lykos.analyze.dynamic.sandbox import RunResult
from lykos.analyze.ingest import ingest
from lykos.db.dao import DynResultDAO, EventDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue


def _target(store, case, tag: bytes, **fields):
    p = pathlib.Path(tempfile.mkdtemp()) / "t.bin"
    p.write_bytes(b"\x7fELF" + tag + b"\x00" * 200)
    t = ingest(store, case.id, p, filename=f"t-{tag.decode()}.bin")
    if fields:
        t = store.targets.upsert(case.id, t.filename, t.sha256, **fields)
    return t


# ---- 1. per-target exception isolation ---------------------------------------------------

def test_one_target_raising_does_not_abort_the_remaining_targets(store, case, monkeypatch):
    ts = [_target(store, case, x, file_type="elf", arch="x86-64", bits=64)
          for x in (b"a", b"b", b"c")]
    bad = ts[1].id
    seen = []

    def fake_staged(bud, st, t, stage, status, stop, params=None, **kw):
        seen.append((t.id, stage))
        if t.id == bad and stage == "disassemble":
            status["stage"] = stage
            raise sqlite3.OperationalError("database is locked")
        return "done"

    monkeypatch.setattr(O, "_staged", fake_staged)
    monkeypatch.setattr(O, "_run_target_stages", lambda *a, **k: {})
    monkeypatch.setattr(O, "_settle", lambda *a, **k: True)
    monkeypatch.setattr(O, "_scorecard", lambda *a, **k: {})
    monkeypatch.setattr(O, "_run_case_stage", lambda *a, **k: None)
    monkeypatch.setattr(O, "_run_poc_diff", lambda *a, **k: None)
    status: dict = {}
    O.run_case_autopilot(store.dir, case.id, [t.id for t in ts], status, threading.Event(),
                         budget_seconds=60)
    # target #3 was still analysed after #2 raised
    assert (ts[2].id, "disassemble") in seen
    assert (ts[2].id, "directed_fuzz") in seen
    # ...and #2's failure is RECORDED, three ways
    assert status["state"] == "done"
    assert [e["target_id"] for e in status["target_errors"]] == [bad]
    assert "database is locked" in status["target_errors"][0]["error"]
    evs = list(EventDAO(store.conn).walk(case_id=case.id))
    errs = [e for e in evs if e.type == "autopilot.target_error"]
    assert errs and errs[0].payload["target_id"] == bad
    done = [e for e in evs if e.type == "autopilot.done"]
    assert done and done[-1].payload["failed_targets"] == [bad]


# ---- 3. fault-PC temp dir leak --------------------------------------------------------------

def test_fault_pc_recovery_removes_its_staged_binary(store, case, monkeypatch, tmp_path):
    from lykos.analyze.dynamic import sandbox
    t = _target(store, case, b"f", file_type="elf", arch=sandbox.host_arch(), bits=64)
    dd = DynResultDAO(store.conn)
    for sha in ("i1", "i2"):
        dd.insert(t.id, case.id, input_sha=sha, input_mode="stdin", crashed=True,
                  signal_name="SIGSEGV")
    made = []
    real_mkdtemp = tempfile.mkdtemp

    def spy_mkdtemp(*a, **k):
        d = real_mkdtemp(*a, dir=str(tmp_path), **{x: v for x, v in k.items() if x != "dir"})
        made.append(pathlib.Path(d))
        return d

    monkeypatch.setattr(tempfile, "mkdtemp", spy_mkdtemp)
    import lykos.analyze.poc.capture as cap
    monkeypatch.setattr(cap, "materialize_helper", lambda: tmp_path / "helper")
    monkeypatch.setattr(cap, "make_capture",
                        lambda *a, **k: (lambda data: {"ok": False}))
    O._FAULTPC_TRIED.clear()
    crashes = [d for d in dd.list_by_target(t.id) if d.crashed]
    O._recover_missing_fault_pcs(store, t.id, crashes)
    assert made, "the recovery never staged the binary (test did not exercise the path)"
    assert all(not d.exists() for d in made), "the staged full-binary copy leaked"
    # and each input is re-captured at most once per process (no repeat cost every call)
    made.clear()
    O._recover_missing_fault_pcs(store, t.id, crashes)
    assert not made


# ---- 5. _distinct_crashes -------------------------------------------------------------------

def test_a_thirteenth_distinct_crash_is_not_dropped(store, case):
    t = _target(store, case, b"d", file_type="elf", arch="x86-64", bits=64)
    dd = DynResultDAO(store.conn)
    for i in range(14):
        dd.insert(t.id, case.id, input_sha=f"s{i}", input_mode="stdin", crashed=True,
                  signal_name="SIGSEGV", fault_pc=0x1000 + i)
    got = O._distinct_crashes(store, t.id)
    assert len(got) == 14
    assert {d.input_sha for d in got} == {f"s{i}" for i in range(14)}


def test_unresolved_crashes_on_different_channels_are_not_folded(store, case):
    t = _target(store, case, b"e", file_type="elf", arch="mips", bits=32)   # foreign: no recovery
    dd = DynResultDAO(store.conn)
    dd.insert(t.id, case.id, input_sha="std", input_mode="stdin", crashed=True,
              signal_name="SIGSEGV")
    dd.insert(t.id, case.id, input_sha="arg", input_mode="arg", crashed=True,
              signal_name="SIGSEGV")
    got = {d.input_sha for d in O._distinct_crashes(store, t.id)}
    assert got == {"std", "arg"}


def test_an_unrecoverable_bucket_keeps_a_second_representative_last(store, case):
    """A wine PE / qemu target records no fault PC and none can be re-captured, so a second
    distinct defect of the same signal used to be unprovable. It gets a second representative,
    ranked after every primary so it only spends leftover budget."""
    t = _target(store, case, b"w", file_type="pe", arch="x86-64", bits=64)
    dd = DynResultDAO(store.conn)
    for sha in ("p1", "p2", "p3"):
        dd.insert(t.id, case.id, input_sha=sha, input_mode="stdin", crashed=True,
                  signal_name="SIGSEGV")
        time.sleep(0.001)
    dd.insert(t.id, case.id, input_sha="abrt", input_mode="stdin", crashed=True,
              signal_name="SIGABRT", defect_key="asan:heap-buffer-overflow:x.c:1")
    got = O._distinct_crashes(store, t.id)
    shas = [d.input_sha for d in got]
    assert len(shas) == 3                             # SIGSEGV x2 (cap) + the SIGABRT bucket
    assert "abrt" in shas[:2]                         # the primary buckets come first
    assert len({s for s in shas if s.startswith("p")}) == 2


def test_a_native_hijack_bucket_still_collapses_to_one(store, case, monkeypatch):
    """Where a fault PC CAN be recovered, an unresolved bucket means a hijack -- one stack smash
    must not fan out into several proofs."""
    from lykos.analyze.dynamic import sandbox
    t = _target(store, case, b"h", file_type="elf", arch=sandbox.host_arch(), bits=64)
    monkeypatch.setattr(O, "_recover_missing_fault_pcs", lambda *a, **k: None)
    dd = DynResultDAO(store.conn)
    for sha in ("h1", "h2", "h3"):
        dd.insert(t.id, case.id, input_sha=sha, input_mode="stdin", crashed=True,
                  signal_name="SIGSEGV")
    assert len(O._distinct_crashes(store, t.id)) == 1


# ---- 2 + 4. worker retirement, reaper vs. a live owner ---------------------------------------

def test_reap_spares_a_run_whose_owner_is_alive_but_reaps_a_dead_one(store, case):
    q = JobQueue(store.conn)
    r1 = q.enqueue(case.id, "noop_a", params={"i": 1}, max_attempts=1)
    r2 = q.enqueue(case.id, "noop_b", params={"i": 2}, max_attempts=1)
    assert q.claim("w1", ["quick"], 1) and q.claim("w2", ["quick"], 1)
    future = int(time.time()) + 100
    assert q.reap(now=future, live={r1.id}) == 1           # only the dead owner's run
    assert q.runs.get(r1.id).status == "running"          # starved heartbeat: lease renewed
    assert q.runs.get(r1.id).lease_expires_at > int(time.time())
    assert q.runs.get(r2.id).status == "error"
    types = [r["type"] for r in store.conn.execute("SELECT type FROM event").fetchall()]
    assert "job.lease_renewed" in types                   # visible, not silent


def test_reap_still_cancels_a_live_run_that_was_cancel_requested(store, case):
    q = JobQueue(store.conn)
    r = q.enqueue(case.id, "noop_c", params={"i": 3})
    assert q.claim("w1", ["quick"], 1)
    q.cancel(r.id)
    q.reap(now=int(time.time()) + 100, live={r.id})
    assert q.runs.get(r.id).status == "cancelled"


def test_pool_live_run_ids_exclude_a_run_past_its_hard_deadline(store):
    from lykos.jobs.worker import WorkerPool, _Active, _Slot
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=1))
    sem = threading.BoundedSemaphore(1)
    sem.acquire()
    pool._active[0] = _Active(_Slot(sem), time.time() + 60, run_id="alive")
    pool._active[1] = _Active(_Slot(sem), time.time() - 1, run_id="wedged")
    pool._active[2] = _Active(_Slot(sem), None, run_id="unbounded")
    assert pool._live_run_ids() == {"alive", "unbounded"}


def test_a_replaced_worker_retires_instead_of_running_as_a_surplus(store):
    from lykos.jobs.worker import WorkerPool
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.01))
    with pool._tlock:
        old = pool._spawn_worker(0)                       # generation 0 owns idx 0
        pool._spawn_worker(0).join(0)                     # generation 1 replaces it
    old.join(timeout=5)
    assert not old.is_alive(), "the replaced generation kept running as an untracked worker"
    assert pool.metrics().get("retired_replaced") == 1
    pool._stopping.set()


# ---- 6. hang / DoS capture (doc 47 P7) ------------------------------------------------------

class _Tgt:
    arch, endianness, bits, id, case_id = "x86-64", "little", 64, "t", "c"


def test_hang_eligibility_needs_a_control_and_a_minority_of_timeouts():
    from lykos.analyze.fuzz import stage as S
    assert S._hang_eligible(100, 1, True)
    assert not S._hang_eligible(100, 1, False)            # nothing ever terminated
    assert not S._hang_eligible(100, 60, True)            # hangs on most inputs: its normal state
    assert not S._hang_eligible(5, 1, True)               # too little evidence
    assert S._hang_timeout(2) == 4.0 and S._hang_timeout(1) == 4.0
    assert S._hang_timeout(10) == 20.0 and S._hang_timeout(100) == 30.0


def test_verify_hang_requires_the_differential(monkeypatch):
    from lykos.analyze.fuzz import stage as S
    out = {"ctrl": RunResult(isolation="bwrap", duration_ms=3),
           "hang": RunResult(isolation="bwrap", timed_out=True, duration_ms=4000)}
    seen_t = []

    def fake_run(exe, mode, wf, timeout, arch, data, **kw):
        seen_t.append(timeout)
        return [], out[data.decode()]

    monkeypatch.setattr(S, "run_input", fake_run)
    v = S._verify_hang("exe", "stdin", "wf", 2.0, _Tgt, (b"hang", [], False),
                       (b"ctrl", [], False))
    assert v is not None and v[0].timed_out and not v[1].timed_out
    assert seen_t == [4.0, 4.0]                           # both at >= 2x the campaign timeout
    # the hang did not reproduce -> nothing
    out["hang"] = RunResult(isolation="bwrap", duration_ms=5)
    assert S._verify_hang("exe", "stdin", "wf", 2.0, _Tgt, (b"hang", [], False),
                          (b"ctrl", [], False)) is None
    # the control ALSO hangs under the long timeout -> no differential -> nothing
    out["hang"] = RunResult(isolation="bwrap", timed_out=True)
    out["ctrl"] = RunResult(isolation="bwrap", timed_out=True)
    assert S._verify_hang("exe", "stdin", "wf", 2.0, _Tgt, (b"hang", [], False),
                          (b"ctrl", [], False)) is None


def test_a_reproducible_hang_is_filed_as_cwe_835(store, case):
    from lykos.analyze.fuzz import stage as S
    t = _target(store, case, b"g", file_type="elf", arch="x86-64", bits=64)

    class Ctx:
        run_id = None
        conn = store.conn
        events = []

        def put_artifact(self, kind, data):
            return store.put_artifact(case.id, kind, data=data).sha256

        def emit(self, typ, payload=None):
            self.events.append(typ)

    ctx = Ctx()
    hang = RunResult(isolation="bwrap", timed_out=True, duration_ms=4000)
    ctrl = RunResult(isolation="bwrap", duration_ms=2)
    sha = S._file_hang(ctx, t, FindingDAO(store.conn), mode="file", data=b"\xff" * 8,
                       prefix=["-x", "@@"], hang=hang, control=ctrl, exec_timeout=2.0,
                       detector="fuzz", event_prefix="fuzz")
    f = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.cwe == "CWE-835"]
    assert f and f[0].state == "corroborated"
    ev = f[0].evidence[0]
    assert ev["input_sha"] == sha and ev["input_mode"] == "file" and ev["argv"] == ["-x", "@@"]
    assert store.content.get_bytes(sha) == b"\xff" * 8                # the replayable input
    # no crash row: the PoC ladder must never chase a hang as a crash, and the seed-gathering
    # stages (concolic, mem_oracle) must not replay it
    assert DynResultDAO(store.conn).list_by_target(t.id) == []
    assert "fuzz.hang" in ctx.events


# ---- 7. other audit fixes -------------------------------------------------------------------

def test_a_clock_refusal_does_not_quote_the_previous_stages_sizing_verdict():
    from lykos.analyze import budget as B
    b = B.CaseBudget(100)
    b.set_exec_rate(0.6)
    assert b.slice("fuzz", want_execs=100_000) == 0.0
    assert "below the" in b.sizing()["refused"]           # this stage's own reason
    b.phase("prove")
    b._start -= 99.5                                      # the clock is now spent
    assert b.slice("directed_fuzz", want_execs=10) == 0.0
    assert b.sizing() == {}                               # NOT the fuzz stage's stale verdict
    assert b.spent()["last_sizing"]["stage"] == "fuzz"    # the scorecard keeps the last one


def test_run_subprocess_kills_the_child_when_the_cancel_poll_raises(store, case):
    from lykos.jobs.context import JobContext
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "noop_d", params={"i": 4})
    ctx = JobContext(store.conn, store.content, store.runs.get(run.id))
    procs = []
    import subprocess as sp
    real_popen = sp.Popen

    def spy(*a, **k):
        p = real_popen(*a, **k)
        procs.append(p)
        return p

    calls = {"n": 0}

    def boom():
        calls["n"] += 1
        raise RuntimeError("unexpected poll failure")

    ctx.should_cancel = boom
    import lykos.jobs.context as C
    orig = C.subprocess.Popen
    C.subprocess.Popen = spy
    try:
        with pytest.raises(RuntimeError):
            ctx.run_subprocess(["sleep", "30"], poll=0.05)
    finally:
        C.subprocess.Popen = orig
    assert procs and procs[0].poll() is not None, "the tool was orphaned, still running"


def test_cancel_poll_survives_a_locked_database(store, case, monkeypatch):
    from lykos.jobs.context import JobContext
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "noop_e", params={"i": 5})

    class Locked:
        def execute(self, *a, **k):
            raise sqlite3.OperationalError("database is locked")

    ctx = JobContext(Locked(), store.content, store.runs.get(run.id))
    assert ctx.should_cancel() is False                   # retried next poll, no crash


def test_emit_rides_out_a_transient_lock(store, case, monkeypatch):
    from lykos.jobs import context as C
    q = JobQueue(store.conn)
    run = q.enqueue(case.id, "noop_f", params={"i": 6})
    ctx = C.JobContext(store.conn, store.content, store.runs.get(run.id))
    real = C.EventDAO.append
    n = {"fail": 2}

    def flaky(self, *a, **k):
        if n["fail"]:
            n["fail"] -= 1
            raise sqlite3.OperationalError("database is locked")
        return real(self, *a, **k)

    monkeypatch.setattr(C.EventDAO, "append", flaky)
    ctx.emit("x.progress", payload={"a": 1})
    assert n["fail"] == 0
    monkeypatch.setattr(C.EventDAO, "append",
                        lambda self, *a, **k: (_ for _ in ()).throw(
                            sqlite3.OperationalError("no such table: event")))
    with pytest.raises(sqlite3.OperationalError):          # a non-lock error is not retried
        ctx.emit("x.progress")


def test_case_export_chunks_large_in_lists(monkeypatch):
    import lykos.casestore as CS
    monkeypatch.setattr(CS, "_IN_CHUNK", 3)
    steps = CS._in_chunks("artifact", "sha256", [str(i) for i in range(7)])
    assert [len(p) for _t, _w, p in steps] == [3, 3, 1]
    assert all(w.count("?") == len(p) for _t, w, p in steps)
    assert CS._in_chunks("finding_site", "finding_id", []) == [("finding_site", "0=1", ())]


def test_export_case_round_trips_with_chunked_steps(store, case, tmp_path, monkeypatch):
    import lykos.casestore as CS
    monkeypatch.setattr(CS, "_IN_CHUNK", 2)
    for i in range(5):
        store.put_artifact(case.id, "blob", data=f"b{i}".encode())
    arc = store.export_case(case.id, tmp_path / "c.tar.gz")
    other = CS.CaseStore.open(tmp_path / "other")
    try:
        assert other.import_archive(arc) == [case.id]
        n = other.conn.execute("SELECT COUNT(*) c FROM artifact WHERE case_id=?",
                               (case.id,)).fetchone()["c"]
        assert n == 5
    finally:
        other.close()


if __name__ == "__main__":                                 # pragma: no cover
    pytest.main([__file__, "-q"])


def test_scorecard_events_are_scoped_to_the_target(store, case):
    """In a multi-target case one target's engine signals must not land on another's card."""
    a = _target(store, case, b"x", file_type="elf", arch="x86-64", bits=64)
    b = _target(store, case, b"y", file_type="elf", arch="x86-64", bits=64)
    q = JobQueue(store.conn)
    ra = q.enqueue(case.id, "fuzz", target_id=a.id, params={"k": "a"})
    rb = q.enqueue(case.id, "fuzz", target_id=b.id, params={"k": "b"})
    rc = q.enqueue(case.id, "link_case", params={"k": "c"})          # case-level: kept for both
    ev = EventDAO(store.conn)
    ev.append("fuzz.done", case_id=case.id, run_id=ra.id, payload={"execs": 111})
    ev.append("fuzz.done", case_id=case.id, run_id=rb.id, payload={"execs": 222})
    ev.append("link.done", case_id=case.id, run_id=rc.id, payload={})
    ev.append("autopilot.stage", case_id=case.id, payload={"target_id": b.id})
    ev.append("autopilot.note", case_id=case.id, payload={})
    allev = list(ev.walk(case_id=case.id))
    got = O._target_events(store, a, allev)
    execs = [e.payload.get("execs") for e in got if e.type == "fuzz.done"]
    assert execs == [111]
    assert {e.type for e in got} - {"job.queued"} == {"fuzz.done", "link.done", "autopilot.note"}
    assert all(e.run_id != rb.id for e in got)            # nothing from the other target's run


# ---- hang proof selection (prove phase) -----------------------------------------------------


def test_prove_phase_selects_unproved_hang_inputs_only(store, case):
    """Recorded hangs (CWE-835, no dyn_result row) are handed to build_poc's hang path; one a
    verified PoC already backs is not re-proved, and a non-hang finding is never picked up."""
    from lykos.db.dao import PocDAO
    t = _target(store, case, b"hangs")
    fd = FindingDAO(store.conn)
    for mode, sha in (("stdin", "a" * 64), ("file", "b" * 64)):
        fd.upsert(t.id, case.id, {
            "cwe": "CWE-835", "title": "hang", "severity": "medium", "detector": "fuzz",
            "state": "corroborated", "confidence": 0.75, "dedup_key": f"CWE-835:hang:{mode}",
            "evidence": [{"channel": "dynamic", "detail": "x", "input_sha": sha}]})
    fd.upsert(t.id, case.id, {
        "cwe": "CWE-787", "title": "oob", "severity": "high", "detector": "fuzz",
        "state": "corroborated", "confidence": 0.9, "dedup_key": "CWE-787:x",
        "evidence": [{"channel": "dynamic", "detail": "y", "input_sha": "c" * 64}]})
    PocDAO(store.conn).insert(t.id, case.id, level="L1", verified=True, input_sha="b" * 64)
    assert O._unproved_hang_inputs(store, t.id) == ["a" * 64]
