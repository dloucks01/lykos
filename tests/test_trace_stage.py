"""The `behavior_trace` stage's own decisions: which backend it picks, which substrates it
declines, and which observations become findings.

test_behavior.py drives one native inventory end to end and covers the parsers underneath.
What it does not cover is the stage's dispatch -- native gdb vs qemu, and the four different
"cannot trace this" answers, each of which has to reach the operator as a DIFFERENT statement.
"the gdb backend is native-only" and "no qemu-user installed" call for opposite actions, and
collapsing either into "no behaviour observed" would have the operator draw the wrong
conclusion about the target rather than about the tool.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_behavior_trace
from lykos.analyze.debug import trace_stage as ts
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import EventDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_QUIET_C = "int main(void){ return 0; }\n"


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
        p.stop(grace=5.0)


def _build(gcc, tmp_path, src, name):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    exe = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip(f"cannot build {name}")
    return exe


def _done_payload(store, case_id):
    for e in reversed(EventDAO(store.conn).list(case_id=case_id, limit=500)):
        if (e.type or "") == "behavior.done":
            return e.payload or {}
    return {}


def _run(store, pool, target, params=None):
    q = JobQueue(store.conn)
    run = enqueue_behavior_trace(q, target, params={"timeout": 25, **(params or {})})
    assert pool.wait_idle(180)
    return q.runs.get(run.id)


# ---- which addresses count as reaching outside the host ----------------------------------

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "0.0.0.0",
                                "172.16.0.1", "172.31.255.254"])
def test_private_and_loopback_addresses_are_not_outbound(ip):
    assert ts._private(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1",
                                "11.0.0.1", "193.168.1.1"])
def test_a_routable_address_is_outbound(ip):
    """172.15 and 172.32 are OUTSIDE the private range -- the /12 boundary is the part that
    gets written wrong, and getting it wrong either hides a real callout or cries wolf on a
    loopback connection."""
    assert not ts._private(ip)


# ---- substrate dispatch ------------------------------------------------------------------

@pytest.mark.parametrize("file_type", ["macho", "jar", "class"])
def test_a_substrate_with_no_tracer_declines_with_its_own_reason(store, case, pool, gcc,
                                                                 tmp_path, file_type):
    exe = _build(gcc, tmp_path, _QUIET_C, f"q{file_type}")
    t = ingest(store, case.id, exe)
    store.conn.execute("UPDATE target SET file_type=? WHERE id=?", (file_type, t.id))
    store.conn.commit()
    rec = _run(store, pool, t)
    assert rec.status == "done", rec.error
    pay = _done_payload(store, case.id)
    assert pay.get("supported") is False
    assert file_type.upper() in str(pay.get("note", "")).upper()
    assert not FindingDAO(store.conn).list_by_target(t.id)


def test_the_gdb_backend_refuses_a_cross_architecture_target_by_name(store, case, pool, gcc,
                                                                    tmp_path):
    """Forcing the native backend at an emulated target has to say THAT, not "no behaviour"."""
    exe = _build(gcc, tmp_path, _QUIET_C, "xarch")
    t = ingest(store, case.id, exe)
    other = "aarch64" if sandbox.host_arch() != "aarch64" else "x86-64"
    store.conn.execute("UPDATE target SET file_type='elf', arch=? WHERE id=?", (other, t.id))
    store.conn.commit()
    rec = _run(store, pool, t, {"backend": "gdb"})
    assert rec.status == "done", rec.error
    note = str(_done_payload(store, case.id).get("note", ""))
    assert "native-only" in note and other in note
    assert "backend=qemu" in note, "the operator is not told what to do instead"


def test_a_missing_emulator_is_reported_as_a_missing_emulator(store, case, pool, gcc,
                                                              tmp_path):
    exe = _build(gcc, tmp_path, _QUIET_C, "noemu")
    t = ingest(store, case.id, exe)
    store.conn.execute("UPDATE target SET file_type='elf', arch='nosucharch' WHERE id=?",
                       (t.id,))
    store.conn.commit()
    rec = _run(store, pool, t, {"backend": "qemu"})
    assert rec.status == "done", rec.error
    note = str(_done_payload(store, case.id).get("note", ""))
    assert "qemu" in note.lower() and "nosucharch" in note


def test_the_stage_refuses_to_run_without_a_target():
    class _Ctx:
        target_id = None
        params: dict = {}
    with pytest.raises(ValueError, match="target_id"):
        ts.behavior_trace_stage(_Ctx())


# ---- a quiet program is a quiet program, not a failure ------------------------------------

def test_a_program_that_does_nothing_produces_an_inventory_and_no_findings(store, case, pool,
                                                                          gcc, tmp_path):
    """The negative has to be available: "we watched and it did nothing" is a result, and it
    must not be confused with "we could not watch"."""
    exe = _build(gcc, tmp_path, _QUIET_C, "quiet")
    t = ingest(store, case.id, exe)
    rec = _run(store, pool, t)
    assert rec.status == "done", rec.error
    pay = _done_payload(store, case.id)
    if pay.get("supported") is False:
        pytest.skip("no syscall tracer on this host: " + str(pay.get("note")))
    assert pay.get("ok") is True
    inv = pay.get("inventory") or {}
    assert inv.get("exec") == [] and inv.get("network") == []
    assert not [f for f in FindingDAO(store.conn).list_by_target(t.id)
                if f.detector == "behavior"]


def test_a_partial_trace_caveat_is_available_to_the_native_path_too():
    """`_partial_note` is shared: a cut-short trace is a partial inventory whichever tracer
    produced it, and the operator has to be told either way."""
    assert ts._partial_note({"timed_out": True})
    assert ts._partial_note({"truncated": True})
    assert ts._partial_note({}) == ""
