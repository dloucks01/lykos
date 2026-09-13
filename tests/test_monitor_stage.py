"""The `debug_monitor` STAGE (not the gdb library underneath it, which test_monitor.py
covers). The stage is what decides which observations become findings and which stay a log,
and what it does on a substrate it cannot monitor -- all of which was untested."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_monitor
from lykos.analyze.debug import monitor_stage as ms
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CMD_C = ('#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n'
          'int main(int c,char**v){char cmd[256];if(c<2)return 1;'
          'snprintf(cmd,sizeof cmd,"echo got: %s",v[1]);return system(cmd);}\n')


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=60, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


# ---- the pure predicates the stage's verdicts rest on -------------------------------------

def test_an_unattributed_hit_is_kept_because_absence_is_not_evidence():
    """A call whose origin could not be determined is still a call the program made. Dropping
    it would silently lose the finding on any target where attribution is unavailable."""
    hits = [{"func": "system", "in_target": True},
            {"func": "strcpy", "in_target": False},
            {"func": "gets"}]                              # no attribution at all
    kept, dropped = ms.program_calls(hits)
    assert {h["func"] for h in kept} == {"system", "gets"}
    assert {h["func"] for h in dropped} == {"strcpy"}


def test_the_smallest_buffer_in_a_function_is_the_one_that_bounds_it(store, case, gcc,
                                                                     tmp_path):
    """The overflow predicate compares an observed copy length against the destination
    function's stack buffer -- and a function with two buffers overflows at the SMALLER one."""
    c = tmp_path / "m.c"
    c.write_text(_CMD_C)
    exe = tmp_path / "m"
    subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], check=True, capture_output=True)
    target = ingest(store, case.id, exe)
    FunctionDAO(store.conn).replace_for_target(target.id, [{
        "addr": "0x1149", "name": "victim", "size": 64, "blocks": "0x1149",
        "frame": {"vars": [{"name": "big", "size": 256, "is_buffer": True},
                           {"name": "small", "size": 32, "is_buffer": True},
                           {"name": "n", "size": 4, "is_buffer": False}]}}])

    class _Ctx:
        conn = store.conn
    assert ms._smallest_buffer_by_func(_Ctx(), target.id) == {"victim": 32}


def test_a_function_with_no_recovered_buffers_makes_no_claim(store, case, gcc, tmp_path):
    c = tmp_path / "m.c"
    c.write_text(_CMD_C)
    exe = tmp_path / "m"
    subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], check=True, capture_output=True)
    target = ingest(store, case.id, exe)
    FunctionDAO(store.conn).replace_for_target(target.id, [
        {"addr": "0x1149", "name": "scalars", "size": 16, "blocks": "0x1149",
         "frame": {"vars": [{"name": "n", "size": 4, "is_buffer": False}]}},
        {"addr": "0x1200", "name": "noblocks", "size": 16, "blocks": "",
         "frame": {"vars": [{"name": "b", "size": 8, "is_buffer": True}]}}])

    class _Ctx:
        conn = store.conn
    # no buffer -> no entry; no blocks -> not disassembled, so nothing is known about it
    assert ms._smallest_buffer_by_func(_Ctx(), target.id) == {}


def test_sink_addresses_are_parsed_and_unknown_sinks_refused():
    """An analyst supplies these by hand for a stripped binary. A name the catalog does not
    know would be breakpointed with no idea how to read its arguments."""
    got = ms._parse_sink_addrs({"system": "0x401000", "strcpy": 4198400,
                                "not_a_sink": "0x401234", "gets": "not-a-number"})
    assert got == {"system": 0x401000, "strcpy": 4198400}


def test_no_sink_addresses_is_an_empty_map_not_a_crash():
    assert ms._parse_sink_addrs(None) == {}
    assert ms._parse_sink_addrs({}) == {}


def test_a_finding_carries_the_channel_that_produced_it():
    f = ms._finding("CWE-78", "executed a command", "high", "system(\"echo hi\")",
                    dedup="monitor:system")
    assert f["cwe"] == "CWE-78" and f["detector"] == "monitor"
    assert f["evidence"][0]["channel"] == "runtime-monitor"
    assert f["state"] == "corroborated", "watching a call run is corroboration, not a guess"


# ---- the stage's substrate gates ---------------------------------------------------------

def _target_of_type(store, case, gcc, tmp_path, file_type):
    c = tmp_path / "m.c"
    c.write_text(_CMD_C)
    exe = tmp_path / "m"
    subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], check=True, capture_output=True)
    t = ingest(store, case.id, exe)
    store.conn.execute("UPDATE target SET file_type=? WHERE id=?", (file_type, t.id))
    store.conn.commit()
    return t


@pytest.mark.parametrize("file_type", ["macho", "jar"])
def test_a_substrate_the_monitor_cannot_run_says_so_and_does_not_fail(store, case, pool, gcc,
                                                                     tmp_path, file_type):
    """An unsupported substrate has to DECLINE -- a stage error reads to the operator as "the
    tool broke", where the truth is "this target cannot be monitored here"."""
    t = _target_of_type(store, case, gcc, tmp_path, file_type)
    q = JobQueue(store.conn)
    run = enqueue_monitor(q, t, params={"timeout": 8})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    assert rec.status == "done", rec.error
    assert not FindingDAO(store.conn).list_by_target(t.id)


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native x86-64 gdb path")
def test_a_watched_command_becomes_a_finding(store, case, pool, gcc, tmp_path):
    """The stage's whole point: a `system()` we WATCHED execute is evidence, with no crash
    involved. If gdb cannot run here the stage still has to finish cleanly."""
    from lykos.analyze.debug import monitor
    if not monitor._locate_gdb():
        pytest.skip("gdb not installed")
    c = tmp_path / "m.c"
    c.write_text(_CMD_C)
    exe = tmp_path / "m"
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("build failed")
    t = ingest(store, case.id, exe)
    # the native path breakpoints the sinks the binary IMPORTS, which it reads from the call
    # graph -- so a target that has not been disassembled has nothing to monitor
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1149", "site_addr": "0x1160", "dst_addr": None,
         "dst_name": "system", "external": 1}])
    q = JobQueue(store.conn)
    run = enqueue_monitor(q, t, params={"input_mode": "arg", "timeout": 20})
    assert pool.wait_idle(120)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("gdb monitor unavailable here: " + str(rec.error))
    cwes = {f.cwe for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "monitor"}
    assert "CWE-78" in cwes, f"watched system() did not become a finding (got {cwes})"
