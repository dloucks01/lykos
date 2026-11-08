"""Durable autopilot run history + run comparison (analyze/run_history.py, api/run_history.py).

The operator's workflow: FreeRDP analysed several times, as separate cases of the same source tree
("freerdp-v2" / "freerdp-v3"), and they want the past runs and what changed between two of them --
across cases. So the identity of a finding must survive a rebuild (new target ids, new binary
hashes, new addresses), the records must survive a server restart (case store, not memory), and no
response may carry a server filesystem path. Driven over the real unix socket, like the GUI.
"""
from __future__ import annotations

import json
import os
import threading
import time

import pytest

from lykos.api.server import serve, shutdown
from lykos.analyze import orchestrate
from lykos.analyze import run_history as rh
from lykos.casestore import CaseStore
from lykos.db.dao import FindingDAO, FunctionDAO, PocDAO

from tests.test_api_routes import _json


@pytest.fixture
def api(tmp_path):
    sock = str(tmp_path / "s.sock")
    servers, pool = serve(tmp_path / "cs", sock, workers=1, block=False)
    for _ in range(200):
        if os.path.exists(sock):
            break
        time.sleep(0.02)
    try:
        yield sock, tmp_path / "cs"
    finally:
        shutdown(servers, pool)


def _src(fp, line, what="x"):
    return [{"channel": "source", "detail": f"{fp}:{line}: {what}"}]


def _set_state(s, fid_key, tid, state):
    s.conn.execute("UPDATE finding SET state=? WHERE target_id=? AND dedup_key=?",
                   (state, tid, fid_key))


def _fid(s, tid, key):
    return s.conn.execute("SELECT id FROM finding WHERE target_id=? AND dedup_key=?",
                          (tid, key)).fetchone()[0]


def _populate(cs, cid_a, cid_b):
    """Two cases of one 'source tree': same filenames, different target ids/shas/addresses."""
    s = CaseStore.open(cs)
    try:
        fd = FindingDAO(s.conn)
        ta = s.targets.upsert(cid_a, "client", "aa" * 32, arch="x86_64", bits=64)
        tb = s.targets.upsert(cid_b, "client", "bb" * 32, arch="x86_64", bits=64)
        # the same function at a DIFFERENT address in each rebuild
        FunctionDAO(s.conn).replace_for_target(ta.id, [{"addr": "0x401000", "name": "parse_pdu"}])
        FunctionDAO(s.conn).replace_for_target(tb.id, [{"addr": "0x402200", "name": "parse_pdu"}])
        common = {"severity": "high", "confidence": 0.5}
        # bug1: present in both, candidate -> confirmed + a detonated L2 PoC in B (CHANGED, up)
        fd.upsert(ta.id, cid_a, {**common, "cwe": "CWE-787", "title": "oob write in decode",
                                 "detector": "oob_write", "dedup_key": "b1",
                                 "evidence": _src("libfreerdp/codec/clear.c", 120)})
        fd.upsert(tb.id, cid_b, {**common, "cwe": "CWE-787", "title": "oob write in decode",
                                 "detector": "oob_write", "dedup_key": "b1-rebuilt",
                                 "evidence": _src("libfreerdp/codec/clear.c", 120)})
        _set_state(s, "b1-rebuilt", tb.id, "confirmed")
        PocDAO(s.conn).insert(tb.id, cid_b, finding_id=_fid(s, tb.id, "b1-rebuilt"),
                              level="L2", verified=True)
        # bug2: only in A (GONE). Its title carries an absolute server path -> scrubbed.
        fd.upsert(ta.id, cid_a, {**common, "cwe": "CWE-134",
                                 "title": "format string via /home/op/work/tree/src/log.c",
                                 "detector": "format_string", "dedup_key": "b2",
                                 "evidence": _src("/home/op/work/tree/winpr/log.c", 55)})
        # bug3: binary-only, same function name, different address per rebuild (SAME)
        for t, cid, addr in ((ta, cid_a, "0x401000"), (tb, cid_b, "0x402200")):
            fd.upsert(t.id, cid, {**common, "cwe": "CWE-416", "title": f"use-after-free at {addr}",
                                  "detector": "heap_trace", "dedup_key": "b3",
                                  "function_addr": addr, "evidence": []})
        # bug4: only in B (NEW)
        fd.upsert(tb.id, cid_b, {**common, "cwe": "CWE-190", "title": "size overflow",
                                 "detector": "int_overflow", "dedup_key": "b4",
                                 "evidence": _src("channels/audin/server/audin.c", 77)})
        return ta.id, tb.id
    finally:
        s.close()


def _no_server_paths(obj, cs):
    blob = json.dumps(obj)
    for bad in ("/home/op", "/opt/sysroot", "/etc/passwd", "/srv/seeds", str(cs)):
        assert bad not in blob, f"server path {bad!r} leaked"


def test_history_records_survive_and_compare_across_cases(api):
    sock, cs = api
    _, a = _json(sock, "POST", "/cases", {"name": "freerdp-v2"})
    _, b = _json(sock, "POST", "/cases", {"name": "freerdp-v3"})
    ta, tb = _populate(cs, a["id"], b["id"])

    # Record one finished run per case, the way run_case_autopilot's start/end hooks do -- with
    # path-carrying overrides that must never be persisted or served.
    over = {"seed_files": ["/srv/seeds/a", "/srv/seeds/b"], "sysroot": "/opt/sysroot",
            "argv": ["-c", "/etc/passwd"], "input_mode": "file", "deep_seed": True}
    run_ids = {}
    s = CaseStore.open(cs)
    try:
        for cid, tid in ((a["id"], ta), (b["id"], tb)):
            st = {"started": time.time()}
            rec = rh.record_start(s, cid, [tid], st, overrides=over, budget_seconds=600,
                                  skip_stages=["fuzz"])
            assert rec and st["run_id"] == rec["run_id"]
            st.update({"state": "done", "outcome": "static", "per_target": [
                {"target_id": tid, "filename": "client", "stages": {"done": 9}, "elapsed": 42.0,
                 "findings": 3, "poc_backed": 0, "confirmed": int(cid == b["id"])}]})
            rh.record_end(s, cid, rec, st)
            run_ids[cid] = rec["run_id"]
        # a START with no END (the server went down mid-run) -> "interrupted"
        orphan = rh.record_start(s, a["id"], [ta], {"started": time.time() + 5})["run_id"]
    finally:
        s.close()

    # the list: newest first, no snapshots, the synthetic current-state entry last
    st, h = _json(sock, "GET", f"/cases/{a['id']}/runs-history")
    assert st == 200
    runs = h["runs"]
    assert [r["run_id"] for r in runs] == [orphan, run_ids[a["id"]], "current:" + a["id"]]
    assert runs[0]["outcome"] == "interrupted"
    assert runs[1]["outcome"] == "done" and runs[1]["budget_seconds"] == 600
    assert runs[1]["skip_stages"] == ["fuzz"] and runs[1]["counts"]["findings"] == 3
    assert runs[1]["per_target"][0]["filename"] == "client"
    assert runs[1]["overrides"] == {"seeds": 2, "argv": ["-c", "<path>"], "input_mode": "file",
                                    "deep_seed": True}
    assert runs[2]["synthetic"] is True and runs[2]["outcome"] == "current"
    assert all("snapshot" not in r for r in runs)
    _no_server_paths(h, cs)

    # the stage-run list is untouched by the new route
    st, stage_runs = _json(sock, "GET", f"/cases/{a['id']}/runs")
    assert st == 200 and isinstance(stage_runs, list)

    # one record with its snapshot
    st, one = _json(sock, "GET", f"/autopilot-runs/{run_ids[b['id']]}")
    assert st == 200 and one["case_name"] == "freerdp-v3"
    keys = {e["key"]: e for e in one["snapshot"]["findings"]}
    assert keys["CWE-787|clear.c:120"]["level"] == "L2"
    assert keys["CWE-787|clear.c:120"]["site"] == "libfreerdp/codec/clear.c:120"
    _no_server_paths(one, cs)

    # CROSS-CASE compare, recorded A -> recorded B
    st, cmp_ = _json(sock, "GET", f"/autopilot-runs/compare?a={run_ids[a['id']]}&b={run_ids[b['id']]}")
    assert st == 200
    assert [e["cwe"] for e in cmp_["new"]] == ["CWE-190"]
    assert cmp_["new"][0]["site"] == "channels/audin/server/audin.c:77"
    assert [e["cwe"] for e in cmp_["gone"]] == ["CWE-134"]
    assert cmp_["gone"][0]["site"] == "log.c:55"                   # absolute -> basename
    assert "/home" not in cmp_["gone"][0]["title"]
    (ch,) = cmp_["changed"]
    assert ch["key"] == "CWE-787|clear.c:120" and ch["direction"] == "up"
    assert ch["from"] == {"state": "candidate", "level": None}
    assert ch["to"] == {"state": "confirmed", "level": "L2"}
    assert cmp_["same_count"] == 1                     # the UAF: same fn name, new address
    assert cmp_["a"]["case_name"] == "freerdp-v2" and cmp_["b"]["case_name"] == "freerdp-v3"
    (pt,) = cmp_["per_target_delta"]
    assert pt["filename"] == "client" and pt["delta"]["confirmed"] == 1
    _no_server_paths(cmp_, cs)

    # the SYNTHETIC current-state entries compare too (cases with no recorded run)
    st, cur = _json(sock, "GET", f"/autopilot-runs/compare?a=current:{a['id']}&b=current:{b['id']}")
    assert st == 200 and cur["a"]["synthetic"] and cur["b"]["synthetic"]
    assert cur["summary"] == {"new": 1, "gone": 1, "changed": 1, "up": 1, "down": 0, "same": 1}
    st, one = _json(sock, "GET", f"/autopilot-runs/current%3A{b['id']}")
    assert st == 200 and one["synthetic"] and len(one["snapshot"]["findings"]) == 3

    # errors
    assert _json(sock, "GET", "/autopilot-runs/compare?a=x")[0] == 400
    assert _json(sock, "GET", f"/autopilot-runs/compare?a=nope&b={orphan}")[0] == 404
    assert _json(sock, "GET", "/autopilot-runs/nope")[0] == 404
    assert _json(sock, "GET", "/cases/nope/runs-history")[0] == 404


def test_run_case_autopilot_writes_start_and_end_records(api):
    """The real autopilot entry point records the run at start and at its end -- a stopped run
    and a run that errors both leave an END record with the right outcome."""
    sock, cs = api
    _, c = _json(sock, "POST", "/cases", {"name": "rec"})
    s = CaseStore.open(cs)
    try:
        t = s.targets.upsert(c["id"], "tool", "cc" * 32, arch="x86_64", bits=64)
    finally:
        s.close()
    stop = threading.Event()
    stop.set()                                   # stopped before the first target
    status: dict = {}
    orchestrate.run_case_autopilot(cs, c["id"], [t.id], status, stop, 300.0,
                                   {"sysroot": "/opt/sysroot"}, False, ["fuzz"])
    assert status["state"] == "cancelled" and status.get("run_id")

    real = orchestrate._tree_owners
    orchestrate._tree_owners = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    try:
        st2: dict = {}
        orchestrate.run_case_autopilot(cs, c["id"], [t.id], st2, threading.Event(), None)
    finally:
        orchestrate._tree_owners = real
    assert st2["state"] == "error"

    st, h = _json(sock, "GET", f"/cases/{c['id']}/runs-history")
    assert st == 200
    by = {r["run_id"]: r for r in h["runs"]}
    assert by[status["run_id"]]["outcome"] == "stopped"
    assert by[status["run_id"]]["budget_seconds"] == 300.0
    assert by[status["run_id"]]["targets"] == [{"id": t.id, "filename": "tool"}]
    assert by[st2["run_id"]]["outcome"] == "error" and "boom" in by[st2["run_id"]]["error"]
    _no_server_paths(h, cs)
    # each phase was also announced on the event log
    s = CaseStore.open(cs)
    try:
        evs = [e for e in s.events.walk(case_id=c["id"]) if e.type == rh.EVENT]
    finally:
        s.close()
    assert sorted((e.payload["run_id"], e.payload["phase"]) for e in evs) == sorted(
        [(status["run_id"], "start"), (status["run_id"], "end"),
         (st2["run_id"], "start"), (st2["run_id"], "end")])


def test_identity_key_survives_rebuild_and_snapshot_is_bounded(tmp_path, monkeypatch):
    k1 = rh.identity_key("CWE-416", "heap", "uaf at 0x401000 size 123456", None, None, "f", "bin")
    k2 = rh.identity_key("CWE-416", "heap", "uaf at 0x402200 size 654321", None, None, "f", "bin")
    assert k1 == k2
    assert rh.identity_key("CWE-787", "a", "t", "x/y/clear.c", 3, None, "t1") == \
        rh.identity_key("CWE-787", "b", "other", "clear.c", 3, None, "t2")
    assert rh.scrub_text("crash in /tmp/w/x/y.bin now") == "crash in y.bin now"
    assert rh.scrub_text("tree/rel/path.c") == "tree/rel/path.c"

    monkeypatch.setattr(rh, "SNAPSHOT_CAP", 3)
    s = CaseStore.open(tmp_path / "cs")
    try:
        c = s.cases.create("cap")
        t = s.targets.upsert(c.id, "t", "dd" * 32)
        for i in range(5):
            FindingDAO(s.conn).upsert(t.id, c.id, {"cwe": "CWE-20", "title": f"t{i}",
                                                   "dedup_key": f"k{i}", "evidence":
                                                   _src("a.c", i + 1)})
        snap = rh.build_snapshot(s, c.id)
    finally:
        s.close()
    assert len(snap["findings"]) == 3 and snap["truncated"] == 2
    assert snap["counts"]["findings"] == 5
