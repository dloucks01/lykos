"""The operator endpoints added for run honesty and CLI parity (api/ops.py):

  * run-signals -- a target that errored is FAILED, a degraded sandbox / ranked taint / tiered
    recovery / capped crash list / hang / lease renewal is visible, and a reopened case still
    shows them (read from the event log, not the live tail);
  * crash-triage -- crashes grouped by the prove loop's bucket key, ranked by the best VERIFIED
    level (an unverified PoC never sets a group's level), linked to finding + PoC;
  * seeds -- the GUI's `--seed`: uploaded into the case, resolved server-side by hash; a browser
    can no longer hand the autopilot a server PATH;
  * doctor / version -- engine readiness and build identity for the footer;
  * bundle upload ceilings -- a zip/tar bomb is refused, not extracted.
"""
from __future__ import annotations

import http.client
import io
import json
import os
import socket
import tarfile
import time
import zipfile

import pytest
from lykos.api import runsignals, triage
from lykos.api.server import serve, shutdown


# --------------------------------------------------------------------------- harness
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


class _UDS(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def _req(sock, method, url, body=None, headers=None):
    c = _UDS(sock)
    try:
        c.request(method, url, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        try:
            return r.status, json.loads(data) if data else None
        except ValueError:
            return r.status, data
    finally:
        c.close()


def _jreq(sock, method, url, obj=None):
    body = json.dumps(obj).encode() if obj is not None else None
    return _req(sock, method, url, body,
                {"Content-Type": "application/json"} if obj is not None else {})


def _case_with_target(sock, cs, name="t.bin"):
    from lykos.casestore import CaseStore
    _st, case = _jreq(sock, "POST", "/cases", {"name": "ops"})
    st = CaseStore.open(cs)
    try:
        t = st.targets.upsert(case["id"], name, "ab" * 32, file_type="elf", arch="x86_64")
        st.conn.commit()
        return case["id"], t.id
    finally:
        st.close()


# --------------------------------------------------------------------------- run signals
def _row(i, type_, payload, *, level="info", run_target=None, ts=None):
    return {"id": i, "type": type_, "level": level, "ts": ts or i, "payload": payload,
            "run_target": run_target}


def test_a_failed_target_is_failed_not_quietly_absent():
    rows = [
        _row(1, "autopilot.target_error", {"target_id": "T2", "stage": "fuzz",
                                           "error": "OperationalError: database is locked"},
             level="error"),
        _row(2, "autopilot.done", {"outcome": "static", "cancelled": False,
                                   "target_errors": 1, "failed_targets": ["T2"]}),
    ]
    out = runsignals.summarize(rows, filenames={"T2": "b.bin"})
    assert out["failed_targets"] == ["T2"]
    assert out["target_errors"][0]["filename"] == "b.bin"
    assert out["target_errors"][0]["stage"] == "fuzz"
    assert out["outcome"]["target_errors"] == 1
    assert out["level"] == "bad"


def test_the_done_event_alone_still_marks_the_target_failed():
    """The per-target error event write is best-effort; the done payload is the authority."""
    out = runsignals.summarize([_row(5, "autopilot.done", {"outcome": "static",
                                                           "failed_targets": ["T9"],
                                                           "target_errors": 1})])
    assert out["failed_targets"] == ["T9"] and out["level"] == "bad"


def test_degraded_sandbox_ranked_taint_tiered_recovery_capped_hang_and_lease_are_reported():
    rows = [
        _row(1, "coverage.isolation", {"isolation": "bwrap"}, run_target="T1"),     # fine: dropped
        _row(2, "coverage.isolation", {"isolation": "rlimits-only", "note": "no bwrap"},
             level="warn", run_target="T1"),
        _row(3, "env_fuzz.isolation", {"isolation": "rlimits-only"}, level="warn",
             run_target="T1"),
        _row(4, "detect.taint_ranked", {"total": 9000, "cap": 4000, "analyzed": 4000,
                                        "skipped_reachable": 1200, "exact": False,
                                        "note": "1200 reachable function(s) were NOT analysed"},
             run_target="T1"),
        _row(5, "re.done", {"functions": 7000, "total_functions": 9000, "analysis_tier": "aa",
                            "degradations": ["tier cut at aa"], "partial": True},
             run_target="T1"),
        _row(6, "autopilot.crashes_capped", {"target_id": "T1", "distinct": 47, "proving": 32}),
        _row(7, "fuzz.hang", {"input_sha": "h1", "mode": "stdin", "timeout": 4}, run_target="T1"),
        _row(8, "directed.hang", {"input_sha": "h1", "mode": "stdin"}, run_target="T1"),  # dup
        _row(9, "job.lease_renewed", {"reason": "starved"}, level="warn"),
        _row(10, "job.lease_renewed", {"reason": "starved"}, level="warn"),
    ]
    out = runsignals.summarize(rows, running=True, filenames={"T1": "a.bin"})
    assert [(i["engine"], i["isolation"]) for i in out["isolation"]] == [
        ("coverage", "rlimits-only"), ("env_fuzz", "rlimits-only")]
    assert out["taint"][0]["analyzed"] == 4000 and out["taint"][0]["skipped_reachable"] == 1200
    assert out["recovery"][0]["analysis_tier"] == "aa"
    assert out["crashes_capped"][0] == {"target_id": "T1", "filename": "a.bin",
                                        "distinct": 47, "proving": 32}
    assert [h["input_sha"] for h in out["hangs"]] == ["h1"]
    assert out["lease_renewed"]["count"] == 2
    assert out["level"] == "warn"


def test_runtime_env_supplied_is_info_and_an_unopened_gate_is_a_warning():
    applied = {"applied": True, "gated": True, "note": "with 2 supplied item(s) it exits 0",
               "supplied": [{"kind": "file", "path": "/etc/a.conf", "at": "/etc/a.conf",
                             "why": "fopen"},
                            {"kind": "env", "name": "A_HOME", "value": "/tmp"}],
               "degraded": []}
    out = runsignals.summarize([_row(1, "runtime_env", applied, run_target="T1")],
                               filenames={"T1": "a.bin"})
    e = out["runtime_env"][0]
    assert e["applied"] and e["filename"] == "a.bin"
    assert e["supplied"] == ["file /etc/a.conf (fopen)", "env A_HOME=/tmp"]
    assert out["level"] == "ok"                              # supplied cleanly: informational
    gate = {"applied": False, "gated": True, "note": "the target exits early (x)",
            "supplied": [], "degraded": [{"path": "/opt/x", "why": "cannot overlay"}]}
    out = runsignals.summarize([_row(1, "runtime_env", gate, run_target="T2")])
    assert out["runtime_env"][0]["degraded"] == ["/opt/x: cannot overlay"]
    assert out["level"] == "warn"
    # a target that needed nothing is no signal, and the latest event per target stands
    plain = {"applied": False, "gated": False, "note": "runs without"}
    assert runsignals.summarize([_row(1, "runtime_env", plain, run_target="T1")])[
        "runtime_env"] == []
    assert runsignals.summarize([_row(1, "runtime_env", gate, run_target="T1"),
                                 _row(2, "runtime_env", applied, run_target="T1")])[
        "runtime_env"][0]["applied"]


def test_a_later_clean_recovery_supersedes_a_degraded_one():
    rows = [_row(1, "re.done", {"analysis_tier": "aa", "partial": True}, run_target="T1"),
            _row(2, "re.done", {"analysis_tier": "aaa", "partial": False}, run_target="T1")]
    assert runsignals.summarize(rows)["recovery"] == []


def test_run_scoped_signals_come_from_the_latest_run_only():
    rows = [
        _row(1, "autopilot.target_error", {"target_id": "OLD", "stage": "fuzz", "error": "x"}),
        _row(2, "autopilot.done", {"outcome": "static", "failed_targets": ["OLD"]}),
        _row(3, "coverage.isolation", {"isolation": "rlimits-only"}, level="warn"),
        _row(4, "autopilot.done", {"outcome": "crash"}),
    ]
    done = runsignals.summarize(rows, running=False)
    assert done["failed_targets"] == [] and done["outcome"]["outcome"] == "crash"
    assert done["isolation"]                                 # emitted in the latest run
    live = runsignals.summarize(rows + [_row(5, "job.lease_renewed", {})], running=True)
    assert live["isolation"] == [] and live["outcome"] is None   # new run: window after id 4
    assert live["lease_renewed"]["count"] == 1


def test_run_signals_endpoint_reads_the_event_log(api):
    sock, cs = api
    cid, tid = _case_with_target(sock, cs)
    from lykos.casestore import CaseStore
    st = CaseStore.open(cs)
    try:
        st.events.append("autopilot.target_error", level="error", case_id=cid,
                         payload={"target_id": tid, "stage": "detect_cwe", "error": "boom"})
        st.events.append("autopilot.done", case_id=cid,
                         payload={"outcome": "static", "target_errors": 1,
                                  "failed_targets": [tid]})
        st.conn.commit()
    finally:
        st.close()
    code, body = _jreq(sock, "GET", f"/cases/{cid}/run-signals")
    assert code == 200
    assert body["failed_targets"] == [tid] and body["target_errors"][0]["filename"] == "t.bin"
    assert body["level"] == "bad"
    # incremental: a second read after a new event sees it
    st = CaseStore.open(cs)
    try:
        st.events.append("job.lease_renewed", level="warn", case_id=cid, payload={})
        st.conn.commit()
    finally:
        st.close()
    _c, body2 = _jreq(sock, "GET", f"/cases/{cid}/run-signals")
    assert body2["lease_renewed"]["count"] == 1
    assert _jreq(sock, "GET", "/cases/nope/run-signals")[0] == 404


# --------------------------------------------------------------------------- crash triage
def _dyn(sig, pc=None, key=None, sha=None, mode="stdin", iso=None, t=0):
    return {"crashed": True, "signal": sig, "fault_pc": pc, "defect_key": key,
            "input_sha": sha, "input_mode": mode, "isolation": iso, "argv": [],
            "created_at": t}


def test_crashes_group_by_the_prove_loops_bucket_key():
    dyns = [_dyn("SIGSEGV", "0x401136", sha=f"a{i}") for i in range(40)]
    dyns += [_dyn("SIGABRT", key="heap-buffer-overflow@x.c:10", sha="b1"),
             _dyn("SIGABRT", key="use-after-free@y.c:3", sha="b2"),
             _dyn("SIGSEGV", None, sha="c1", mode="stdin"),
             _dyn("SIGSEGV", None, sha="c2", mode="file"),
             {"crashed": False, "signal": None, "input_sha": "z"}]
    out = triage.crash_groups(dyns, [], [])
    assert out["crashes"] == 44 and out["distinct"] == 5
    seg = next(g for g in out["groups"] if g["fault_pc"] == "0x401136")
    assert seg["count"] == 40 and len(seg["inputs"]) <= 20 and seg["input_count"] == 40
    unresolved = [g for g in out["groups"] if not g["resolved"]]
    assert sorted(g["channel"] for g in unresolved) == ["file", "stdin"]


def test_only_a_verified_poc_sets_a_groups_level_and_ranks_it_first():
    dyns = [_dyn("SIGSEGV", "0x10", sha="s1"), _dyn("SIGSEGV", "0x10", sha="s2"),
            _dyn("SIGSEGV", "0x20", sha="t1"), _dyn("SIGABRT", key="k", sha="u1")]
    findings = [
        {"id": "F1", "title": "Stack overflow", "cwe": "CWE-121", "state": "poc-backed",
         "severity": "critical", "dedup_key": "dynamic-crash:SIGSEGV:20",
         "evidence": [{"channel": "exploitability",
                       "detail": "exploitability: EXPLOITABLE (90/100) -- pc control"}]},
        {"id": "F2", "title": "Crash", "cwe": "CWE-125", "state": "confirmed", "severity": "high",
         "dedup_key": "other", "evidence": [{"channel": "dynamic", "input_sha": "s2"}]},
    ]
    pocs = [{"id": "P1", "finding_id": "F1", "level": "L3", "verified": True,
             "input_sha": "t1", "bundle_sha": "B1"},
            {"id": "P2", "finding_id": None, "level": "L3", "verified": False,
             "input_sha": "s1", "bundle_sha": None}]
    out = triage.crash_groups(dyns, findings, pocs, prove_cap=32)
    g0 = out["groups"][0]
    assert g0["fault_pc"] == "0x20" and g0["best_level"] == 3 and g0["rank"] == 1
    assert g0["poc"]["bundle_sha"] == "B1" and g0["exploitability"]["score"] == 90
    assert [f["id"] for f in g0["findings"]] == ["F1"]
    g10 = next(g for g in out["groups"] if g["fault_pc"] == "0x10")
    assert g10["best_level"] == 0                       # unverified L3 is NOT the group's level
    assert g10["candidate_level"] == 3
    assert [f["id"] for f in g10["findings"]] == ["F2"]   # linked via its evidence input
    assert out["over_prove_cap"] is False


def test_crash_triage_endpoint(api):
    sock, cs = api
    cid, tid = _case_with_target(sock, cs)
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO
    st = CaseStore.open(cs)
    try:
        dd = DynResultDAO(st.conn)
        for i in range(3):
            dd.insert(tid, cid, input_sha=f"{i:064x}", signal_name="SIGSEGV", crashed=True,
                      fault_pc=0x401000)
        dd.insert(tid, cid, input_sha="f" * 64, signal_name="SIGABRT", crashed=True,
                  defect_key="asan:heap-buffer-overflow")
        st.conn.commit()
    finally:
        st.close()
    code, body = _jreq(sock, "GET", f"/targets/{tid}/crash-triage")
    assert code == 200 and body["distinct"] == 2 and body["crashes"] == 4
    assert {g["count"] for g in body["groups"]} == {3, 1}
    assert _jreq(sock, "GET", "/targets/nope/crash-triage")[0] == 404


# --------------------------------------------------------------------------- seeds
def test_seed_upload_list_remove_and_autopilot_resolution(api):
    sock, cs = api
    cid, _tid = _case_with_target(sock, cs)
    code, up = _req(sock, "POST", f"/cases/{cid}/seeds", b"key=value\n",
                    {"Content-Type": "application/octet-stream",
                     "X-Filename": "../../etc/conf.ini"})
    assert code == 201 and up["name"] == "conf.ini" and up["size"] == 10
    sha = up["sha256"]
    _c, lst = _jreq(sock, "GET", f"/cases/{cid}/seeds")
    assert [s["sha256"] for s in lst["seeds"]] == [sha]
    # the stored bytes are the seed
    from lykos.casestore import ContentStore
    assert ContentStore(cs).path(sha).read_bytes() == b"key=value\n"
    # resolution: an unknown hash is refused (a seeded run must not quietly run unseeded)
    code, err = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                      {"overrides": {"seed_shas": ["0" * 64]}})
    assert code == 400 and "not in this case" in err["error"]
    code, err = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                      {"overrides": {"seed_shas": "nope"}})
    assert code == 400
    # remove
    assert _req(sock, "DELETE", f"/cases/{cid}/seeds/{sha}")[0] == 200
    assert _jreq(sock, "GET", f"/cases/{cid}/seeds")[1]["seeds"] == []
    assert _req(sock, "DELETE", f"/cases/{cid}/seeds/{sha}")[0] == 404


def test_seed_limits(api):
    sock, cs = api
    cid, _tid = _case_with_target(sock, cs)
    from lykos.api.ops import MAX_SEED_BYTES
    code, _b = _req(sock, "POST", f"/cases/{cid}/seeds", b"x" * (MAX_SEED_BYTES + 1),
                    {"Content-Type": "application/octet-stream", "X-Filename": "big"})
    assert code == 413
    code, _b = _req(sock, "POST", f"/cases/{cid}/seeds", b"",
                    {"Content-Type": "application/octet-stream", "X-Filename": "empty"})
    assert code == 400
    assert _req(sock, "POST", "/cases/nope/seeds", b"x",
                {"Content-Type": "application/octet-stream"})[0] == 404


def test_a_browser_can_no_longer_hand_the_autopilot_a_server_path():
    from lykos.api.autopilot import AutopilotMixin
    out = AutopilotMixin._normalize_overrides({"seed_files": ["/etc/shadow"], "seed_dir": "/root",
                                               "argv": "-c @@"})
    assert "seed_files" not in out and "seed_dir" not in out and out["argv"] == ["-c", "@@"]


# --------------------------------------------------------------------------- doctor / version
def test_version_endpoint(api):
    sock, _cs = api
    code, v = _jreq(sock, "GET", "/version")
    assert code == 200 and v["display"].startswith("lykos")
    assert "version" in v and "source" in v


def test_doctor_endpoint_probes_in_the_background(api, monkeypatch):
    from lykos import toolchain
    from lykos.api import ops

    def fake_survey(progress=None):
        return [(t, ("1.0" if t.tier == "required" else None)) for t in toolchain.TOOLS]
    monkeypatch.setattr(toolchain, "survey", fake_survey)
    monkeypatch.setitem(ops._DOCTOR, "result", None)
    monkeypatch.setitem(ops._DOCTOR, "state", "idle")
    monkeypatch.setitem(ops._DOCTOR, "thread", None)
    sock, _cs = api
    body = None
    for _ in range(100):
        code, body = _jreq(sock, "GET", "/doctor")
        assert code == 200
        if body["state"] == "done":
            break
        time.sleep(0.05)
    assert body["state"] == "done" and body["required_missing"] == []
    assert body["total"] == len(toolchain.TOOLS) and body["tools"][0]["key"]


# --------------------------------------------------------------------------- bundle ceilings
def test_a_zip_bomb_is_refused_before_extraction(tmp_path, monkeypatch):
    from lykos.api import endpoints
    monkeypatch.setattr(endpoints, "_MAX_BUNDLE_BYTES", 1 << 20)
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.bin", b"\0" * (2 << 20))           # 2 MiB of zeros -> a few KB
    with pytest.raises(endpoints.BundleRejected) as ei:
        endpoints._maybe_extract_bundle(z, tmp_path, "bomb.zip")
    assert ei.value.status == 413
    assert not (tmp_path / "bundle").exists()


def test_too_many_members_is_refused(tmp_path, monkeypatch):
    from lykos.api import endpoints
    monkeypatch.setattr(endpoints, "_MAX_BUNDLE_MEMBERS", 5)
    z = tmp_path / "many.tar"
    with tarfile.open(z, "w") as tf:
        for i in range(8):
            data = b"x"
            ti = tarfile.TarInfo(f"f{i}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    with pytest.raises(endpoints.BundleRejected) as ei:
        endpoints._maybe_extract_bundle(z, tmp_path, "many.tar")
    assert ei.value.status == 400


def test_a_normal_bundle_still_extracts(tmp_path):
    from lykos.api import endpoints
    z = tmp_path / "ok.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("chal/bin", b"\x7fELF" + b"\0" * 60)
        zf.writestr("../evil", b"x")
    dest = endpoints._maybe_extract_bundle(z, tmp_path, "ok.zip")
    assert dest is not None and (dest / "chal" / "bin").is_file()
    assert not (tmp_path / "evil").exists()


def test_a_zip_bomb_upload_is_a_413(api, monkeypatch):
    from lykos.api import endpoints
    monkeypatch.setattr(endpoints, "_MAX_BUNDLE_BYTES", 1 << 20)
    sock, cs = api
    _st, case = _jreq(sock, "POST", "/cases", {"name": "bomb"})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.bin", b"\0" * (2 << 20))
    code, body = _req(sock, "POST", f"/cases/{case['id']}/targets", buf.getvalue(),
                      {"Content-Type": "application/octet-stream", "X-Filename": "b.zip"})
    assert code == 413 and "refusing" in body["error"]
