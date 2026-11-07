"""Server side of the app3 Run / Engagement fixes:

  * the interactive console's "save as seed" is a real case seed (artifact + operator.seed event),
    not a bare artifact no seed list or run ever read;
  * an upload name the browser percent-encodes (X-Filename-Encoding: uri) is decoded -- a raw
    non-Latin-1 header value cannot be sent at all;
  * the autopilot's skip allowlist is the CLI's --no-fuzz set (SAMPLER_STAGES) + concolic, and
    its status says when a stop / pause is pending;
  * GET /cases/{id}/console?download=1 is the WHOLE console log;
  * deep-seed / sysroot env settings are scoped to the run (restored after it);
  * the self-test's `only` takes the CLI's comma form.
"""
from __future__ import annotations

import json
import os
import threading
import time

import pytest
from lykos.api import ops
from lykos.api.endpoints import x_filename
from lykos.casestore import CaseStore
from test_api_ops import _jreq, _req, api  # noqa: F401  (fixture + helpers)


def _new_case(cs):
    st = CaseStore.open(cs) if hasattr(CaseStore, "open") else CaseStore(cs)
    c = st.cases.create("parity")
    st.conn.commit()
    return st, c.id


def test_register_seed_is_a_case_seed(tmp_path):
    st, cid = _new_case(tmp_path / "cs")
    try:
        rec = ops.register_seed(st, cid, b"GET / HTTP/1.0\r\n\r\n", "console-session.bin")
        seeds = ops.case_seeds(st.conn, cid)
        assert [s["sha256"] for s in seeds] == [rec["sha256"]]
        assert seeds[0]["name"] == "console-session.bin"
        # saving the same bytes again does not add a second entry
        ops.register_seed(st, cid, b"GET / HTTP/1.0\r\n\r\n", "again.bin")
        assert len(ops.case_seeds(st.conn, cid)) == 1
        with pytest.raises(ValueError):
            ops.register_seed(st, cid, b"", "empty")
        with pytest.raises(ValueError):
            ops.register_seed(st, cid, b"x" * (ops.MAX_SEED_BYTES + 1), "big")
    finally:
        st.close()


def test_x_filename_decodes_only_when_told():
    assert x_filename({"X-Filename": "%E6%B5%8B%E8%AF%95.bin", "X-Filename-Encoding": "uri"}) == "测试.bin"
    # an older client's raw value is taken as-is, '%' and all
    assert x_filename({"X-Filename": "100%25.bin"}) == "100%25.bin"
    assert x_filename({}) is None


def test_console_download_is_the_whole_log(api):  # noqa: F811
    sock, cs = api
    _c, case = _jreq(sock, "POST", "/cases", {"name": "dl"})
    cid = case["id"]
    from lykos.jobs import runlog
    p = runlog.console_path(cs, cid)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({"t": i, "k": "note", "text": f"n{i}"}) for i in range(5000)]
    p.write_text("\n".join(lines) + "\n")
    code, body = _req(sock, "GET", f"/cases/{cid}/console?download=1")
    assert code == 200
    raw = body if isinstance(body, (bytes, bytearray)) else json.dumps(body).encode()
    assert raw.count(b"\n") == 5000
    assert _req(sock, "GET", "/cases/nope/console?download=1")[0] == 404
    # the paged view is unchanged
    code, page = _jreq(sock, "GET", f"/cases/{cid}/console?after=0")
    assert code == 200 and len(page["lines"]) == 2000 and page["size"] == p.stat().st_size


def test_skip_allowlist_and_stop_feedback(api, monkeypatch):  # noqa: F811
    sock, cs = api
    from lykos.analyze import budget, orchestrate
    seen = {}
    release = threading.Event()

    def fake_run(case_dir, cid, target_ids, status, stop, secs, over, converge, skip, pause,
                 only_handed=False):
        seen["skip"] = list(skip)
        status["state"] = "running"
        while not stop.is_set() and not release.is_set():
            time.sleep(0.02)

    monkeypatch.setattr(orchestrate, "run_case_autopilot", fake_run)
    _c, case = _jreq(sock, "POST", "/cases", {"name": "ap"})
    cid = case["id"]
    st = CaseStore(cs)
    try:
        st.targets.upsert(cid, "t.bin", "cd" * 32, file_type="elf", arch="x86_64")
        st.conn.commit()
    finally:
        st.close()
    want = sorted(set(budget.SAMPLER_STAGES) | {"concolic"})
    code, _b = _jreq(sock, "POST", f"/cases/{cid}/autopilot",
                     {"skip_stages": want + ["triage", "disasm"]})
    assert code == 202
    for _ in range(100):
        if "skip" in seen:
            break
        time.sleep(0.02)
    assert sorted(seen["skip"]) == want          # net/env/boundary fuzz now skippable; triage not
    _c, s = _jreq(sock, "GET", f"/cases/{cid}/autopilot")
    assert s["running"] and not s["stopping"] and not s["paused"]
    assert _jreq(sock, "POST", f"/cases/{cid}/autopilot/pause")[0] == 200
    _c, s = _jreq(sock, "GET", f"/cases/{cid}/autopilot")
    assert s["paused"] and not s["pause_waiting"]          # requested; not parked yet
    assert _jreq(sock, "POST", f"/cases/{cid}/autopilot/cancel")[0] == 200
    for _ in range(100):
        _c, s = _jreq(sock, "GET", f"/cases/{cid}/autopilot")
        if not s["running"]:
            break
        time.sleep(0.02)
    assert not s["running"] and not s["stopping"]
    release.set()


def test_run_env_settings_do_not_leak(tmp_path, monkeypatch):
    from lykos.analyze import orchestrate
    monkeypatch.delenv("LYKOS_BUFFER_SEED", raising=False)
    monkeypatch.setenv("LYKOS_QEMU_SYSROOT", "/srv/original")
    st, cid = _new_case(tmp_path / "cs")
    st.close()
    seen = []

    class Status(dict):                      # records the env the run sees while it is running
        def update(self, *a, **k):
            seen.append((os.environ.get("LYKOS_BUFFER_SEED"), os.environ.get("LYKOS_QEMU_SYSROOT")))
            return super().update(*a, **k)

    status = Status()
    orchestrate.run_case_autopilot(tmp_path / "cs", cid, [], status, threading.Event(), 30.0,
                                   {"deep_seed": True, "sysroot": "/tmp/other"})
    assert seen and seen[0] == ("1", "/tmp/other")          # in force DURING the run
    assert "LYKOS_BUFFER_SEED" not in os.environ
    assert os.environ["LYKOS_QEMU_SYSROOT"] == "/srv/original"


def test_selftest_only_takes_the_cli_comma_form():
    from lykos.api.selftest import _only

    class C:
        def __init__(self, label):
            self.label = label

    m = [C("a"), C("b"), C("c")]
    assert [c.label for c in _only(m, "a, c")] == ["a", "c"]
    assert [c.label for c in _only(m, ["b"])] == ["b"]
    assert _only(m, "") is m and _only(m, " , ") is m
    with pytest.raises(ValueError):
        _only(m, "zzz")


def test_upload_name_percent_encoded_by_the_gui(api):  # noqa: F811
    sock, _cs = api
    _c, case = _jreq(sock, "POST", "/cases", {"name": "up"})
    with open("/bin/true", "rb") as f:
        body = f.read()
    code, t = _req(sock, "POST", f"/cases/{case['id']}/targets", body,
                   {"Content-Type": "application/octet-stream",
                    "X-Filename": "%E6%B5%8B%E8%AF%95.bin", "X-Filename-Encoding": "uri"})
    assert code in (200, 201), t
    _c, ts = _jreq(sock, "GET", f"/cases/{case['id']}/targets")
    ts = ts if isinstance(ts, list) else ts.get("targets", [])
    assert [x["filename"] for x in ts] == ["测试.bin"], (t, ts)
