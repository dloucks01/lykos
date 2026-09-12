"""P0.2 / P0.6 — API + event WebSocket integration (stdlib clients over the unix socket)."""
import base64
import http.client
import json
import os
import socket
import struct
import time

import pytest
from lykos.api.server import serve, shutdown


@pytest.fixture
def api(tmp_path):
    sock = str(tmp_path / "s.sock")
    servers, pool = serve(tmp_path / "cs", sock, workers=2, block=False)
    for _ in range(200):
        if os.path.exists(sock):
            break
        time.sleep(0.02)
    try:
        yield sock
    finally:
        shutdown(servers, pool)


@pytest.fixture
def api_http(tmp_path):
    servers, pool = serve(tmp_path / "cs", http=("127.0.0.1", 0), workers=2, block=False)
    port = servers[0].server_address[1]
    try:
        yield port
    finally:
        shutdown(servers, pool)


def _tcp(port, method, url, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port)
    try:
        c.request(method, url, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def _tcp_json(port, method, url, obj=None):
    body = json.dumps(obj).encode() if obj is not None else None
    st, data = _tcp(port, method, url, body,
                    {"Content-Type": "application/json"} if obj is not None else {})
    return st, (json.loads(data) if data else None)


class _UDS(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def _req(sock_path, method, url, body=None, headers=None):
    c = _UDS(sock_path)
    try:
        c.request(method, url, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, data
    finally:
        c.close()


def _json(sock_path, method, url, obj=None):
    body = json.dumps(obj).encode() if obj is not None else None
    st, data = _req(sock_path, method, url, body,
                    {"Content-Type": "application/json"} if obj is not None else {})
    return st, (json.loads(data) if data else None)


def _upload(sock_path, cid, filename, filedata):
    boundary = "----lykostest"
    pre = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
           f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    body = pre + filedata + f"\r\n--{boundary}--\r\n".encode()
    st, data = _req(sock_path, "POST", f"/cases/{cid}/targets", body,
                    {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return st, json.loads(data)


def _wait_run(sock_path, run_id, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, run = _json(sock_path, "GET", f"/runs/{run_id}")
        if st == 200 and run["status"] in ("done", "error", "cancelled"):
            return run
        time.sleep(0.05)
    raise TimeoutError("run did not finish")


# ---- WebSocket minimal client ----
def _ws_connect(path, case_id):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET /events?case_id={case_id} HTTP/1.1\r\nHost: localhost\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\n\r\n")
    s.sendall(req.encode())
    buf = b""
    s.settimeout(3.0)
    while b"\r\n\r\n" not in buf:
        buf += s.recv(1024)
    assert b"101" in buf.split(b"\r\n", 1)[0], buf[:40]
    return s


def _ws_read(s, timeout=3.0):
    s.settimeout(timeout)
    hdr = s.recv(2)
    if len(hdr) < 2:
        return None
    opcode = hdr[0] & 0x0F
    ln = hdr[1] & 0x7F
    if ln == 126:
        ln = struct.unpack("!H", s.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", s.recv(8))[0]
    payload = b""
    while len(payload) < ln:
        payload += s.recv(ln - len(payload))
    if opcode == 0x8:
        return "__close__"
    return json.loads(payload.decode())


# ---- tests ----
def test_health(api):
    st, obj = _json(api, "GET", "/health")
    assert st == 200 and obj["status"] == "ok"


def test_case_crud(api):
    st, c = _json(api, "POST", "/cases", {"name": "demo-001"})
    assert st == 201 and c["name"] == "demo-001"
    st, got = _json(api, "GET", f"/cases/{c['id']}")
    assert st == 200 and got["id"] == c["id"]


def test_upload_triage_end_to_end(api, sample_elf):
    _, c = _json(api, "POST", "/cases", {"name": "eng"})
    st, up = _upload(api, c["id"], "default", sample_elf.read_bytes())
    assert st == 201
    assert up["sha256"] and up["run_id"]

    run = _wait_run(api, up["run_id"])
    assert run["status"] == "done"
    out = [o for o in run["outputs"] if o["kind"] == "triage-json"]
    assert out, run

    st, raw = _req(api, "GET", f"/artifacts/{out[0]['sha256']}")
    rec = json.loads(raw)
    assert rec["file_type"] == "elf" and rec["arch"] == "x86-64"

    # target row denormalized via the API
    st, t = _json(api, "GET", f"/targets/{up['id']}")
    assert t["arch"] == "x86-64" and t["mitigations"]


def test_rerun_cache_hit(api, sample_elf):
    _, c = _json(api, "POST", "/cases", {"name": "eng"})
    _, up = _upload(api, c["id"], "default", sample_elf.read_bytes())
    _wait_run(api, up["run_id"])
    st, r2 = _json(api, "POST", "/runs",
                   {"case_id": c["id"], "target_id": up["id"], "stage": "ingest_triage"})
    assert st == 201
    assert r2["from_cache"] is True                 # cache short-circuit at enqueue


def test_ui_served_over_tcp(api_http):
    st, body = _tcp(api_http, "GET", "/")
    assert st == 200
    assert b"LYKOS" in body and b"<title>" in body


def test_list_targets_and_runs(api_http, sample_elf):
    _, c = _tcp_json(api_http, "POST", "/cases", {"name": "eng"})
    # upload over TCP (multipart)
    boundary = "----lykostest"
    pre = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
           f"filename=\"ls\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    body = pre + sample_elf.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    st, up = _tcp(api_http, "POST", f"/cases/{c['id']}/targets", body,
                  {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    assert st == 201
    st, targets = _tcp_json(api_http, "GET", f"/cases/{c['id']}/targets")
    assert st == 200 and len(targets) == 1
    st, runs = _tcp_json(api_http, "GET", f"/cases/{c['id']}/runs")
    assert st == 200 and len(runs) >= 1


def test_event_websocket_stream(api, sample_elf):
    _, c = _json(api, "POST", "/cases", {"name": "eng"})
    ws = _ws_connect(api, c["id"])
    try:
        _, up = _upload(api, c["id"], "default", sample_elf.read_bytes())
        seen = set()
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                ev = _ws_read(ws, timeout=3.0)
            except socket.timeout:
                break
            if ev in (None, "__close__"):
                break
            seen.add(ev["type"])
            if "job.done" in seen or "triage.done" in seen:
                break
        assert "job.started" in seen or "triage.done" in seen or "job.done" in seen, seen
    finally:
        ws.close()


def test_case_findings_board(tmp_path):
    """Case-level findings board endpoint aggregates findings across targets, enriched with
    target filename/arch and best PoC level."""
    from lykos.casestore import CaseStore
    from lykos.db.dao import FindingDAO

    cspath = tmp_path / "board-cs"
    servers, pool = serve(cspath, http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        _, c = _tcp_json(port, "POST", "/cases", {"name": "board"})
        s = CaseStore.open(cspath)
        try:
            t = s.targets.upsert(c["id"], "vuln.bin", "deadbeef" * 8, arch="x86-64")
            fd = FindingDAO(s.conn)
            fd.upsert(t.id, c["id"], {"cwe": "CWE-121", "title": "stack overflow",
                      "severity": "critical", "state": "poc-backed", "confidence": 0.98,
                      "detector": "primitive", "dedup_key": "k1",
                      "evidence": [{"channel": "poc", "detail": "x"}]})
            fd.upsert(t.id, c["id"], {"cwe": "CWE-476", "title": "null deref",
                      "severity": "medium", "state": "candidate", "confidence": 0.4,
                      "detector": "root_cause", "dedup_key": "k2", "evidence": []})
        finally:
            s.close()
        st, fs = _tcp_json(port, "GET", f"/cases/{c['id']}/findings")
        assert st == 200 and len(fs) == 2
        crit = next(x for x in fs if x["cwe"] == "CWE-121")
        assert crit["target_name"] == "vuln.bin" and crit["target_arch"] == "x86-64"
        assert crit["state"] == "poc-backed"
    finally:
        shutdown(servers, pool)


def test_delete_target_endpoint(api_http, sample_elf):
    """DELETE /targets/{id} removes the target and its runs; a second delete is 404."""
    _, c = _tcp_json(api_http, "POST", "/cases", {"name": "del"})
    boundary = "----lykostest"
    pre = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
           f"filename=\"ls\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    body = pre + sample_elf.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    st, up = _tcp(api_http, "POST", f"/cases/{c['id']}/targets", body,
                  {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    assert st == 201
    tid = json.loads(up)["id"]
    st, res = _tcp_json(api_http, "DELETE", f"/targets/{tid}")
    assert st == 200 and res["deleted"] is True and res["id"] == tid
    st, targets = _tcp_json(api_http, "GET", f"/cases/{c['id']}/targets")
    assert st == 200 and targets == []                       # gone from the case
    st, runs = _tcp_json(api_http, "GET", f"/cases/{c['id']}/runs")
    assert st == 200 and runs == []                          # its triage run cascaded
    st, res = _tcp_json(api_http, "DELETE", f"/targets/{tid}")
    assert st == 404                                         # already gone


def test_format_analyze_suggest_and_preview(api_http):
    """The custom-format builder endpoint: suggest a spec from a sample (auto-find the length
    field), then preview how that spec carves a sample."""
    sample = b"%PDF" + struct.pack("<I", 16) + b"A" * 16
    b64 = base64.b64encode(sample).decode()
    st, out = _tcp_json(api_http, "POST", "/format/analyze", {"sample_b64": b64})
    assert st == 200 and "suggestion" in out
    spec = out["suggestion"]["spec"]
    assert spec[0]["type"] == "magic" and spec[1].get("length_of") == "data"

    st, out = _tcp_json(api_http, "POST", "/format/analyze",
                        {"sample_b64": b64, "spec": spec})
    assert st == 200 and out["preview"]["ok"] and out["preview"]["roundtrip"]
    lenf = [f for f in out["preview"]["fields"] if f["type"] == "u32"][0]
    assert lenf["length_match"] is True


# ------------------------------------------------- stage dispatch (replaced a 90-line chain)
def test_every_dispatch_entry_resolves_to_a_real_enqueue_function():
    """The table replaced an elif chain that had to be edited in two places per stage. A typo
    in a module path or function name would previously surface only when a user asked for that
    stage; resolve them all up front instead."""
    from lykos.api.server import Handler
    table = {**Handler._CASE_STAGES, **Handler._TARGET_STAGES}
    assert len(table) >= 25
    for stage, entry in table.items():
        fn = Handler._enqueue_fn(entry)
        assert callable(fn), f"{stage} -> {entry} is not callable"


def test_dispatch_covers_every_registered_stage():
    """A stage the engine can run but the API cannot reach is a silent capability gap."""
    from lykos.analyze import register
    from lykos.api.server import Handler
    from lykos.jobs import registry
    register()
    reachable = set(Handler._CASE_STAGES) | set(Handler._TARGET_STAGES)
    registered = set(registry.list_stages())
    assert registered, "no stages registered -- the check would pass vacuously"
    assert not registered - reachable, \
        f"registered stages unreachable over the API: {sorted(registered - reachable)}"
    assert not reachable - registered, \
        f"dispatch names no engine stage: {sorted(reachable - registered)}"


def test_unknown_stage_is_rejected_at_the_edge(api):
    """The old final `else` enqueued ANY name, creating a run no worker could execute -- it
    sat queued forever instead of reporting the typo."""
    st, case = _json(api, "POST", "/cases", {"name": "x"})
    st, body = _json(api, "POST", "/runs",
                     {"case_id": case["id"], "stage": "definitely_not_a_stage"})
    assert st == 400, body
    assert "unknown stage" in body["error"]
    assert "detect_cwe" in body["stages"]          # tells the caller what IS valid


def test_a_run_can_be_stopped(tmp_path):
    """The job engine has had `JobQueue.cancel` and `ctx.should_cancel()` all along and
    nothing exposed them, so a ten-minute campaign started from the UI had to be waited out or
    the server killed. Cancelling twice is not an error, and neither is cancelling a run that
    just finished -- the user clicked at the wrong moment, which is not a failure."""
    from lykos.casestore import CaseStore
    from lykos.jobs import JobQueue
    store = CaseStore.open(tmp_path / "case")
    try:
        cid = store.cases.create("c").id
        q = JobQueue(store.conn)
        run = q.enqueue(cid, "detect_cwe", params={}, tool="detect", tool_version="t",
                        resource_class="cpu")
        assert q.cancel(run.id) is True
        assert store.runs.get(run.id).status == "cancelled"
        assert q.cancel(run.id) is False, "already cancelled: reported, not an error"
        assert q.cancel("nosuchrun") is False
    finally:
        store.close()


def test_an_empty_upload_is_refused_with_a_reason(tmp_path):
    """Accepting one produced a target whose every triage field was null, a detect_cwe run
    that reported "done", and an advice panel recommending coverage-guided fuzzing -- a
    confident plan for nothing at all."""
    import pytest
    from lykos.analyze.ingest import NotAnalysable, ingest
    from lykos.casestore import CaseStore
    store = CaseStore.open(tmp_path / "case")
    try:
        cid = store.cases.create("c").id
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        with pytest.raises(NotAnalysable) as e:
            ingest(store, cid, empty, filename="empty.bin")
        assert "0 bytes" in str(e.value) and "empty.bin" in str(e.value)
        # anything with content is still accepted: a raw dump is a legitimate target
        blob = tmp_path / "dump.bin"
        blob.write_bytes(b"\x00\x01\x02\x03")
        assert ingest(store, cid, blob, filename="dump.bin").size == 4
    finally:
        store.close()


def test_advice_does_not_plan_for_a_file_it_cannot_identify():
    """A text file uploaded by mistake was answered with "AFL++ is available -- coverage-guided
    fuzzing explores new paths instead of mutating blindly"."""
    from lykos.analyze.advise import advise
    out = advise(imports=[], functions=0, findings=0, seeds=0, has_format=False,
                 afl_usable=True, executable=False)
    assert out["analysable"] is False
    assert out["backend"] is None, "no strategy for something we cannot identify"
    assert "not a recognised executable" in out["headline"]
    # a real target is unaffected
    ok = advise(imports=["fopen"], functions=40, findings=2, seeds=0, has_format=False,
                afl_usable=True, executable=True)
    assert ok["analysable"] is True and ok["backend"]
