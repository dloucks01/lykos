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
