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


def _tcp_ct(port, method, url, body=None, headers=None):
    """Like _tcp, but also returns the Content-Type header (bytes)."""
    c = http.client.HTTPConnection("127.0.0.1", port)
    try:
        c.request(method, url, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read(), (r.getheader("Content-Type") or "").encode()
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
    # The workbench shell: a title, the mount point, and the ES-module entry point. The app
    # itself lives in ./app/*.js loaded via the import map, not inline in this page.
    assert b"<title>" in body and b"lykos" in body.lower()
    assert b'id="root"' in body and b"app/app.js" in body


def test_ui_assets_served_over_tcp(api_http):
    # The SPA is nothing without its modules and the vendored Preact runtime. These load as
    # separate requests after index.html, so the server must serve them with a JS media type
    # (a wrong type makes the browser refuse the module and the page renders blank).
    for pth in ("/app/app.js", "/app/api.js", "/vendor/preact.module.js"):
        st, body, ctype = _tcp_ct(api_http, "GET", pth)
        assert st == 200, (pth, st)
        assert b"javascript" in ctype.lower(), (pth, ctype)
        assert body, pth
    # Path traversal out of the static subtree is refused, not served.
    st, _, _ = _tcp_ct(api_http, "GET", "/app/../server.py")
    assert st == 404
    # The preserved classic UI, linked from the new app, is reachable and is HTML.
    st, body, ctype = _tcp_ct(api_http, "GET", "/classic.html")
    assert st == 200 and b"html" in ctype.lower() and body


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


def test_a_proven_finding_is_not_badged_low(tmp_path):
    """Severity means demonstrated impact, and a working reproducer is the strongest evidence
    of it the platform can produce. jhead's proven out-of-bounds read kept the severity its
    pattern detector guessed -- low -- so the one finding in the report backed by a verified
    PoC sorted below unproven advisories."""
    from lykos.casestore import CaseStore
    from lykos.db.dao import FindingDAO
    store = CaseStore.open(tmp_path / "case")
    try:
        cid = store.cases.create("c").id
        t = store.targets.upsert(cid, "t", "a" * 64)
        fd = FindingDAO(store.conn)
        base = {"cwe": "CWE-125", "title": "oob read", "severity": "low",
                "detector": "tainted_deref", "dedup_key": "k1", "evidence": [],
                "function_addr": None, "site_addr": None}
        fd.upsert(t.id, cid, {**base, "state": "candidate", "confidence": 0.35})
        f = fd.list_by_target(t.id)[0]
        assert f.severity == "low", "unproven: the detector's own guess stands"
        fd.upsert(t.id, cid, {**base, "state": "poc-backed", "confidence": 0.95})
        f = fd.list_by_target(t.id)[0]
        assert f.state == "poc-backed" and f.severity == "high"
        # something already worse is not dragged down to high
        crit = {**base, "dedup_key": "k2", "severity": "critical", "state": "poc-backed",
                "confidence": 0.95}
        fd.upsert(t.id, cid, crit)
        got = next(x for x in fd.list_by_target(t.id) if x.dedup_key == "k2")
        assert got.severity == "critical"
    finally:
        store.close()


def test_strings_can_be_paged_past_the_cap(tmp_path):
    """A binary can hold far more strings than the cap returns -- jhead has 3,805 and the
    response stopped at exactly 2,000 with nothing saying so, indistinguishable from "that is
    all of them"."""
    from lykos.casestore import CaseStore
    from lykos.db.dao import StringDAO
    store = CaseStore.open(tmp_path / "case")
    try:
        cid = store.cases.create("c").id
        t = store.targets.upsert(cid, "t", "b" * 64)
        sd = StringDAO(store.conn)
        sd.replace_for_target(t.id, [{"addr": "0x%06x" % i, "value": f"s{i}"}
                                     for i in range(50)])
        assert sd.count_by_target(t.id) == 50
        first = sd.list_by_target(t.id, limit=10)
        rest = sd.list_by_target(t.id, limit=10, offset=10)
        assert len(first) == len(rest) == 10
        assert first[0].addr != rest[0].addr, "offset must actually move the window"
        assert sd.list_by_target(t.id, limit=10, offset=45) and \
            len(sd.list_by_target(t.id, limit=10, offset=45)) == 5
    finally:
        store.close()


def test_a_check_that_could_not_run_does_not_report_ok():
    """heap_check returned `ok: true, "no heap errors observed"` on a statically linked target
    where the LD_PRELOAD shim can never load -- a clean bill of health from a check that never
    ran. The caveat was in the note while the verdict said the opposite."""
    import inspect

    from lykos.analyze.dynamic import heap_stage
    src = inspect.getsource(heap_stage)
    assert '"applicable": False' in src
    assert 'linking or ""' in src, "the static case has to be tested for explicitly"
    i_guard = src.index('"applicable": False')
    i_ok = src.index('"ok": True, "errors": len(errors)')
    assert i_guard < i_ok, "the not-applicable verdict must come before the ok one"


def test_advice_carries_the_discovered_invocation_and_checks_it(api, tmp_path):
    """A service behind `-c <config> -d <display>` prints its usage and exits without them, so
    every execution is identical and the campaign reports a clean run against a program it
    never entered. The advice now carries the flags the binary itself documents -- and the
    proposal is CHECKED by running it, because a proposal read off the strings is a hypothesis
    and applying one unchecked is the failure it exists to prevent."""
    import shutil as _sh
    import subprocess
    if not _sh.which("cc"):
        pytest.skip("no C compiler")
    src = tmp_path / "svc.c"
    src.write_text(
        "#include <stdio.h>\n#include <unistd.h>\n"
        "int main(int argc,char**argv){int o;char*c=0,*d=0;\n"
        " while((o=getopt(argc,argv,\"c:d:v\"))!=-1){"
        "if(o=='c')c=optarg; else if(o=='d')d=optarg;}\n"
        " if(!c||!d){fprintf(stderr,\"usage: %s -c <config> -d <display-id>\\n\",argv[0]);"
        "return 2;}\n"
        " FILE*f=fopen(c,\"rb\"); if(f){char b[4096];fread(b,1,sizeof b,f);fclose(f);}\n"
        " return 0;}\n")
    exe = tmp_path / "svc"
    if subprocess.run(["cc", "-w", "-o", str(exe), str(src)]).returncode != 0:
        pytest.skip("compile failed")

    st, case = _json(api, "POST", "/cases", {"name": "inv"})
    st, t = _upload(api, case["id"], "svc", exe.read_bytes())
    tid = t["id"]
    # deliberately WITHOUT running disassemble: how to invoke a target is the first question
    # an operator has, and putting it behind a Ghidra run would answer it after the campaign
    # it was needed to set up.
    st, adv = _json(api, "GET", f"/targets/{tid}/advice")
    assert st == 200, adv
    inv = adv.get("invocation")
    assert inv, "advice should carry the invocation read off the binary"
    assert {f["flag"] for f in inv["flags"]} >= {"-c", "-d"}
    assert "@@" in inv["proposed_argv"], inv["proposed_argv"]

    st, got = _json(api, "POST", f"/targets/{tid}/invocation", {"timeout": 30})
    assert st == 200, got
    v = got["verified"]
    assert v["bare_rejected"], "bare svc prints its usage and exits 2"
    assert v["accepted"], v["why"]


def test_capabilities_says_what_can_run_and_why_not(api, tmp_path):
    """Separate from /advice on purpose: advice says what to do NEXT, this says what is
    POSSIBLE. The workbench needs both -- it highlights the recommendation and disables the
    impossible with its reason, instead of rendering the same twenty-two controls for an ELF,
    a PE, a jar and a firmware image."""
    import shutil as _sh
    import subprocess
    if not all(_sh.which(t) for t in ("javac", "jar")):
        pytest.skip("no JDK")
    src = tmp_path / "A.java"
    src.write_text("public class A { public static void main(String[] a){} }")
    cl = tmp_path / "c"
    cl.mkdir()
    if subprocess.run(["javac", "-d", str(cl), str(src)], capture_output=True).returncode:
        pytest.skip("javac failed")
    mf = tmp_path / "m"
    mf.write_text("Main-Class: A\n")
    jar = tmp_path / "a.jar"
    subprocess.run(["jar", "cfm", str(jar), str(mf), "-C", str(cl), "."], check=True,
                   capture_output=True)

    st, case = _json(api, "POST", "/cases", {"name": "caps"})
    st, t = _upload(api, case["id"], "a.jar", jar.read_bytes())
    assert st in (200, 201), t
    # the server enqueues triage on upload; wait for it the way the GUI does
    for _ in range(300):
        st, cur = _json(api, "GET", f"/targets/{t['id']}")
        if (cur or {}).get("file_type"):
            break
        time.sleep(0.1)
    assert (cur or {}).get("file_type") == "jar", cur

    st, caps = _json(api, "GET", f"/targets/{t['id']}/capabilities")
    assert st == 200, caps
    assert caps["file_type"] == "jar"
    assert {g["key"] for g in caps["groups"]} == {"feed", "find", "prove"}
    flat = {s["stage"]: s for g in caps["stages"].values() for s in g}
    assert flat["disassemble"]["available"] is False
    assert "constant pool" in flat["disassemble"]["why"]
    assert flat["poc_primitive"]["available"] is False
    assert "instruction pointer" in flat["poc_primitive"]["why"]
    # what works is not disabled, and the reason field is empty for it
    assert flat["fuzz"]["available"] is True and flat["fuzz"]["why"] is None
    assert flat["build_poc"]["available"] is True
    assert "disassemble" in caps["unavailable"]

    st, missing = _json(api, "GET", "/targets/doesnotexist/capabilities")
    assert st == 404


def test_a_missing_case_is_404_not_an_empty_list(api):
    """A case that does not exist is not a case with no targets. Returning [] with 200 made a
    typo'd or deleted id indistinguishable from an empty case, and a caller polling for its
    targets would wait forever on nothing."""
    st, body = _json(api, "GET", "/cases/deadbeefdeadbeef/targets")
    assert st == 404, body
    st, case = _json(api, "POST", "/cases", {"name": "real"})
    st, body = _json(api, "GET", f"/cases/{case['id']}/targets")
    assert st == 200 and body == []


def test_an_unknown_report_format_is_refused_rather_than_silently_html(api):
    """`?format=md` returned 200 and a web page, so a caller asking for something this build
    does not produce got a plausible-looking answer in the wrong format."""
    st, case = _json(api, "POST", "/cases", {"name": "fmt"})
    cid = case["id"]
    st, body = _json(api, "GET", f"/cases/{cid}/report?format=md")
    assert st == 400, body
    assert "unknown report format" in body["error"]
    assert set(body["formats"]) == {"html", "json", "pdf", "sarif"}
    # the real ones still work
    code, _ = _req(api, "GET", f"/cases/{cid}/report?format=html")
    assert code == 200


def test_a_crash_row_carries_how_it_was_fed_and_where_it_faulted():
    """Both are recorded and neither was projected. argv is HOW the input was delivered --
    now that a target may need `-c @@` to run at all, "which invocation produced this" is not
    a detail -- and fault_pc is WHERE it faulted, which is what the dedup key is built from,
    so two rows that look identical were distinguishable only by a field the API withheld."""
    from lykos.api.server import _dynresult

    class _D:
        id, crashed, timed_out = "d1", True, False
        signal_name, exit_code, isolation = "SIGSEGV", None, "bwrap"
        input_mode, input_sha, duration_ms = "file", "ab" * 32, 12
        note, created_at = None, 1
        argv = ["-c", "@@"]
        fault_pc = 0x1234
    got = _dynresult(_D())
    assert got["argv"] == ["-c", "@@"]
    assert got["fault_pc"] == "0x1234"

    class _Old(_D):
        argv, fault_pc = None, None
    old = _dynresult(_Old())
    assert old["argv"] == [] and old["fault_pc"] is None


# ---- security / framing regressions ----
def test_get_reads_reject_a_nonlocal_host(api_http):
    """DNS-rebinding: a data-READ GET whose Host is an attacker name (resolved to 127.0.0.1)
    must be refused, exactly as the write side and the WS upgrades already are."""
    st, _ = _tcp(api_http, "GET", "/cases", headers={"Host": "evil.example.com"})
    assert st == 403


def test_get_reads_allow_a_loopback_host(api_http):
    st, _ = _tcp(api_http, "GET", "/cases", headers={"Host": "127.0.0.1"})
    assert st == 200


def _raw_request(port, raw: bytes) -> bytes:
    s = socket.create_connection(("127.0.0.1", port))
    try:
        s.sendall(raw)
        s.shutdown(socket.SHUT_WR)   # signal EOF so a short body is seen as truncated
        s.settimeout(3.0)
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
        return resp
    finally:
        s.close()


def test_a_truncated_body_is_rejected_not_read_as_complete(api_http):
    """Content-Length promises 100 bytes; only 12 arrive. The server must 400, never treat the
    partial body as a complete (but shorter) request."""
    raw = (b"POST /cases HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n"
           b'{"name":"x"}')
    resp = _raw_request(api_http, raw)
    status_line = resp.split(b"\r\n", 1)[0]
    assert b" 400 " in status_line, resp[:120]
    assert b"truncated" in resp.lower()


def test_a_refused_cross_host_request_closes_the_connection(api_http):
    """An early-return error path with an unread body must tear the keep-alive connection down
    (Connection: close) so the leftover body can't desync the next request on the socket."""
    raw = (b"POST /cases HTTP/1.1\r\nHost: evil.example.com\r\n"
           b"Content-Type: application/json\r\nContent-Length: 9\r\n\r\n"
           b'{"a":"b"}')
    resp = _raw_request(api_http, raw)
    assert b" 403 " in resp.split(b"\r\n", 1)[0], resp[:120]
    assert b"connection: close" in resp.lower()


class _FakeSock:
    """Feeds queued bytes to ws.read_frame one recv() at a time."""
    def __init__(self, data: bytes):
        self._d = data

    def recv(self, n: int) -> bytes:
        chunk, self._d = self._d[:n], self._d[n:]
        return chunk


def _client_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    b0 = (0x80 if fin else 0) | opcode
    n = len(payload)
    if n < 126:
        hdr = bytes([b0, 0x80 | n])
    elif n < 65536:
        hdr = bytes([b0, 0x80 | 126]) + struct.pack("!H", n)
    else:
        hdr = bytes([b0, 0x80 | 127]) + struct.pack("!Q", n)
    return hdr + b"\x00\x00\x00\x00" + payload   # zero mask: XOR is identity


def test_read_frame_reassembles_fragmented_messages():
    from lykos.api import ws
    data = _client_frame(0x1, b"hel", fin=False) + _client_frame(0x0, b"lo", fin=True)
    op, payload = ws.read_frame(_FakeSock(data))
    assert op == 0x1 and payload == b"hello"


def test_read_frame_returns_control_frames_inline():
    from lykos.api import ws
    op, payload = ws.read_frame(_FakeSock(_client_frame(0x9, b"ping!")))   # ping
    assert op == 0x9 and payload == b"ping!"
    op, _ = ws.read_frame(_FakeSock(_client_frame(0x8, b"")))             # close
    assert op == 0x8


def test_artifact_bundle_endpoint(api_http, tmp_path):
    """GET /artifacts/{sha}/bundle opens a PoC bundle and returns its inner files -- meta, the
    reproduce script (text), and a hexdump of the payload -- so the UI can inspect the exploit
    instead of only downloading the tarball."""
    from lykos.analyze.poc import bundle
    from lykos.casestore import CaseStore
    data = bundle.build(
        b"\x7fELF" + b"\x00" * 200, bytes(range(64)),
        {"level": "L3", "exploit": "magic-overwrite", "arch": "x86-64", "target_sha256": "z"},
        b"", "stdin", [], None,
        primitive={"type": "magic-overwrite", "confirmed": True},
        extra_files={"exploit.py": b"#!/usr/bin/env python3\nprint('repro')\n"},
        run_cmd="python3 ./exploit.py ./target.bin")
    store = CaseStore.open(tmp_path / "cs")
    try:
        sha, _rel, _sz = store.content.put_bytes(data)
    finally:
        store.close()
    st, body = _tcp(api_http, "GET", f"/artifacts/{sha}/bundle")
    assert st == 200, (st, body[:200])
    d = json.loads(body)
    assert d["level"] == "L3" and d["exploit"] == "magic-overwrite"
    names = {f["name"].split("/")[-1]: f for f in d["files"]}
    assert "exploit.py" in names and names["exploit.py"]["kind"] == "text"
    assert "repro" in names["exploit.py"]["text"]
    assert names["input.bin"]["kind"] == "payload" and "00000000" in names["input.bin"]["hexdump"]
    assert names["target.bin"]["kind"] == "binary"          # never inlines the raw binary


def test_artifact_bundle_endpoint_rejects_non_bundle(api_http, tmp_path):
    from lykos.casestore import CaseStore
    store = CaseStore.open(tmp_path / "cs")
    try:
        sha, _r, _s = store.content.put_bytes(b"not a tar.gz at all")
    finally:
        store.close()
    st, _body = _tcp(api_http, "GET", f"/artifacts/{sha}/bundle")
    assert st == 415
