"""Operator curation of findings (doc 47 P3) + the API hardening that came with the audit.

Curation is the operator's verdict (false-positive / true-positive / needs-review + a note),
persisted per case as append-only `finding.curation` events. The precision invariant pinned here:
curating a finding NEVER changes what the tool says about it (state / severity / L-level); the
verdict rides beside it in a separate `curation` object. Driven over the real unix socket, like
the UI.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
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
        return r.status, r.read()
    finally:
        c.close()


def _json(sock_path, method, url, obj=None, headers=None, raw=None):
    body = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else None)
    hdrs = {"Content-Type": "application/json"} if body is not None else {}
    hdrs.update(headers or {})
    st, data = _req(sock_path, method, url, body, hdrs)
    try:
        return st, (json.loads(data) if data else None)
    except ValueError:
        return st, data


def _wait_run(sock_path, run_id, timeout=60.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, run = _json(sock_path, "GET", f"/runs/{run_id}")
        if st == 200 and run["status"] in ("done", "error", "cancelled"):
            return run
        time.sleep(0.05)
    raise TimeoutError("run did not finish")


@pytest.fixture
def curated(api, sample_elf, tmp_path):
    """A case with one triaged ELF and two seeded findings (one poc-backed, one candidate)."""
    from lykos.casestore import CaseStore
    from lykos.db.dao import FindingDAO
    _st, case = _json(api, "POST", "/cases", {"name": "curation"})
    cid = case["id"]
    st, up = _req(api, "POST", f"/cases/{cid}/targets", sample_elf.read_bytes(),
                  {"Content-Type": "application/octet-stream", "X-Filename": "sample"})
    assert st == 201, up
    up = json.loads(up)
    tid = up["id"]
    if up.get("run_id"):
        _wait_run(api, up["run_id"])
    s = CaseStore.open(tmp_path / "cs")
    try:
        fd = FindingDAO(s.conn)
        fd.upsert(tid, cid, {"dedup_key": "k-demo", "cwe": "CWE-121", "title": "stack overflow",
                             "severity": "critical", "state": "poc-backed", "detector": "poc",
                             "evidence": [{"channel": "dynamic", "detail": "SIGSEGV"}]})
        fd.upsert(tid, cid, {"dedup_key": "k-cand", "cwe": "CWE-134", "title": "fmt string",
                             "severity": "medium", "state": "candidate", "detector": "static"})
        ids = {f.dedup_key: f.id for f in fd.list_by_target(tid)}
    finally:
        s.close()
    return api, cid, tid, ids


# ---- the feature ---------------------------------------------------------------------------

def test_curation_round_trips_and_never_rewrites_the_tools_verdict(curated):
    api, cid, tid, ids = curated
    fid = ids["k-demo"]
    _st, before = _json(api, "GET", f"/findings/{fid}")
    st, rec = _json(api, "POST", f"/findings/{fid}/curation",
                    {"status": "false_positive", "note": "  benign: test harness only  "})
    assert st == 200, rec
    assert rec["status"] == "false_positive" and rec["note"] == "benign: test harness only"

    st, cmap = _json(api, "GET", f"/cases/{cid}/curation")
    assert st == 200 and cmap["curation"][fid]["status"] == "false_positive"
    assert set(cmap["statuses"]) == {"false_positive", "true_positive", "needs_review"}

    # every findings reader carries the curation BESIDE the tool's fields, which are unchanged
    _st, case_fs = _json(api, "GET", f"/cases/{cid}/findings")
    _st, tgt_fs = _json(api, "GET", f"/targets/{tid}/findings")
    _st, one = _json(api, "GET", f"/findings/{fid}")
    for f in (next(x for x in case_fs if x["id"] == fid),
              next(x for x in tgt_fs if x["id"] == fid), one):
        assert f["curation"]["status"] == "false_positive"
        assert f["state"] == before["state"] == "poc-backed"
        assert f["severity"] == before["severity"]
    other = next(x for x in case_fs if x["id"] == ids["k-cand"])
    assert other["curation"] is None


def test_curation_keeps_an_audit_trail_and_can_be_cleared(curated):
    api, cid, _tid, ids = curated
    fid = ids["k-cand"]
    _json(api, "POST", f"/findings/{fid}/curation", {"status": "needs_review"})
    _json(api, "POST", f"/findings/{fid}/curation", {"status": "true_positive", "note": "real"})
    st, h = _json(api, "GET", f"/findings/{fid}/curation")
    assert st == 200
    assert [e["status"] for e in h["history"]] == ["needs_review", "true_positive"]
    assert h["current"]["status"] == "true_positive" and h["current"]["note"] == "real"

    st, rec = _json(api, "POST", f"/findings/{fid}/curation", {"status": None, "note": ""})
    assert st == 200 and rec["cleared"] is True
    _st, cmap = _json(api, "GET", f"/cases/{cid}/curation")
    assert fid not in cmap["curation"]
    _st, one = _json(api, "GET", f"/findings/{fid}")
    assert one["curation"] is None
    _st, h = _json(api, "GET", f"/findings/{fid}/curation")
    assert len(h["history"]) == 3                      # the clear is itself on the record


def test_a_note_alone_is_a_curation(curated):
    api, cid, _tid, ids = curated
    fid = ids["k-cand"]
    st, _ = _json(api, "POST", f"/findings/{fid}/curation", {"note": "check the length field"})
    assert st == 200
    _st, cmap = _json(api, "GET", f"/cases/{cid}/curation")
    assert cmap["curation"][fid]["status"] is None
    assert cmap["curation"][fid]["note"] == "check the length field"


@pytest.mark.parametrize("body", [
    {"status": "confirmed"},                  # the TOOL's state name is not an operator verdict
    {"status": "bogus"},
    {"status": 3},
    {"note": 5},
    {"status": "needs_review", "note": "x" * 4001},
])
def test_bad_curation_is_a_400_and_records_nothing(curated, body):
    api, cid, _tid, ids = curated
    st, err = _json(api, "POST", f"/findings/{ids['k-demo']}/curation", body)
    assert st == 400, err
    _st, cmap = _json(api, "GET", f"/cases/{cid}/curation")
    assert cmap["curation"] == {}


def test_curation_of_unknowns_is_a_404(api):
    assert _json(api, "POST", "/findings/nope/curation", {"status": "needs_review"})[0] == 404
    assert _json(api, "GET", "/findings/nope/curation")[0] == 404
    assert _json(api, "GET", "/cases/nope/curation")[0] == 404


def test_curation_is_behind_the_csrf_and_rebinding_guard(curated):
    api, _cid, _tid, ids = curated
    fid = ids["k-demo"]
    st, _ = _json(api, "POST", f"/findings/{fid}/curation", {"status": "false_positive"},
                  headers={"Origin": "http://evil.example"})
    assert st == 403
    st, _ = _json(api, "POST", f"/findings/{fid}/curation", {"status": "false_positive"},
                  headers={"Host": "evil.example"})
    assert st == 403
    st, _ = _json(api, "GET", f"/findings/{fid}/curation", headers={"Host": "evil.example"})
    assert st == 403


def test_curation_survives_case_export_and_import(curated, tmp_path):
    api, cid, _tid, ids = curated
    fid = ids["k-demo"]
    _json(api, "POST", f"/findings/{fid}/curation", {"status": "false_positive", "note": "fp"})
    st, blob = _req(api, "GET", f"/cases/{cid}/export")
    assert st == 200
    sock2 = str(tmp_path / "s2.sock")
    servers, pool = serve(tmp_path / "cs2", sock2, workers=1, block=False)
    try:
        for _ in range(200):
            if os.path.exists(sock2):
                break
            time.sleep(0.02)
        st, out = _req(sock2, "POST", "/import", blob,
                       {"Content-Type": "application/gzip"})
        assert st == 201, out
        new_cid = json.loads(out)["cases"][0]
        st, cmap = _json(sock2, "GET", f"/cases/{new_cid}/curation")
        assert st == 200
        assert [c["status"] for c in cmap["curation"].values()] == ["false_positive"]
    finally:
        shutdown(servers, pool)


def test_the_incremental_cache_sees_a_curation_appended_after_the_first_read(curated):
    api, cid, _tid, ids = curated
    assert _json(api, "GET", f"/cases/{cid}/curation")[1]["curation"] == {}
    for i, k in enumerate(("k-demo", "k-cand")):
        _json(api, "POST", f"/findings/{ids[k]}/curation", {"status": "needs_review"})
        assert len(_json(api, "GET", f"/cases/{cid}/curation")[1]["curation"]) == i + 1


# ---- the audit fixes -----------------------------------------------------------------------

@pytest.mark.parametrize("raw", [b"[]", b'"x"', b"3", b"null"])
def test_a_non_object_json_body_is_a_400_not_a_500(api, raw):
    for url in ("/cases", "/runs", "/format/analyze"):
        st, _ = _json(api, "POST", url, raw=raw)
        assert st == 400, (url, raw, st)


def test_case_create_refuses_non_string_fields(api):
    assert _json(api, "POST", "/cases", {"name": 5})[0] == 400
    assert _json(api, "POST", "/cases", {"name": "ok", "notes": ["x"]})[0] == 400
    assert _json(api, "POST", "/cases", {"name": ""})[0] == 201      # blank -> default name


def test_a_case_stage_without_a_case_is_refused_at_the_edge(api):
    st, err = _json(api, "POST", "/runs", {"stage": "link_case"})
    assert st == 400 and "case_id" in err["error"]
    assert _json(api, "POST", "/runs", {"stage": "link_case", "case_id": "nope"})[0] == 404
    assert _json(api, "POST", "/runs", {"stage": ["x"]})[0] == 400
    assert _json(api, "POST", "/runs", {"stage": "disassemble", "target_id": "t",
                                        "params": [1]})[0] == 400


def test_autopilot_refuses_malformed_or_foreign_target_ids(curated):
    api, cid, tid, _ids = curated
    st, err = _json(api, "POST", f"/cases/{cid}/autopilot", {"target_ids": tid})
    assert st == 400 and "list" in err["error"]
    st, err = _json(api, "POST", f"/cases/{cid}/autopilot", {"target_ids": [tid, "not-mine"]})
    assert st == 400 and err["unknown"] == ["not-mine"]
    # nothing was started by either refusal
    assert _json(api, "GET", f"/cases/{cid}/autopilot")[1]["state"] == "none"


def test_invocation_refuses_a_string_argv(curated):
    api, _cid, tid, _ids = curated
    st, err = _json(api, "POST", f"/targets/{tid}/invocation", {"argv": "-c @@"})
    assert st == 400 and "argv" in err["error"]


def test_attempt_log_routes_are_scoped(curated):
    api, cid, tid, _ids = curated
    assert _json(api, "GET", "/cases/nope/attempt-logs")[0] == 404
    assert _json(api, "GET", f"/cases/{cid}/attempt-logs") == (200, [])
    # the TARGET binary is an artifact, but not an attempt log: refused without being parsed
    _st, t = _json(api, "GET", f"/targets/{tid}")
    st, err = _json(api, "GET", f"/artifacts/{t['sha256']}/attempts")
    assert st == 415, err
    # and a bundle read of a non-tarball is a 415 too (opened from disk, not slurped)
    assert _json(api, "GET", f"/artifacts/{t['sha256']}/bundle")[0] == 415
    # the attempts route sits behind the same Host guard as every read
    assert _json(api, "GET", f"/artifacts/{t['sha256']}/attempts",
                 headers={"Host": "evil.example"})[0] == 403


def test_events_tail_returns_the_newest_events(curated):
    api, cid, _tid, ids = curated
    for _ in range(3):
        _json(api, "POST", f"/findings/{ids['k-demo']}/curation", {"status": "needs_review"})
    _st, all_ev = _json(api, "GET", f"/cases/{cid}/events?after=0")
    st, tail = _json(api, "GET", f"/cases/{cid}/events?tail=2")
    assert st == 200 and len(tail) == 2
    assert [e["id"] for e in tail] == [e["id"] for e in all_ev[-2:]]
    assert _json(api, "GET", f"/cases/{cid}/events?tail=abc")[0] == 200   # malformed -> default


def test_console_ignores_non_object_messages_and_pong_is_well_formed():
    from lykos.api import console, ws
    assert console._parse(b"[]") is None and console._parse(b"3") is None
    assert console._parse(b'{"t":"eof"}') == {"t": "eof"}
    f = ws.pong_frame(b"x" * 300)
    assert f[0] == 0x8A and f[1] == 125 and len(f) == 127
