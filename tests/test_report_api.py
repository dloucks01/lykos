"""Phase 7 — report + export/import HTTP endpoints."""
from __future__ import annotations

import http.client
import json

import pytest
from lykos.api.server import serve, shutdown
from lykos.casestore import CaseStore
from lykos.db.dao import FindingDAO, PocDAO
from lykos.hashing import hash_bytes


@pytest.fixture
def srv(tmp_path):
    cs = tmp_path / "cs"
    servers, pool = serve(cs, http=("127.0.0.1", 0), workers=1, block=False)
    port = servers[0].server_address[1]
    try:
        yield port, cs
    finally:
        shutdown(servers, pool)


def _get(port, url):
    c = http.client.HTTPConnection("127.0.0.1", port)
    try:
        c.request("GET", url)
        r = c.getresponse()
        return r.status, r.getheader("Content-Type"), r.read()
    finally:
        c.close()


def _post(port, url, body, ctype="application/octet-stream"):
    c = http.client.HTTPConnection("127.0.0.1", port)
    try:
        c.request("POST", url, body=body, headers={"Content-Type": ctype})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def _seed(cs_dir):
    s = CaseStore(cs_dir)
    try:
        c = s.cases.create("Acme audit", notes="scope")
        content = b"\x7fELFvuln"
        sha = hash_bytes(content)
        t = s.targets.upsert(c.id, filename="vuln", sha256=sha, size=len(content),
                             arch="x86_64", bits=64, mitigations={"nx": True})
        fd = FindingDAO(s.conn)
        fd.upsert(t.id, c.id, {"dedup_key": "k1", "cwe": "CWE-121",
                               "title": "Stack overflow", "severity": "high",
                               "state": "poc-backed", "confidence": 0.9,
                               "evidence": [{"channel": "dynamic", "detail": "SIGSEGV"}]})
        f = fd.list_by_target(t.id)[0]
        b = s.put_artifact(c.id, "poc-bundle", data=b"BUNDLE")
        PocDAO(s.conn).insert(t.id, c.id, finding_id=f.id, level="L2", verified=True,
                              bundle_sha=b.sha256)
        s.runs.create(c.id, "concolic", target_id=t.id, status="done",
                      tool="angr", tool_version="9.3.4")
        return c.id
    finally:
        s.close()


def test_report_html(srv):
    port, cs = srv
    cid = _seed(cs)
    st, ctype, body = _get(port, f"/cases/{cid}/report?format=html")
    assert st == 200 and "text/html" in ctype
    assert b"Stack overflow" in body and b"CWE-121" in body
    assert b"data:application/gzip;base64," in body  # embedded PoC


def test_report_pdf(srv):
    port, cs = srv
    cid = _seed(cs)
    st, ctype, body = _get(port, f"/cases/{cid}/report?format=pdf")
    assert st == 200 and ctype == "application/pdf"
    assert body[:5] == b"%PDF-" and b"%%EOF" in body[-8:]


def test_report_sarif(srv):
    port, cs = srv
    cid = _seed(cs)
    st, ctype, body = _get(port, f"/cases/{cid}/report?format=sarif")
    assert st == 200
    doc = json.loads(body)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-121"


def test_report_filter_and_json(srv):
    port, cs = srv
    cid = _seed(cs)
    st, _, body = _get(port, f"/cases/{cid}/report?format=json&states=candidate")
    doc = json.loads(body)
    assert doc["schema"] == "lykos.case-export/1"
    assert doc["summary"]["findings"] == 0     # only poc-backed exists; filtered out


def test_report_unknown_case_404(srv):
    port, _ = srv
    st, _, _ = _get(port, "/cases/nope/report?format=html")
    assert st == 404


def test_export_then_import(srv):
    port, cs = srv
    cid = _seed(cs)
    st, ctype, archive = _get(port, f"/cases/{cid}/export")
    assert st == 200 and ctype == "application/gzip"
    assert archive[:2] == b"\x1f\x8b"          # gzip magic
    # re-import into the same store is idempotent and returns the case id
    st2, body2 = _post(port, "/import", archive)
    assert st2 == 201
    assert json.loads(body2)["cases"] == [cid]


def test_a_bundle_is_embedded_once_and_within_a_budget(tmp_path):
    """A PoC bundle carries the target binary so it reproduces standalone, which is the point
    of it -- 660 KB of a 694 KB jhead report was one bundle. The per-bundle cap says nothing
    about how many there are, and several findings can share one PoC, so ten PoCs on that
    target would have produced a 7 MB page with the same binary in it repeatedly."""
    from lykos.report import model

    class _Store:
        class content:
            @staticmethod
            def exists(_sha):
                return True

            @staticmethod
            def get_bytes(_sha):
                return b"\x00" * (1024 * 1024)       # 1 MiB -> ~1.37 MiB of base64
    budget = {"left": model._MAX_EMBED_TOTAL}
    embedded = set()
    got = []
    for i in range(6):
        sha = "%064x" % i
        b64 = model._embed(_Store(), sha, budget)
        if b64:
            embedded.add(sha)
            budget["left"] -= len(b64)
        got.append(bool(b64))
    assert got[0] is True, "the first bundle is always embedded"
    assert not all(got), "the budget has to stop somewhere"
    assert budget["left"] >= 0
    total = model._MAX_EMBED_TOTAL - budget["left"]
    assert total <= model._MAX_EMBED_TOTAL

    # one bundle larger than the per-bundle cap is refused regardless of budget
    class _Big(_Store):
        class content:
            @staticmethod
            def exists(_sha):
                return True

            @staticmethod
            def get_bytes(_sha):
                return b"\x00" * (model._MAX_EMBED_BUNDLE + 1)
    assert model._embed(_Big(), "f" * 64, {"left": 1 << 40}) is None


def test_a_bundle_that_is_not_embedded_says_where_to_get_it():
    """With embedding off, or the budget spent, the report showed a bare hash and nothing to
    do about it. Air-gapped does not mean unhelpful: the bundle is still on the analysis
    server, and the report can say where."""
    from lykos.report.html import to_html
    base = {"case": {"name": "c", "id": "1"}, "generated_at": "now", "summary": {},
            "targets": [{"filename": "t", "sha256": "a" * 64, "findings": [
                {"id": "f1", "cwe": "CWE-125", "title": "oob", "severity": "high",
                 "state": "poc-backed", "confidence": 0.9, "detector": "d", "evidence": [],
                 "crashes": [], "pocs": [{"level": "L1", "verified": True, "signal": "SIGSEGV",
                                          "bundle_sha": "b" * 64,
                                          "bundle_href": "/artifacts/" + "b" * 64}]}]}]}
    html = to_html(base)
    assert "not embedded" in html and "/artifacts/" + "b" * 64 in html
    # and a bundle shared by a second finding is named, not silently dropped
    base["targets"][0]["findings"][0]["pocs"][0] = {
        "level": "L1", "verified": True, "signal": "SIGSEGV",
        "bundle_sha": "b" * 64, "bundle_same_as": "b" * 64}
    assert "same bundle as above" in to_html(base)


class _T:
    def __init__(self, **kw):
        for k in ("id", "case_id", "filename", "sha256", "md5", "sha1", "size", "file_type",
                  "arch", "bits", "endianness", "linking", "stripped", "mitigations",
                  "entropy", "ingested_at"):
            setattr(self, k, kw.get(k))


def test_the_report_names_the_runtime_and_its_ceiling():
    """A 47 KB report over a case holding a jar mentioned "Java" zero times and printed
    `Arch: jvm/64 big` -- placeholder fields from triage rendered as though they described a
    processor. A reader could not tell a finding came from a managed runtime, nor why no L2/L3
    appears for it, so "no exploit was produced" read as a gap rather than as the runtime's own
    guarantee."""
    from lykos.report.model import _runtime
    jar = _runtime(_T(file_type="jar", arch="jvm", bits=64, endianness="big"))
    assert jar["substrate"] == "jvm"
    assert jar["describes_cpu"] is False, "a jar has no processor to describe"
    assert jar["ceiling"] == "L1"
    assert "instruction pointer" in jar["ceiling_why"]
    assert "not a gap in the" in jar["ceiling_why"]
    assert "disassemble" in jar["unavailable"]

    native = _runtime(_T(file_type="elf", arch="x86-64", bits=64, linking="dynamic"))
    assert native["substrate"] == "native" and native["ceiling"] == "L3"
    assert native["describes_cpu"] is True
    assert not native["ceiling_why"], "a native target has no ceiling worth stating"


def test_the_html_drops_the_meaningless_cpu_row_for_a_jar():
    from lykos.report.html import _target_html
    from lykos.report.model import _runtime
    t = {"filename": "app.jar", "sha256": "a" * 64, "file_type": "jar", "arch": "jvm",
         "bits": 64, "endianness": "big", "findings": [],
         "runtime": _runtime(_T(file_type="jar", arch="jvm", bits=64, endianness="big"))}
    h = _target_html(t)
    assert "jvm/64 big" not in h
    assert "Java (JVM)" in h and "Analysis ceiling" in h

    n = {"filename": "jhead", "sha256": "b" * 64, "file_type": "elf", "arch": "x86-64",
         "bits": 64, "endianness": "little", "linking": "static", "findings": [],
         "runtime": _runtime(_T(file_type="elf", arch="x86-64", bits=64, linking="static"))}
    hn = _target_html(n)
    assert "x86-64/64" in hn and "Analysis ceiling" not in hn
