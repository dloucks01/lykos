"""Phase 7 — report engine (model + HTML + PDF + SARIF + case-JSON)."""
from __future__ import annotations

import json

from lykos.db.dao import DynResultDAO, FindingDAO, PocDAO
from lykos.hashing import hash_bytes
from lykos.report import build_report, to_case_json, to_html, to_pdf, to_sarif
from lykos.report.casejson import to_case_json_bytes


def _seed(store, case):
    """A target with two findings; one poc-backed with a stored bundle + crash."""
    content = b"\x7fELFsample-binary"
    sha = hash_bytes(content)
    t = store.targets.upsert(case.id, filename="vuln", sha256=sha, size=len(content),
                             arch="x86_64", bits=64, endianness="little", stripped=False,
                             file_type="ELF", linking="dynamic",
                             mitigations={"nx": True, "canary": False, "pie": False})
    fd = FindingDAO(store.conn)
    # high-severity poc-backed finding
    fd.upsert(t.id, case.id, {
        "dedup_key": "k1", "cwe": "CWE-121", "title": "Stack overflow in main",
        "severity": "high", "state": "poc-backed", "confidence": 0.95,
        "function_addr": "0x401136", "site_addr": "0x401160", "detector": "dynamic",
        "evidence": [{"channel": "dynamic", "detail": "SIGSEGV reproduced"},
                     {"channel": "primitive", "detail": "IP control at offset 72"}],
    })
    # a low candidate
    fd.upsert(t.id, case.id, {
        "dedup_key": "k2", "cwe": "CWE-134", "title": "printf format",
        "severity": "low", "state": "candidate", "confidence": 0.2,
        "detector": "rule", "evidence": [{"channel": "static", "detail": "printf sink"}],
    })
    f1 = next(f for f in fd.list_by_target(t.id) if f.dedup_key == "k1")

    inp = hash_bytes(b"AAAAAAAA")
    DynResultDAO(store.conn).insert(t.id, case.id, input_sha=inp, input_mode="arg",
                                    signal=11, signal_name="SIGSEGV", crashed=True,
                                    isolation="bwrap+netns")
    bundle = store.put_artifact(case.id, "poc-bundle", data=b"POCBUNDLEDATA")
    PocDAO(store.conn).insert(t.id, case.id, finding_id=f1.id, level="L2", verified=True,
                              signal_name="SIGSEGV", input_sha=inp,
                              bundle_sha=bundle.sha256)
    # a run carrying tool/version for the reproducibility panel
    store.runs.create(case.id, "concolic", target_id=t.id, status="done",
                      tool="angr", tool_version="9.3.4")
    return t, f1


def test_model_shape_and_summary(store, case):
    _seed(store, case)
    r = build_report(store, case.id)
    assert r["schema"] == "lykos.report/1"
    assert r["case"]["name"] == "demo"
    assert r["summary"]["findings"] == 2
    assert r["summary"]["targets"] == 1
    assert r["summary"]["poc_backed"] == 1
    assert r["summary"]["confirmed"] == 1
    assert r["summary"]["by_severity"].get("high") == 1
    assert {"tool": "angr", "version": "9.3.4"} in r["engines"]
    f = r["targets"][0]["findings"][0]
    assert f["cwe_name"].startswith("Stack-based")
    assert f["pocs"][0]["level"] == "L2"
    assert f["crashes"][0]["signal"] == "SIGSEGV"


def test_filters(store, case):
    _seed(store, case)
    high = build_report(store, case.id, min_severity="high")
    assert high["summary"]["findings"] == 1
    conf = build_report(store, case.id, states=["poc-backed"])
    assert conf["summary"]["findings"] == 1
    # explicit selection
    r_all = build_report(store, case.id)
    fid = r_all["targets"][0]["findings"][0]["id"]
    sel = build_report(store, case.id, finding_ids=[fid])
    assert sel["summary"]["findings"] == 1


def test_embed_pocs(store, case):
    _seed(store, case)
    r = build_report(store, case.id, embed_pocs=True)
    poc = r["targets"][0]["findings"][0]["pocs"][0]
    assert poc["bundle_b64"]
    import base64
    assert base64.b64decode(poc["bundle_b64"]) == b"POCBUNDLEDATA"


def test_html_self_contained(store, case):
    _seed(store, case)
    r = build_report(store, case.id, embed_pocs=True)
    html = to_html(r)
    assert html.startswith("<!doctype html>")
    assert "Stack overflow in main" in html
    assert "CWE-121" in html
    assert "data:application/gzip;base64," in html   # embedded PoC download
    assert "http://" not in html.split("</style>")[0].replace("http://www.w3", "")  # no ext assets in css
    assert "SIGSEGV reproduced" in html


def test_sarif_valid(store, case):
    _seed(store, case)
    r = build_report(store, case.id)
    s = to_sarif(r)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "lykos"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert "CWE-121" in rule_ids
    res = [x for x in run["results"] if x["ruleId"] == "CWE-121"][0]
    assert res["level"] == "error"
    assert res["properties"]["state"] == "poc-backed"
    assert run["artifacts"][0]["hashes"]["sha-256"]
    # round-trips as JSON
    json.dumps(s)


def test_pdf_is_valid(store, case):
    _seed(store, case)
    r = build_report(store, case.id)
    pdf = to_pdf(r)
    assert pdf[:5] == b"%PDF-"
    assert b"%%EOF" in pdf[-8:]
    assert b"/Type /Catalog" in pdf
    assert b"/Type /Page" in pdf
    assert b"xref" in pdf
    # trailer Size matches object count; startxref points inside the file
    startxref = int(pdf.split(b"startxref")[1].split(b"%%EOF")[0].strip())
    assert 0 < startxref < len(pdf)
    assert pdf[startxref:startxref + 4] == b"xref"


def test_case_json_export(store, case):
    _seed(store, case)
    r = build_report(store, case.id, embed_pocs=True)
    cj = to_case_json(r)
    assert cj["schema"] == "lykos.case-export/1"
    b = to_case_json_bytes(r)
    back = json.loads(b)
    assert back["case"]["name"] == "demo"
    assert back["targets"][0]["findings"][0]["pocs"][0]["bundle_b64"]


def test_empty_case(store, case):
    r = build_report(store, case.id)
    assert r["summary"]["findings"] == 0
    assert to_html(r).startswith("<!doctype html>")
    assert to_pdf(r)[:5] == b"%PDF-"
    assert to_sarif(r)["runs"][0]["results"] == []
