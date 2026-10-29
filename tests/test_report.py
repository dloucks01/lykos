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
    # The engine entry gained status counts (an engine that ABORTED is not one that ran), so
    # check the reproducibility fields by subset rather than by exact dict identity.
    angr = next(e for e in r["engines"] if e["tool"] == "angr")
    assert angr["version"] == "9.3.4"
    assert angr["ran"] is True and angr["completed"] >= 1
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
    # no ext assets in css
    assert "http://" not in html.split("</style>")[0].replace("http://www.w3", "")
    assert "SIGSEGV reproduced" in html
    # methodology section + the confidence/level legends (defines the states the findings use)
    assert "Methodology &amp; evidence standard" in html
    assert "confirmation ladder" in html and "negative control" in html
    assert "Confidence states" in html and "Impact levels" in html


def test_source_snippet_helpers():
    from lykos.report.model import _finding_src_loc, _match_src_member, _snippet
    assert _finding_src_loc({"evidence": [{"channel": "source", "detail": "a/b.c:42: x"}]}) == ("a/b.c", 42)
    assert _finding_src_loc({"evidence": [{"detail": "no source location here"}]}) is None
    snip = _snippet(["l1", "l2", "l3", "l4", "l5"], 3, "x.c", ctx=1)
    assert snip["line"] == 3 and [r["n"] for r in snip["rows"]] == [2, 3, 4]
    assert [r["hit"] for r in snip["rows"]] == [False, True, False]
    # the tree is archived under a top dir -> suffix match on the relative path
    assert _match_src_member(["freerdp-3.20.0/winpr/wlog.c", "x"], "winpr/wlog.c") \
        == "freerdp-3.20.0/winpr/wlog.c"
    assert _match_src_member(["a/foo.c"], "bar.c") is None


def test_html_renders_vulnerable_code_snippet_and_cwe_reference():
    from lykos.report.html import _finding_html
    f = {"title": "format string", "severity": "high", "state": "corroborated", "cwe": "CWE-134",
         "cwe_name": "Uncontrolled Format String", "detector": "source_sink",
         "evidence": [{"channel": "source", "detail": "winpr/wlog.c:362: non-literal format"}],
         "effects": ["format-string %n write-what-where", "%s/%p stack disclosure"],
         "source_snippet": {"file": "winpr/wlog.c", "line": 362, "rows": [
             {"n": 361, "text": "  PRAGMA_IGNORE", "hit": False},
             {"n": 362, "text": "  vsnprintf(buf, n, cmessage->FormatString, args);", "hit": True},
             {"n": 363, "text": "    return FALSE;", "hit": False}]}}
    h = _finding_html(f)
    assert "Vulnerable code" in h and "winpr/wlog.c:362" in h
    assert 'class="cline hit"' in h and "vsnprintf" in h           # the finding line, highlighted
    assert "cwe.mitre.org/data/definitions/134.html" in h          # the CWE reference link
    assert "Demonstrated effects" in h and "write-what-where" in h  # per-finding effects rendered


def test_html_headline_tolerates_a_non_escalation_verdict_level(store):
    """A tag-only verdict level such as `L0-secret` (a hardcoded-secret finding) must not crash the
    headline, which only escalates on the dynamic rungs L1/L2/L3."""
    rep = {
        "case": {"name": "c"}, "tool": {"version": "t"}, "generated_at": "now",
        "summary": {"targets": 1, "findings": 1, "by_state": {"candidate": 1}},
        "engines": [],
        "targets": [{"filename": "libx.so", "verdict": {"level": "L0-secret",
                     "label": "Secret exposed", "tone": "info"}, "findings": [], "execution": {}}],
    }
    html = to_html(rep)                               # must not raise KeyError('L0-secret')
    assert html.startswith("<!doctype html>")
    assert "Static findings reported" in html or "No defects were demonstrated" in html


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


def test_pdf_embeds_figures_as_vector_graphics_and_stays_valid(store, case):
    """doc 49 Theme 4: the report figures are translated into PDF vector ops (not rasterized), and
    the document stays structurally valid with the figures in it."""
    from lykos.db.dao import CallEdgeDAO
    t, _f = _seed(store, case)
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x401000", "dst_addr": "0x401136", "dst_name": "main"},
        {"src_addr": "0x401136", "dst_addr": "0x401200", "dst_name": "strcpy"}])
    r = build_report(store, case.id)
    assert r["targets"][0]["figures"]["call_graph"], "precondition: a call-graph figure exists"
    pdf = to_pdf(r)
    # structurally valid (same invariants as test_pdf_is_valid)
    assert pdf[:5] == b"%PDF-" and b"%%EOF" in pdf[-8:]
    startxref = int(pdf.split(b"startxref")[1].split(b"%%EOF")[0].strip())
    assert pdf[startxref:startxref + 4] == b"xref"
    # the figure became PDF vector graphics (a rect path op) + a function label from the call graph
    assert b" re\n" in pdf, "no rectangle operator -- the figure was not drawn as vector graphics"
    assert b"(strcpy)" in pdf or b"(main)" in pdf, "the call-graph node labels are missing"
    assert to_pdf(r) == pdf, "PDF output must be deterministic"


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
