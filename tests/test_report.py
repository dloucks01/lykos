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


def _seed_timing(store, case):
    """Runs across three techniques: one that spent the MOST time and produced nothing (the honest
    zero-yield case the timing table exists to surface), and two that produced findings / a crash."""
    content = b"\x7fELFtiming-sample"
    sha = hash_bytes(content)
    t = store.targets.upsert(case.id, filename="t", sha256=sha, size=len(content),
                             arch="x86_64", bits=64, endianness="little", stripped=False,
                             file_type="ELF", linking="dynamic")
    rd = store.runs
    # fuzz: 300s wall, ZERO findings, ZERO crashes -- the "no yield" row
    rf = rd.create(case.id, "fuzz", target_id=t.id, status="done")
    rd.set_status(rf.id, "done", started_at=1000, ended_at=1300)
    # int_overflow_scan: 10s, two findings
    ri = rd.create(case.id, "int_overflow_scan", target_id=t.id, status="done")
    rd.set_status(ri.id, "done", started_at=1000, ended_at=1010)
    # concolic: 50s, one finding AND one reproduced crash tied to this run
    rc = rd.create(case.id, "concolic", target_id=t.id, status="done")
    rd.set_status(rc.id, "done", started_at=1010, ended_at=1060)
    fd = FindingDAO(store.conn)
    for k in ("io1", "io2"):
        fd.upsert(t.id, case.id, {
            "dedup_key": k, "cwe": "CWE-190", "title": f"int overflow {k}",
            "severity": "high", "state": "candidate", "detector": "int_overflow",
            "stage": "int_overflow_scan", "evidence": [{"channel": "static", "detail": "x"}]})
    fd.upsert(t.id, case.id, {
        "dedup_key": "cc1", "cwe": "CWE-787", "title": "concolic bug", "severity": "high",
        "state": "corroborated", "detector": "concolic", "stage": "concolic",
        "evidence": [{"channel": "dynamic", "detail": "x"}]})
    DynResultDAO(store.conn).insert(t.id, case.id, run_id=rc.id, input_sha=hash_bytes(b"c"),
                                    input_mode="arg", signal=11, signal_name="SIGSEGV",
                                    crashed=True, isolation="bwrap")
    return t


def test_timing_per_technique_and_overall(store, case):
    _seed_timing(store, case)
    tm = build_report(store, case.id)["timing"]
    ov = tm["overall"]
    # wall-clock is the SPAN (1000..1300 = 300s); compute is the SUM (300+10+50 = 360s), larger
    # because techniques overlap in wall-clock -- both reported so the gap is explained.
    assert ov["wall_seconds"] == 300
    assert ov["compute_seconds"] == 360
    assert ov["wall_human"] == "5m 0s"
    assert ov["started_at"].endswith("Z") and ov["ended_at"].endswith("Z")
    # dearest-first ordering
    assert tm["techniques"][0]["stage"] == "fuzz"
    by = {d["stage"]: d for d in tm["techniques"]}
    # the honest no-yield case: most time, nothing produced
    assert by["fuzz"]["seconds"] == 300
    assert by["fuzz"]["findings"] == 0 and by["fuzz"]["crashes"] == 0
    # yield sits beside the cost
    assert by["int_overflow_scan"]["findings"] == 2
    assert by["concolic"]["findings"] == 1 and by["concolic"]["crashes"] == 1


def test_html_shows_time_and_yield(store, case):
    _seed_timing(store, case)
    html = to_html(build_report(store, case.id))
    assert "Time &amp; yield per technique" in html
    assert "5m 0s" in html            # overall wall-clock tile
    assert "no yield" in html         # the fuzz row is flagged


def test_sarif_carries_timing(store, case):
    _seed_timing(store, case)
    s = to_sarif(build_report(store, case.id))
    inv = s["runs"][0]["invocations"][0]
    assert inv["startTimeUtc"].endswith("Z") and inv["endTimeUtc"].endswith("Z")
    tm = s["runs"][0]["properties"]["timing"]
    assert tm["overall"]["compute_seconds"] == 360
    assert any(d["stage"] == "fuzz" and d["findings"] == 0 for d in tm["techniques"])


def test_pdf_with_timing_is_valid(store, case):
    _seed_timing(store, case)
    assert to_pdf(build_report(store, case.id))[:5] == b"%PDF-"


def test_finding_confirmation_ladder(store, case):
    """Each finding carries WHERE it sits on the ladder, WHY, and what would climb it."""
    _seed(store, case)
    r = build_report(store, case.id)
    fs = {f["cwe"]: f for t in r["targets"] for f in t["findings"]}
    cand = fs["CWE-134"]["analysis"]          # the low candidate
    assert cand["state"] == "candidate"
    assert cand["next_state"] == "corroborated"
    assert "corroborate" in cand["to_promote"].lower()
    poc = fs["CWE-121"]["analysis"]           # the poc-backed finding
    assert poc["state"] == "poc-backed"
    assert poc["next_state"] is None
    assert poc["to_promote"] is None
    assert "fired" in poc["why_state"]
    html = to_html(r)
    assert "To reach corroborated" in html
    assert "no independent signal has corroborated" in html


def test_finding_reachability_path_and_attack_surface(store, case):
    """Each finding exposes the structured call path from an input source + its attack surface."""
    from lykos.db.dao import CallEdgeDAO
    t = store.targets.upsert(
        case.id, filename="svc2", sha256=hash_bytes(b"svc2"), size=8, arch="x86_64", bits=64,
        endianness="little", stripped=False, file_type="ELF", linking="dynamic")
    # sink finding at the parser function; its file is on the fuzzed attack surface
    FindingDAO(store.conn).upsert(t.id, case.id, {
        "dedup_key": "r1", "cwe": "CWE-787", "title": "oob write in parse", "severity": "high",
        "state": "corroborated", "detector": "source_recipe", "function_addr": "0x402200",
        "evidence": [{"channel": "surface",
                      "detail": "on the fuzzed attack surface (compiled into an in-tree harness)"}]})
    # entry() reads input (recv) and calls parse() -> the sink function
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x402000", "dst_addr": "0x402100", "dst_name": "recv"},
        {"src_addr": "0x402000", "dst_addr": "0x402200", "dst_name": "parse"}])
    r = build_report(store, case.id)
    ff = next(x for tt in r["targets"] for x in tt["findings"])
    rch = ff["reachability"]
    assert rch["attack_surface"] == "on"
    assert rch["path"] and rch["path"][-1] == "parse"       # ends at the sink function
    html = to_html(r)
    assert "ON the fuzzed attack surface" in html
    assert "Path from an input source" in html


def test_verification_shortlist_and_noise(store, case):
    """The report triages distinct issues into prove-out shortlist / off-surface / noise, and each
    finding carries its verdict -- the de-noise step, without touching the earned `confirmed` state."""
    t = store.targets.upsert(case.id, filename="svc3", sha256=hash_bytes(b"svc3"), size=8,
                             arch="x86_64", bits=64, endianness="little", stripped=False,
                             file_type="ELF", linking="dynamic")
    fd = FindingDAO(store.conn)
    # a real on-surface finding (shortlist)
    fd.upsert(t.id, case.id, {"dedup_key": "on1", "cwe": "CWE-190", "title": "ovf", "severity": "high",
              "state": "corroborated", "detector": "source_recipe", "evidence": [
                  {"channel": "surface", "detail": "on the fuzzed attack surface (in-tree harness)"}]})
    # an off-surface finding
    fd.upsert(t.id, case.id, {"dedup_key": "off1", "cwe": "CWE-416", "title": "uaf", "severity": "high",
              "state": "corroborated", "detector": "uaf", "evidence": [
                  {"channel": "surface", "detail": "off the fuzzed attack surface (a build tool)"}]})
    # an instrumentation artifact (noise)
    fd.upsert(t.id, case.id, {"dedup_key": "noise1", "cwe": "CWE-129",
              "title": "oob _ZN11__sanitizer internal_allocator", "severity": "high",
              "state": "corroborated", "detector": "oob_index", "evidence": [
                  {"channel": "surface", "detail": "on the fuzzed attack surface"}]})
    r = build_report(store, case.id)
    vz = r["summary"]["verification"]
    assert vz["shortlist"] == 1 and vz["off_surface"] == 1 and vz["noise"] == 1
    verdicts = {f["title"]: f["verification"]["verdict"] for t in r["targets"] for f in t["findings"]}
    assert verdicts["ovf"] == "prove-out-shortlist"
    assert verdicts["uaf"] == "off-surface"
    assert verdicts["oob _ZN11__sanitizer internal_allocator"] == "instrumentation-noise"
    html = to_html(r)
    assert "prove-out shortlist" in html and "instrumentation artifact" in html
    # the shortlisted finding carries a directed prove-out plan; off-surface/noise do not
    byt = {f["title"]: f for t in r["targets"] for f in t["findings"]}
    assert byt["ovf"].get("prove_out") and byt["ovf"]["prove_out"]["steps"]
    assert "prove_out" not in byt["uaf"] and "prove_out" not in byt["oob _ZN11__sanitizer internal_allocator"]
    assert "Prove it out" in html


def test_finding_exploitability_and_ceiling(store, case):
    """Each finding carries the class primitive, the target's mitigations in the way, and the
    tool's own honest ceiling lifted from the evidence."""
    tt = store.targets.upsert(
        case.id, filename="svc", sha256=hash_bytes(b"svc"), size=8, arch="x86_64", bits=64,
        endianness="little", stripped=False, file_type="ELF", linking="dynamic",
        mitigations={"nx": True, "pie": True, "canary": False, "relro": "partial"})
    FindingDAO(store.conn).upsert(tt.id, case.id, {
        "dedup_key": "e1", "cwe": "CWE-134", "title": "format string", "severity": "high",
        "state": "corroborated", "detector": "source_recipe", "evidence": [
            {"channel": "static", "detail": "vsnprintf uses a non-literal format"},
            {"channel": "weaponization", "detail": "weaponization reached L2 and stopped: PIE: "
                                                   "no in-band leak recovered the image base"},
            {"channel": "recipe", "detail": "... Targets L3 if run against the live target."}]})
    r = build_report(store, case.id)
    ex = next(ff for t in r["targets"] for ff in t["findings"])["exploitability"]
    assert "format string" in ex["class_primitive"]
    assert ex["ceiling"] == "L2" and "PIE" in ex["ceiling_reason"]
    assert ex["targets_live"] == "L3"
    joined = " ".join(ex["mitigations_in_way"])
    assert "NX" in joined and "PIE" in joined and "partial RELRO" in joined
    html = to_html(r)
    assert "Exploitability" in html
    assert "weaponization reached L2 and stopped" in html


def test_distinct_issues_dedup_across_targets(store, case):
    """One source bug compiled into two targets is ONE distinct issue spanning two, not two."""
    fd = FindingDAO(store.conn)
    ts = {}
    for name in ("libA", "libB"):
        ts[name] = store.targets.upsert(
            case.id, filename=name, sha256=hash_bytes(name.encode()), size=4, arch="x86_64",
            bits=64, endianness="little", stripped=False, file_type="ELF", linking="dynamic")
        fd.upsert(ts[name].id, case.id, {
            "dedup_key": "shared-bug", "cwe": "CWE-190", "title": "int overflow in common.c",
            "severity": "high", "state": "corroborated", "detector": "source_recipe",
            "evidence": [{"channel": "static", "detail": "x"}]})
    # a second, unique bug present in libA only
    fd.upsert(ts["libA"].id, case.id, {
        "dedup_key": "uniq", "cwe": "CWE-22", "title": "path traversal", "severity": "medium",
        "state": "candidate", "detector": "cpg", "evidence": [{"channel": "static", "detail": "y"}]})

    r = build_report(store, case.id)
    summ = r["summary"]
    assert summ["findings"] == 3                 # raw rows: shared x2 + uniq x1
    assert summ["distinct"]["issues"] == 2       # distinct issues
    assert summ["distinct"]["raw_findings"] == 3
    assert summ["distinct"]["multi_target"] == 1
    spans = {f["dedup_key"]: f["target_span"] for t in r["targets"] for f in t["findings"]}
    assert spans["shared-bug"] == 2
    assert spans["uniq"] == 1

    html = to_html(r)
    assert "distinct issues" in html
    assert "in 2 targets" in html
