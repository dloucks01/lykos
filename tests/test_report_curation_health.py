"""Report honesty round 2: engine health, verified-only levels, operator curation, SARIF validity.

Each test pins a defect that was live in the report layer:
  * the scorecard carried `fuzz_health` and the report model dropped it, so the deliverable was
    the one surface that could not say "no fuzzer could execute this target";
  * a target with no executions and no autopilot record rendered "No defects demonstrated";
  * an UNVERIFIED L3 PoC headlined "Exploited (L3)" in the HTML while the summary counted only
    verified levels;
  * SARIF used a region with no startLine/offset, a per-run uuid as its fingerprint, raw
    filenames as URIs, and merged two different binaries with the same name;
  * a typo'd min_state silently widened the report to every candidate.
"""
from __future__ import annotations

import json

import pytest
from lykos.analyze.orchestrate import SCORECARD_EVENT
from lykos.db.dao import FindingDAO, PocDAO
from lykos.hashing import hash_bytes
from lykos.report import build_report, to_html, to_pdf, to_sarif
from lykos.report.model import target_verdict


def _target(store, case, name="vuln", content=b"\x7fELF-one"):
    return store.targets.upsert(case.id, filename=name, sha256=hash_bytes(content),
                                size=len(content), arch="x86_64", bits=64,
                                endianness="little", stripped=False, file_type="ELF",
                                linking="dynamic", mitigations={})


def _finding(store, case, t, key="k1", **kw):
    fd = FindingDAO(store.conn)
    row = {"dedup_key": key, "cwe": "CWE-121", "title": "Stack overflow in parse",
           "severity": "high", "state": "candidate", "confidence": 0.5,
           "site_addr": "0x401160", "function_addr": "0x401136", "detector": "rule",
           "evidence": [{"channel": "static", "detail": "strcpy into a 64-byte stack buffer"}]}
    row.update(kw)
    fd.upsert(t.id, case.id, row)
    return next(f for f in fd.list_by_target(t.id) if f.dedup_key == key)


def _scorecard(store, case, t, fuzz_health, **extra):
    payload = {"target_id": t.id, "baseline": {"ran": True}, "executions": {"total": 0},
               "fuzz_health": fuzz_health, **extra}
    store.events.append(SCORECARD_EVENT, case_id=case.id, payload=payload)


_DARK = {"verdict": "none", "note": "No dynamic engine could execute the target, so nothing "
                                    "escalated past L0 (static findings only). coverage_fuzz: "
                                    "afl handshake failed: missing libfoo.so.1",
         "engines": [{"engine": "coverage_fuzz", "status": "failed",
                      "reason": "afl handshake failed: missing libfoo.so.1", "execs": 0},
                     {"engine": "net_fuzz", "status": "declined",
                      "reason": "not a network server", "execs": 0}]}


# ---- engine health reaches every renderer -----------------------------------------------------

def test_engine_health_is_carried_by_the_model_and_shown_in_html_pdf_sarif(store, case):
    t = _target(store, case)
    _finding(store, case, t)
    _scorecard(store, case, t, _DARK, declined={"libfuzzer": "no source for this target"})
    rep = build_report(store, case.id)
    tg = rep["targets"][0]
    assert tg["engine_health"]["verdict"] == "none"
    assert tg["engine_health"]["failed"] == ["coverage_fuzz"]
    assert tg["verdict"]["nothing_executed"] is True
    assert "no dynamic engine executed the target" in tg["verdict"]["label"]
    assert rep["summary"]["engine_health"]["verdict"] == "none"
    assert tg["execution"]["declined"][0]["stage"] == "libfuzzer"

    html = to_html(rep)
    assert "Dynamic engine health" in html
    assert "afl handshake failed: missing libfoo.so.1" in html
    assert "No dynamic engine executed 1 of 1 target(s)" in html

    pdf = to_pdf(rep)
    assert b"Dynamic engine health: none" in pdf
    assert b"afl handshake failed" in pdf

    run = to_sarif(rep)["runs"][0]
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is False
    texts = " ".join(n["message"]["text"] for n in inv["toolExecutionNotifications"])
    assert "coverage_fuzz failed" in texts and "engine health none" in texts
    assert run["properties"]["engine_health"]["verdict"] == "none"


def test_no_findings_and_nothing_executed_is_not_reported_clean(store, case):
    """No scorecard, no executions: "No defects demonstrated" was printed for a target that the
    report had no evidence anything ever ran."""
    _target(store, case)
    rep = build_report(store, case.id)
    v = rep["targets"][0]["verdict"]
    assert v["nothing_executed"] is True
    assert v["label"].startswith("Inconclusive")
    html = to_html(rep)
    assert "No defects demonstrated" not in html
    assert "not a clean result" in html
    assert b"not a clean result" in to_pdf(rep)


def test_an_engine_that_really_ran_keeps_the_clean_verdict(store, case):
    t = _target(store, case)
    _scorecard(store, case, t, {"verdict": "ok", "note": "1 engine(s) executed the target",
                                "engines": [{"engine": "fuzz", "status": "ok", "execs": 2756}]})
    rep = build_report(store, case.id)
    assert rep["targets"][0]["verdict"]["label"] == "No defects demonstrated"
    assert "not a clean result" not in to_html(rep)
    assert to_sarif(rep)["runs"][0]["invocations"][0]["executionSuccessful"] is True


# ---- verified-only levels ---------------------------------------------------------------------

def test_an_unverified_poc_never_sets_the_claimed_level(store, case):
    t = _target(store, case)
    f = _finding(store, case, t, state="corroborated")
    PocDAO(store.conn).insert(t.id, case.id, finding_id=f.id, level="L3", verified=False,
                              signal_name="SIGSEGV")
    rep = build_report(store, case.id)
    fo = rep["targets"][0]["findings"][0]
    assert fo["level"] is None
    assert rep["summary"]["highest_level"] == ""
    v = rep["targets"][0]["verdict"]
    assert v["level"] == "" and v["built_level"] == "L3"
    html = to_html(rep)
    assert "Exploited" not in html
    assert "working exploit demonstrated" not in html
    assert "did not verify" in html
    assert to_sarif(rep)["runs"][0]["results"][0]["properties"]["impact_level"] is None
    assert b"L3 built, NOT verified" in to_pdf(rep)


def test_a_verified_poc_sets_the_level_everywhere(store, case):
    t = _target(store, case)
    f = _finding(store, case, t, state="poc-backed")
    PocDAO(store.conn).insert(t.id, case.id, finding_id=f.id, level="L2", verified=True)
    rep = build_report(store, case.id)
    assert rep["summary"]["highest_level"] == "L2"
    assert rep["targets"][0]["verdict"]["level"] == "L2"
    assert to_sarif(rep)["runs"][0]["results"][0]["properties"]["impact_level"] == "L2"
    assert "Exploitation primitive established (L2)" in to_html(rep)


# ---- operator curation ------------------------------------------------------------------------

def test_curation_from_the_store_demotes_false_positives_without_dropping_them(store, case):
    t = _target(store, case)
    f1 = _finding(store, case, t, key="a", title="Real overflow")
    f2 = _finding(store, case, t, key="b", title="Noise <b>bold</b>", cwe="CWE-134")
    f3 = _finding(store, case, t, key="c", title="Unsure", cwe="CWE-190")
    ev = store.events
    ev.append("finding.curation", case_id=case.id,
              payload={"finding_id": f2.id, "status": "false_positive",
                       "note": "dead code <script>x</script>", "at": 1760000000})
    ev.append("finding.curation", case_id=case.id,
              payload={"finding_id": f3.id, "status": "needs_review", "note": "", "at": 1})
    ev.append("finding.curation", case_id=case.id,
              payload={"finding_id": f1.id, "status": "true_positive", "note": "", "at": 2})
    rep = build_report(store, case.id)
    # The tool's count is unchanged: a false positive is demoted, never subtracted.
    assert rep["summary"]["findings"] == 3
    assert rep["summary"]["curation"] == {"true_positive": 1, "needs_review": 1,
                                          "false_positive": 1}
    by = {f["id"]: f for f in rep["targets"][0]["findings"]}
    assert by[f2.id]["curation"]["status"] == "false_positive"
    assert by[f2.id]["curation"]["updated_at"].startswith("2025-")
    assert by[f2.id]["state"] == "candidate"            # tool state untouched

    html = to_html(rep)
    i_fp = html.index("Dismissed by the operator as false positive (1)")
    assert html.index("Real overflow") < i_fp < html.index("Noise &lt;b&gt;")
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html

    res = {r["properties"]["finding_id"]: r for r in to_sarif(rep)["runs"][0]["results"]}
    assert res[f2.id]["suppressions"] == [{"kind": "external", "status": "accepted",
                                           "justification": "dead code <script>x</script>"}]
    assert "suppressions" not in res[f3.id]               # needs-review is not a dismissal
    assert res[f3.id]["properties"]["curation"]["status"] == "needs_review"
    assert "suppressions" not in res[f1.id]
    assert b"Dismissed by the operator as false positive" in to_pdf(rep)


def test_a_cleared_curation_disappears_and_an_explicit_map_wins(store, case):
    t = _target(store, case)
    f = _finding(store, case, t)
    store.events.append("finding.curation", case_id=case.id,
                        payload={"finding_id": f.id, "status": "false_positive", "note": "x"})
    store.events.append("finding.curation", case_id=case.id,
                        payload={"finding_id": f.id, "status": None, "note": ""})
    assert build_report(store, case.id)["targets"][0]["findings"][0]["curation"] is None
    rep = build_report(store, case.id,
                       curation={f.id: {"status": "needs_review", "note": "check"}})
    assert rep["targets"][0]["findings"][0]["curation"]["status"] == "needs_review"


# ---- SARIF validity ---------------------------------------------------------------------------

def test_sarif_location_fingerprint_uri_and_artifacts(store, case):
    t1 = _target(store, case, name="my server#1.bin", content=b"one")
    t2 = _target(store, case, name="my server#1.bin", content=b"two")
    _finding(store, case, t1)
    _finding(store, case, t2)
    s1 = to_sarif(build_report(store, case.id))
    run = s1["runs"][0]
    assert len(run["artifacts"]) == 2, "two different binaries share one artifact entry"
    assert run["artifacts"][0]["location"]["uri"] == "my%20server%231.bin"
    r0 = run["results"][0]
    phys = r0["locations"][0]["physicalLocation"]
    assert "region" not in phys
    assert phys["address"]["absoluteAddress"] == 0x401160
    fp = r0["partialFingerprints"]["lykosFindingHash/v1"]
    assert len(fp) == 64 and fp != r0["properties"]["finding_id"]
    # Same binary + same defect in a NEW case -> the same fingerprint.
    c2 = store.cases.create("again")
    t3 = _target(store, c2, name="other-name", content=b"one")
    _finding(store, c2, t3)
    again = to_sarif(build_report(store, c2.id))["runs"][0]["results"][0]
    assert again["partialFingerprints"]["lykosFindingHash/v1"] == fp
    json.dumps(s1)


def test_sarif_omits_a_null_driver_version():
    s = to_sarif({"tool": {"name": "lykos", "version": None}, "targets": []})
    assert "version" not in s["runs"][0]["tool"]["driver"]


# ---- model robustness -------------------------------------------------------------------------

def test_unknown_filter_values_raise_instead_of_widening(store, case):
    with pytest.raises(ValueError):
        build_report(store, case.id, min_state="confirmd")
    with pytest.raises(ValueError):
        build_report(store, case.id, min_severity="hgih")
    with pytest.raises(ValueError):
        build_report(store, case.id, states=["poc_backed"])


def test_html_tolerates_missing_and_null_fields_and_does_not_double_escape():
    rep = {"case": {"name": "x"}, "summary": {}, "tool": {}, "targets": [{
        "filename": "t", "findings": [{"title": "<img src=x onerror=alert(1)>", "severity": None,
                                       "state": None, "pocs": [{"level": "L1", "verified": True,
                                                                "bundle_b64": "QUFB\"><x"}]}],
        "execution": {"baseline": {"ran": False, "note": "needs <config> & args"},
                      "executions_attempted": None, "executions_by_engine": {"afl": None},
                      "budget": {"total": 60, "elapsed": None},
                      "in_process": {"doors": [{"entry": "parse", "built": True}]}}}]}
    html = to_html(rep)
    assert "<img src=x" not in html
    assert "needs &lt;config&gt; &amp; args" in html
    assert "&amp;lt;" not in html
    assert '"><x' not in html
    assert target_verdict(rep["targets"][0])["level"] == "L1"
    assert to_pdf(rep)[:5] == b"%PDF-"
    to_sarif(rep)


# ---- runtime environment / startup gate -------------------------------------------------------

def _renv_event(store, case, t, **payload):
    run = store.runs.create(case.id, "dynamic_run", target_id=t.id, status="done")
    store.events.append("runtime_env", case_id=case.id, run_id=run.id, payload=payload)


def test_an_unopened_startup_gate_is_inconclusive_in_every_renderer(store, case):
    t = _target(store, case)
    _scorecard(store, case, t, {"verdict": "ok", "engines": [
        {"engine": "coverage_fuzz", "status": "ok", "execs": 5000}]})
    _renv_event(store, case, t, applied=False, gated=True, note="gate held", supplied=[],
                degraded=[])
    rep = build_report(store, case.id)
    tt = rep["targets"][0]
    assert tt["execution"]["runtime_env"]["gate_closed"] is True
    assert tt["execution"]["has_gaps"] is True
    v = tt["verdict"]
    assert v["gate_closed"] and v["label"].startswith("Inconclusive") and "startup gate" in v["label"]
    assert "No defects demonstrated" not in v["label"]
    assert any(d["stage"] == "runtime_env" for d in tt["execution"]["diagnostics"])
    assert "startup gate" in to_html(rep)
    assert to_pdf(rep)[:5] == b"%PDF-"
    notes = json.dumps(to_sarif(rep))
    assert "lykos/startup-gate" in notes
    # with a static finding the label still says the dynamic side only measured the gate
    _finding(store, case, t)
    lab = target_verdict(build_report(store, case.id)["targets"][0])["label"]
    assert lab.startswith("Static findings only") and "startup gate" in lab


def test_a_supplied_environment_is_shown_and_is_not_a_gap(store, case):
    t = _target(store, case)
    _renv_event(store, case, t, applied=True, gated=True, note="",
                supplied=[{"kind": "env", "name": "APP_HOME", "value": "/opt/app"},
                          {"kind": "file", "at": "/etc/app.conf"}],
                degraded=[{"path": "/var/lib/app", "why": "not creatable"}])
    rep = build_report(store, case.id)
    tt = rep["targets"][0]
    renv = tt["execution"]["runtime_env"]
    assert renv["applied"] and not renv["gate_closed"]
    assert renv["supplied"] == ["env APP_HOME=/opt/app", "file /etc/app.conf"]
    assert not tt["verdict"]["gate_closed"] and "startup gate" not in tt["verdict"]["label"]
    assert not any(d["stage"] == "runtime_env" for d in tt["execution"]["diagnostics"])
    html = to_html(rep)
    assert "Runtime environment supplied" in html and "APP_HOME=/opt/app" in html
    assert "/var/lib/app: not creatable" in html
    assert to_pdf(rep)[:5] == b"%PDF-"


def test_a_target_that_needed_nothing_has_no_runtime_env_entry(store, case):
    t = _target(store, case)
    _renv_event(store, case, t, applied=False, gated=False, note="nothing needed")
    tt = build_report(store, case.id)["targets"][0]
    assert "runtime_env" not in tt["execution"]
    assert not tt["verdict"]["gate_closed"]


def test_never_executed_still_mentions_an_unopened_gate(store, case):
    t = _target(store, case)
    _renv_event(store, case, t, applied=False, gated=True, note="gate held")
    v = build_report(store, case.id)["targets"][0]["verdict"]
    assert v["nothing_executed"] and "startup gate" in v["label"]
