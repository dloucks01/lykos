"""The engagement narrative (report/dossier.py): pure pieces, pinned on what the jhead and md4c
demo reports got wrong."""
from lykos.report import dossier as D

_ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6dc2 at pc 0x57 bp 0x7ff
READ of size 1 at 0x6dc2059e00c6 thread T0
    #0 0x57ec in process_EXIF /src/jhead/exif.c:1069
    #1 0x57ec in create_EXIF /src/jhead/exif.c:1227
0x6dc2059e00c6 is located 0 bytes after 134-byte region [0x6dc2,0x6dc2)
allocated by thread T0 here:
    #0 0x70f2 in malloc ../asan_malloc_linux.cpp:67
"""


def test_sanitizer_report_is_read_not_guessed():
    s = D.parse_sanitizer(_ASAN)
    assert s["kind"] == "heap-buffer-overflow" and s["access"] == "read" and s["size"] == 1
    assert s["frames"][0] == {"fn": "process_EXIF", "file": "exif.c", "line": 1069,
                              "path": "/src/jhead/exif.c"}
    assert all(f["fn"] != "malloc" for f in s["frames"])        # stops at "allocated by"
    assert s["region"] == {"offset": 0, "where": "after", "size": 134}
    assert D.parse_sanitizer("Segmentation fault") is None


def test_severity_follows_the_demonstrated_effect():
    f = {"cwe": "CWE-119", "severity": "critical"}
    sev, why = D.assess_severity(f, "L1", access="read", effect="denial-of-service",
                                 controlled=False)
    assert sev == "medium" and "READ" in why                     # jhead: was 'critical'
    assert D.assess_severity(f, "L1", access="write", effect=None, controlled=False)[0] == "high"
    assert D.assess_severity(f, "L2", access="read", effect="arbitrary-read",
                             controlled=True)[0] == "high"
    assert D.assess_severity(f, "L2", access=None, effect="control-flow-hijack",
                             controlled=True)[0] == "critical"
    assert D.assess_severity(f, "L3", access=None, effect=None, controlled=False)[0] == "critical"


def test_evidence_trail_is_compacted_for_a_reader():
    ev = [{"channel": "pattern", "detail": f"call to strncpy() at 0x{a:x}"} for a in range(10)]
    ev += [{"channel": "grounding-map", "detail": '{"cwe": "CWE-120"}'},
           {"channel": "taint-dataflow", "detail": "tainted value reaches a sink"}]
    out = D.compact_evidence(ev)
    assert len(out) == 2
    assert out[0]["detail"].startswith("call to strncpy() at 10 site(s): 0x0, 0x1, 0x2, 0x3 (+6")
    assert all(e["channel"] != "grounding-map" for e in out)


def test_a_crash_attributed_static_finding_merges_into_the_crash_dossier():
    crash = {"id": "c", "input": {"sha256": "x"}, "location": {"site": "0xa3f0"}, "evidence": []}
    static = {"id": "s", "location": {"site": "0xa8e8"}, "evidence": []}
    t = {"findings": [{"id": "c", "evidence": []},
                      {"id": "s", "detector": "tainted_deref", "evidence": [{
                          "channel": "crash-attribution",
                          "detail": "the faulting instruction IS this site (0xa3f0 in 0xa130) -- "
                                    "reproduced SIGSEGV crash"}]}]}
    out = D._merge_attributed([crash, static], t)
    assert out == [crash]
    assert "tainted_deref" in crash["evidence"][-1] and "0xa3f0" in crash["evidence"][-1]


def test_leads_explain_why_and_fold_call_sites():
    t = {"findings": [
        {"id": "1", "state": "corroborated", "detector": "dangerous_api", "cwe": "CWE-78",
         "title": "Command execution via system()", "severity": "high",
         "evidence": [{"channel": "pattern", "detail": "call to system() at 0x1"},
                      {"channel": "pattern", "detail": "call to system() at 0x2"}]},
        {"id": "2", "state": "candidate", "detector": "uc_symbolic", "cwe": "CWE-94",
         "title": "Control flow reaches data-derived pointer in f()", "severity": "medium",
         "evidence": []}]}
    g = {x["detector"]: x for x in D._leads(t)}
    assert g["dangerous_api"]["sites"] == 2 and g["dangerous_api"]["kind"] == "API-use pattern"
    assert "not a defect" in g["dangerous_api"]["why"]
    assert "assumed" in g["uc_symbolic"]["why"] or "isolation" in g["uc_symbolic"]["why"]
