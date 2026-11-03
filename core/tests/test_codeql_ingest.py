"""F3 (doc 60): CodeQL SARIF ingest — deterministic core of the codeql stage."""
import json
from lykos.analyze.codeql_stage import ingest_sarif, _rule_cwe


class _FD:
    def __init__(self): self.rows = []
    def upsert(self, tid, cid, c): self.rows.append(c)


class _T:
    id = "t1"; case_id = "c1"


SARIF = {
  "runs": [{
    "tool": {"driver": {"rules": [
      {"id": "cpp/path-injection", "properties": {"tags": ["security", "external/cwe/cwe-022"],
                                                  "problem.severity": "warning"}}]}},
    "results": [{
      "ruleId": "cpp/path-injection",
      "message": {"text": "This path depends on a user-provided value."},
      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/foo.c"},
                                          "region": {"startLine": 42}}}],
      "codeFlows": [{"threadFlows": [{"locations": [
        {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/net.c"},
                                           "region": {"startLine": 5}},
                      "message": {"text": "source"}}},
        {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/foo.c"},
                                           "region": {"startLine": 42}},
                      "message": {"text": "sink"}}}]}]}]}]}]}


def test_rule_cwe_parsing():
    assert _rule_cwe({"properties": {"tags": ["external/cwe/cwe-022"]}}) == "CWE-22"
    assert _rule_cwe({"properties": {"tags": ["external/cwe/cwe-787"]}}) == "CWE-787"
    assert _rule_cwe({"properties": {"tags": ["maintainability"]}}) is None


def test_ingest_files_finding_with_dataflow(tmp_path):
    p = tmp_path / "r.sarif"
    p.write_text(json.dumps(SARIF))
    fd = _FD()
    n = ingest_sarif(str(p), fd, _T(), root="")
    assert n == 1
    c = fd.rows[0]
    assert c["cwe"] == "CWE-22" and c["detector"] == "codeql" and c["severity"] == "medium"
    chans = {e["channel"] for e in c["evidence"]}
    assert "codeql" in chans and "codeql-dataflow" in chans
    flow = next(e["detail"] for e in c["evidence"] if e["channel"] == "codeql-dataflow")
    assert "net.c:5" in flow and "foo.c:42" in flow and "->" in flow     # source -> sink path
