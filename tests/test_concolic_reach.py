"""T3 (doc 46): sink-directed concolic -> reachability certificates.

Three honest outcomes for a flagged sink, driven through the real stage with a stub solver that
stands in for angr's exploration result:

  * REACHED      -- a concolic-solved input reaches the sink: the lead is promoted to corroborated
                    AND a replayable reachability certificate (concrete input + invocation terms)
                    is filed.
  * UNREACHABLE  -- the search hit a NATURAL FIXPOINT (drained, not cut off) without reaching the
                    sink: the lead is ANNOTATED for de-prioritization but NEVER dropped/downgraded.
  * INCOMPLETE   -- the search was CUT OFF (budget/timeout): no reachability claim either way; the
                    finding is left exactly as it was.
"""
import json

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.symbolic import enqueue_concolic
from lykos.db.dao import ArtifactDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_GATED = ("#include <string.h>\n#include <unistd.h>\n"
          "void handle(char*in){ if(strstr(in,\"OVERFLOWME\")){char s[16];strcpy(s,in);} }\n"
          "int main(void){char b[256];int n=read(0,b,255);if(n<0)n=0;b[n]=0;handle(b);"
          "return 0;}\n")


@pytest.fixture
def gated(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("gated")
    c = d / "g.c"; c.write_text(_GATED)
    b = d / "g"
    import subprocess
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    return b


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _stub_result(tmp_path, result: dict):
    """A fake angr interpreter: the `-c import angr` probe exits 0; a driver invocation writes the
    given canned result JSON to its output path ($3)."""
    py = tmp_path / "fake-angr-python"
    blob = json.dumps(result).replace("'", "'\\''")
    py.write_text("#!/bin/sh\n"
                  'if [ "$1" = "-c" ]; then exit 0; fi\n'
                  f"printf '%s' '{blob}' > \"$3\"\n")
    py.chmod(0o755)
    return py


def _seed_candidate(store, target, site="0x2020"):
    FindingDAO(store.conn).upsert(target.id, target.case_id, {
        "cwe": "CWE-120", "title": "Unbounded strcpy into a buffer", "severity": "high",
        "state": "candidate", "confidence": 0.4, "detector": "dangerous_api",
        "function_addr": "0x2000", "site_addr": site,
        "dedup_key": "CWE-120:0x2000:0x2020:strcpy", "evidence": []})


def _run(store, pool, target, py):
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "input_mode": "stdin", "targets": ["0x2020"], "angr_python": str(py),
        "max_seconds": 10, "exec_timeout": 1})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    return next(x for x in FindingDAO(store.conn).list_by_target(target.id)
                if x.dedup_key == "CWE-120:0x2000:0x2020:strcpy")


def test_reached_sink_files_a_reachability_certificate(store, case, pool, gated, tmp_path):
    import base64
    inp = base64.b64encode(b"OVERFLOWME").decode()            # reaches the sink, no overflow
    py = _stub_result(tmp_path, {
        "ok": True, "angr_version": "stub",
        "generated": [{"input_b64": inp, "reached": "0x2020"}],
        "reached_targets": ["0x2020"], "drained": False, "cutoff": False, "stats": {"steps": 3}})
    target = ingest(store, case.id, gated)
    _seed_candidate(store, target)
    f = _run(store, pool, target, py)

    assert f.state == "corroborated"
    assert any(e.get("channel") == "symbolic" and "certificate" in e.get("detail", "")
               for e in f.evidence)
    certs = [a for a in ArtifactDAO(store.conn).list_by_case(case.id)
             if a.kind == "reachability-certificate"]
    assert certs, "a reachability certificate artifact should be filed"
    cert = json.loads(store.content.get_bytes(certs[0].sha256))
    assert cert["sink_addr"] == "0x2020" and cert["input_mode"] == "stdin"
    assert cert["input_sha"] and cert["kind"] == "reachability-certificate"


def test_drained_without_reaching_annotates_but_never_drops(store, case, pool, gated, tmp_path):
    # natural fixpoint, sink never reached -> annotate, do NOT downgrade.
    py = _stub_result(tmp_path, {
        "ok": True, "angr_version": "stub", "generated": [],
        "reached_targets": [], "drained": True, "cutoff": False, "stats": {"steps": 50}})
    target = ingest(store, case.id, gated)
    _seed_candidate(store, target)
    f = _run(store, pool, target, py)

    assert f.state == "candidate", "an unreachable verdict must NOT drop or downgrade the finding"
    assert abs((f.confidence or 0.0) - 0.4) < 1e-6, "confidence must be preserved"
    assert any(e.get("channel") == "reachability" and "DE-PRIORITIZE" in e.get("detail", "")
               for e in f.evidence), "the de-prioritization annotation should be attached"


def test_cutoff_search_makes_no_reachability_claim(store, case, pool, gated, tmp_path):
    # the search was cut off (budget) -> missing the sink proves nothing; leave the finding alone.
    py = _stub_result(tmp_path, {
        "ok": True, "angr_version": "stub", "generated": [],
        "reached_targets": [], "drained": False, "cutoff": True, "stats": {"steps": 2000}})
    target = ingest(store, case.id, gated)
    _seed_candidate(store, target)
    f = _run(store, pool, target, py)

    assert f.state == "candidate"
    assert not any(e.get("channel") == "reachability" for e in f.evidence), \
        "a cut-off search must not emit an unreachable annotation"
