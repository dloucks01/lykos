"""Phase 3 — CWE detection engine: finding lifecycle, detectors, reachability, stage."""
import pytest
from factories import make_target
from lykos.analyze import ingest, register  # noqa: F401
from lykos.analyze.detect.detectors import (
    DetectContext,
    correlate,
    dangerous_api,
    hardcoded_secrets,
)
from lykos.analyze.detect.stage import enqueue_detect
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, StringDAO
from lykos.db.models import CallEdge, StringRef
from lykos.jobs import JobConfig, JobQueue, WorkerPool


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=8, poll_interval=0.02, heartbeat_interval=2.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _edge(src, site, dst, name, ext):
    return CallEdge(id="x", target_id="t", created_at=0, src_addr=src, site_addr=site,
                    dst_addr=dst, dst_name=name, external=ext)


def test_finding_dao_upsert_merges_and_promotes(store, case):
    t = make_target(store, case.id)
    fd = FindingDAO(store.conn)
    base = dict(cwe="CWE-120", title="strcpy", severity="high", function_addr="0x2000",
                site_addr="0x2004", detector="dangerous_api", dedup_key="k1")
    fd.upsert(t.id, case.id, {**base, "state": "candidate", "confidence": 0.4,
                              "evidence": [{"channel": "pattern", "detail": "a"}]})
    fd.upsert(t.id, case.id, {**base, "state": "corroborated", "confidence": 0.65,
                              "evidence": [{"channel": "taint-reachability", "detail": "b"}]})
    fs = fd.list_by_target(t.id)
    assert len(fs) == 1                                  # merged, not duplicated
    f = fs[0]
    assert f.state == "corroborated" and f.confidence == 0.65
    assert len(f.evidence) == 2                          # evidence unioned


def test_dangerous_api_detector():
    ctx = DetectContext("t", "c", call_edges=[
        _edge("0x2000", "0x2004", "0x9100", "strcpy", True),
        _edge("0x2000", "0x2008", "0x9200", "__isoc99_scanf", True),
        _edge("0x2000", "0x200c", "0x3000", "my_helper", False),   # not dangerous
    ], strings=[])
    cands = dangerous_api(ctx)
    cwes = {c["cwe"] for c in cands}
    assert "CWE-120" in cwes                              # strcpy + scanf
    assert len(cands) == 2 and all(c["detector"] == "dangerous_api" for c in cands)


def test_hardcoded_secrets_detector():
    ctx = DetectContext("t", "c", call_edges=[], strings=[
        StringRef(id="1", target_id="t", addr="0x3000", created_at=0,
                  value="password=admin123", xrefs=["0x1200"]),
        StringRef(id="2", target_id="t", addr="0x3010", created_at=0,
                  value="just a normal string", xrefs=[]),
        StringRef(id="3", target_id="t", addr="0x3020", created_at=0,
                  value="-----BEGIN RSA PRIVATE KEY-----", xrefs=[]),
    ])
    cands = hardcoded_secrets(ctx)
    cwes = {c["cwe"] for c in cands}
    assert "CWE-798" in cwes and "CWE-321" in cwes
    assert len(cands) == 2                                # the benign string is ignored


def test_correlate_promotes_reachable_sink():
    # main(0x1000) reads input (recv) and calls parse(0x2000); parse calls strcpy (sink)
    edges = [
        _edge("0x1000", "0x1004", "0x9000", "recv", True),      # source in main
        _edge("0x1000", "0x1008", "0x2000", "parse", False),    # main -> parse
        _edge("0x2000", "0x2004", "0x9100", "strcpy", True),    # sink in parse
    ]
    ctx = DetectContext("t", "c", call_edges=edges, strings=[])
    cands = correlate(dangerous_api(ctx), ctx)
    sink = next(c for c in cands if c["function_addr"] == "0x2000")
    assert sink["state"] == "corroborated"               # reachable from recv via main->parse
    assert any(e["channel"] == "taint-reachability" for e in sink["evidence"])


def test_detect_stage_end_to_end(store, case, pool):
    t = make_target(store, case.id)
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "main"}, {"addr": "0x2000", "name": "parse"}])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [
        {"src_addr": "0x1000", "site_addr": "0x1004", "dst_addr": "0x9000",
         "dst_name": "recv", "external": True},
        {"src_addr": "0x1000", "site_addr": "0x1008", "dst_addr": "0x2000",
         "dst_name": "parse", "external": False},
        {"src_addr": "0x2000", "site_addr": "0x2004", "dst_addr": "0x9100",
         "dst_name": "strcpy", "external": True},
    ])
    StringDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x3000", "value": "api_key=deadbeefcafebabe", "xrefs": ["0x1200"]}])

    q = JobQueue(store.conn)
    run = enqueue_detect(q, t)
    assert pool.wait_idle(10)
    assert q.runs.get(run.id).status == "done"

    fd = FindingDAO(store.conn)
    findings = fd.list_by_target(t.id)
    cwes = {f.cwe for f in findings}
    assert "CWE-120" in cwes and "CWE-798" in cwes
    strcpy = next(f for f in findings if f.cwe == "CWE-120")
    assert strcpy.state == "corroborated"                # reachability promoted it

    # re-run is idempotent (dedup/merge, not duplicate)
    before = fd.count_by_target(t.id)
    run2 = enqueue_detect(q, t)
    assert pool.wait_idle(10) and q.runs.get(run2.id).status == "done"
    assert fd.count_by_target(t.id) == before


def test_weak_crypto_detector():
    from lykos.analyze.detect.detectors import weak_crypto
    ctx = DetectContext("t", "c", call_edges=[
        _edge("0x1", "0x1", "0x9", "MD5_Init", True),
        _edge("0x1", "0x2", "0x9", "DES_set_key", True),
        _edge("0x1", "0x3", "0x9", "destroy_object", False),   # must NOT match 'des'
        _edge("0x1", "0x4", "0x9", "arc4random", True),        # must NOT match 'rc4'
    ], strings=[])
    cands = weak_crypto(ctx)
    assert {c["cwe"] for c in cands} == {"CWE-328", "CWE-327"}   # MD5 + DES only
    assert len(cands) == 2


def test_weak_random_detector():
    from lykos.analyze.detect.detectors import weak_random
    ctx = DetectContext("t", "c", strings=[], call_edges=[
        _edge("0x1", "0x1", "0x9", "rand", True),
        _edge("0x1", "0x2", "0x9", "arc4random", True)])       # not in the weak set
    cands = weak_random(ctx)
    assert len(cands) == 1 and cands[0]["cwe"] == "CWE-330"


def test_insecure_tmp_detector():
    from lykos.analyze.detect.detectors import insecure_tmp
    ctx = DetectContext("t", "c", strings=[], call_edges=[
        _edge("0x1", "0x1", "0x9", "mktemp", True),
        _edge("0x1", "0x2", "0x9", "mkstemp", True)])          # mkstemp is safe
    cands = insecure_tmp(ctx)
    assert len(cands) == 1 and cands[0]["cwe"] == "CWE-377"


def test_hardening_detector():
    from lykos.analyze.detect.detectors import hardening
    ctx = DetectContext("t", "c", call_edges=[], strings=[],
                        mitigations={"nx": "off", "canary": "off", "pie": "on",
                                     "relro": "partial"})
    cands = hardening(ctx)
    assert {c["cwe"] for c in cands} == {"CWE-693"}
    assert len(cands) == 3           # nx off + canary off + relro partial (pie on -> none)
    assert cands[0]["detector"] == "hardening"
