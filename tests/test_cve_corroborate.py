"""CVE <-> demonstrated-crash corroboration (tier 2).

The link is a triage signal, not proof: a CVE finding gets a corroboration note when the same
target has a confirmed crash of a matching CWE class, confidence nudges up, but it is never
promoted to poc-backed and never claims the crash IS the CVE.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from lykos.analyze.fingerprint import corroborate
from lykos.casestore import CaseStore
from lykos.db.dao import FindingDAO, TargetDAO


class _Ctx:
    def __init__(self, store, target_id):
        self.conn = store.conn
        self.target_id = target_id
        self.run_id = None

    def emit(self, *a, **k):
        pass

    def progress(self, *a, **k):
        pass


def _store(tmp):
    store = CaseStore.open(Path(tmp) / "case")
    cid = store.cases.create("corrob").id
    t = TargetDAO(store.conn).upsert(cid, "bin", "a" * 64, size=10, arch="x86-64")
    return store, cid, t


def _cve(cwe, key):
    return {"cwe": cwe, "title": f"Vulnerable component: zlib 1.2.11 — {key}", "severity": "high",
            "state": "corroborated", "detector": "cve_fingerprint", "dedup_key": key,
            "confidence": 0.85, "evidence": [{"channel": "cve", "detail": "x"}]}


def _crash(cwe, key):
    return {"cwe": cwe, "title": "Reproduced crash (SIGSEGV)", "severity": "high",
            "state": "confirmed", "detector": "directed_fuzz", "dedup_key": key,
            "confidence": 0.9, "evidence": [{"channel": "dynamic", "detail": "y"}]}


def test_matching_class_gets_a_corroboration_note():
    with tempfile.TemporaryDirectory() as tmp:
        store, cid, t = _store(tmp)
        fd = FindingDAO(store.conn)
        fd.upsert(t.id, cid, _cve("CWE-787", "CVE-2022-37434:zlib:1.2.11"))
        fd.upsert(t.id, cid, _crash("CWE-119", "crash:SIGSEGV"))
        corroborate.corroborate_stage(_Ctx(store, t.id))
        cve = next(f for f in fd.list_by_target(t.id) if f.detector == "cve_fingerprint")
        chans = {e.get("channel") for e in cve.evidence}
        assert "corroboration" in chans
        assert cve.confidence > 0.85                 # nudged, not promoted
        assert cve.state != "poc-backed"             # never over-claimed
        store.close()


def test_mismatched_class_is_not_linked():
    with tempfile.TemporaryDirectory() as tmp:
        store, cid, t = _store(tmp)
        fd = FindingDAO(store.conn)
        fd.upsert(t.id, cid, _cve("CWE-787", "CVE-x:zlib:1"))     # memory
        fd.upsert(t.id, cid, _crash("CWE-89", "crash:sqli"))       # injection, unrelated
        corroborate.corroborate_stage(_Ctx(store, t.id))
        cve = next(f for f in fd.list_by_target(t.id) if f.detector == "cve_fingerprint")
        assert "corroboration" not in {e.get("channel") for e in cve.evidence}
        store.close()


def test_no_demonstrated_finding_means_no_link():
    with tempfile.TemporaryDirectory() as tmp:
        store, cid, t = _store(tmp)
        fd = FindingDAO(store.conn)
        fd.upsert(t.id, cid, _cve("CWE-787", "CVE-y:zlib:1"))
        # a crash that is only a candidate (not demonstrated) must not corroborate
        cand = _crash("CWE-119", "crash:cand"); cand["state"] = "candidate"
        fd.upsert(t.id, cid, cand)
        corroborate.corroborate_stage(_Ctx(store, t.id))
        cve = next(f for f in fd.list_by_target(t.id) if f.detector == "cve_fingerprint")
        assert "corroboration" not in {e.get("channel") for e in cve.evidence}
        store.close()
