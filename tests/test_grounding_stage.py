"""The grounding stage wires the precision layer (grounding + malicious-peer reachability) into a
live run: it annotates each finding with a grounding verdict + reachability basis as a VIEW (never
demoting), and the coverage ledger rolls those annotations into an attacker-reachable shortlist."""
import json

from lykos.analyze import coverage_ledger as CL
from lykos.analyze.grounding_stage import _finding_dict, grounding_stage
from lykos.db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO


class _Ctx:
    def __init__(self, store, target_id):
        self.conn = store.conn
        self.target_id = target_id
        self._emitted = []

    def emit(self, t, payload=None):
        self._emitted.append((t, payload))

    def progress(self, **k):
        pass


def _seed(store, case):
    t = TargetDAO(store.conn).upsert(case.id, "svc", "a" * 64, arch="x86-64", bits=64)
    # a real on-surface-by-role peer parser finding, a provable-FP (instrumentation noise), and a
    # 64-bit-safe integer multiply (arch-safe FP).
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, {"cwe": "CWE-787", "title": "oob write", "severity": "high",
              "detector": "cpg", "state": "candidate", "confidence": 0.5, "dedup_key": "real",
              "evidence": [{"channel": "source", "detail": "core/foo.c:10: oob in codec_process_block"}]})
    fd.upsert(t.id, case.id, {"cwe": "CWE-125", "title": "oob read", "severity": "high",
              "detector": "cpg", "state": "candidate", "confidence": 0.5, "dedup_key": "noise",
              "evidence": [{"channel": "pcode", "detail": "INT_ADD at 0x1 in method.fuzzer.FuzzerDriver"}]})
    fd.upsert(t.id, case.id, {"cwe": "CWE-190", "title": "mul", "severity": "high",
              "detector": "int_overflow", "state": "candidate", "confidence": 0.5,
              "dedup_key": "archsafe",
              "evidence": [{"channel": "source", "detail": "core/bar.c:5: alloc mul in local_cfg"}]})
    # a call graph where a peer parser reaches the real finding's function
    FunctionDAO(store.conn).replace_for_target(t.id, [
        {"addr": "0x1000", "name": "codec_process_message"}, {"addr": "0x1100", "name": "codec_process_block"}])
    CallEdgeDAO(store.conn).replace_for_target(t.id, [{"src_addr": "0x1000", "dst_addr": "0x1100"}])
    return t


def test_stage_annotates_and_tiers_without_demoting(store, case):
    t = _seed(store, case)
    before = {f.dedup_key: f.confidence for f in FindingDAO(store.conn).list_by_target(t.id)}
    grounding_stage(_Ctx(store, t.id))
    fd = FindingDAO(store.conn)
    rows = {f.dedup_key: f for f in fd.list_by_target(t.id)}
    # every finding got a grounding + grounding-map channel, and NONE was demoted
    for k, f in rows.items():
        ev = f.evidence
        chans = {e["channel"] for e in ev if isinstance(e, dict)}
        assert "grounding" in chans and "grounding-map" in chans, k
        assert f.confidence >= before[k]              # a VIEW: never lowers confidence
    # verdicts: the peer-parser-reachable oob is the shortlist; noise + arch-safe are set aside
    maps = {k: json.loads(next(e["detail"] for e in f.evidence
                               if e.get("channel") == "grounding-map"))
            for k, f in rows.items()}
    assert maps["real"]["shortlist"] is True and maps["real"]["reachable"] is True
    assert maps["noise"]["verdict"] == "instrumentation-noise" and not maps["noise"]["grounded"]
    # no source tree in this unit test, so the CWE-190 arch-safe check (needs the source line,
    # covered in test_grounding.py) does not fire; local_cfg is simply not attacker-reachable.
    assert maps["archsafe"]["verdict"] == "unreached" and maps["archsafe"]["shortlist"] is False


def test_ledger_rolls_up_the_grounded_shortlist(store, case):
    t = _seed(store, case)
    grounding_stage(_Ctx(store, t.id))
    g = CL.build_ledger(store, case.id)["grounding"]
    assert g is not None
    assert g["annotated"] == 3 and g["shortlist"] == 1 and g["attacker_reachable"] == 1
    assert g["by_verdict"].get("instrumentation-noise") == 1
    assert g["by_verdict"].get("unreached") == 1


def test_ledger_grounding_is_none_before_the_stage_runs(store, case):
    _seed(store, case)
    assert CL.build_ledger(store, case.id)["grounding"] is None


def test_finding_dict_shape():
    class _F:
        cwe, title, detector = "CWE-787", "t", "cpg"
        evidence = [{"channel": "source", "detail": "x"}]
        function_addr = target_id = dedup_key = severity = state = confidence = None
    d = _finding_dict(_F())
    assert d["cwe"] == "CWE-787" and d["evidence"][0]["channel"] == "source"
