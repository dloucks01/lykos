"""Cross-stage information flow: a finding one stage produces must reach the stage that can use it.

Two handoffs that were measured to be missing (findings produced, consumed by nobody) and are now
wired:
  - extract_secrets recovers the values the program compares input against (gates) -> the fuzz
    dictionary seeds them, so the fuzzer gets PAST the gate (GAP 1).
  - synthesize_injection confirms a CWE-134 format-string leak that resolves a base -> build_exploit's
    leak recon replays that proven input instead of re-deriving the %p offset (GAP 2).
These are unit tests over the consumer helpers reading fabricated producer events; the full e2e is
covered by the autopilot phase ordering."""
import os
import tempfile

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.casestore import CaseStore
from lykos.jobs.queue import JobQueue


@pytest.fixture
def store(tmp_path):
    register()
    return CaseStore(str(tmp_path / "cases"))


def _target(store):
    p = os.path.join(tempfile.mkdtemp(), "b")
    open(p, "wb").write(b"\x7fELF" + b"\x00" * 200)
    cid = store.cases.create("x").id
    return cid, ingest(store, cid, p, filename="b")


def _emit(store, cid, target_id, stage, etype, payload):
    """Append an event the way a stage's ctx.emit does: linked to a DONE run of that stage+target
    (the consumers read status='done' payloads, as the stage's run is when a later stage reads it)."""
    q = JobQueue(store.conn)
    run = q.enqueue(cid, stage, target_id=target_id)
    q.runs.set_status(run.id, "done")
    store.events.append(etype, case_id=cid, run_id=run.id, payload=payload)


class _Ctx:
    def __init__(self, store):
        self.conn = store.conn
        self.content = store.content


def test_fuzz_dictionary_consumes_recovered_gate_values(store):
    """GAP 1: _recovered_gate_tokens returns the extract_secrets gates (gate=True) only, de-duped --
    so the fuzz dictionary can seed the magic bytes the program checks input against."""
    from lykos.analyze.fuzz.stage import _recovered_gate_tokens
    cid, t = _target(store)
    _emit(store, cid, t.id, "extract_secrets", "secrets.done", {
        "ok": True, "recovered": [
            {"value": "SECRETPASS", "gate": True, "via": "strcmp"},
            {"value": "/lib64/ld-linux.so", "gate": False, "via": "strcmp"},  # loader noise, not a gate
            {"value": "magichdr", "gate": True, "via": "memcmp"},
            {"value": "SECRETPASS", "gate": True, "via": "strcmp"}]})          # duplicate
    toks = _recovered_gate_tokens(_Ctx(store), store.targets.get(t.id))
    assert toks == [b"SECRETPASS", b"magichdr"]      # gate-only, de-duped, order preserved


def test_build_exploit_consumes_the_injection_confirmed_leak(store):
    """GAP 2: _l2_disclosure_triggers replays the input synthesize_injection already proved leaks a
    base (CWE-134, resolved_base, stdin), instead of re-deriving it."""
    from lykos.analyze.poc.exploit_stage import _l2_disclosure_triggers
    cid, t = _target(store)
    leak_input = b"%p.%p.%p.%p.%p.%p\n"
    sha, _, _ = store.content.put_bytes(leak_input)
    noise, _, _ = store.content.put_bytes(b"AAAA")
    _emit(store, cid, t.id, "synthesize_injection", "inject.done", {
        "ok": True, "confirmed": 2, "results": [
            {"probe": "fmt", "cwe": "CWE-134", "mode": "stdin",
             "input_sha": sha, "level": "L2", "resolved_base": True},     # the proven leak -> used
            {"probe": "cmd", "cwe": "CWE-78", "mode": "stdin",
             "input_sha": noise, "level": "L1", "resolved_base": False}]})  # not a base leak -> skipped
    triggers = _l2_disclosure_triggers(_Ctx(store), store.targets.get(t.id))
    assert leak_input in triggers
    assert b"AAAA" not in triggers


def test_injection_leak_not_used_when_it_resolved_no_base(store):
    """A CWE-134 leak that disclosed nothing useful (no base) is NOT replayed -- only a proven
    disclosure recipe crosses, so build_exploit's recon is not polluted with dead inputs."""
    from lykos.analyze.poc.exploit_stage import _l2_disclosure_triggers
    cid, t = _target(store)
    sha, _, _ = store.content.put_bytes(b"%x%x%x\n")
    _emit(store, cid, t.id, "synthesize_injection", "inject.done", {
        "ok": True, "confirmed": 1, "results": [
            {"probe": "fmt", "cwe": "CWE-134", "mode": "stdin",
             "input_sha": sha, "level": "L1", "resolved_base": False}]})
    assert _l2_disclosure_triggers(_Ctx(store), store.targets.get(t.id)) == []


def test_l2_to_l3_prefers_the_crash_being_weaponized(store):
    """GAP 4: with several confirmed L2s on one target, build_exploit inherits the offset measured on
    the crash it is weaponizing (_STAGE.input_sha), not the newest from an unrelated defect -- while
    the crashless early attempt (no input_sha) still takes the newest, and a lone unrelated L2 is a
    fallback, not filtered out."""
    from lykos.analyze.poc import exploit_stage
    from lykos.analyze.poc.exploit_stage import _confirmed_l2, _l2_offset, _STAGE
    cid, t = _target(store)
    # crash A (offset 40), then crash B (offset 72) -- B is newer
    _emit(store, cid, t.id, "poc_primitive", "primitive.done",
          {"primitive": "ret", "supported": True, "confirmed": True, "offset": 40,
           "mode": "stdin", "input_sha": "shaA"})
    _emit(store, cid, t.id, "poc_primitive", "primitive.done",
          {"primitive": "ret", "supported": True, "confirmed": True, "offset": 72,
           "mode": "stdin", "input_sha": "shaB"})
    ctx = _Ctx(store); tgt = store.targets.get(t.id)
    try:
        _STAGE.input_sha = "shaA"                      # weaponizing crash A
        assert _l2_offset(ctx, tgt) == 40, "did not prefer the weaponized crash's L2"
        _STAGE.input_sha = "shaB"
        assert _l2_offset(ctx, tgt) == 72
        _STAGE.input_sha = None                        # crashless early attempt -> newest
        assert _l2_offset(ctx, tgt) == 72
        _STAGE.input_sha = "shaC"                      # no L2 for this crash -> falls back to some L2
        assert _l2_offset(ctx, tgt) in (40, 72)
    finally:
        _STAGE.input_sha = None


def test_directed_fuzz_boosts_sinks_of_a_matched_cve_class():
    """GAP 5: a sink whose CWE class a version-matched CVE named leads the directed-fuzz ranking,
    above an equal-state sink of an unmatched class -- so a known-vulnerable linked component steers
    the campaign, not just cve_poc."""
    from types import SimpleNamespace as NS
    from lykos.analyze.fuzz.directed import select_targets
    fs = [
        NS(detector="dangerous_api", function_addr="0x1000", site_addr="0x1004",
           cwe="CWE-134", title="printf(user)", state="candidate", severity="high",
           confidence=0.8, evidence=[]),
        NS(detector="dangerous_api", function_addr="0x2000", site_addr="0x2004",
           cwe="CWE-787", title="memcpy overflow", state="candidate", severity="high",
           confidence=0.8, evidence=[]),
        NS(detector="cve_fingerprint", function_addr=None, site_addr=None, cwe="CWE-787",
           title="CVE-2020-0000 libfoo 1.2.3", state="corroborated", severity="critical",
           confidence=0.9, evidence=[]),
    ]
    # Without the CVE signal, the two sinks tie (same state/sev/conf) -> input order.
    base = select_targets(fs)
    assert {t["cwe"] for t in base} == {"CWE-134", "CWE-787"}
    # With the matched CVE class, the CWE-787 sink (the known CVE's class) leads.
    ranked = select_targets(fs, cve_cwes=frozenset({"CWE-787"}))
    assert ranked[0]["cwe"] == "CWE-787" and ranked[0]["cve_class"] is True
    assert ranked[1]["cwe"] == "CWE-134" and ranked[1]["cve_class"] is False
