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
