"""The `confirm` stage (verify_stage.py): populate the confirmed rung soundly, then weaponize.

Pins the precision contract -- confirmed requires ALL THREE legs (corroborated + real + reachable),
never promotes a bare candidate or an unreached/FP finding -- and that a confirmed RCE-capable
finding gets exactly the honest artifact for its class (a self-calibrating exploit SCRIPT for
format-string/injection; a recipe for overflow), emitted once.
"""
import hashlib
import json

from lykos.analyze import verify_stage as V
from lykos.db.dao import FindingDAO, TargetDAO


class _FakeCtx:
    def __init__(self, conn):
        self.conn = conn
        self.target_id = None
        self.run_id = "run-test"
        self.stored = {}
        self.events = []

    def put_artifact(self, kind, *, data, meta=None):
        sha = hashlib.sha256(bytes(data)).hexdigest()
        self.stored[sha] = (kind, bytes(data), meta or {})
        return sha

    def emit(self, type, level="info", payload=None):
        self.events.append((type, payload))

    def progress(self, pct=None, msg=None):
        pass


def _target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "t", "d" * 64, arch="source", bits=64)


def _file(fd, t, *, cwe, key, state, grounded, reachable, detector="src",
          derivation=True, title=None):
    """A finding carrying a grounding-map channel exactly as the grounding stage writes it. By
    default it also carries a real analysis (taint-dataflow) channel -- the dataflow leg; set
    derivation=False to model a finding corroborated on a flat pattern only."""
    shortlist = bool(grounded) and reachable is True
    verdict = ("exploitable-candidate" if shortlist else "unreached" if reachable is False
               else "format-literal" if not grounded else "reachability-unknown")
    mapv = {"verdict": verdict, "grounded": grounded, "reachable": reachable,
            "reach_basis": "peer-parser", "shortlist": shortlist}
    ev = [{"channel": "source", "detail": "sink in parser at src/foo.c:42"},
          {"channel": "grounding-map", "detail": json.dumps(mapv, sort_keys=True)}]
    ev.append({"channel": "taint-dataflow" if derivation else "pattern", "detail": "src/foo.c:42"})
    fd.upsert(t.id, t.case_id, {
        "cwe": cwe, "title": title or f"{cwe} defect", "severity": "high", "detector": detector,
        "state": state, "confidence": 0.5, "dedup_key": key, "evidence": ev})
    return fd.id_for_dedup(t.id, key)


def _state(fd, t, key):
    return next(f.state for f in fd.list_by_target(t.id) if f.dedup_key == key)


def test_promotes_only_corroborated_real_and_reachable(store, case):
    fd = FindingDAO(store.conn)
    t = _target(store, case)
    _file(fd, t, cwe="CWE-134", key="ok", state="corroborated", grounded=True, reachable=True)
    _file(fd, t, cwe="CWE-134", key="bare", state="candidate", grounded=True, reachable=True)
    _file(fd, t, cwe="CWE-134", key="fp", state="corroborated", grounded=False, reachable=True)
    _file(fd, t, cwe="CWE-134", key="unreached", state="corroborated", grounded=True, reachable=False)
    _file(fd, t, cwe="CWE-134", key="undecided", state="corroborated", grounded=True, reachable=None)
    _file(fd, t, cwe="CWE-134", key="patternonly", state="corroborated", grounded=True,
          reachable=True, derivation=False)
    _file(fd, t, cwe="CWE-134", key="recipe", state="corroborated", grounded=True, reachable=True,
          title="Exploitation recipe: format-string (targets L3)")

    V.promote(fd, t, "run-1")

    assert _state(fd, t, "ok") == "confirmed"            # all three legs -> confirmed
    assert _state(fd, t, "bare") == "candidate"          # a bare candidate is never promoted
    assert _state(fd, t, "fp") == "corroborated"         # provable FP: not real -> not confirmed
    assert _state(fd, t, "unreached") == "corroborated"  # not attacker-reachable -> not confirmed
    assert _state(fd, t, "undecided") == "corroborated"  # reach UNDECIDED is not enough
    assert _state(fd, t, "patternonly") == "corroborated"  # pattern-only: no dataflow leg
    assert _state(fd, t, "recipe") == "corroborated"     # a recipe is never promoted (honesty contract)


def test_confirmed_format_and_injection_get_an_exploit_script(store, case):
    fd = FindingDAO(store.conn)
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    ctx.target_id = t.id
    _file(fd, t, cwe="CWE-134", key="fmt", state="corroborated", grounded=True, reachable=True)
    _file(fd, t, cwe="CWE-78", key="inj", state="corroborated", grounded=True, reachable=True)

    out = V.verify_stage(ctx)

    assert out["metrics"]["confirmed"] == 2
    scripts = [m for (k, d, m) in ctx.stored.values() if k == "exploit-script"]
    assert len(scripts) == 2
    # honest: synthesized, never claimed proven.
    assert all(m["proven"] is False for m in scripts)
    kinds = {m["kind"] for m in scripts}
    assert kinds == {"format", "injection"}
    # each script is a runnable python program referencing the class.
    for (k, data, m) in ctx.stored.values():
        if k == "exploit-script":
            assert data.startswith(b"#!/usr/bin/env python3")


def test_confirmed_overflow_gets_a_recipe_not_a_fabricated_script(store, case):
    fd = FindingDAO(store.conn)
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    ctx.target_id = t.id
    _file(fd, t, cwe="CWE-787", key="oob", state="corroborated", grounded=True, reachable=True)

    V.verify_stage(ctx)

    # no exploit-script (we have no recovered offset) -- an honest recipe row instead.
    assert not [m for (k, d, m) in ctx.stored.values() if k == "exploit-script"]
    recs = [f for f in fd.list_by_target(t.id) if (f.title or "").startswith("Exploitation recipe")]
    assert len(recs) == 1 and recs[0].state == "corroborated"


def test_weaponize_is_idempotent(store, case):
    fd = FindingDAO(store.conn)
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    ctx.target_id = t.id
    _file(fd, t, cwe="CWE-134", key="fmt", state="corroborated", grounded=True, reachable=True)
    V.verify_stage(ctx)
    V.verify_stage(ctx)                                  # second run must not emit again
    scripts = [m for (k, d, m) in ctx.stored.values() if k == "exploit-script"]
    assert len(scripts) == 1


def test_non_rce_confirmed_finding_is_not_weaponized(store, case):
    fd = FindingDAO(store.conn)
    t = _target(store, case)
    ctx = _FakeCtx(store.conn)
    ctx.target_id = t.id
    # CWE-22 (path traversal) confirms but its ceiling is 'logic' -- no exploit script.
    _file(fd, t, cwe="CWE-22", key="trav", state="corroborated", grounded=True, reachable=True)
    V.verify_stage(ctx)
    assert _state(fd, t, "trav") == "confirmed"
    assert not ctx.stored
