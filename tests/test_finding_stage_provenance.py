"""Findings record the pipeline stage that discovered them (doc 49, Themes 1a/2b).

The job worker stamps the ambient stage around each stage's execution; FindingDAO records it on the
finding, with the DISCOVERER keeping the credit (mirroring `detector`). This provenance is what lets
the GUI/report link a finding back to the stage that produced it. These tests pin the stamping, the
discoverer-credit rule, and that unknown provenance is left blank -- never guessed.
"""
import time

import pytest
from lykos.db.dao import FindingDAO, TargetDAO
from lykos.db.provenance import current_stage, reset_current_stage, set_current_stage
from lykos.jobs import JobConfig, JobQueue, WorkerPool
from lykos.jobs.registry import register_stage


@pytest.fixture
def target(store, case):
    return TargetDAO(store.conn).upsert(case.id, "x", "a" * 64, size=1, arch="x86_64",
                                        bits=64, endianness="little")


def _cand(**kw):
    c = {"dedup_key": "k", "cwe": "CWE-121", "title": "t", "severity": "medium"}
    c.update(kw)
    return c


# ---- migration + DAO stamping ---------------------------------------------------------------

def test_finding_table_has_stage_column(store):
    cols = {r[1] for r in store.conn.execute("PRAGMA table_info(finding)").fetchall()}
    assert "stage" in cols


def test_ambient_stage_is_stamped_on_insert(store, case, target):
    F = FindingDAO(store.conn)
    tok = set_current_stage("detect_cwe")
    try:
        F.upsert(target.id, case.id, _cand(detector="dangerous_api"))
    finally:
        reset_current_stage(tok)
    f = next(f for f in F.list_by_target(target.id) if f.dedup_key == "k")
    assert f.stage == "detect_cwe"


def test_explicit_stage_in_candidate_wins_over_ambient(store, case, target):
    F = FindingDAO(store.conn)
    tok = set_current_stage("fuzz")
    try:
        F.upsert(target.id, case.id, _cand(stage="concolic", detector="x"))
    finally:
        reset_current_stage(tok)
    f = next(f for f in F.list_by_target(target.id) if f.dedup_key == "k")
    assert f.stage == "concolic"


def test_discoverer_keeps_credit_on_non_authoritative_merge(store, case, target):
    F = FindingDAO(store.conn)
    tok = set_current_stage("detect_cwe")
    try:
        F.upsert(target.id, case.id, _cand(detector="dangerous_api"))
    finally:
        reset_current_stage(tok)
    # a later stage merges in on the same key, NOT authoritative -> must not steal the credit
    tok = set_current_stage("fuzz")
    try:
        F.upsert(target.id, case.id, _cand(detector="crash", severity="high",
                                           evidence=[{"channel": "dynamic", "detail": "d"}]))
    finally:
        reset_current_stage(tok)
    f = next(f for f in F.list_by_target(target.id) if f.dedup_key == "k")
    assert f.stage == "detect_cwe"


def test_authoritative_classifier_takes_the_credit(store, case, target):
    F = FindingDAO(store.conn)
    tok = set_current_stage("fuzz")
    try:
        F.upsert(target.id, case.id, _cand(detector="crash"))
    finally:
        reset_current_stage(tok)
    tok = set_current_stage("root_cause")
    try:
        F.upsert(target.id, case.id, _cand(authoritative=True, cwe="CWE-416", title="uaf",
                                           evidence=[{"channel": "root-cause", "detail": "rc"}]))
    finally:
        reset_current_stage(tok)
    f = next(f for f in F.list_by_target(target.id) if f.dedup_key == "k")
    assert f.stage == "root_cause"


def test_no_ambient_stage_leaves_provenance_blank(store, case, target):
    """Provenance we do not know is left None -- never guessed from the detector."""
    assert current_stage() is None
    F = FindingDAO(store.conn)
    F.upsert(target.id, case.id, _cand(detector="x"))
    f = next(f for f in F.list_by_target(target.id) if f.dedup_key == "k")
    assert f.stage is None


# ---- the API/report serializer carries the provenance ---------------------------------------

def test_serializer_exposes_stage_and_label():
    from lykos.api.serializers import _finding
    from lykos.db.models import Finding
    f = Finding(id="i", target_id="t", case_id="c", dedup_key="k", created_at=0, updated_at=0,
                cwe="CWE-121", detector="dangerous_api", stage="detect_cwe")
    d = _finding(f)
    assert d["stage"] == "detect_cwe"
    assert d["stage_label"] == "Static detectors"      # from the stage registry
    # unknown stage serializes cleanly as null, not a fabricated label
    g = Finding(id="i2", target_id="t", case_id="c", dedup_key="k2", created_at=0, updated_at=0)
    assert _finding(g)["stage"] is None and _finding(g)["stage_label"] is None


# ---- the WORKER actually sets the ambient stage (not just the DAO) ---------------------------

@pytest.fixture
def _registry_snapshot():
    """Add a throwaway stage for a worker test, then restore the registry exactly -- so the real
    stages (and the stage-registry invariant test) are untouched whatever the test order."""
    from lykos.jobs import registry
    saved = dict(registry._STAGES)
    try:
        yield
    finally:
        registry._STAGES.clear()
        registry._STAGES.update(saved)


def _wait_idle(pool, t=5.0):
    return pool.wait_idle(t)


def test_worker_sets_the_ambient_stage_around_fn(store, case, target, _registry_snapshot):
    captured = {}

    def _probe(ctx):
        captured["stage"] = current_stage()
        return None

    register_stage("__provprobe__", _probe)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=5, poll_interval=0.02,
                                heartbeat_interval=1.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        q.enqueue(case.id, "__provprobe__", target_id=target.id, input_hashes=["1"])
        assert _wait_idle(pool)
    finally:
        pool.stop(grace=3.0)
    assert captured.get("stage") == "__provprobe__", "worker did not stamp the running stage"
    # and after the stage, the ambient value is reset (no leak into the worker thread's next job)
    assert current_stage() is None


def test_a_finding_filed_by_a_stage_records_that_stage_end_to_end(store, case, target,
                                                                  _registry_snapshot):
    def _files(ctx):
        FindingDAO(ctx.conn).upsert(target.id, case.id, _cand(dedup_key="e2e", detector="x"))
        return None

    register_stage("__provfiler__", _files)
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=1, lease_seconds=5, poll_interval=0.02,
                                heartbeat_interval=1.0))
    pool.start()
    try:
        q = JobQueue(store.conn)
        q.enqueue(case.id, "__provfiler__", target_id=target.id, input_hashes=["2"])
        assert _wait_idle(pool)
    finally:
        pool.stop(grace=3.0)
    f = next(f for f in FindingDAO(store.conn).list_by_target(target.id) if f.dedup_key == "e2e")
    assert f.stage == "__provfiler__"
