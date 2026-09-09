"""IT-01/18 + JE-26 — the ingest_triage stage end-to-end through the worker pool."""
import json

import pytest

from lykos.analyze import ingest, register
from lykos.analyze.ingest import enqueue_triage
from lykos.analyze.triage import validate
from lykos.jobs import JobConfig, JobQueue, WorkerPool


@pytest.fixture
def pool(store):
    register()  # ensure the stage is registered regardless of test order
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=5, poll_interval=0.02,
                             heartbeat_interval=1.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _triage_output_bytes(store, run_id):
    links = store.run_artifacts.list_by_run(run_id)
    outs = [l for l in links if l.role == "output"]
    assert outs, "no output artifact linked"
    return store.content.get_bytes(outs[0].artifact_sha256)


def test_ingest_triage_end_to_end(store, case, pool, sample_elf):
    target = ingest(store, case.id, sample_elf)
    q = JobQueue(store.conn)
    run = enqueue_triage(q, target)
    assert pool.wait_idle(8)

    assert q.runs.get(run.id).status == "done"
    rec = json.loads(_triage_output_bytes(store, run.id))
    assert validate(rec) == []
    assert rec["arch"] == "x86-64" and rec["file_type"] == "elf"

    # target row was denormalized
    t = store.targets.get(target.id)
    assert t.arch == "x86-64" and t.mitigations and t.file_type == "elf"


def test_ingest_triage_cache_hit(store, case, pool, sample_elf):
    target = ingest(store, case.id, sample_elf)
    q = JobQueue(store.conn)
    r1 = enqueue_triage(q, target)
    assert pool.wait_idle(8) and q.runs.get(r1.id).status == "done"
    first = [l.artifact_sha256 for l in store.run_artifacts.list_by_run(r1.id)]

    r2 = enqueue_triage(q, target)          # identical -> cache hit at enqueue time
    assert r2.id != r1.id and r2.status == "done"
    second = [l.artifact_sha256 for l in store.run_artifacts.list_by_run(r2.id)]
    assert second == first                  # same triage output reused
    hits = [e for e in q.events.list(case_id=case.id, limit=1000)
            if e.type == "job.cachehit"]
    assert len(hits) == 1
