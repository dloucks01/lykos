"""DM-20 — test data factories."""
from __future__ import annotations

from lykos.casestore import CaseStore
from lykos.hashing import hash_bytes


def make_target(store: CaseStore, case_id: str, content: bytes = b"\x7fELFdummy", **fields):
    sha = hash_bytes(content)
    return store.targets.upsert(case_id, filename="sample.bin", sha256=sha,
                                size=len(content), **fields)


def make_run(store: CaseStore, case_id: str, *, target_id=None, stage="ingest_triage",
             status="queued", **kw):
    return store.runs.create(case_id, stage, target_id=target_id, status=status, **kw)


def make_artifact(store: CaseStore, case_id: str, kind="triage-json", data=b"{}"):
    return store.put_artifact(case_id, kind, data=data)
