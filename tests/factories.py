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


def replay_l3_bundle(store: CaseStore, target_id: str, workdir):
    """Unpack the target's verified L3 bundle and run its runner.sh, as an operator would.

    A verified L3 used to be checked only by the live confirmation; the shipped reproducer never
    ran in a test, which is how bundles that piped a Python script into the target, or fed it the
    text of the offset, went unnoticed."""
    import io
    import subprocess
    import tarfile
    from pathlib import Path

    from lykos.db.dao import PocDAO
    l3 = [p for p in PocDAO(store.conn).list_by_target(target_id) if p.level == "L3" and p.verified]
    assert l3, "no verified L3 PoC to replay"
    out = Path(workdir) / "bundle"
    with tarfile.open(fileobj=io.BytesIO(store.content.get_bytes(l3[0].bundle_sha)),
                      mode="r:gz") as tf:
        tf.extractall(out, filter="data")
    root = next(p.parent for p in out.rglob("runner.sh"))
    return subprocess.run(["sh", "./runner.sh"], cwd=root, capture_output=True, timeout=120)
