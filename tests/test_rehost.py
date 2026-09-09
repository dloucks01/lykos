"""Phase 8 (doc 17.5) — emulation-based rehosting (Unicorn, Fuzzware-style MMIO)."""
from __future__ import annotations

import pytest

from lykos.analyze import register
from lykos.analyze.firmware.rehost import locate_unicorn_python, run_rehost
from lykos.analyze.firmware.rehost_stage import enqueue_rehost
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# ARM Cortex-M blob: vector table (SP + Thumb handlers) + a reset handler that reads an MMIO
# byte and, when it is 0x2a, writes to an unmapped address (an emulation fault).
_FW_HEX = ("0000012041000008410000084100000841000008410000084100000841000008"
           "410000084100000841000008410000084100000841000008410000084100000840"
           "f20000c4f2000001782a2904d140f20002caf200021160fee7")
_FW = bytes.fromhex(_FW_HEX)


@pytest.fixture
def unicorn_py():
    p = locate_unicorn_python()
    if p is None:
        pytest.skip("unicorn interpreter not available")
    return p


def test_run_rehost_fuzz_finds_mmio_crash(unicorn_py, tmp_path):
    blob = tmp_path / "fw.bin"; blob.write_bytes(_FW)
    spec = {"blob": str(blob), "base": 0x08000000, "mode": "fuzz",
            "budget": 3000, "max_iters": 400, "seed": 1337}
    res = run_rehost(unicorn_py, spec, timeout=60)
    assert res["ok"] and res["arch"] == "cortex-m"
    crash = res["fuzz"]["crash"]
    assert crash and crash["fault"]["kind"] == "write"
    assert res["fuzz"]["coverage"] >= 2          # executed real firmware blocks


def test_run_rehost_single_run_no_crash_on_benign_mmio(unicorn_py, tmp_path):
    import base64
    blob = tmp_path / "fw.bin"; blob.write_bytes(_FW)
    spec = {"blob": str(blob), "base": 0x08000000, "mode": "run",
            "budget": 3000, "fuzz_b64": base64.b64encode(b"\x00").decode()}
    res = run_rehost(unicorn_py, spec, timeout=30)
    assert res["ok"] and res["run"]["halt"] == "budget" and res["run"]["fault"] is None


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_firmware_rehost_stage_confirms_fault(store, case, pool, unicorn_py, tmp_path):
    img = tmp_path / "fw.bin"; img.write_bytes(_FW)
    t = ingest(store, case.id, img, filename="cortexm.bin")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(20)
    run = enqueue_rehost(q, t, params={"budget": 3000, "max_iters": 400})
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    fs = [f for f in FindingDAO(store.conn).list_by_target(t.id)
          if f.detector == "firmware_rehost"]
    assert fs and fs[0].cwe == "CWE-787" and fs[0].state == "confirmed"
    assert any("under emulation" in e.get("detail", "") for e in fs[0].evidence)


def test_firmware_rehost_unsupported_on_non_cortexm(store, case, pool):
    # a non-Cortex-M blob -> the stage reports unsupported, files nothing (no unicorn needed)
    import os
    sha = store.put_artifact(case.id, "target-blob", data=os.urandom(4096)).sha256
    t = store.targets.upsert(case.id, filename="blob.bin", sha256=sha, size=4096,
                             file_type="raw")
    q = JobQueue(store.conn)
    run = enqueue_rehost(q, t)
    assert pool.wait_idle(20) and q.runs.get(run.id).status == "done"
    assert not [f for f in FindingDAO(store.conn).list_by_target(t.id)
                if f.detector == "firmware_rehost"]


def test_firmware_rehost_graceful_without_unicorn(store, case, pool, monkeypatch):
    monkeypatch.setattr("lykos.analyze.firmware.rehost_stage.locate_unicorn_python",
                        lambda *a, **k: None)
    sha = store.put_artifact(case.id, "target-blob", data=_FW).sha256
    t = store.targets.upsert(case.id, filename="cortexm.bin", sha256=sha, size=len(_FW),
                             file_type="raw")
    q = JobQueue(store.conn)
    run = enqueue_rehost(q, t)
    assert pool.wait_idle(20) and q.runs.get(run.id).status == "done"
    assert not [f for f in FindingDAO(store.conn).list_by_target(t.id)
                if f.detector == "firmware_rehost"]
