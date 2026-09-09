"""Phase 8 (doc 17.5) — firmware image decomposition + headerless loader."""
from __future__ import annotations

import gzip
import struct
import subprocess

import pytest

from lykos.analyze import register
from lykos.analyze.firmware.carve import extract_components, scan_signatures
from lykos.analyze.firmware.headerless import analyze_blob, detect_cortex_m
from lykos.analyze.firmware.stage import enqueue_firmware
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_KEY = (b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        b"-----END RSA PRIVATE KEY-----\n")


def _tiny_elf(gcc, tmp, tag):
    c = tmp / f"{tag}.c"; c.write_text(f"int main(){{return {len(tag)};}}\n")
    out = tmp / tag
    if subprocess.run([gcc, "-O0", str(c), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build ELF")
    return out.read_bytes()


def _cortex_m_image(size=0x1000):
    base = 0x08000000
    words = [0x20005000, base + 0x101] + [base + 0x140 + i * 4 + 1 for i in range(12)]
    vt = b"".join(struct.pack("<I", w) for w in words)
    return vt + b"\x00" * (size - len(vt))


def test_scan_signatures_finds_embedded_artifacts(gcc, tmp_path):
    e1 = _tiny_elf(gcc, tmp_path, "aa")
    fw = b"UBOOT-HEADER----" + e1 + b"\xff" * 32 + _KEY + b"\x00" * 16
    hits = {h["type"] for h in scan_signatures(fw)}
    assert "elf" in hits and "privkey" in hits


def test_extract_components_embedded_and_compressed_elf(gcc, tmp_path):
    e1 = _tiny_elf(gcc, tmp_path, "aa")
    e2 = _tiny_elf(gcc, tmp_path, "bbbb")
    fw = b"HDR." + e1 + b"\x00" * 16 + gzip.compress(e2) + b"\xff" * 8
    comps = extract_components(fw)
    kinds = [c["kind"] for c in comps]
    assert kinds.count("elf") >= 2                     # the raw ELF and the gzip'd ELF
    assert any("gzip" in c["note"] for c in comps)
    # the extracted raw ELF really is e1 (correctly bounded)
    raw = next(c for c in comps if "gzip" not in c["note"])
    assert raw["bytes"][:4] == b"\x7fELF"


def test_detect_cortex_m_vector_table():
    d = detect_cortex_m(_cortex_m_image())
    assert d and d["arch"] == "arm" and d["sub"] == "cortex-m"
    assert d["base_addr"] == 0x08000000 and d["entry"] == 0x08000100
    assert d["endianness"] == "little" and d["confidence"] > 0.8


def test_analyze_blob_inconclusive_on_random():
    import os
    d = analyze_blob(os.urandom(2048))
    assert d["arch"] in (None,) or d["confidence"] < 0.5


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_firmware_carve_stage_registers_components_and_key(store, case, pool, gcc, tmp_path):
    e1 = _tiny_elf(gcc, tmp_path, "aa")
    e2 = _tiny_elf(gcc, tmp_path, "bbbb")
    fw = b"UBOOT-HEADER----" + e1 + b"\x00" * 16 + gzip.compress(e2) + b"\xff" * 8 + _KEY
    img = tmp_path / "firmware.bin"; img.write_bytes(fw)

    target = ingest(store, case.id, img, filename="firmware.bin")
    q = JobQueue(store.conn)
    from lykos.analyze.ingest import enqueue_triage
    enqueue_triage(q, target, force=True)
    assert pool.wait_idle(20)

    run = enqueue_firmware(q, target)
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"

    # two embedded ELFs were registered as new case targets (plus the image itself)
    names = [t.filename for t in store.targets.list_by_case(case.id)]
    carved = [n for n in names if "firmware.bin:carved_" in n]
    assert len(carved) >= 2
    # the embedded private key became a CWE-321 finding on the image
    keys = [f for f in FindingDAO(store.conn).list_by_target(target.id)
            if f.detector == "firmware_carve"]
    assert keys and keys[0].cwe == "CWE-321"


def test_firmware_carve_headerless_cortex_m(store, case, pool, tmp_path):
    img = tmp_path / "fw.bin"; img.write_bytes(_cortex_m_image())
    target = ingest(store, case.id, img, filename="fw.bin")
    q = JobQueue(store.conn)
    from lykos.analyze.ingest import enqueue_triage
    enqueue_triage(q, target, force=True); assert pool.wait_idle(20)
    run = enqueue_firmware(q, target)
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    # the decomposition report identified the bare-metal architecture
    outs = q.runs.get(run.id)
    from lykos.db.dao import RunArtifactDAO, ArtifactDAO
    import json
    art = None
    for link in RunArtifactDAO(store.conn).list_by_run(run.id):
        a = ArtifactDAO(store.conn).get(link.artifact_sha256)
        if a and a.kind == "firmware-decomposition":
            art = json.loads(store.content.get_bytes(a.sha256))
    assert art and art["headerless"]["arch"] == "arm"
    assert art["headerless"]["sub"] == "cortex-m"
