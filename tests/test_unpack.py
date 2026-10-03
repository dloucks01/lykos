"""The `unpack` stage: a UPX-packed executable is a compressed stub, so the machine-code stages
would analyse the decompressor, not the program. The stage decompresses it (losslessly, via UPX's
own `-d`) and registers the UNPACKED binary as a child target that triage + every analysis stage
then process -- the same container -> child-target shape as firmware_carve. Unit tests pin the
detector/unpacker; an E2E test runs the stage and asserts the child target appears and triages."""
import shutil
import subprocess

import pytest
from lykos.analyze import unpack

_GCC = shutil.which("gcc") or shutil.which("cc")
_UPX = shutil.which("upx")


def _packed(tmp_path):
    src = tmp_path / "h.c"
    src.write_text('#include <stdio.h>\nint main(void){ puts("packed hello world marker"); return 0; }\n')
    exe, packed = tmp_path / "h", tmp_path / "h.upx"
    if subprocess.run([_GCC, "-O1", str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    if subprocess.run([_UPX, "-q", "-o", str(packed), str(exe)], capture_output=True).returncode:
        pytest.skip("upx could not pack the fixture")
    return exe, packed


def test_is_upx_discriminates():
    assert not unpack.is_upx(b"\x7fELF" + b"A" * 4000)       # a plain ELF is not packed
    assert not unpack.is_upx(b"")
    # a byte blob with the marker only at the start is not enough (needs both ends, or UPX0/UPX1)
    assert not unpack.is_upx(b"UPX!" + b"\x00" * 4000)


@pytest.mark.skipif(not (_GCC and _UPX), reason="needs a C compiler + upx")
def test_upx_roundtrip_is_lossless(tmp_path):
    exe, packed = _packed(tmp_path)
    pdata, odata = packed.read_bytes(), exe.read_bytes()
    assert unpack.is_upx(pdata) and not unpack.is_upx(odata)
    out, note = unpack.upx_unpack(pdata)
    assert out == odata, note                                # UPX -d restores the original exactly


def test_unpack_missing_tool_is_honest(tmp_path, monkeypatch):
    # a packed image with no upx tool available -> (None, reason), never a false success
    monkeypatch.setattr(unpack, "upx_available", lambda: None)
    out, note = unpack.upx_unpack(b"UPX!" + b"\x00" * 100 + b"UPX!")
    assert out is None and "not installed" in note


@pytest.mark.skipif(not (_GCC and _UPX), reason="needs a C compiler + upx")
def test_stage_registers_unpacked_child_target(store, tmp_path):
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.unpack import UNPACK_STAGE
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    _, packed = _packed(tmp_path)
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        case = store.cases.create("unpackcase")
        t = ingest(store, case.id, packed, filename="h.upx")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(60)
        assert unpack.looks_packed(store, store.targets.get(t.id))   # triaged ELF, UPX marker
        run = q.enqueue(case.id, UNPACK_STAGE, target_id=t.id, force=True)
        assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    # a child target "<name>:unpacked" must now exist, larger than the packed input, and triaged ELF
    kids = [x for x in store.targets.list_by_case(case.id) if x.filename.endswith(":unpacked")]
    assert kids, "no unpacked child target registered"
    child = kids[0]
    assert child.size > store.targets.get(t.id).size
    assert (child.file_type or "").lower() == "elf"          # the real program, now analyzable
