"""Phase 6 — PoC bundle build + self-verification + poc-backed promotion."""
import io
import subprocess
import tarfile

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import bundle
from lykos.analyze.poc.stage import enqueue_build_poc
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH_ON_A = ("#include <unistd.h>\nint main(){char b[64];int n=read(0,b,63);"
               "for(int i=0;i<n;i++) if(b[i]=='A'){volatile int*p=0;*p=1;}return 0;}\n")
_OK = "#include <unistd.h>\nint main(){char b[64];read(0,b,63);return 0;}\n"


@pytest.fixture(scope="module")
def bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("pocbins")
    out = {}
    for name, src in (("crash", _CRASH_ON_A), ("ok", _OK)):
        c = d / (name + ".c"); c.write_text(src)
        b = d / name
        if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True).returncode == 0:
            out[name] = b
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=30, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_bundle_contents():
    data = bundle.build(b"\x7fELFbinary", b"AAAA", {"target_sha256": "abc", "arch": "x86-64"},
                        b"stack smashing detected", "stdin", [], "SIGSEGV")
    names = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        names = set(t.getnames())
        runner = t.extractfile("poc/runner.sh").read()
        inp = t.extractfile("poc/input.bin").read()
    assert {"poc/target.bin", "poc/input.bin", "poc/runner.sh", "poc/meta.json",
            "poc/README.txt"}.issubset(names)
    assert inp == b"AAAA" and b"input.bin" in runner


def test_bundle_readme_is_actionable():
    data = bundle.build(b"\x7fELFbin", b"AAAA", {"target_sha256": "abc", "arch": "x86-64",
                        "level": "L2"}, b"", "stdin", [], "SIGSEGV")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        readme = t.extractfile("poc/README.txt").read().decode()
    for section in ("WHAT THIS IS", "HOW TO RUN", "WHAT TO DO WITH IT", "FILES"):
        assert section in readme
    assert "sandbox" in readme.lower() and "sh ./runner.sh" in readme
    assert "PRIMITIVE" in readme      # L2 -> mentions the primitive


def test_script_bundle_ships_exploit_py_and_runs_it():
    """A leak-based (PIE) bundle carries a live exploit.py reproducer, and the runner runs it
    (a static payload can't re-hijack under fresh ASLR)."""
    script = b"#!/usr/bin/env python3\nprint('demo')\n"
    data = bundle.build(b"\x7fELFbin", b"payload", {"target_sha256": "abc", "arch": "x86-64",
                        "level": "L3"}, b"", "stdin", [], "SIGSEGV",
                        extra_files={"exploit.py": script},
                        run_cmd="python3 ./exploit.py ./target.bin")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        assert "poc/exploit.py" in t.getnames()
        runner = t.extractfile("poc/runner.sh").read().decode()
        readme = t.extractfile("poc/README.txt").read().decode()
    assert "python3 ./exploit.py" in runner
    assert "exploit.py" in readme and "ASLR" in readme


def test_build_poc_verifies_and_promotes(store, case, pool, bins):
    if "crash" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["crash"])
    input_sha = store.put_artifact(case.id, "fuzz-crash-input", data=b"AAAA").sha256

    q = JobQueue(store.conn)
    run = enqueue_build_poc(q, target, params={"input_sha": input_sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"

    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs and pocs[0].verified and pocs[0].level == "L1"
    assert pocs[0].bundle_sha
    # the bundle is a real, retrievable archive
    data = store.content.get_bytes(pocs[0].bundle_sha)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        assert "poc/target.bin" in t.getnames()

    pb = [f for f in FindingDAO(store.conn).list_by_target(target.id) if f.state == "poc-backed"]
    assert pb and any(e["channel"] == "poc" for e in pb[0].evidence)
    # the PoC row is linked to its finding so the report can attach the bundle (Phase 7)
    assert pocs[0].finding_id == pb[0].id


def test_build_poc_unverified_when_no_crash(store, case, pool, bins):
    if "ok" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["ok"])
    input_sha = store.put_artifact(case.id, "fuzz-crash-input", data=b"AAAA").sha256
    q = JobQueue(store.conn)
    run = enqueue_build_poc(q, target, params={"input_sha": input_sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(target.id)
    assert pocs and not pocs[0].verified and pocs[0].level == "L0"
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "poc-backed"]


def test_build_poc_forwards_endianness_and_bits(store, case, pool, monkeypatch, bins):
    """_qemu_for routes ppc64->ppc64le, mips->mipsel and riscv->riscv32/64 on endianness and
    bits. build_poc omitted both, so a little-endian ppc64 target was handed the BIG-endian
    emulator, could not run, produced no crash, and was filed as an unverified L0 instead of
    a verified L1 -- silently, since "did not reproduce" is a legitimate outcome.
    """
    if "crash" not in bins:
        pytest.skip("no C compiler")
    from lykos.analyze.poc import stage as poc_stage

    seen = {}
    real = poc_stage.sandbox.run

    def spy(exe, **kw):
        seen.update(kw)
        return real(exe, **kw)

    monkeypatch.setattr(poc_stage.sandbox, "run", spy)

    t = ingest(store, case.id, bins["crash"], filename="crash")
    store.targets.update_triage(t.id, arch="ppc64", endianness="little", bits=64)
    sha = store.put_artifact(case.id, "seed", data=b"A" * 64).sha256
    q = JobQueue(store.conn)
    enqueue_build_poc(q, t, params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(60)

    assert seen.get("endianness") == "little", "build_poc dropped endianness"
    assert seen.get("bits") == 64, "build_poc dropped bits"
