"""Phase 6 — SymQEMU concolic backend (alternate to angr).

SymQEMU is an optional QEMU-based tool. These tests cover the locator, the generated-input
harvester, and the full concolic stage driven by the SymQEMU backend using a *stub* symqemu
binary (stands in for the real engine on a real target). The real engine runs only when it is
actually installed (skipped otherwise)."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import ingest
from lykos.analyze.symbolic import enqueue_concolic, symqemu
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_GATED = ("#include <string.h>\n#include <unistd.h>\n"
          "void handle(char*in){ if(strstr(in,\"OVERFLOWME\")){char s[16];strcpy(s,in);} }\n"
          "int main(void){char b[256];int n=read(0,b,255);if(n<0)n=0;b[n]=0;handle(b);"
          "return 0;}\n")


@pytest.fixture
def gated(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("sq")
    c = d / "g.c"; c.write_text(_GATED)
    b = d / "g"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", str(c), "-o", str(b)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    return b


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=120, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _stub_symqemu(tmp_path, payload: bytes):
    """A fake symqemu-x86_64: writes one generated test case into SYMCC_OUTPUT_DIR."""
    py = tmp_path / "symqemu-x86_64"
    hexpayload = payload.hex()
    py.write_text(
        "#!/bin/sh\n"
        'mkdir -p "$SYMCC_OUTPUT_DIR"\n'
        f'printf %s "{hexpayload}" | (command -v xxd >/dev/null && xxd -r -p '
        f'|| python3 -c "import sys,binascii;'
        f'sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read()))") '
        f'> "$SYMCC_OUTPUT_DIR/000000"\n')
    py.chmod(0o755)
    return py


def test_locate_symqemu(tmp_path, monkeypatch):
    monkeypatch.delenv("LYKOS_SYMQEMU", raising=False)
    stub = _stub_symqemu(tmp_path, b"x")
    assert symqemu.locate_symqemu(str(stub)) == stub          # explicit path
    assert symqemu.locate_symqemu(str(tmp_path)) == stub      # dir containing symqemu-x86_64
    monkeypatch.setenv("LYKOS_SYMQEMU", str(stub))
    assert symqemu.locate_symqemu() == stub
    monkeypatch.setenv("LYKOS_SYMQEMU", str(tmp_path / "nope"))
    assert symqemu.locate_symqemu(arch="ppc64") is None       # no symqemu-ppc64 anywhere


def test_harvest_dedups(tmp_path):
    out = tmp_path / "out"; out.mkdir()
    (out / "000000").write_bytes(b"AAAA")
    (out / "000001").write_bytes(b"AAAA")          # dup
    (out / "000002").write_bytes(b"BBBBBB")
    got = symqemu.harvest(out)
    assert sorted(got) == [b"AAAA", b"BBBBBB"]


def test_concolic_symqemu_backend_confirms_crash(store, case, pool, gated, tmp_path):
    """Stage with backend=symqemu: the stub emits a token overflow input, which the sandbox
    replay confirms as a crash -> a Confirmed concolic finding."""
    stub = _stub_symqemu(tmp_path, b"OVERFLOWME" + b"A" * 80)
    target = ingest(store, case.id, gated)
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "backend": "symqemu", "input_mode": "stdin", "symqemu_path": str(stub),
        "rounds": 1, "max_seconds": 20, "exec_timeout": 1})
    assert pool.wait_idle(40) and q.runs.get(run.id).status == "done"
    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed" and f.detector == "concolic"]
    assert confirmed and confirmed[0].cwe in ("CWE-119", "CWE-787")


@pytest.mark.skipif(symqemu.locate_symqemu() is None, reason="symqemu not installed")
def test_symqemu_real_generates_inputs(store, case, pool, gated):
    target = ingest(store, case.id, gated)
    q = JobQueue(store.conn)
    run = enqueue_concolic(q, target, params={
        "backend": "symqemu", "input_mode": "stdin", "max_seconds": 60, "exec_timeout": 2,
        "seeds": ["QUFBQQ=="]})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
