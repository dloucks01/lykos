"""Phase 4 — sandboxed dynamic analysis: crash detection + crash -> Confirmed finding."""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.dynamic.stage import enqueue_dynamic
from lykos.db.dao import DynResultDAO, FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_CRASH = "int main(){volatile int*p=0;*p=1;return 0;}\n"
_OK = "int main(){return 0;}\n"
_LOOP = "#include <unistd.h>\nint main(){while(1){}return 0;}\n"


@pytest.fixture(scope="module")
def bins(gcc, tmp_path_factory):
    d = tmp_path_factory.mktemp("dynbins")
    out = {}
    for name, src in (("crash", _CRASH), ("ok", _OK), ("loop", _LOOP)):
        c = d / (name + ".c"); c.write_text(src)
        b = d / name
        r = subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True)
        if r.returncode == 0:
            out[name] = b
    return out


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=15, poll_interval=0.02,
                             heartbeat_interval=3.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_host_arch():
    assert isinstance(sandbox.host_arch(), str) and sandbox.host_arch()


def test_sandbox_detects_crash(bins):
    if "crash" not in bins:
        pytest.skip("build failed")
    res = sandbox.run(bins["crash"], timeout=10)
    assert res.crashed and res.signal_name == "SIGSEGV"
    assert res.isolation in ("bwrap+netns", "rlimits-only")


def test_sandbox_clean_exit(bins):
    if "ok" not in bins:
        pytest.skip("build failed")
    res = sandbox.run(bins["ok"], timeout=10)
    assert not res.crashed and not res.timed_out and res.exit_code == 0


def test_sandbox_timeout(bins):
    if "loop" not in bins:
        pytest.skip("build failed")
    res = sandbox.run(bins["loop"], timeout=1)
    assert res.timed_out and not res.crashed


def test_dynamic_stage_crash_confirms_finding(store, case, pool, bins):
    from lykos.analyze.ingest import ingest
    if "crash" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["crash"])
    q = JobQueue(store.conn)
    run = enqueue_dynamic(q, target, params={"input_mode": "none", "timeout": 10})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"

    dr = DynResultDAO(store.conn).list_by_target(target.id)
    assert dr and dr[0].crashed and dr[0].signal_name == "SIGSEGV"

    confirmed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
                 if f.state == "confirmed"]
    assert confirmed and confirmed[0].detector == "dynamic"
    assert "dynamic" in {e["channel"] for e in confirmed[0].evidence}


def test_dynamic_stage_clean_no_confirmed(store, case, pool, bins):
    from lykos.analyze.ingest import ingest
    if "ok" not in bins:
        pytest.skip("build failed")
    target = ingest(store, case.id, bins["ok"])
    q = JobQueue(store.conn)
    run = enqueue_dynamic(q, target, params={"input_mode": "none", "timeout": 10})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    dr = DynResultDAO(store.conn).list_by_target(target.id)
    assert dr and not dr[0].crashed
    assert not [f for f in FindingDAO(store.conn).list_by_target(target.id)
                if f.state == "confirmed"]


# ----------------------------------------------------- multi-architecture (qemu-user)
def test_qemu_routing_honours_endianness_and_bits(monkeypatch):
    """The ELF arch name is endianness/bit blind, so the sandbox must route little-endian
    MIPS/PPC64 and RISC-V/S390 to the right qemu-user binary (regression: riscv/s390 were
    unmapped and LE targets got the big-endian emulator)."""
    seen = {}
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: seen.setdefault("q", name))
    def q(arch, endianness=None, bits=None):
        seen.clear(); sandbox._qemu_for(arch, endianness, bits); return seen.get("q")
    assert q("mips", "little") == "qemu-mipsel" and q("mips", "big") == "qemu-mips"
    assert q("ppc64", "little") == "qemu-ppc64le" and q("ppc64", "big") == "qemu-ppc64"
    assert q("riscv", bits=64) == "qemu-riscv64" and q("riscv", bits=32) == "qemu-riscv32"
    assert q("s390") == "qemu-s390x" and q("aarch64") == "qemu-aarch64"
    assert sandbox._qemu_for("made-up-arch") is None      # unknown -> None, not a crash


def _mini_elf(path, e_machine, code=b"\x00\x00\x00\x00", little=True):
    import struct
    base, ehsz, phsz = 0x400000, 64, 56
    entry = base + ehsz + phsz
    filesz = ehsz + phsz + len(code)
    ident = b"\x7fELF" + bytes([2, 1 if little else 2, 1, 0, 0]) + b"\x00" * 7
    eh = ident + struct.pack("<HHIQQQIHHHHHH", 2, e_machine, 1, entry, ehsz, 0, 0,
                             ehsz, phsz, 1, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 7, 0, base, base, filesz, filesz, 0x1000)
    path.write_bytes(eh + ph + code)
    path.chmod(0o755)
    return path


def test_cross_arch_execution_detects_crash(tmp_path):
    """Run a foreign-arch (aarch64) binary that executes an illegal instruction, under
    qemu-user, and confirm the sandbox detects the crash -- proving cross-arch dynamic
    analysis works end to end (exe staged under /tmp, as the real pipeline does)."""
    if sandbox.host_arch() == "aarch64" or not sandbox._qemu_for("aarch64"):
        pytest.skip("needs a non-aarch64 host with qemu-aarch64")
    exe = _mini_elf(tmp_path / "crash_aarch64", 0xB7)     # EM_AARCH64; 0x00000000 = UDF -> SIGILL
    res = sandbox.run(str(exe), arch="aarch64", endianness="little", bits=64, timeout=3)
    assert "qemu" in res.isolation                        # emulated, not native
    assert res.crashed and res.signal_name == "SIGILL"    # crash detected through emulation


def test_unsupported_arch_reported_not_crashed(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)   # no qemu at all
    exe = _mini_elf(tmp_path / "x", 0xB7)
    res = sandbox.run(str(exe), arch="aarch64", host="x86-64")
    assert res.isolation == "unsupported-arch" and not res.crashed and "qemu" in (res.note or "")


# a file-parsing target: reads argv[1] as a file; overflows a 64-byte buffer on a big length
_FILE_PARSER = (
    "#include <stdio.h>\n#include <string.h>\n"
    "int main(int c,char**v){ if(c<2) return 1; FILE*f=fopen(v[1],\"rb\"); if(!f) return 1;\n"
    "  char m[4]; if(fread(m,1,4,f)!=4){fclose(f);return 0;} if(memcmp(m,\"IMG\",3)!=0){fclose(f);return 0;}\n"
    "  unsigned len=0; fread(&len,4,1,f); char buf[64]; fread(buf,1,len,f); fclose(f); return 0; }\n")


def test_dynamic_stage_file_input_mode(store, case, pool, gcc, tmp_path):
    """dynamic_run must deliver a FILE input (write it, pass its path as argv) -- a document/
    image parser is invoked that way. Regression: file mode was silently ignored."""
    import base64

    from lykos.analyze.ingest import ingest
    src = tmp_path / "fp.c"; src.write_text(_FILE_PARSER)
    exe = tmp_path / "fp"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(src),
                       "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("build failed")
    target = ingest(store, case.id, exe, filename="fp")
    q = JobQueue(store.conn)
    good = b"IMG\x00" + (8).to_bytes(4, "little") + b"A" * 8        # valid -> no crash
    bad = b"IMG\x00" + (300).to_bytes(4, "little") + b"A" * 300     # oversized -> overflow
    for data, want_crash in ((good, False), (bad, True)):
        run = enqueue_dynamic(q, target, params={
            "input_mode": "file", "input_b64": base64.b64encode(data).decode(), "timeout": 5})
        assert pool.wait_idle(20) and q.runs.get(run.id).status == "done"
    drs = DynResultDAO(store.conn).list_by_target(target.id)
    assert any(d.crashed and d.signal_name == "SIGSEGV" for d in drs)   # bad file crashed
    assert any(not d.crashed for d in drs)                             # good file did not
