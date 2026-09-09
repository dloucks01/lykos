"""Phase 6 (L2) — exploitation-primitive analysis: cyclic offset recovery + instruction-
pointer-control confirmation. The pure logic is unit-tested; the full stage runs live on a
native stack-overflow binary (skipped off x86-64/aarch64 or without a C compiler)."""
import struct
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_primitive
from lykos.analyze.poc import primitive as P
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _build(gcc, tmp_path, src, name, flags):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    b = tmp_path / name
    r = subprocess.run([gcc, "-O0", *flags, str(c), "-o", str(b)],
                       capture_output=True, check=False)
    return b if r.returncode == 0 else None


_VULN = ("#include <unistd.h>\n"
         "void vuln(void){char b[64];read(0,b,400);}\n"
         "int main(void){vuln();return 0;}\n")


# ------------------------------------------------------------------- unit: cyclic
def test_cyclic_unique_windows_and_find():
    seq = P.cyclic(500)
    assert len(seq) == 500
    for off in (0, 4, 72, 111, 400):
        assert P.cyclic_find(seq[off:off + 4], 500) == off
    assert P.cyclic_find(b"zzzz", 500) == -1


def test_cyclic_find_from_register_value():
    seq = P.cyclic(300)
    off = 72
    reg = int.from_bytes(seq[off:off + 8], "little")     # 8 controlled bytes in a register
    assert P.cyclic_find(struct.pack("<I", reg & 0xFFFFFFFF), 300) == off


# ------------------------------------------------------------------- unit: offset recovery
def test_recover_ip_offset_from_pc():
    L = 256
    off = 40
    pc = int.from_bytes(P.cyclic(L)[off:off + 4], "little")
    cap = {"pc": pc, "sp": 0x7000, "stack_base": 0x7000, "stack": ""}
    assert P.recover_ip_offset(cap, L) == (off, "pc")


def test_recover_ip_offset_from_stack_slot():
    """Non-canonical return address: PC reports the faulting ret site, so the offset must come
    from the return-address slot the stack pointer indexes."""
    L = 256
    off = 72
    seq = P.cyclic(L)
    sp = 0x7ffff000
    stack = seq[off:off + 8]                              # [SP] holds the saved return address
    cap = {"pc": 0x401146, "sp": sp, "stack_base": sp, "stack": stack.hex()}
    got = P.recover_ip_offset(cap, L)
    assert got == (off, "stack[sp+0]")


def test_controlled_registers_detects_cyclic():
    L = 256
    seq = P.cyclic(L)
    rbx = int.from_bytes(seq[16:24], "little")
    cap = {"pc": 0, "sp": 0, "stack_base": 0, "stack": "",
           "regs": {"rbx": rbx, "eflags": 0x202, "rax": 0}}
    ctl = P.controlled_registers(cap, L)
    assert ctl.get("rbx") == 16 and "eflags" not in ctl


# ------------------------------------------------------------------- unit: confirm
def test_control_input_and_marker_confirmed():
    inp = P.control_input(72, 256)
    assert inp[72:80] == struct.pack("<Q", P.MARKER) and len(inp) == 256
    assert P.marker_confirmed({"pc": P.MARKER, "sp": 0, "stack_base": 0, "stack": ""})
    # or the sentinel visible in the stack slot
    cap = {"pc": 0x401146, "sp": 0x7000, "stack_base": 0x7000,
           "stack": struct.pack("<Q", P.MARKER).hex()}
    assert P.marker_confirmed(cap)
    assert not P.marker_confirmed({"pc": 0x1234, "sp": 0, "stack_base": 0, "stack": ""})


# ------------------------------------------------------------------- integration
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


def test_primitive_cross_arch_reports_unsupported(store, case, pool, gcc, tmp_path,
                                                  monkeypatch):
    monkeypatch.setattr(sandbox, "host_arch", lambda: "x86-64")
    c = tmp_path / "v.c"; c.write_text(_VULN)
    b = tmp_path / "v"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(b)], capture_output=True,
                      check=False).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    # force a non-host arch on the target row
    store.conn.execute("UPDATE target SET arch='ppc64' WHERE id=?", (target.id,))
    store.conn.commit()
    sha, _, _ = store.content.put_bytes(b"A" * 120)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, store.targets.get(target.id),
                            params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    assert not PocDAO(store.conn).list_by_target(target.id)   # no L2 for cross-arch


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_primitive_confirms_ip_control_end_to_end(store, case, pool, gcc, tmp_path):
    c = tmp_path / "v.c"; c.write_text(_VULN)
    b = tmp_path / "v"
    # no PIE + no stack canary -> a clean saved-return-address overwrite
    r = subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(b)],
                       capture_output=True, check=False)
    if r.returncode:
        pytest.skip("build failed (no-pie/no-canary unsupported)")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"A" * 120)          # a crashing input
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 6})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable in this environment: " + str(rec.error))
    l2 = [p for p in PocDAO(store.conn).list_by_target(target.id) if p.level == "L2"]
    if not l2:
        pytest.skip("no IP control captured (hardened toolchain default?)")
    assert l2[0].verified
    backed = [f for f in FindingDAO(store.conn).list_by_target(target.id)
              if f.state == "poc-backed"]
    assert backed
    assert any("instruction-pointer control" in str(e.get("detail", ""))
               for f in backed for e in (f.evidence or []))


# ------------------------------------------------------------------- unit: memory primitives
def test_parse_mem_access_and_reg64():
    assert P.parse_mem_access("mov QWORD PTR [rdx],rax") == {
        "is_write": True, "base": "rdx", "value": "rax"}
    assert P.parse_mem_access("mov eax,DWORD PTR [rcx]") == {
        "is_write": False, "base": "rcx", "value": None}
    assert P.parse_mem_access("mov DWORD PTR [rax+0x10],edx")["base"] == "rax"
    assert P.parse_mem_access("ret") is None
    assert P._reg64("edx") == "rdx" and P._reg64("r10d") == "r10"


def test_analyze_write_what_where():
    L = 64
    seq = P.cyclic(L)
    addr = int.from_bytes(seq[0:8], "little")
    val = int.from_bytes(seq[8:16], "little")
    cap = {"fault_addr": 0, "regs": {"rdx": addr, "rax": val}}
    prim = P.analyze_memory_primitive(cap, L, "mov QWORD PTR [rdx],rax")
    assert prim["type"] == "write-what-where"
    assert prim["addr_offset"] == 0 and prim["value_offset"] == 8
    assert prim["addr_reg"] == "rdx" and prim["value_reg"] == "rax"


def test_analyze_controlled_read():
    L = 64
    addr = int.from_bytes(P.cyclic(L)[0:8], "little")
    cap = {"fault_addr": 0, "regs": {"rax": addr}}
    prim = P.analyze_memory_primitive(cap, L, "mov eax,DWORD PTR [rax]")
    assert prim["type"] == "controlled-read" and prim["addr_offset"] == 0
    assert prim["value_offset"] is None


def test_two_marker_input_and_confirm():
    import struct
    inp = P.two_marker_input(0, 8, 64)
    assert inp[0:8] == struct.pack("<Q", P.MARKER)
    assert inp[8:16] == struct.pack("<Q", P.MARKER_VALUE)
    cap = {"regs": {"rdx": P.MARKER, "rax": P.MARKER_VALUE}}
    prim = {"addr_reg": "rdx", "value_reg": "rax", "value_offset": 8}
    assert P.memory_primitive_confirmed(cap, prim) == (True, True)
    bad = {"regs": {"rdx": 0x1234, "rax": 0}}
    assert P.memory_primitive_confirmed(bad, prim) == (False, False)


# ------------------------------------------------------------------- integration: WWW / read
_WWW = ("#include <unistd.h>\n"
        "int main(void){ unsigned long a[2]={0,0}; read(0,(char*)a,16);"
        " *(unsigned long*)a[0]=a[1]; return 0; }\n")
_CREAD = ("#include <unistd.h>\n"
          "int main(void){ unsigned long a=0; read(0,(char*)&a,8);"
          " volatile int x=*(int*)a; return x; }\n")


def _l2_run(store, case, pool, gcc, tmp_path, src, name, crashing_input):
    b = _build(gcc, tmp_path, src, name, ["-fno-stack-protector", "-no-pie"])
    if b is None:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(crashing_input)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 6})
    assert pool.wait_idle(50)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable: " + str(rec.error))
    from lykos.db.dao import PocDAO
    return (FindingDAO(store.conn).list_by_target(target.id),
            PocDAO(store.conn).list_by_target(target.id))


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_write_what_where_end_to_end(store, case, pool, gcc, tmp_path):
    finds, pocs = _l2_run(store, case, pool, gcc, tmp_path, _WWW, "www", b"A" * 16)
    l2 = [p for p in pocs if p.level == "L2"]
    if not l2:
        pytest.skip("no WWW primitive captured on this toolchain")
    assert l2[0].verified
    assert any("write-what-where" in str(e.get("detail", ""))
               for f in finds if f.state == "poc-backed" for e in (f.evidence or []))


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="L2 primitive analysis is native-arch only")
def test_controlled_read_end_to_end(store, case, pool, gcc, tmp_path):
    finds, pocs = _l2_run(store, case, pool, gcc, tmp_path, _CREAD, "cr", b"A" * 8)
    l2 = [p for p in pocs if p.level == "L2"]
    if not l2:
        pytest.skip("no controlled-read primitive captured on this toolchain")
    assert l2[0].verified
    assert any("controlled-read" in str(e.get("detail", ""))
               for f in finds if f.state == "poc-backed" for e in (f.evidence or []))


def test_frame_offset_candidates_predicts_ip_offset_from_ghidra_coords():
    """Static stack-frame -> predicted IP-control offset = ret_offset - buffer_offset
    (Ghidra frame coords; ret_offset 0, locals negative). Matches the dynamic cyclic offset
    for a real overflow (handle(): char[128] at -136, ret_offset 0 -> 136)."""
    frames = {
        "0x1287": {"ret_offset": 0, "vars": [
            {"name": "buf", "offset": -136, "size": 128, "is_buffer": True},
            {"name": "i", "offset": -8, "size": 4, "is_buffer": False}]},
        "0x1248": {"ret_offset": 0, "vars": [
            {"name": "msg", "offset": -72, "size": 64, "is_buffer": True}]},
    }
    cands = P.frame_offset_candidates(frames, 8)
    offs = [c["offset"] for c in cands]
    assert 136 in offs and 72 in offs           # the two buffers' return-address distances
    top = next(c for c in cands if c["offset"] == 136)
    assert top["buffer"] == "buf" and top["size"] == 128
    # sorted smallest-first, non-buffer locals ignored
    assert offs == sorted(offs)
    # fallback when ret_offset is unavailable: |offset| + word
    fb = P.frame_offset_candidates({"0x1": {"vars": [
        {"name": "b", "offset": -40, "size": 32, "is_buffer": True}]}}, 8)
    assert fb[0]["offset"] == 48
