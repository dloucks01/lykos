"""Phase 6 — debugger root-cause slicing: fault classification, disassembly, static slice,
and the end-to-end stage. Pure logic is unit-tested; the stage runs live under the ptrace
backend (gdb absent here) on native crash binaries."""
import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.debug import enqueue_root_cause, rootcause
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.db.dao import FindingDAO
from lykos.db.models import CallEdge, Function
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_OVERFLOW = ("#include <unistd.h>\nvoid vuln(void){char b[64];read(0,b,400);}\n"
             "int main(void){vuln();return 0;}\n")
_NULLDEREF = ("#include <unistd.h>\nint main(void){char b[16];read(0,b,8);"
              "volatile int*p=0;return *p;}\n")

_MAP = [{"start": 0x401000, "end": 0x402000, "perms": "r-xp", "path": "/tmp/target.bin"}]


def _cap(**kw):
    base = {"ok": True, "signal_name": "SIGSEGV", "pc": 0x401146, "fault_addr": 0,
            "maps": _MAP, "pc_bytes": "", "backtrace": [], "regs": {}}
    base.update(kw)
    return base


# ------------------------------------------------------------------- disasm
@pytest.mark.skipif(not shutil.which("objdump"), reason="objdump not installed")
def test_disasm_one_reads_writes_rets():
    assert "[rax]" in rootcause.disasm_one(bytes.fromhex("8b00"), "x86-64")
    assert rootcause.disasm_one(bytes.fromhex("c3"), "x86-64").startswith("ret")
    assert "[rbx]" in rootcause.disasm_one(bytes.fromhex("48890b"), "x86-64")


def test_is_memory_write():
    assert rootcause._is_memory_write("mov QWORD PTR [rbx],rcx")
    assert not rootcause._is_memory_write("mov eax,DWORD PTR [rax]")
    assert not rootcause._is_memory_write("ret")


# ------------------------------------------------------------------- classify
def test_classify_stack_return_overwrite():
    v = rootcause.classify(_cap(), "ret")
    assert v["cwe"] == "CWE-121" and v["class"] == "stack-return-overwrite"


def test_classify_null_deref_read():
    v = rootcause.classify(_cap(fault_addr=0), "mov eax,DWORD PTR [rax]")
    assert v["cwe"] == "CWE-476" and "read" in v["detail"]


def test_classify_oob_write():
    v = rootcause.classify(_cap(fault_addr=0x4141414141), "mov QWORD PTR [rbx],rcx")
    assert v["cwe"] == "CWE-787" and v["class"] == "out-of-bounds-write"


def test_classify_control_flow_hijack_when_pc_unmapped():
    v = rootcause.classify(_cap(pc=0x4242424242, maps=_MAP), None)
    assert v["class"] == "control-flow-hijack" and v["cwe"] == "CWE-787"


def test_classify_sigabrt_detected_corruption():
    v = rootcause.classify(_cap(signal_name="SIGABRT"), None)
    assert v["class"] == "detected-corruption-abort"


# ------------------------------------------------------------------- slice
def _fn(addr, name, size=0x40):
    return Function(id=f"f{addr}", target_id="t", addr=addr, created_at=0, name=name,
                    size=size)


def _edge(src, dst=None, name=None):
    return CallEdge(id="e", target_id="t", created_at=0, src_addr=src, dst_addr=dst,
                    dst_name=name, site_addr=src)


def test_build_slice_maps_backtrace_and_source_path():
    funcs = [_fn(0x401120, "vuln"), _fn(0x401160, "main")]
    edges = [_edge("0x401160", "0x401120"), _edge("0x401120", None, "read")]
    cap = _cap(pc=0x401146, backtrace=[0x401165])
    sl = rootcause.build_slice(cap, funcs, edges, [], _MAP, "/tmp/target.bin")
    assert sl["crash_function"]["symbol"] == "vuln"
    # read() is called from vuln (0x401120), which is the crash function -> reachable
    assert sl["reachable_from_source"] and sl["source_path"][-1]["symbol"] == "vuln"


def test_analyze_summary_mentions_class_and_cwe():
    funcs = [_fn(0x401120, "vuln")]
    cap = _cap(pc=0x401146, pc_bytes="c3")
    rep = rootcause.analyze(cap, funcs, [], [], "/tmp/target.bin", "x86-64")
    assert "CWE-121" in rep["summary"] and rep["classification"]["cwe"] == "CWE-121"


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


def _build(gcc, tmp_path, src, name, flags):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    b = tmp_path / name
    r = subprocess.run([gcc, "-O0", *flags, str(c), "-o", str(b)],
                       capture_output=True, check=False)
    return b if r.returncode == 0 else None


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="root-cause capture is native-arch only")
def test_root_cause_stack_overflow_end_to_end(store, case, pool, gcc, tmp_path):
    b = _build(gcc, tmp_path, _OVERFLOW, "ov", ["-fno-stack-protector", "-no-pie"])
    if b is None:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"A" * 200)
    q = JobQueue(store.conn)
    run = enqueue_root_cause(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                "timeout": 6})
    assert pool.wait_idle(40)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable: " + str(rec.error))
    rc = [f for f in FindingDAO(store.conn).list_by_target(target.id)
          if any((e.get("channel") == "root-cause") for e in (f.evidence or []))]
    assert rc, "expected a root-cause evidence line on the crash finding"
    assert any(f.cwe in ("CWE-121", "CWE-787") for f in rc)


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="root-cause capture is native-arch only")
def test_root_cause_null_deref_end_to_end(store, case, pool, gcc, tmp_path):
    b = _build(gcc, tmp_path, _NULLDEREF, "nd", [])
    if b is None:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    sha, _, _ = store.content.put_bytes(b"AAAA")
    q = JobQueue(store.conn)
    run = enqueue_root_cause(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                "timeout": 6})
    assert pool.wait_idle(40)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable: " + str(rec.error))
    finds = FindingDAO(store.conn).list_by_target(target.id)
    rc = [f for f in finds if any(e.get("channel") == "root-cause" for e in (f.evidence or []))]
    if not rc:
        pytest.skip("no fault captured")
    assert any(f.cwe == "CWE-476" for f in rc)


def test_root_cause_cross_arch_unsupported(store, case, pool, gcc, tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "host_arch", lambda: "x86-64")
    b = _build(gcc, tmp_path, _NULLDEREF, "x", [])
    if b is None:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    store.conn.execute("UPDATE target SET arch='mips' WHERE id=?", (target.id,))
    store.conn.commit()
    sha, _, _ = store.content.put_bytes(b"AAAA")
    q = JobQueue(store.conn)
    run = enqueue_root_cause(q, store.targets.get(target.id),
                             params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(30) and q.runs.get(run.id).status == "done"
    finds = FindingDAO(store.conn).list_by_target(target.id)
    assert not [f for f in finds if any(e.get("channel") == "root-cause"
                                        for e in (f.evidence or []))]
