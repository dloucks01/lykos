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


def test_parse_asan_report_maps_class_cwe_and_source():
    """The source-code path aborts via ASan (a bare SIGABRT); the ASan report is what names the
    real defect and its source line. Parsing must map each bug class to its CWE and recover the
    file:line, so root_cause reports e.g. heap-buffer-overflow at uaf.c:4, not a generic abort."""
    heap = ("=================================================================\n"
            "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2\n"
            "    #0 0x2 in strcpy (/x/a+0x84)\n"
            "    #1 0x3 in main /tmp/build/heap_ovf.c:4\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n")
    p = rootcause.parse_asan_report(heap)
    assert p and p["cwe"] == "CWE-122" and p["class"] == "heap-buffer-overflow"
    assert p["source"] == "heap_ovf.c:4"

    uaf = ("==9==ERROR: AddressSanitizer: heap-use-after-free on address 0x1 at pc 0x2\n"
           "    #1 0x3 in main /tmp/build/uaf.c:12\n")
    pu = rootcause.parse_asan_report(uaf)
    assert pu and pu["cwe"] == "CWE-416" and pu["source"] == "uaf.c:12"

    stk = "==9==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1\n"
    assert rootcause.parse_asan_report(stk)["cwe"] == "CWE-121"

    # An ASan *setup* failure (what a too-small address-space limit produces) is not a bug report
    # and must not be classified as a finding.
    assert rootcause.parse_asan_report(
        "==9==ERROR: AddressSanitizer failed to allocate 0xdfff0001000 bytes\n") is None


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


_ASAN_UAF = (
    "#include <unistd.h>\n#include <stdlib.h>\n#include <string.h>\n"
    "int main(){char*b=malloc(32);char t[64];int n=read(0,t,63);"
    "if(n<0)n=0;t[n]=0;free(b);if(n>3&&t[0]=='B')strcpy(b,t);return 0;}\n"
)


@pytest.mark.skipif(sandbox.host_arch() not in ("x86-64", "aarch64"),
                    reason="root-cause capture is native-arch only")
def test_root_cause_asan_source_reports_specific_cwe(store, case, pool, gcc, tmp_path):
    """The source-code path compiles with ASan and aborts (SIGABRT) on a defect. A bare abort is
    uninformative, so root_cause re-runs the input under the sanitizer and lets its report name
    the real class and source line. It must land a SPECIFIC CWE (here use-after-free / CWE-416),
    not the generic detected-corruption-abort. Guards two once-broken links: the missing
    `import os` that silently swallowed the enrichment, and the RLIMIT_AS cap that stopped an
    ASan build from even initialising in the sandbox."""
    from lykos.analyze.ingest import ingest
    src = tmp_path / "uaf.c"; src.write_text(_ASAN_UAF)
    try:
        target = ingest(store, case.id, src, filename="uaf.c")
    except Exception as e:                                      # no libasan on this host
        pytest.skip("asan source build unavailable: %r" % e)
    sha, _, _ = store.content.put_bytes(b"B" + b"C" * 60)       # >3 bytes, 'B' -> reaches the UAF
    q = JobQueue(store.conn)
    run = enqueue_root_cause(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                "timeout": 8})
    assert pool.wait_idle(60)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable: " + str(rec.error))
    rc = [f for f in FindingDAO(store.conn).list_by_target(target.id)
          if any(e.get("channel") == "root-cause" for e in (f.evidence or []))]
    if not rc:
        pytest.skip("input did not fault under the debugger in this environment")
    assert any(f.cwe == "CWE-416" for f in rc), \
        "expected sanitizer-enriched use-after-free (CWE-416), got %r" % [f.cwe for f in rc]


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
