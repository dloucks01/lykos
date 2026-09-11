"""Cross-architecture L2/root-cause via qemu-user's gdbstub (emulated targets)."""
import struct

import pytest
from lykos.analyze import register
from lykos.analyze.debug import qemu_gdb
from lykos.analyze.debug.stage import enqueue_root_cause
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.poc import primitive
from lykos.analyze.poc.primitive_stage import enqueue_primitive
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# aarch64: read 8 bytes from stdin, then `br` to them -> PC = the input (control-flow hijack).
_AARCH64_BRANCH_TO_INPUT = [
    0xD28007E8,  # movz x8, #63      (read)
    0xD2800000,  # movz x0, #0       (fd=0)
    0xD2801301,  # movz x1, #0x98    (&buf lo)
    0xF2A00801,  # movk x1, #0x40,lsl#16  (&buf hi -> 0x400098)
    0xD2800102,  # movz x2, #8       (count)
    0xD4000001,  # svc #0
    0xF9400029,  # ldr x9, [x1]
    0xD61F0120,  # br x9
]


def _aarch64_elf(path):
    code = b"".join(struct.pack("<I", w) for w in _AARCH64_BRANCH_TO_INPUT) + b"\x00" * 8
    base, ehsz, phsz = 0x400000, 64, 56
    entry, fsz = base + ehsz + phsz, ehsz + phsz + len(code)
    eh = (b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
          + struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, entry, ehsz, 0, 0, ehsz, phsz, 1, 0, 0, 0))
    ph = struct.pack("<IIQQQQQQ", 1, 7, 0, base, base, fsz, fsz, 0x1000)
    path.write_bytes(eh + ph + code)
    path.chmod(0o755)
    return path


def _need_qemu_aarch64():
    if sandbox.host_arch() == "aarch64" or not sandbox._qemu_for("aarch64"):
        pytest.skip("needs a non-aarch64 host with qemu-aarch64")


def test_qemu_gdbstub_captures_crossarch_fault_registers(tmp_path):
    """The stdlib RSP client recovers the exact fault-time PC (the hijacked value) and signal
    from a foreign-ISA guest under qemu-user -- the basis for cross-arch L2/root-cause."""
    _need_qemu_aarch64()
    exe = _aarch64_elf(tmp_path / "rb")
    cap = qemu_gdb.capture(str(exe), "aarch64", stdin=b"ABCDEFGH", endianness="little", bits=64)
    assert cap["ok"] and cap["signal_name"] == "SIGSEGV"
    assert cap["pc"] & 0xFFFFFFFF == int.from_bytes(b"ABCD", "little")   # low bytes = input
    # a cyclic pattern in PC -> the control offset is recovered (offset 0 here)
    cap2 = qemu_gdb.capture(str(exe), "aarch64", stdin=primitive.cyclic(64)[:8],
                            endianness="little", bits=64)
    assert primitive.recover_ip_offset(cap2, 64) == (0, "pc")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=2, lease_seconds=90, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _ingest_aarch64(store, case, pool, tmp_path):
    exe = _aarch64_elf(tmp_path / "rb")
    q = JobQueue(store.conn)
    t = ingest(store, case.id, exe, filename="rb")
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    t = store.targets.get(t.id)
    assert t.arch == "aarch64" and t.endianness == "little"      # arch read from the ELF
    return q, t


def test_l2_primitive_confirmed_on_emulated_target(store, case, pool, tmp_path):
    """The L2 primitive recovers and CONFIRMS instruction-pointer control on a cross-arch
    (aarch64) target through the qemu gdbstub -- the app figures out the control offset."""
    _need_qemu_aarch64()
    q, t = _ingest_aarch64(store, case, pool, tmp_path)
    sha = store.put_artifact(case.id, "crash", data=b"AAAAAAAA").sha256
    run = enqueue_primitive(q, t, params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    payload = next(e.payload for e in q.events.list(run_id=run.id, limit=50)
                   if e.type == "primitive.done")
    assert payload["primitive"] == "instruction-pointer-control"
    assert payload["confirmed"] and payload["offset"] == 0 and payload["level"] == "L2"
    pocs = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.verified]
    assert pocs and pocs[0].level == "L2"


def test_root_cause_on_emulated_target(store, case, pool, tmp_path):
    """Root-cause captures the fault of a cross-arch target via the qemu gdbstub and files a
    confirmed root-cause finding (classification is best-effort without a fault address)."""
    _need_qemu_aarch64()
    q, t = _ingest_aarch64(store, case, pool, tmp_path)
    sha = store.put_artifact(case.id, "crash", data=b"BBBBBBBB").sha256
    run = enqueue_root_cause(q, t, params={"input_sha": sha, "input_mode": "stdin"})
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    payload = next(e.payload for e in q.events.list(run_id=run.id, limit=50)
                   if e.type == "rootcause.done")
    assert payload["supported"] and payload["backend"] == "qemu-gdbstub"
    assert any(f.detector == "root_cause" and f.state == "confirmed"
               for f in FindingDAO(store.conn).list_by_target(t.id))


# ------------------------------------------------- stub-derived register layouts (no table)
def test_stub_abi_declares_what_the_description_cannot():
    """A target description lists registers and widths, but not WHICH one is the stack pointer
    or program counter -- and the names are not guessable: i386 calls them esp/eip, and
    LoongArch has no register named "sp" at all (its stack pointer is r3). Those stay declared.
    """
    from lykos.analyze.debug import qemu_gdb as qg
    assert qg._sp_name("x86") == "esp" and qg._pc_name("x86") == "eip"
    assert qg._sp_name("loongarch") == "r3" and qg._pc_name("loongarch") == "pc"
    assert qg._sp_name("m68k") == "sp" and qg._pc_name("m68k") == "pc"
    # hand-written layouts keep their existing sp names and the default pc
    assert qg._sp_name("aarch64") == "sp" and qg._pc_name("aarch64") == "pc"
    assert qg._sp_name("mips") == "r29"


def test_derivable_arches_report_supported_without_a_hardcoded_layout():
    """These have no _LAYOUTS entry -- support comes from fetching the stub's description."""
    from lykos.analyze.debug import qemu_gdb as qg
    for arch in ("loongarch", "m68k", "sparcv9", "x86"):
        assert arch not in qg._LAYOUTS
        assert qg.supported(arch), f"{arch} should be supported via the stub description"
    # qemu-sh4 serves no description at all, so SuperH stays honestly unsupported
    assert not qg.supported("sh")


def test_fetch_layout_parses_a_target_description():
    """Register order and widths come from the description, including xi:include expansion."""
    from lykos.analyze.debug import qemu_gdb as qg

    core = ('<target><xi:include href="core.xml"/>'
            '<reg name="pc" bitsize="32"/></target>')
    inc = ('<feature><reg name="d0" bitsize="32"/><reg name="a0" bitsize="32"/>'
           '<reg name="fp80" bitsize="80"/></feature>')
    replies = {"target.xml": core, "core.xml": inc}

    class FakeSock:
        def __init__(self):
            self.n = 0

        def _reply(self, req):
            # qXfer:features:read:<name>:<off>,<len>
            name = req.split(":")[3]
            off = int(req.split(":")[4].split(",")[0], 16)
            body = replies[name]
            return "l" + body[off:]

    sock = FakeSock()
    orig = qg._txn
    qg._txn = lambda s, data, timeout=5.0: sock._reply(data)
    try:
        lay = qg._fetch_layout(sock)
    finally:
        qg._txn = orig
    # target.xml's own regs first, then the include, in document order
    assert ("pc", 4) in lay and ("d0", 4) in lay and ("a0", 4) in lay
    assert ("fp80", 10) in lay          # 80 bits rounds up to 10 bytes
