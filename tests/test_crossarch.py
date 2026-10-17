"""Cross-architecture L2/root-cause via qemu-user's gdbstub (emulated targets)."""
import shutil
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
    # SuperH is the counterexample: qemu-sh4 serves no description, so it is the one layout
    # that has to be hand-written -- and it IS written, so the arch is supported.
    assert "sh" in qg._LAYOUTS and qg.supported("sh")


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


def test_breakpoints_go_at_the_even_address_on_lsb_masking_isas():
    """ARM marks a Thumb function by setting bit 0 of its SYMBOL value, but the code lives at
    the even address. A breakpoint placed at the odd address never fires -- verified against
    qemu-arm: bp at 0x10355 produced no stop at all, bp at 0x10354 hit immediately -- so a
    ret2win that genuinely redirected execution was reported as "hijack not reached".

    The payload must still carry the ODD address (bit 0 selects Thumb state), so the two
    cannot simply be normalised together: place even, report back what the caller asked for.
    """
    from lykos.analyze.debug import qemu_gdb as qg
    assert "arm" in qg.LSB_MASKED_PC and "aarch64" in qg.LSB_MASKED_PC
    assert "riscv" in qg.LSB_MASKED_PC
    # x86 code addresses are arbitrary bytes; masking one would move the breakpoint
    assert "x86" not in qg.LSB_MASKED_PC and "x86-64" not in qg.LSB_MASKED_PC
    assert "m68k" not in qg.LSB_MASKED_PC and "ppc64" not in qg.LSB_MASKED_PC


def test_win_address_packing_follows_the_target_not_the_host():
    """A 4-byte big-endian return address written as 8 little-endian bytes lands nowhere."""
    from lykos.analyze.poc import exploit
    be32 = exploit.ret2win_input(8, 0x80000420, 32, word=4, endian="big")
    assert be32[8:12] == b"\x80\x00\x04\x20"
    le64 = exploit.ret2win_input(8, 0x401146, 32, word=8, endian="little")
    assert le64[8:16] == (0x401146).to_bytes(8, "little")
    # the default stays x86-64 so existing callers are unaffected
    assert exploit.ret2win_input(8, 0x401146, 32)[8:16] == le64[8:16]


def test_superh_layout_is_hand_written_and_self_consistent():
    """qemu-sh4 serves no target description, so SuperH is the one layout that cannot be
    derived. Transcribed from qemu's SH4 gdbstub and verified against a live g-packet: 59
    32-bit registers (236 bytes), with an all-'A' overflow landing at indices 14, 16 and 17 --
    r14 (frame pointer), pc and pr (link register).
    """
    from lykos.analyze.debug import qemu_gdb as qg
    lay = qg._LAYOUTS["sh"]
    assert len(lay) == 59, "SuperH g-packet is 59 registers"
    assert sum(w for _, w in lay) == 236, "236 bytes total"
    names = [n for n, _ in lay]
    assert names[14] == "r14" and names[16] == "pc" and names[17] == "pr"
    assert qg._sp_name("sh") == "r15"
    assert qg.supported("sh") and qg.breakpoints_supported("sh")


# --------------------------------------------------------------------- cross-arch DECLINES
# The first foreign-architecture binary this project ever put through `real_corpus_gate.py` --
# busybox 1.21.1 for big-endian MIPS, static, stripped -- FAILED the gate, and not one of the
# five problems it reported was about MIPS. It ran: 3,934 executions at 61/s under qemu-user.
# What failed was the bookkeeping around the run.
#
#   busybox-mips-be  yes  3,934  60.7  82s  WORK 9  DECL 7  ERR 1
#     - stage errored: coverage_fuzz
#     - oob_index declined, unclassified: out-of-bounds array-index probing is native x86-64 ...
#     - heap_trace declined, unclassified: custom-allocator tracing is native x86-64 / ELF only
#     - heap_check declined, unclassified: heap check is native-arch only (target mips, host ...
#     - chain_primitive declined, unclassified: primitive chaining is native x86-64 / ELF only
#
# Each of those four declines was honest and correctly reached -- a host-ABI ptrace helper or
# LD_PRELOAD shim genuinely cannot reach into a qemu-emulated guest. They were all unclassified
# because the sentence was hand-written at each site and no phrasing matched the taxonomy in
# `capabilities`, which is a classifier fed by substring. So the gate could not score ANY
# cross-arch target: every one of them would fail on reasons that were right.
_FOREIGN = ("mips", "mipsel", "mips64", "ppc", "ppc64", "ppc64le", "s390x", "sparc", "sh4",
            "m68k", "riscv64", "aarch64", "arm", "microblaze")


class _Foreign:
    """The fields `_why_unavailable` reads. A foreign-arch ELF: real machine code, real
    execution (under qemu-user), and no host process to instrument."""
    def __init__(self, arch):
        self.arch, self.file_type, self.linking = arch, "elf", "static"
        self.mitigations, self.symbols = {}, []


def test_no_cross_arch_decline_is_unclassified():
    """Every stage that refuses a foreign-arch target must say so in words the taxonomy knows.

    Asserted over the whole capability map rather than over the five sites that were wrong,
    because the defect was not any one sentence -- it was that the sentence is written where
    the stage happens to be and read somewhere else entirely.
    """
    from lykos.analyze.capabilities import STAGES, _why_unavailable, classify_decline
    unknown = []
    for arch in _FOREIGN:
        t = _Foreign(arch)
        for stage in STAGES:
            why = _why_unavailable(stage, t)
            if why and classify_decline(why) == "unknown":
                unknown.append(f"{arch}/{stage}: {why[:80]}")
    assert not unknown, "unclassified cross-arch declines:\n" + "\n".join(unknown)


def test_cross_arch_decline_names_the_arch_and_the_host():
    """The canonical sentence, so an operator reading one decline knows which side refused."""
    from lykos.analyze import substrate
    why = substrate.foreign_cpu_reason("mips", "elf", "x86-64", "custom-allocator tracing")
    assert why and "mips" in why and "x86-64" in why
    assert "custom-allocator tracing" in why          # reads as the stage's own
    assert substrate.foreign_cpu_reason("x86-64", "elf", "x86-64", "anything") is None
    # A managed target has no CPU named in `arch`, so this is not the reason that applies.
    assert substrate.foreign_cpu_reason("jvm", "jar", "x86-64", "anything") is None


def test_coverage_fuzz_declines_for_a_guest_it_has_no_tracer_for(monkeypatch):
    """A missing GUEST tracer is a decline; a missing tracer on the NATIVE arch still raises.

    `coverage_fuzz` ERRORED on the MIPS target, and an error is never an acceptable outcome in
    this project -- a decline is. The reasoning that made it raise was sound for the case it was
    written for (Ubuntu's afl++ omits afl-qemu-trace on a native host, which an operator fixes
    in ten minutes) and wrong for this one: no distribution ships a MIPS tracer at all, the
    orchestrator had already fuzzed the target 3,934 times through the black-box stage, and the
    run still reported a broken stage.
    """
    from lykos.analyze.capabilities import classify_decline
    from lykos.analyze.fuzz import aflpp, coverage
    monkeypatch.setattr(aflpp, "locate_afl", lambda *a, **k: "/usr/bin/afl-fuzz")
    monkeypatch.setattr(aflpp, "locate_qemu_trace", lambda *a, **k: None)
    monkeypatch.setattr(aflpp, "locate_qemu_trace_for", lambda *a, **k: None)

    why = coverage._unsupported(_Foreign("mips"), True)
    assert why and why != coverage.toolchain_missing()      # a decline, so the stage will not raise
    assert "mips" in why and "CPU_TARGET=mips" in why       # and it says how to get the capability
    assert classify_decline(why) == "target"

    host = sandbox.host_arch()
    native = _Foreign(host)
    assert coverage._unsupported(native, True) == coverage.toolchain_missing()


def test_a_decline_survives_the_window_the_scorecard_stores_it_in():
    """Classification must not depend on how long the sentence is.

    `_declines_from_events` keeps a bounded prefix of each decline note, and
    `classify_decline` reads that prefix -- so a note whose category phrase sits past the cut
    is "unclassified", which the gate prints as a defect. That is exactly what happened: the
    coverage_fuzz cross-arch decline put "cross-arch" in its last clause, and all ten
    foreign-architecture binaries in the first sweep failed the gate on it. The window was
    widened AND the sentences now lead with their category; this asserts the pair.
    """
    from lykos.analyze.capabilities import STAGES, _why_unavailable, classify_decline
    bad = []
    for arch in _FOREIGN:
        for stage in STAGES:
            why = _why_unavailable(stage, _Foreign(arch))
            if not why:
                continue
            full, cut = classify_decline(why), classify_decline(why[:240])
            if full != cut or cut == "unknown":
                bad.append(f"{arch}/{stage}: full={full} truncated={cut}: {why[:70]}")
    assert not bad, "a decline's classification changes when it is truncated:\n" + "\n".join(bad)


def test_alpha_is_derivable_and_hppa_is_not():
    """Both were PROBED against a live stub on 2026-10-16, which is the only way to know.

    `qemu-alpha` serves a target description of 66 registers, naming them symbolically -- v0,
    t0-t7, s0-s5, fp, a0-a5, t8-t12, ra, at, gp, sp, zero, f0-f30, fpcr, pc, unique -- so `sp`
    and `pc` are those exact names and the layout needs no hand-written table. `qemu-hppa`,
    probed the same way with the same code, answers with NO description at all (0 registers),
    like qemu-sh4: PA-RISC would need its layout transcribed from qemu's source and verified
    against a live g-packet, so it stays at L1 with that recorded as the reason.

    This is the pair the archgate rows for the two arches rest on; asserting the ISA manual
    instead would be asserting a guess.
    """
    from lykos.analyze.debug import qemu_gdb as qg
    assert qg.supported("alpha") and "alpha" not in qg._LAYOUTS
    assert qg._sp_name("alpha") == "sp" and qg._pc_name("alpha") == "pc"
    assert qg._ARG_REGS["alpha"][0] == "a0", "the stub names them a0-a5, not r16-r21"
    # hppa is supported too, as of the same day -- but by the OTHER route, which is the point of
    # this pair: nothing can be derived from a stub that serves no description, so PA-RISC has a
    # hand-written layout (verified against a live g-packet) while alpha has none at all.
    assert qg.supported("hppa") and "hppa" in qg._LAYOUTS
    assert "hppa" not in qg._STUB_ABI, "there is no description to derive hppa from"


# --------------------------------------------------------------- PA-RISC, the second hand-written
# layout. `qemu-hppa` serves NO target description -- `qXfer:features:read` comes back with zero
# registers, probed 2026-10-16 -- so hppa cannot be derived the way alpha, m68k, loongarch,
# sparcv9 and x86 are. Like sh4's, its layout is transcribed and then VERIFIED against a live
# g-packet, because a register order read off a manual is a guess with a citation.
def test_the_hppa_layout_is_shaped_the_way_the_live_stub_answered():
    """The three facts in the measured dump that pin the layout, as assertions.

    128 words came back for a static hppa binary stopped at a fault:
      * words 33 and 35 differ by exactly 4 -- the instruction-address queue pair (iaoq_f is the
        executing instruction, iaoq_b the next), which is what identifies the PC at all;
      * word 30 held a stack address, i.e. r30 == SP on this ABI;
      * word 0 held 0x0001ff00, which cannot be gr0 (architecturally always zero), so the GPRs
        start at index 1 and the first word is the PSW.
    """
    from lykos.analyze.debug import qemu_gdb as qg
    lay = qg._layout_for("hppa")
    names = [n for n, _ in lay]
    assert names[0] == "psw", "gr0 is always zero; a non-zero word 0 is the PSW"
    assert names[1:32] == [f"r{i}" for i in range(1, 32)]
    assert names.index("pc") == 33 and names.index("iaoq_b") == 35
    assert all(w == 4 for _n, w in lay), "PA-RISC here is 32-bit"
    assert qg._sp_name("hppa") == "r30" and qg._pc_name("hppa") == "pc"
    assert qg._ARG_REGS["hppa"] == ["r26", "r25", "r24", "r23"]
    assert qg.supported("hppa") and "hppa" not in qg._STUB_ABI


@pytest.mark.skipif(not shutil.which("qemu-hppa") or not shutil.which("hppa-linux-gnu-gcc"),
                    reason="needs qemu-hppa and an hppa cross compiler")
def test_hppa_registers_come_back_from_a_live_stub(tmp_path):
    """The layout, parsed by the project's own `_parse_regs`, off a real fault."""
    import binascii
    import socket
    import subprocess
    import time

    from lykos.analyze.debug import qemu_gdb as qg
    src = tmp_path / "ov.c"
    src.write_text("#include <stdio.h>\nint main(void){char b[64];"
                   "if(scanf(\"%s\", b)!=1) return 0; printf(\"%s\\n\", b); return 0;}\n")
    exe = tmp_path / "ov"
    if subprocess.run(["hppa-linux-gnu-gcc", "-O0", "-fno-stack-protector", "-static", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("hppa build failed")
    port = 12833
    p = subprocess.Popen(["qemu-hppa", "-g", str(port), str(exe)], stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        sock = None
        for _ in range(60):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                break
            except OSError:
                time.sleep(0.1)
        if sock is None:
            pytest.skip("no gdbstub connection")
        qg._txn(sock, "qSupported")
        p.stdin.write(b"A" * 400 + b"\n")
        p.stdin.flush()
        assert qg._txn(sock, "c", timeout=15).startswith("T"), "the stub reported no stop"
        g = qg._txn(sock, "g", timeout=15)
        assert len(g) >= 36 * 8, "the g-packet is shorter than the layout"
        regs = qg._parse_regs(g, "hppa", endianness="big")
        assert regs["iaoq_b"] == regs["pc"] + 4, "the instruction queue pair did not line up"
        assert regs["r30"] > 0x1000, "r30 does not look like a stack pointer"
        assert binascii.unhexlify(g[:8]) != b"\x00\x00\x00\x00", "word 0 is not gr0"
    finally:
        p.kill()


def test_a_shared_object_is_not_executed(tmp_path):
    """A library is LINKED AGAINST, not run -- and running one fabricated the worst finding this
    tool can emit.

    Measured on json-c 0.13.1: its cmake build produces no executables, so the source-project
    builder fell back to shared objects and returned `libjson-c.so` as the primary target,
    labelled `kind: "library"` and then executed anyway. The loader faulted before any user code
    at a non-executable page in its own mapping, and root_cause read that exactly as it reads:

      control-flow-hijack (CWE-787) in entry0: program counter 0x7ffff7f6b000 is not in
      executable memory (attacker-controlled execution transfer)

    filed poc-backed as "Remote code execution / control-flow hijack" in a JSON library, 17
    times. The refusal lives at the single door every execution goes through.
    """
    import subprocess

    from lykos.analyze.capabilities import classify_decline
    from lykos.analyze.dynamic import sandbox as S
    src = tmp_path / "l.c"; src.write_text("int answer(void){return 42;}\n")
    lib = tmp_path / "libl.so"
    if subprocess.run(["gcc", "-shared", "-fPIC", "-w", str(src), "-o", str(lib)],
                      capture_output=True).returncode:
        pytest.skip("cannot build a shared object here")
    assert S._is_elf_shared_object(str(lib))
    # a PIE EXECUTABLE is also ET_DYN, which is why the type alone decides nothing
    exe = tmp_path / "p"
    src2 = tmp_path / "p.c"; src2.write_text("int main(void){return 0;}\n")
    subprocess.run(["gcc", "-pie", "-fPIE", "-w", str(src2), "-o", str(exe)],
                   capture_output=True, check=False)
    if exe.exists():
        assert not S._is_elf_shared_object(str(exe))

    r = S.run(str(lib), argv=[], stdin=b"", timeout=5)
    assert not r.crashed, "a library that 'crashes' is the loader, not the program"
    assert r.isolation == "not-runnable" and "no entry point" in (r.note or "")
    assert S.run_batch(str(lib), [b"A"], timeout=2) is None
    # and the refusal has to be classifiable, or the gate reads it as our defect
    assert classify_decline(r.note) == "target"
