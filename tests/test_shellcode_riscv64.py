"""Cross-architecture ret2shellcode on RISC-V 64: inject execve("/bin/sh") shellcode into an
execstack overflow and run it under qemu-user. Mirrors tests/test_shellcode_aarch64.py -- the NX-off
companion to the ret2libc ladder, extended to RISC-V through the shared `_shellcode_emu_exploit`
path (a per-arch jump-through-register gadget + per-arch shellcode stubs)."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import rop, shellcode

_RV_GCC = shutil.which("riscv64-linux-gnu-gcc")
_RV_QEMU = shutil.which("qemu-riscv64") or shutil.which("qemu-riscv64-static")


def test_execve_binsh_riscv64_shape():
    """The execve stub is 24 bytes of (all-4-byte, no compressed) code + "/bin/sh\\0" -- the +24
    PC-relative offset that points a0 at the string depends on that exact length."""
    sc = shellcode.execve_binsh_riscv64()
    assert len(sc) == 32 and sc.endswith(b"/bin/sh\x00")
    assert sc[:4] == struct.pack("<I", 0x00000517)       # auipc a0, 0


def test_write_marker_riscv64_patches_length():
    sc = shellcode.write_marker_riscv64(b"LYKOS!!")       # 7-byte marker
    assert sc.endswith(b"LYKOS!!") and len(sc) == 36 + 7
    # the length immediate (7) is patched into `addi a2, zero, len` (the 4th word)
    assert struct.unpack("<I", sc[12:16])[0] == (0x00000613 | (7 << 20))


def test_find_jr_gadgets_riscv64_decodes_jr_and_jalr():
    seg = struct.pack("<II", 0x00050067, 0x000500E7)      # jr a0 ; jalr a0
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x10000, 1)]
    try:
        g = rop.find_jr_gadgets_riscv64(seg)
    finally:
        rop._loads = orig
    assert any(x["insn"] == "jr" and x["reg"] == "x10" and x["va"] == 0x10000 for x in g)
    assert any(x["insn"] == "jalr" and x["reg"] == "x10" for x in g)


@pytest.mark.skipif(not (_RV_GCC and _RV_QEMU), reason="needs riscv64-linux-gnu-gcc + qemu-riscv64")
def test_auto_files_l3_riscv64_ret2shellcode(store, tmp_path):
    """strategy=auto drives a RISC-V 64 execstack overflow with a `jr a0` gadget (a0 left pointing at
    the buffer) to a confirmed L3: injected execve("/bin/sh") shellcode runs under qemu-user and
    spawns a real shell (or writes a marker), the redirect recovered with no leak."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(
        '#include <unistd.h>\n#include <stdio.h>\n'
        '__asm__(".text\\n.globl g\\ng:\\n .word 0x00050067\\n");\n'   # jr a0  (jalr x0,a0,0)
        'void vuln(void){ char b[256]; read(0,b,1024);'
        ' __asm__ volatile("mv a0, %0"::"r"(b):"a0","memory"); }\n'
        'int main(void){ setbuf(stdout,0); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_RV_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-march=rv64g", "-z", "execstack", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build riscv64 execstack fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("rv64sc").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"   # execstack
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 RISC-V 64 ret2shellcode"
