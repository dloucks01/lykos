"""Cross-architecture ret2shellcode: inject AArch64 shellcode into an execstack overflow and run
it under qemu-user, reaching it through a `br/blr <Xn>` gadget (the aarch64 `jmp <reg>`) with no
info leak. Confirmed by a WRITTEN marker -- execve('/bin/sh') under qemu-user is unreliable, a
write(2) marker is not -- with an echo-guard negative control."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import rop, shellcode

_A64_GCC = shutil.which("aarch64-linux-gnu-gcc")
_QEMU = shutil.which("qemu-aarch64") or shutil.which("qemu-aarch64-static")


def test_write_marker_aarch64_encoding():
    """The stub is 7 fixed instructions + the marker; the length immediate is patched in."""
    sc = shellcode.write_marker_aarch64(b"HELLO\n")
    words = struct.unpack("<7I", sc[:28])
    assert words[0] == 0xD2800020                        # mov x0, #1
    assert words[1] == 0x100000C1                        # adr x1, marker (+24)
    assert words[2] == 0xD2800002 | (6 << 5)             # movz x2, #6  (len "HELLO\n")
    assert words[3] == 0xD2800808 and words[4] == 0xD4000001   # mov x8,#64 ; svc
    assert words[5] == 0xD2800BA8 and words[6] == 0xD4000001   # mov x8,#93 ; svc
    assert sc[28:] == b"HELLO\n"


def test_find_br_gadgets_aarch64():
    # blr x0 (d63f0000), br x1 (d61f0020) in a fake exec segment
    seg = struct.pack("<I", 0xD63F0000) + b"\x00\x00\x00\x00" + struct.pack("<I", 0xD61F0020)
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x400000, 1)]
    try:
        gs = rop.find_br_gadgets_aarch64(seg)
    finally:
        rop._loads = orig
    found = {(g["insn"], g["reg"]) for g in gs}
    assert ("blr", "x0") in found and ("br", "x1") in found


@pytest.mark.skipif(not (_A64_GCC and _QEMU),
                    reason="needs aarch64-linux-gnu-gcc + qemu-aarch64")
def test_auto_files_l3_aarch64_ret2shellcode(store, tmp_path):
    """strategy=auto drives an AArch64 execstack overflow with a blr gadget (a register left
    pointing at the buffer) to a confirmed L3 -- injected shellcode runs under qemu and writes a
    unique marker; the redirect is recovered with no leak."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(
        '#include <unistd.h>\n#include <stdio.h>\n'
        '__asm__(".text\\n.globl g\\ng:\\n .inst 0xd63f0000\\n");\n'   # blr x0 gadget
        'void vuln(void){ char b[256]; read(0,b,1024);'
        ' __asm__ volatile("mov x0, %0"::"r"(b):"x0","memory"); }\n'
        'int main(void){ setbuf(stdout,0); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_A64_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-z", "execstack", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build aarch64 execstack fixture")

    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("a64").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"  # execstack
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 AArch64 ret2shellcode"
