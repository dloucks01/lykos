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


def test_find_aarch64_r2libc_gadgets():
    """The byte-decode scanner (no objdump) finds the caller (mov x0,xS; blr xB) and loader
    (ldp xR1,xR2,[sp]; ldp x29,x30,[sp],#M; ret), and a {src,br}=={r1,r2} pair chains them."""
    def ldp(rt, rt2, rn, imm, base):                      # 64-bit LDP, base picks the index mode
        return base | ((imm // 8 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt
    seg = struct.pack("<I", 0xAA0003E0 | (19 << 16))      # mov x0, x19
    seg += struct.pack("<I", 0xD63F0000 | (20 << 5))      # blr x20   (caller @ +0)
    loader = struct.pack("<I", ldp(19, 20, 31, 16, 0xA9400000))   # ldp x19,x20,[sp,#16]
    loader += struct.pack("<I", ldp(29, 30, 31, 32, 0xA8C00000))  # ldp x29,x30,[sp],#32 (post)
    loader += struct.pack("<I", 0xD65F03C0)               # ret       (loader @ +8)
    seg += loader
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x400000, 1)]
    try:
        g = rop.find_aarch64_r2libc_gadgets(seg)
    finally:
        rop._loads = orig
    assert any(c["src"] == 19 and c["br"] == 20 for c in g["callers"])
    assert any(ll["r1"] == 19 and ll["r2"] == 20 for ll in g["loaders"])
    assert any({c["src"], c["br"]} == {ll["r1"], ll["r2"]}
               for c in g["callers"] for ll in g["loaders"])


@pytest.mark.skipif(not (_A64_GCC and _QEMU),
                    reason="needs aarch64-linux-gnu-gcc + qemu-aarch64")
def test_auto_files_l3_aarch64_ret2libc(store, tmp_path):
    """strategy=auto drives an NX-ON AArch64 stack overflow to a confirmed L3 ret2libc: a two-gadget
    chain (ldp loader + `mov x0,x19; blr x20` caller) calls system("/bin/sh"), confirmed by reaching
    `system` with x0=&"/bin/sh" under the qemu debugger + a negative control. No execstack, no leak."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(
        '#include <stdlib.h>\n#include <unistd.h>\n'
        'char cmd[16] = "/bin/sh";\n'
        # the ret2libc caller gadget (the rare piece; a solvable target provides it, as x86-64
        # fixtures provide "pop rdi; ret"). The ldp x19,x20/ldp x29,x30 loader is ubiquitous.
        '__asm__(".text\\n.global r2l_gadget\\nr2l_gadget:\\n mov x0, x19\\n blr x20\\n");\n'
        'void vuln(void){ char b[64]; read(0,b,1024); }\n'
        'int main(int argc,char**argv){ if(argc>99) system(argv[0]); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_A64_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-mbranch-protection=none", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build aarch64 ret2libc fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("a64r2l").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") != "off"   # NX on
        run = enqueue_exploit(q, t, params={"strategy": "auto", "timeout": 12})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 AArch64 ret2libc"


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
