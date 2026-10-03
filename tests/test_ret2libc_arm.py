"""Cross-architecture NX-on ret2libc for ARM (32-bit): a `pop {r0, ..., pc}` gadget sets r0=&"/bin/sh"
and pc=&system in one step, driven under qemu-user and confirmed by reaching `system` with
r0=&"/bin/sh" (register check over the gdbstub) + a negative control. No execstack, no info leak."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import rop

_ARM_GCC = shutil.which("arm-linux-gnueabihf-gcc") or shutil.which("arm-linux-gnueabi-gcc")
_QEMU = shutil.which("qemu-arm") or shutil.which("qemu-arm-static")


def test_find_arm_r0pc_gadgets():
    """The byte-decode scanner (no objdump) finds `pop {r0, pc}` (and {r0,r4,pc}) and ranks the
    fewest-register one first. Encoding: pop {rlist} = 0xE8BD0000 | rlist; r0=bit0, pc=bit15."""
    seg = struct.pack("<I", 0xE8BD8001)                  # pop {r0, pc}         (2 regs)
    seg += struct.pack("<I", 0xE8BD8011)                 # pop {r0, r4, pc}     (3 regs)
    seg += struct.pack("<I", 0xE8BD8002)                 # pop {r1, pc}  (no r0 -> ignored)
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x10000, 1)]
    try:
        gs = rop.find_arm_r0pc_gadgets(seg)
    finally:
        rop._loads = orig
    assert gs and gs[0]["nregs"] == 2 and gs[0]["va"] == 0x10000      # {r0,pc} first (fewest regs)
    assert any(g["nregs"] == 3 for g in gs)
    assert all(g["va"] != 0x10008 for g in gs)           # the r0-less pop is not a gadget


@pytest.mark.skipif(not (_ARM_GCC and _QEMU),
                    reason="needs arm-linux-gnueabihf-gcc + qemu-arm")
def test_auto_files_l3_arm_ret2libc(store, tmp_path):
    """strategy=auto drives an NX-ON ARM (32-bit) stack overflow to a confirmed L3 ret2libc: a
    `pop {r0, pc}` gadget calls system("/bin/sh"), confirmed by reaching `system` with r0=&"/bin/sh"
    under the qemu debugger + a negative control. No execstack, no leak."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(
        '#include <stdlib.h>\n#include <unistd.h>\n'
        'char cmd[16] = "/bin/sh";\n'
        # the ret2libc primitive gadget (provided like x86-64 fixtures provide "pop rdi; ret")
        '__asm__(".text\\n.global r0pc\\n.arm\\nr0pc:\\n pop {r0, pc}\\n");\n'
        'void vuln(void){ char b[64]; read(0,b,512); }\n'
        'int main(int argc,char**argv){ if(argc>99) system(argv[0]); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_ARM_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static", "-marm",
                       "-w", str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build arm ret2libc fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("armr2l").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") != "off"   # NX on
        run = enqueue_exploit(q, t, params={"strategy": "auto", "timeout": 12})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 ARM ret2libc"
