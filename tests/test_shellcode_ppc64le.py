"""Cross-architecture ret2shellcode on PowerPC64 (ELFv2, little-endian): inject execve("/bin/sh")
shellcode into an execstack overflow and run it under qemu-user. The PPC `jmp <reg>` is `mtctr rX;
bctr`, so the execstack fixture leaves r3 pointing at the buffer and carries that gadget."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import rop, shellcode

_PPC_GCC = shutil.which("powerpc64le-linux-gnu-gcc")
_PPC_QEMU = shutil.which("qemu-ppc64le") or shutil.which("qemu-ppc64le-static")


def test_execve_binsh_ppc64le_shape():
    sc = shellcode.execve_binsh_ppc64le()
    assert len(sc) == 36 and sc.endswith(b"/bin/sh\x00")
    assert struct.unpack("<I", sc[:4])[0] == 0x48000005          # bl .+4


def test_write_marker_ppc64le_patches_length():
    sc = shellcode.write_marker_ppc64le(b"PPCMK")                 # 5-byte marker
    assert sc.endswith(b"PPCMK") and len(sc) == 36 + 5
    assert struct.unpack("<I", sc[16:20])[0] == (0x38A00000 | 5)  # li r5, len


def test_find_mtctr_bctr_gadgets_ppc():
    seg = struct.pack("<II", 0x7C6903A6, 0x4E800420)             # mtctr r3 ; bctr  (LE words)
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x10000000, 1)]
    try:
        g = rop.find_mtctr_bctr_gadgets_ppc(seg, endian="little")
    finally:
        rop._loads = orig
    assert any(x["reg"] == "r3" and x["va"] == 0x10000000 for x in g)


@pytest.mark.skipif(not (_PPC_GCC and _PPC_QEMU),
                    reason="needs powerpc64le-linux-gnu-gcc + qemu-ppc64le")
def test_auto_files_l3_ppc64le_ret2shellcode(store, tmp_path):
    """strategy=auto drives a PowerPC64 (LE) execstack overflow with a `mtctr r3; bctr` gadget (r3
    left pointing at the buffer) to a confirmed L3: injected execve("/bin/sh") shellcode runs under
    qemu-user and spawns a real shell (or writes a marker), the redirect recovered with no leak."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(
        '#include <unistd.h>\n#include <stdio.h>\n'
        '__asm__(".text\\n.globl g\\ng:\\n mtctr 3\\n bctr\\n");\n'   # mtctr r3; bctr -> jump to r3
        'void vuln(void){ char b[256]; read(0,b,1024);'
        ' __asm__ volatile("mr 3, %0"::"r"(b):"r3","memory"); }\n'
        'int main(void){ setbuf(stdout,0); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_PPC_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-z", "execstack", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ppc64le execstack fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("ppc64sc").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"   # execstack
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 PowerPC64 (LE) ret2shellcode"
