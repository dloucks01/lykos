"""Cross-architecture ret2shellcode on s390x (IBM Z, big-endian): inject execve("/bin/sh") shellcode
into an execstack overflow and run it under qemu-user. The s390x `jmp <reg>` is `br %rX`, so the
fixture leaves r1 pointing at the buffer and carries that gadget. First big-endian execstack arch --
it exercises the endian-aware return-address packing in the shared `_shellcode_emu_exploit` path."""
import shutil
import subprocess

import pytest
from lykos.analyze.poc import rop, shellcode

_SZ_GCC = shutil.which("s390x-linux-gnu-gcc")
_SZ_QEMU = shutil.which("qemu-s390x") or shutil.which("qemu-s390x-static")


def test_execve_binsh_s390x_shape():
    sc = shellcode.execve_binsh_s390x()
    assert len(sc) == 24 and sc.endswith(b"/bin/sh\x00")
    assert sc[:2] == b"\xc0\x20"                          # larl r2, ...


def test_write_marker_s390x_patches_length():
    sc = shellcode.write_marker_s390x(b"ZOK")             # 3-byte marker
    assert sc.endswith(b"ZOK") and len(sc) == 22 + 3
    assert sc[10:14] == b"\xa7\x49\x00\x03"               # lghi r4, 3 (big-endian immediate)


def test_find_br_gadgets_s390x():
    seg = bytes.fromhex("07f1")                           # br %r1  (bcr 15, %r1)
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x400000, 1)]
    try:
        g = rop.find_br_gadgets_s390x(seg)
    finally:
        rop._loads = orig
    assert any(x["reg"] == "r1" and x["va"] == 0x400000 for x in g)


@pytest.mark.skipif(not (_SZ_GCC and _SZ_QEMU), reason="needs s390x-linux-gnu-gcc + qemu-s390x")
def test_auto_files_l3_s390x_ret2shellcode(store, tmp_path):
    """strategy=auto drives an s390x (big-endian) execstack overflow with a `br %r1` gadget (r1 left
    pointing at the buffer) to a confirmed L3: injected execve("/bin/sh") shellcode runs under
    qemu-user and spawns a real shell (or writes a marker), the redirect recovered with no leak."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(
        '#include <unistd.h>\n#include <stdio.h>\n'
        '__asm__(".text\\n.globl g\\ng:\\n br %r1\\n");\n'            # br %r1 -> jump to r1
        'void vuln(void){ char b[256]; read(0,b,1024);'
        ' __asm__ volatile("lgr %%r1, %0"::"r"(b):"r1"); }\n'
        'int main(void){ setbuf(stdout,0); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_SZ_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-z", "execstack", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build s390x execstack fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("s390sc").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"   # execstack
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 s390x ret2shellcode"
