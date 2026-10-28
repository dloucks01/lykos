"""Cross-architecture PIE defeat via a runtime info-leak on AArch64: the target prints a code
pointer, the exploit stage recovers the randomized load base from it (no static address oracle),
relocates a ret2win payload onto that base, and confirms the hijack by a spawned shell evaluating a
forgery-proof nonce -- all driven under qemu-user. Fills the doc-49 5a hole: the info-leak path was
x86-64 only (poc/leak.py). qemu-user randomizes the PIE base run-to-run, so this is a genuine ASLR
defeat, not a fixed-base replay."""
import shutil
import subprocess

import pytest

_AA_GCC = shutil.which("aarch64-linux-gnu-gcc")
_AA_QEMU = shutil.which("qemu-aarch64") or shutil.which("qemu-aarch64-static")

# A PIE binary that (1) leaks a code pointer (&main) on startup -> the load base is recoverable,
# (2) has a win() that execve's a shell -> confirmable by a nonce challenge, no analyst marker,
# (3) overflows a small stack buffer -> the saved return (x30) is controllable.
_SRC = (
    '#include <stdio.h>\n#include <unistd.h>\n'
    'void win(void){ execl("/bin/sh","sh",(char*)0); }\n'
    'void vuln(void){ char b[64]; read(0,b,512); }\n'
    'int main(void){ setbuf(stdout,0); printf("ptr=%p\\n",(void*)main); vuln(); return 0; }\n'
)


@pytest.mark.skipif(not (_AA_GCC and _AA_QEMU),
                    reason="needs aarch64-linux-gnu-gcc + qemu-aarch64")
def test_auto_pie_leak_ret2win_aarch64(store, tmp_path):
    """strategy=auto drives an AArch64 PIE target to a confirmed L3 by leaking its load base and
    relocating a ret2win onto it -- the info-leak ASLR defeat, cross-arch under qemu-user."""
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    if subprocess.run([_AA_GCC, "-O0", "-fno-stack-protector", "-pie", "-fPIE", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build aarch64 PIE fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("aapie").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        assert (store.targets.get(t.id).mitigations or {}).get("pie") == "on"
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, "no confirmed L3 aarch64 PIE leak->ret2win"
