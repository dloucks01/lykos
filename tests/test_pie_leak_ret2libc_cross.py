"""Cross-architecture NX-on PIE ret2libc via a runtime info-leak -- the "no win()" case the
ISA-neutral ret2win leak path cannot reach. A static-PIE target (NX on) leaks two code pointers; the
exploit stage recovers the randomized-by-the-loader load base from them (no static address oracle),
rebases a ret2libc CHAIN (the shared RISC-style loader+caller) onto that base -> system("/bin/sh"),
and confirms SINGLE-PROCESS under qemu-user by a spawned shell that evaluates a forgery-proof nonce.

Static-PIE collapses the usual two-base problem: system, "/bin/sh" and the gadgets all sit at
base + their ELF vaddr, so one leaked code pointer rebases the whole chain. Covers the two arches the
shared stack-ret2libc builder handles (riscv64, loongarch64)."""
import shutil
import subprocess

import pytest

# STATIC-PIE: NO win() -> the ret2win leak path declines, forcing the ret2libc chain. Two leaked
# code pointers corroborate the base. `if(getpid()==-1)` keeps system()+"/bin/sh" linked (never run);
# everything (gadgets, system, "/bin/sh") is in the one image, rebased by the single leaked base.
_SRC_STATIC = (
    '#include <stdio.h>\n#include <unistd.h>\n#include <stdlib.h>\n'
    'void vuln(void){ char b[64]; read(0,b,1024); }\n'
    'int main(void){ setbuf(stdout,0); printf("a=%p b=%p\\n",(void*)main,(void*)vuln);'
    ' vuln(); if(getpid()==-1) system("/bin/sh"); return 0; }\n'
)
# DYNAMIC-PIE: no win(), no system/"/bin/sh" in the image -> the ret2libc chain lives entirely in a
# SEPARATELY-based libc. Leaks two libc data pointers (stdout, stderr) so recover_libc_base
# corroborates the (genuinely randomised) libc base; the chain is rebased onto it.
_SRC_DYNAMIC = (
    '#include <stdio.h>\n#include <unistd.h>\n'
    'void vuln(void){ char b[64]; read(0,b,1024); }\n'
    'int main(void){ setbuf(stdout,0); printf("o=%p e=%p\\n",(void*)stdout,(void*)stderr);'
    ' vuln(); return 0; }\n'
)


def _run(store, tmp_path, gcc, arch_hint, *, link):
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_SRC_STATIC if link == "static-pie" else _SRC_DYNAMIC)
    exe = tmp_path / "v"
    flags = ["-static-pie"] if link == "static-pie" else ["-pie"]
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", *flags, "-fPIE", "-w",
                       str(src), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip(f"cannot build {arch_hint} {link} fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("pr2l").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        m = store.targets.get(t.id).mitigations or {}
        assert m.get("pie") == "on" and m.get("nx") != "off"      # NX-on PIE: ret2libc territory
        run = enqueue_exploit(q, t, params={"strategy": "auto"})
        assert pool.wait_idle(400) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, f"no confirmed L3 {arch_hint} PIE leak->ret2libc"


_RV_GCC = shutil.which("riscv64-linux-gnu-gcc")
_RV_QEMU = shutil.which("qemu-riscv64") or shutil.which("qemu-riscv64-static")
_LA_GCC = shutil.which("loongarch64-linux-gnu-gcc")
_LA_QEMU = shutil.which("qemu-loongarch64") or shutil.which("qemu-loongarch64-static")


@pytest.mark.skipif(not (_RV_GCC and _RV_QEMU), reason="needs riscv64-linux-gnu-gcc + qemu-riscv64")
def test_auto_static_pie_leak_ret2libc_riscv64(store, tmp_path):
    _run(store, tmp_path, _RV_GCC, "riscv64", link="static-pie")


@pytest.mark.skipif(not (_LA_GCC and _LA_QEMU),
                    reason="needs loongarch64-linux-gnu-gcc + qemu-loongarch64")
def test_auto_static_pie_leak_ret2libc_loongarch64(store, tmp_path):
    _run(store, tmp_path, _LA_GCC, "loongarch64", link="static-pie")


@pytest.mark.skipif(not (_RV_GCC and _RV_QEMU), reason="needs riscv64-linux-gnu-gcc + qemu-riscv64")
def test_auto_dynamic_pie_leak_ret2libc_riscv64(store, tmp_path):
    """DYNAMIC-PIE: the chain lives in a separately-randomised libc, recovered from a leaked libc
    pointer -- the common real-world case, and the libc base genuinely randomises under qemu."""
    _run(store, tmp_path, _RV_GCC, "riscv64", link="dynamic-pie")


@pytest.mark.skipif(not (_LA_GCC and _LA_QEMU),
                    reason="needs loongarch64-linux-gnu-gcc + qemu-loongarch64")
def test_auto_dynamic_pie_leak_ret2libc_loongarch64(store, tmp_path):
    _run(store, tmp_path, _LA_GCC, "loongarch64", link="dynamic-pie")
