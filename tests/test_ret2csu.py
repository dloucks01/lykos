"""ret2csu: call system("/bin/sh") through the __libc_csu_init gadgets (3-arg call *[r12+rbx*8]
with edi/rsi/rdx set), so a no-PIE binary with csu gadgets + imported system + a "/bin/sh" string
is exploited with NO analyst-supplied call target. x86-64, native."""
import shutil
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import rop

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="ret2csu fixture + detonation are native x86-64 only")

def _src(read_call: str) -> str:
    """A no-PIE binary with inline __libc_csu_init gadgets (the exact CSU_POP / CSU_CALL byte shapes
    find_csu matches), an imported `system` (a dead call forces the PLT/GOT entry) and a "/bin/sh"
    string. Parameterised ONLY by the read that owns the overflow, so the positive and its negative
    control are byte-identical but for that call (supwngo _90_neg discipline)."""
    return (
        '#include <stdlib.h>\n#include <unistd.h>\n#include <stdio.h>\n'
        'char binsh[] = "/bin/sh";\n'
        '__asm__(".text\\n"\n'
        '  ".global csu_pop\\n csu_pop: pop %rbx\\n pop %rbp\\n pop %r12\\n pop %r13\\n'
        ' pop %r14\\n pop %r15\\n ret\\n"\n'
        '  ".global csu_call\\n csu_call: mov %r15,%rdx\\n mov %r14,%rsi\\n mov %r13d,%edi\\n'
        ' call *(%r12,%rbx,8)\\n ret\\n");\n'
        'void vuln(void){ char b[32]; ' + read_call + '; }\n'
        'int main(void){ setvbuf(stdout,0,2,0); if(binsh[99]) system(binsh); vuln(); return 0; }\n')


def _build(tmp_path_factory, name, read_call):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "v.c").write_text(_src(read_call))
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-w",
                       str(d / "v.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ret2csu fixture")
    return exe


@pytest.fixture
def csu_bin(tmp_path_factory):
    return _build(tmp_path_factory, "csu", "read(0,b,400)")           # overflow: the bug


@pytest.fixture
def csu_safe_bin(tmp_path_factory):
    return _build(tmp_path_factory, "csu_safe", "read(0,b,sizeof b)")  # bounds-fixed: no bug


def test_build_ret2csu_alignment_pad_is_optional():
    import struct
    plain = rop.build_ret2csu(40, 0x401136, 0x401141, 0x404000, 0x404028, 0, 0, 512, rbp=1)
    padded = rop.build_ret2csu(40, 0x401136, 0x401141, 0x404000, 0x404028, 0, 0, 512, rbp=1,
                               align_ret=0x40101a)
    # without align, the pop-gadget word sits right after the overflow; with align, a `ret` does
    assert plain[40:48] == struct.pack("<Q", 0x401136)               # -> the csu pop gadget
    assert padded[40:48] == struct.pack("<Q", 0x40101a)              # -> the alignment `ret`
    assert padded[48:56] == struct.pack("<Q", 0x401136)             # then the csu pop gadget


def test_plan_finds_csu_system_pieces(csu_bin):
    from lykos.analyze.poc import exploit_stage as E
    data = csu_bin.read_bytes()
    plan = E._plan_ret2csu_system(data, str(csu_bin), 40, 512)
    assert plan and plan["csu"] and plan["binsh"] and plan["system_got"]


@pytest.fixture
def _stage(store):
    from lykos.analyze import register
    from lykos.jobs import JobConfig, WorkerPool
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _drive(store, pool, exe):
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, store.cases.create("csu").id, exe, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "ret2csu", "offset": 40})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    return [pc for pc in PocDAO(store.conn).list_by_target(t.id)
            if pc.level == "L3" and pc.verified]


def test_exploit_stage_files_l3_ret2csu_system(store, _stage, csu_bin):
    """strategy=ret2csu with NO analyst call_ptr auto-derives system("/bin/sh") via the csu 3-arg
    call, detonates for real, and files an L3 PoC confirmed by the forgery-proof marker."""
    assert _drive(store, _stage, csu_bin), "no confirmed L3 ret2csu PoC"


def test_ret2csu_declines_the_patched_target(store, _stage, csu_safe_bin):
    """Negative control (supwngo _90_neg): the SAME binary with the overflow removed must NOT yield
    a confirmed L3 -- byte-identical but for the read length, so the decline is the missing overflow
    alone (the csu gadgets, "/bin/sh" and system import are all still present)."""
    assert not _drive(store, _stage, csu_safe_bin), "patched target wrongly credited an L3"
