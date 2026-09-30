"""Autonomous ret2shellcode on an EXECUTABLE stack, no leak: a plain overflow of an execstack
binary that carries a `jmp rsp` gadget is driven to a live shell WITHOUT an analyst selecting the
shellcode strategy -- the redirect goes through the fixed (no-PIE) gadget, so the randomised stack
address is never needed. x86-64, native."""
import shutil
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="ret2shellcode fixture + detonation are native x86-64 only")


def _src(read_call: str) -> str:
    """An execstack, no-PIE binary with an incidental `jmp rsp` (0xff 0xe4) gadget -- as many real
    binaries carry -- and a vuln() that owns the overflow. Parameterised ONLY by the read, so the
    positive and its negative control are byte-identical but for the call that overflows."""
    return (
        '#include <unistd.h>\n#include <stdio.h>\n'
        '__asm__(".text\\n.globl sc_gadget\\nsc_gadget:\\n .byte 0xff,0xe4\\n");\n'
        'void vuln(void){ char b[64]; ' + read_call + '; }\n'
        'int main(void){ setbuf(stdout,0); puts("go"); vuln(); return 0; }\n')


def _build(tmp_path_factory, name, read_call):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "v.c").write_text(_src(read_call))
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-z", "execstack", "-w",
                       str(d / "v.c"), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build ret2shellcode fixture")
    return exe


@pytest.fixture
def sc_bin(tmp_path_factory):
    return _build(tmp_path_factory, "sc", "read(0,b,512)")            # overflow: the bug


@pytest.fixture
def sc_safe_bin(tmp_path_factory):
    return _build(tmp_path_factory, "sc_safe", "read(0,b,sizeof b)")  # bounds-fixed: no bug


def test_gadget_is_found():
    from lykos.analyze.poc import rop
    src = _src("read(0,b,512)")
    # the gadget byte pair is present in the source's inline asm; a full build is exercised below
    assert rop.GADGETS["jmp_rsp"] == b"\xff\xe4"
    assert src.count("0xff,0xe4") == 1


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
    t = ingest(store, store.cases.create("sc").id, exe, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    # triage reads nx=off (execstack) from the GNU_STACK header; strategy=auto must reach shellcode.
    assert (store.targets.get(t.id).mitigations or {}).get("nx") == "off"
    run = enqueue_exploit(q, t, params={"strategy": "auto", "offset": 72})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    return [pc for pc in PocDAO(store.conn).list_by_target(t.id)
            if pc.level == "L3" and pc.verified]


def test_auto_files_l3_ret2shellcode_on_execstack(store, _stage, sc_bin):
    """strategy=auto (NOT strategy=shellcode) drives an execstack overflow with a jmp-rsp gadget to
    a confirmed L3 shell -- autonomous, no leak, proven by the forgery-proof marker."""
    assert _drive(store, _stage, sc_bin), "no confirmed L3 ret2shellcode PoC"


def test_declines_the_patched_target(store, _stage, sc_safe_bin):
    """Negative control: the SAME execstack binary with the overflow removed must NOT yield a
    confirmed L3 -- byte-identical but for the read length, so the decline is the missing overflow
    alone (the jmp-rsp gadget and the executable stack are unchanged)."""
    assert not _drive(store, _stage, sc_safe_bin), "patched target wrongly credited an L3"


def test_find_reg_control_gadgets_recognises_jmp_and_call():
    """find_reg_control_gadgets picks out every `jmp <reg>` / `call <reg>` encoding, rsp first."""
    from lykos.analyze.poc import rop
    # a fake exec segment: jmp rsp (ff e4), jmp rax (ff e0), call rdi (ff d7)
    seg = b"\x90\xff\xe4\x90\xff\xe0\x90\xff\xd7\x90"
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x400000, 1)]
    try:
        gs = rop.find_reg_control_gadgets(seg)
    finally:
        rop._loads = orig
    found = {(g["insn"], g["reg"]) for g in gs}
    assert ("jmp", "rsp") in found and ("jmp", "rax") in found and ("call", "rdi") in found
    assert gs[0]["reg"] == "rsp"                          # rsp is ordered first


def test_sc_payload_layouts():
    """The two ret2shellcode layouts, and the gadget always at [offset:offset+8]."""
    from lykos.analyze.poc.exploit_stage import _sc_payload
    sc = b"\xcc" * 20
    g = 0x401146
    gb = g.to_bytes(8, "little")
    # rsp: shellcode AFTER the return address
    rsp = _sc_payload("rsp", 72, g, sc)
    assert rsp[:72] == b"A" * 72 and rsp[72:80] == gb and rsp[80:] == sc
    # a general register pointing at the buffer: shellcode FIRST, gadget at the return slot
    rax = _sc_payload("rax", 72, g, sc)
    assert rax[:20] == sc and rax[20:72] == b"\x90" * 52 and rax[72:80] == gb
    # shellcode too big to fit before the return address -> no layout
    assert _sc_payload("rax", 8, g, sc) is None
