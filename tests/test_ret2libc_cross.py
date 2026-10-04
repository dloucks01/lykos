"""Cross-architecture NX-on ret2libc for RISC-V 64 and PowerPC64 (ELFv2 LE) -- the first non-x86/ARM
ROP-to-shell on these ISAs. Both are no-execstack, no-leak, no-PIE, driven under qemu-user and
confirmed by reaching `system` with the first argument = &"/bin/sh" (register check over the gdbstub)
plus a negative control. The gadget finders are pure byte decoders (host objdump cannot disassemble
either ISA), so they are also unit-tested against synthetic encodings."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import rop

_RV_GCC = shutil.which("riscv64-linux-gnu-gcc")
_RV_QEMU = shutil.which("qemu-riscv64") or shutil.which("qemu-riscv64-static")
_PPC_GCC = shutil.which("powerpc64le-linux-gnu-gcc")
_PPC_QEMU = shutil.which("qemu-ppc64le") or shutil.which("qemu-ppc64le-static")
_A64_GCC = shutil.which("aarch64-linux-gnu-gcc")
_A64_QEMU = shutil.which("qemu-aarch64") or shutil.which("qemu-aarch64-static")
_ARM_GCC = shutil.which("arm-linux-gnueabihf-gcc")
_ARM_QEMU = shutil.which("qemu-arm") or shutil.which("qemu-arm-static")


def _one_seg(seg, va=0x10000):
    """Run a byte-decode finder over a single synthetic executable segment."""
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), va, 1)]
    try:
        return seg
    finally:
        rop._loads = orig


def test_find_riscv64_gadgets_decodes_compressed_and_base():
    """The RISC-V scanner finds a caller (`c.mv a0,s1 ; c.jalr s2`) and a contiguous epilogue loader
    that restores two s-regs + ra, reading each load's sp offset exactly -- across compressed (RVC)
    and base encodings."""
    seg = b""
    seg += struct.pack("<H", 0x8526)      # 10000: c.mv a0, s1 (x9)
    seg += struct.pack("<H", 0x9902)      # 10002: c.jalr s2 (x18)      -> caller
    # a loader epilogue: ld s1,8(sp); ld s2,0(sp); ld ra,24(sp); addi sp,sp,32; ret
    seg += struct.pack("<I", 0x00813483)  # 10004: ld s1(x9), 8(sp)
    seg += struct.pack("<I", 0x00013903)  # 10008: ld s2(x18), 0(sp)
    seg += struct.pack("<I", 0x01813083)  # 1000c: ld ra(x1), 24(sp)
    seg += struct.pack("<H", 0x6105)      # 10010: c.addi16sp sp, 32
    seg += struct.pack("<H", 0x8082)      # 10012: c.ret
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x10000, 1)]
    try:
        g = rop.find_riscv64_r2libc_gadgets(seg)
    finally:
        rop._loads = orig
    assert any(c["va"] == 0x10000 and c["src"] == 9 and c["br"] == 18 for c in g["callers"])
    ld = next(ll for ll in g["loaders"] if 9 in ll["regs"] and 18 in ll["regs"])
    assert ld["regs"][9] == 8 and ld["regs"][18] == 0 and ld["raoff"] == 24 and ld["spadj"] == 32


def test_find_ppc64_gadgets_requires_callee_saved_regs():
    """The PPC64 scanner finds `mtctr rC ; mr r3,rT ; bctr` only when rC and rT are callee-saved
    (r14..r31) -- a volatile-reg source cannot be controlled by the overflow, so it is not a gadget."""
    good = (struct.pack("<I", 0x7FC903A6)   # mtctr r30
            + struct.pack("<I", 0x7FE3FB78)  # mr r3, r31
            + struct.pack("<I", 0x4E800420))  # bctr
    bad = (struct.pack("<I", 0x7D0903A6)    # mtctr r8  (volatile)
           + struct.pack("<I", 0x7D23FB78)   # mr r3, r9 (volatile)
           + struct.pack("<I", 0x4E800420))
    seg = good + bad
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x10000, 1)]
    try:
        g = rop.find_ppc64_r2libc_gadgets(seg)
    finally:
        rop._loads = orig
    assert any(c["ctr"] == 30 and c["arg"] == 31 for c in g["callers"])
    assert all(c["ctr"] != 8 for c in g["callers"])      # the volatile-reg window is not a gadget


def test_find_aarch64_gadgets_records_ldp_offset():
    """The AArch64 loader scanner records the FIRST ldp's `[sp,#A]` displacement (a_off), so the
    chain-builder can place &system / &"/bin/sh" at their true stack slots. A real gcc epilogue pops
    the callee-saved pair far from sp (e.g. `ldp x27,x28,[sp,#80]`), so assuming A==16 left x0 unset
    and aarch64 filed no PoC at all. Encodings (byte-decoded, no objdump): mov x0,x28 / blr x27, then
    ldp x27,x28,[sp,#80] ; ldp x29,x30,[sp],#96 ; ret."""
    def le(w):
        return struct.pack("<I", w)
    mov_x0_x28 = 0xAA0003E0 | (28 << 16)                  # mov x0, x28
    blr_x27 = 0xD63F0000 | (27 << 5)                      # blr x27
    ldp_2728_80 = 0xA9400000 | (10 << 15) | (28 << 10) | (31 << 5) | 27   # ldp x27,x28,[sp,#80]
    ldp_2930_96 = 0xA8C00000 | (12 << 15) | (30 << 10) | (31 << 5) | 29   # ldp x29,x30,[sp],#96
    ret = 0xD65F03C0
    seg = le(mov_x0_x28) + le(blr_x27) + le(ldp_2728_80) + le(ldp_2930_96) + le(ret)
    _one_seg(seg)
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x10000, 1)]
    try:
        g = rop.find_aarch64_r2libc_gadgets(seg)
    finally:
        rop._loads = orig
    assert any(c["src"] == 28 and c["br"] == 27 for c in g["callers"])
    ld = next(l for l in g["loaders"] if {l["r1"], l["r2"]} == {27, 28})
    assert ld["a_off"] == 80, f"ldp [sp,#80] offset not recovered: {ld}"


@pytest.mark.skipif(not (_RV_GCC and _RV_QEMU), reason="needs riscv64-linux-gnu-gcc + qemu-riscv64")
def test_auto_files_l3_riscv64_ret2libc(store, tmp_path):
    """strategy=auto drives an NX-on RISC-V 64 stack overflow to a confirmed L3 ret2libc: an epilogue
    loader restores s-regs + ra, a `mv a0,sS ; jr sB` caller calls system("/bin/sh"); confirmed by
    reaching `system` with a0=&"/bin/sh" under the qemu debugger + a negative control."""
    _run_cross_e2e(store, tmp_path, _RV_GCC, "riscv", "riscv64-ret2libc",
                   extra=["-march=rv64g", "-mabi=lp64d"])


@pytest.mark.skipif(not (_PPC_GCC and _PPC_QEMU),
                    reason="needs powerpc64le-linux-gnu-gcc + qemu-ppc64le")
def test_auto_files_l3_ppc64_ret2libc(store, tmp_path):
    """strategy=auto drives an NX-on PowerPC64 (ELFv2 LE) overflow to a confirmed L3 ret2libc: the
    saved LR -> a `mtctr; mr r3; bctr` caller gadget with &system / &"/bin/sh" in controllable
    callee-saved GPRs; confirmed by reaching `system` with r3=&"/bin/sh" + a negative control."""
    _run_cross_e2e(store, tmp_path, _PPC_GCC, "ppc64", "ppc64-ret2libc", opt="-O2")


@pytest.mark.skipif(not (_A64_GCC and _A64_QEMU),
                    reason="needs aarch64-linux-gnu-gcc + qemu-aarch64")
def test_auto_files_l3_aarch64_ret2libc(store, tmp_path):
    """strategy=auto drives an NX-on AArch64 overflow to a confirmed L3 ret2libc: the overwritten
    saved x30 -> a two-gadget chain (signed-offset `ldp xR1,xR2,[sp,#A]` + post-indexed `ldp x29,x30`
    loader, then a `mov x0,xS; blr xB` caller) calls system("/bin/sh"); confirmed by a spawned shell
    under qemu-user. Regression guard: a real gcc loader pops the callee-saved pair at [sp,#80], so
    the chain MUST honour a_off (not assume 16) or x0 stays 0 and no PoC is filed."""
    _run_cross_e2e(store, tmp_path, _A64_GCC, "aarch64", "aarch64-ret2libc")


@pytest.mark.skipif(not (_ARM_GCC and _ARM_QEMU),
                    reason="needs arm-linux-gnueabihf-gcc + qemu-arm")
def test_auto_files_l3_arm_ret2libc(store, tmp_path):
    """strategy=auto drives an NX-on ARM (32-bit) overflow to a confirmed L3 ret2libc: a
    `pop {r0,..,pc}` gadget sets r0=&"/bin/sh" and pc=&system -> system("/bin/sh"); confirmed by a
    spawned shell under qemu-user + a negative control."""
    _run_cross_e2e(store, tmp_path, _ARM_GCC, "arm", "arm-ret2libc")


# A vulnerable program whose `vuln` keeps several values live ACROSS the overflowing read(), forcing
# the compiler to hold them in callee-saved registers (saved/restored around vuln's frame) -- exactly
# the registers a PPC64 `mtctr/mr r3/bctr` gadget needs the overflow to control. system + "/bin/sh"
# stay in the static image but off the pre-overflow path (argc>99 is never true).
_SRC = (
    '#include <stdlib.h>\n#include <unistd.h>\n'
    'void never(int c,char**v){ if(c>99){ char*s="/bin/sh"; system(s); } }\n'
    'long sink(long x){ volatile long v=x; return v*2654435761UL + 1; }\n'
    'void vuln(long s){\n'
    '    char buf[64];\n'
    '    long a=sink(s), b=sink(s^0x55), c=sink(s^0xAA);\n'
    '    read(0, buf, 512);\n'
    '    sink(a); sink(b); sink(c);\n'
    '}\n'
    'int main(int argc,char**argv){ never(argc,argv); vuln(argc); write(1,"ok\\n",3); return 0; }\n')


def _run_cross_e2e(store, tmp_path, gcc, arch_name, exploit_name, opt="-O1", extra=()):
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = tmp_path / "v.c"
    src.write_text(_SRC)
    exe = tmp_path / "v"
    cmd = [gcc, opt, "-fno-stack-protector", "-no-pie", "-static", "-w",
           *extra, str(src), "-o", str(exe)]
    if subprocess.run(cmd, capture_output=True).returncode:
        pytest.skip(f"cannot build {arch_name} ret2libc fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, store.cases.create("xr2l").id, exe, filename="v")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(180)
        mit = store.targets.get(t.id).mitigations or {}
        assert mit.get("nx") != "off" and mit.get("pie") != "on"     # NX on, no PIE
        run = enqueue_exploit(q, t, params={"strategy": "auto", "timeout": 14})
        assert pool.wait_idle(600) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    from lykos.db.dao import FindingDAO
    l3 = [pc for pc in PocDAO(store.conn).list_by_target(t.id) if pc.level == "L3" and pc.verified]
    assert l3, f"no confirmed L3 {arch_name} ret2libc"
    # the confirmed L3 must be THIS arch's ret2libc (not some other L3), identified by its dedup key
    fdao = FindingDAO(store.conn)
    fid = fdao.id_for_dedup(t.id, f"exploit:{exploit_name}:{t.id}")
    assert fid, f"no {exploit_name} finding filed"
    # DEMONSTRATED EFFECT: the chain must spawn a real shell that evaluates a forgery-proof marker
    # under qemu-user, not merely reach system with the arg register set. The driver raises the
    # finding to RCE/demonstrated only when a live shell actually ran.
    f = fdao.get(fid)
    assert "Remote code execution (demonstrated)" in f.title, \
        f"{arch_name} ret2libc did not demonstrate a spawned-shell effect: {f.title!r}"
