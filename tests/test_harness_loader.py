"""Doc 51 item 5: the harness emulator loads an image the way a loader would, and a program-level
crash promotes a harness finding only when it happens in the function the harness drove.

Loader -- all measured before the fix:
  * Ghidra places a PIE at 0x100000; the emulator mapped it at 0, so every function it drove
    "faulted" on its first instruction and was filed as a high-severity control-flow corruption;
  * an lld PIE keeps .rodata in page 0, which the loader-at-0 unmapped -- every string read
    "faulted" as an out-of-bounds read;
  * `-fno-plt` calls libc through GOT slots the emulator left 0 -- a "fetch fault" at address 0.
"""
from __future__ import annotations

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from lykos.analyze import register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.harness import emulate
from lykos.analyze.harness.harness_stage import _locate_program_crash
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

pytestmark = pytest.mark.skipif(not emulate.available(), reason="needs unicorn")

_TABLE = r"""
#include <unistd.h>
#include <string.h>
static const char *names[] = {"alpha", "beta", "gamma", "delta"};
__attribute__((noinline)) int table_parse(const char *s, long n) {
    if (n < 1) return 0;
    const char *nm = names[(unsigned char)s[0] & 3];
    return (int)strlen(nm) + s[0];
}
__attribute__((noinline)) int null_parse(const char *s, long n) {
    volatile int *p = 0;
    if (n > 1 && s[0] == 'N') return *p;
    return 0;
}
int main(void) { static char in[64]; long n = read(0, in, sizeof in);
                 return table_parse(in, n) + null_parse(in, n); }
"""


def _build(tmp_path, name, cc, *flags):
    c = tmp_path / "t.c"
    c.write_text(_TABLE)
    out = tmp_path / name
    if subprocess.run([cc, "-O0", "-w", *flags, str(c), "-o", str(out)],
                      capture_output=True).returncode:
        pytest.skip(f"cannot build with {cc} {' '.join(flags)}")
    return out


def _addr(path, name):
    out = subprocess.run(["nm", str(path)], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if line.endswith(" " + name):
            return int(line.split()[0], 16)
    pytest.skip(f"{name} not in the symbol table")


def _variants(tmp_path, gcc):
    yield "gnu-ld pie", _build(tmp_path, "pie", gcc, "-pie", "-fPIE")
    yield "fno-plt pie", _build(tmp_path, "noplt", gcc, "-pie", "-fPIE", "-fno-plt")
    yield "no-pie", _build(tmp_path, "nopie", gcc, "-no-pie")
    if shutil.which("clang") and shutil.which("ld.lld"):
        yield "lld pie", _build(tmp_path, "lld", "clang", "-fuse-ld=lld", "-pie", "-fPIE")


@pytest.mark.parametrize("load_base", [0, 0x100000], ids=["native-coords", "ghidra-coords"])
def test_a_harmless_function_returns_cleanly_whatever_the_linker_or_decompiler(
        tmp_path, gcc, load_base):
    for label, exe in _variants(tmp_path, gcc):
        data = exe.read_bytes()
        pie = data[0x10] == 3
        base = load_base if pie else 0
        fa = _addr(exe, "table_parse") + base
        for inp in (b"\x00xyz", b"\x03abc"):
            r = emulate.run_function(data, fa, inp, load_base=base)
            assert not r.crashed and r.returned, (label, hex(base), r.access, r.note)
        # coverage comes back in the decompiler's coordinates, inside the function
        assert fa in r.blocks, (label, sorted(hex(b) for b in r.blocks)[:5])


def test_a_null_dereference_in_a_pie_still_faults_at_its_site(tmp_path, gcc):
    exe = _build(tmp_path, "pie", gcc, "-pie", "-fPIE")
    data = exe.read_bytes()
    for base in (0, 0x100000):
        fa = _addr(exe, "null_parse") + base
        r = emulate.run_function(data, fa, b"NN", load_base=base)
        assert r.crashed and r.access == "read" and r.fault_addr == 0
        assert fa <= r.fault_pc < fa + 0x80, (hex(base), hex(r.fault_pc))


def test_an_address_outside_the_image_is_a_mismatch_never_a_finding(tmp_path, gcc):
    exe = _build(tmp_path, "pie", gcc, "-pie", "-fPIE")
    data = exe.read_bytes()
    # A Ghidra address handed over WITHOUT its base: exactly the old failure.
    r = emulate.run_function(data, _addr(exe, "table_parse") + 0x100000, b"\x00", load_base=0)
    assert not r.crashed and "not in the loaded image" in r.note


# --------------------------------------------------------------------- program-crash attribution
_TWO_SITES = r"""
#include <unistd.h>
#include <string.h>
__attribute__((noinline)) void parse(const char *s, long n) {
    char b[16];
    if (n >= 2 && s[0] == 'Z') memcpy(b, s, 256);   /* smash: a control-flow fault */
    write(1, b, 1);
}
__attribute__((noinline)) void other(const char *s) {
    volatile int *p = 0;
    if (s[1] == 'Q') *p = 1;                        /* a DIFFERENT bug, hit first */
}
int main(void) { static char in[4096]; long n = read(0, in, sizeof in);
                 if (n > 1) { other(in); parse(in, n); } return 0; }
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_a_program_crash_at_another_site_does_not_promote(store, case, pool, gcc, tmp_path):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the ptrace capture is x86-64 here")
    c = tmp_path / "two.c"
    c.write_text(_TWO_SITES)
    out = tmp_path / "two"
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(c), "-o",
                       str(out)], capture_output=True).returncode:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="two")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True)
    assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True)
    assert pool.wait_idle(180)
    fns = {f.name: f.addr for f in FunctionDAO(store.conn).list_by_target(t.id)}
    if "parse" not in fns:
        pytest.skip("the backend did not name parse")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    def run_subprocess(cmd, timeout=None, **kw):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)

    ctx = SimpleNamespace(conn=store.conn, run_subprocess=run_subprocess)
    exe = store.content.stage_target(t, scratch, "two")
    lead = {"function_addr": fns["parse"], "func_name": "parse", "access": "fetch"}

    # 'Q' second: `other` NULL-derefs before parse is ever called -- a crash, but not parse's.
    ours, detail = _locate_program_crash(ctx, t, exe, "stdin", [], b"ZQ" + b"A" * 60, lead, 10)
    assert not ours and "other" in detail and "not in parse" in detail, detail

    # Without the 'Q', parse's own smash is what kills the program: promoted, and says why.
    ours, detail = _locate_program_crash(ctx, t, exe, "stdin", [], b"ZA" + b"A" * 60, lead, 10)
    assert ours and "parse" in detail, detail
