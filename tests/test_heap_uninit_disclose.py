"""CWE-457/reclaimed-heap read -> information disclosure (doc 58).

The heap tracer could already RECOVER a libc base from a freed/reclaimed chunk's stale allocator
metadata, but filed it only as 'corroborated' -- a demonstrated disclosure with no runnable bundle,
the "corroboration, nothing further" the operator banned. _heap_uninit_disclose promotes it to a
poc-backed L3: free a large chunk (frees to the unsorted bin, whose fd is a libc main_arena
pointer), read the reclaimed memory, and recover the base -- ASLR defeated, the leak a ret2libc /
FSOP / tcache-poison chain consumes. Forgery-proof (page-aligned base) + a negative control (the
same view of a LIVE chunk discloses no base).

A libc leak works on any glibc, so this runs on the host.
"""
import shutil
import subprocess
import sys

import pytest

from lykos.analyze.poc import chain_primitive
from lykos.analyze.poc import heap as _heap

# A heap menu: 1 add(idx,size)+read data · 2 free(idx) · 3 view(idx) [16 bytes] · 4 quit.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void *slots[64];
static long rdl(void){ char b[64]; if (!fgets(b, sizeof b, stdin)) exit(0); return strtol(b, 0, 10); }
int main(void){
    char cmd[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (fgets(cmd, sizeof cmd, stdin)) {
        long c = strtol(cmd, 0, 10);
        if (c == 1) { long i = rdl(); long sz = rdl();
            slots[i] = malloc(sz); if (read(0, slots[i], sz) < 0) return 1; }
        else if (c == 2) { long i = rdl(); free(slots[i]); }       /* no clear -> reclaimable */
        else if (c == 3) { long i = rdl(); write(1, slots[i], 16); write(1, "\n", 1); }
        else if (c == 4) return 0;
    }
    return 0;
}
"""

_ROLES = {"add": "1", "free": "2", "view": "3"}
_MODEL = {"1": ["idx", "num", "str"], "2": ["idx"], "3": ["idx"]}


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


def _uoff(exe):
    path = subprocess.check_output(["bash", "-c", f"ldd {exe} | awk '/libc/{{print $3}}'"]).decode().strip()
    return _heap.unsorted_bin_offset(path)


def _plain_spawn(exe):
    return lambda: subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_reclaimed_heap_read_discloses_libc_base(tmp_path):
    exe = _build(tmp_path)
    tb = exe.read_bytes()
    uoff = _uoff(exe)
    assert uoff, "unsorted-bin offset not measurable"
    spawn = _plain_spawn(exe)

    hit = chain_primitive._heap_uninit_run(_Ctx(), spawn, None, _ROLES, _MODEL, uoff, tb,
                                           skip_free=False)
    assert hit is not None and hit["kind"] == "libc", "reclaimed-heap read did not disclose libc"
    assert hit["base"] > 0 and hit["base"] % 0x1000 == 0        # a real, page-aligned libc base

    # Negative control: the SAME view WITHOUT the free (a live chunk) must disclose no base.
    neg = chain_primitive._heap_uninit_run(_Ctx(), spawn, None, _ROLES, _MODEL, uoff, tb,
                                           skip_free=True)
    assert neg is None, "a live-chunk read fabricated a base (unsound)"


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_heap_uninit_repro_script_discloses(tmp_path):
    exe = _build(tmp_path)
    tb = exe.read_bytes()
    uoff = _uoff(exe)
    hit = chain_primitive._heap_uninit_run(_Ctx(), _plain_spawn(exe), None, _ROLES, _MODEL, uoff, tb,
                                           skip_free=False)
    assert hit, "no disclosure to reproduce"
    script = chain_primitive._heap_uninit_repro_script(_ROLES, hit, _MODEL["1"])
    sp = tmp_path / "exploit.py"
    sp.write_bytes(script)
    r = subprocess.run([sys.executable, str(sp), str(exe)], capture_output=True, timeout=20)
    assert r.returncode == 0 and b"base" in r.stdout, f"repro failed: {r.stdout[-120:]!r}"
