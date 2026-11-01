"""Stack-local out-of-bounds read -> canary / saved-return disclosure (doc 58).

Extends the disclosure column to STACK secrets: steer a read of a stack-local buffer up its own
frame to disclose the stack CANARY (the secret that bypasses the canary mitigation) or a saved
RETURN address (-> PIE base). Both forgery-proof:
  * canary -- a canary-shaped value (NUL low byte, non-pointer) that CHANGES between two runs of
    the same input, which an echo cannot and an ASLR pointer (canonical range) is not;
  * PIE    -- recover_pie_base over disclosed saved returns.
Runs on the host (a stack-protected PIE binary).
"""
import shutil
import subprocess
import sys

import pytest

from lykos.analyze.poc import chain_primitive

# A PIE, stack-protected binary: option 1 -> reader() reads an index and prints buf[idx] from a
# stack-local buffer (OOB for idx >= 8, walking up the frame); option 2 quits.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
static long rdl(void){ char b[64]; if (!fgets(b, sizeof b, stdin)) exit(0); return strtol(b, 0, 10); }
void reader(void){
    long buf[8];
    for (int i = 0; i < 8; i++) buf[i] = i;
    long i = rdl();
    printf("%ld\n", buf[i]);                 /* OOB read up the stack for i >= 8 */
}
int main(void){
    char cmd[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (fgets(cmd, sizeof cmd, stdin)) {
        long c = strtol(cmd, 0, 10);
        if (c == 1) reader();
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
    src = tmp_path / "stk.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "stk"
    r = subprocess.run(["gcc", "-fPIE", "-pie", "-fstack-protector-all", "-O0", "-w", "-o", str(exe),
                        str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)
    return exe


def _plain_spawn(exe):
    return lambda: subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)


def test_is_canary_shape():
    assert chain_primitive._is_canary(0x44ff1db647fb0c00)      # NUL low byte, non-pointer, populated
    assert not chain_primitive._is_canary(0x7ffff9f566d0)      # a stack pointer (canonical range)
    assert not chain_primitive._is_canary(0x1a)                # a small integer
    assert not chain_primitive._is_canary(0x55e0deadbe00)      # canonical-range (a 00-ending pointer)


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_stack_canary_detection_changes_across_runs(tmp_path):
    # The forgery-proof core: the canary index is canary-shaped in two runs AND differs.
    exe = _build(tmp_path)
    spawn = _plain_spawn(exe)
    a = chain_primitive._sweep_read(spawn, None, "1", _MODEL, 0, 48)
    b = chain_primitive._sweep_read(spawn, None, "1", _MODEL, 0, 48)
    canaries = [i for i, v in a.items()
                if chain_primitive._is_canary(v) and i in b and chain_primitive._is_canary(b[i])
                and b[i] != v]
    assert canaries, f"no canary index changed across runs: a={[(i, hex(v)) for i, v in a.items()]}"


@pytest.mark.skipif(not shutil.which("gcc"), reason="needs gcc")
def test_stack_secret_disclose_end_to_end(tmp_path):
    exe = _build(tmp_path)
    tb = exe.read_bytes()
    hit = chain_primitive._stack_secret_disclose(_Ctx(), _plain_spawn(exe), None, _OPTS, _MODEL, tb)
    assert hit is not None and hit["kind"] in ("canary", "pie")
    if hit["kind"] == "canary":
        assert chain_primitive._is_canary(hit["canary"])
    else:
        assert hit["base"] > 0 and hit["base"] % 0x1000 == 0

    # The shipped reproducer recovers the secret against a fresh run.
    script = chain_primitive._stack_secret_repro_script(hit)
    sp = tmp_path / "exploit.py"
    sp.write_bytes(script)
    r = subprocess.run([sys.executable, str(sp), str(exe)], capture_output=True, timeout=20)
    assert r.returncode == 0, f"repro failed: {r.stdout[-120:]!r}"
