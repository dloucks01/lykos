"""Doc 62 item 5: the emulated harness's REDZONE + QUARANTINE heap.

The old bump allocator let a heap overflow run silently into the next chunk and treated free() as a
no-op, so the harness could only see a heap bug that walked off the whole 16 MiB heap. Every case
here is a real heap defect the harness must now report -- with the right class -- and every case
has an in-bounds negative control from the SAME function that must return cleanly."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.harness.emulate import _Heap, available, run_function
from lykos.analyze.harness.harness_stage import _fault_cwe

pytestmark = pytest.mark.skipif(not available(), reason="unicorn not installed")

_SRC = r"""
#include <stdlib.h>
#include <string.h>
/* inline store loop: the overflow is the EMULATED code's own write (the memory hook) */
__attribute__((noinline)) int loop_copy(char *buf, int len){
  char *p = malloc(16);
  for (int i = 0; i < len; i++) p[i] = buf[i];
  int r = p[0]; free(p); return r;
}
/* the overflow happens inside a libc stub (memcpy) */
__attribute__((noinline)) int stub_copy(char *buf, int len){
  char *p = malloc(16);
  memcpy(p, buf, len);
  int r = p[0]; free(p); return r;
}
/* attacker index into an 8-byte chunk: an over-READ */
__attribute__((noinline)) int idx_read(char *buf, int len){
  if (len < 1) return 0;
  char *p = malloc(8);
  memset(p, 7, 8);
  int r = p[(unsigned char)buf[0]];
  free(p); return r;
}
/* 'U' -> read after free */
__attribute__((noinline)) int uaf(char *buf, int len){
  char *p = malloc(16);
  p[0] = 1;
  free(p);
  if (len > 0 && buf[0] == 'U') return p[0];
  return 0;
}
/* 'D' -> double free */
__attribute__((noinline)) int dfree(char *buf, int len){
  char *p = malloc(16);
  free(p);
  if (len > 0 && buf[0] == 'D') free(p);
  return 0;
}
/* 'I' -> free of an interior pointer */
__attribute__((noinline)) int ifree(char *buf, int len){
  char *p = malloc(16);
  free((len > 0 && buf[0] == 'I') ? p + 4 : p);
  return 0;
}
int main(int c, char **v){ (void)v; char b[1]={0};
  return loop_copy(b,1)+stub_copy(b,1)+idx_read(b,1)+uaf(b,1)+dfree(b,1)+ifree(b,1)+c; }
"""

_FUNCS = ("loop_copy", "stub_copy", "idx_read", "uaf", "dfree", "ifree")


@pytest.fixture(scope="module")
def bin_(tmp_path_factory):
    import shutil
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("rz")
    (d / "t.c").write_text(_SRC)
    exe = d / "t"
    subprocess.run([gcc, "-no-pie", "-O0", "-w", "-fno-builtin", str(d / "t.c"), "-o", str(exe)],
                   check=True)
    syms = {}
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] in _FUNCS:
            syms[p[2]] = int(p[0], 16)
    assert set(syms) == set(_FUNCS), syms
    return exe.read_bytes(), syms


def _run(bin_, fn, data):
    blob, syms = bin_
    return run_function(blob, syms[fn], data)


@pytest.mark.parametrize("fn", ["loop_copy", "stub_copy"])
def test_one_byte_heap_overflow_write_is_caught(bin_, fn):
    ok = _run(bin_, fn, b"A" * 16)
    assert ok.returned and not ok.crashed, ok.note        # exactly fills the chunk: clean
    bad = _run(bin_, fn, b"A" * 17)                        # ONE byte past a 16-byte chunk
    assert bad.crashed and bad.heap_kind == "heap-buffer-overflow", (bad.note, bad.heap_detail)
    assert bad.access == "write"
    assert "16-byte chunk" in bad.heap_detail
    assert _fault_cwe(bad)[0] == "CWE-122"


def test_heap_over_read_is_a_read(bin_):
    ok = _run(bin_, "idx_read", b"\x07")
    assert ok.returned and not ok.crashed, ok.note
    bad = _run(bin_, "idx_read", b"\x08")
    assert bad.crashed and bad.heap_kind == "heap-buffer-overflow" and bad.access == "read"
    assert _fault_cwe(bad)[0] == "CWE-125"


def test_use_after_free(bin_):
    assert _run(bin_, "uaf", b"x").returned
    bad = _run(bin_, "uaf", b"U")
    assert bad.crashed and bad.heap_kind == "heap-use-after-free", bad.heap_detail
    assert _fault_cwe(bad)[0] == "CWE-416"


def test_double_free(bin_):
    assert _run(bin_, "dfree", b"x").returned
    bad = _run(bin_, "dfree", b"D")
    assert bad.crashed and bad.heap_kind == "double-free"
    assert _fault_cwe(bad)[0] == "CWE-415"


def test_invalid_free(bin_):
    assert _run(bin_, "ifree", b"x").returned
    bad = _run(bin_, "ifree", b"I")
    assert bad.crashed and bad.heap_kind == "invalid-free"
    assert _fault_cwe(bad)[0] == "CWE-763"


def test_heap_model_unit():
    h = _Heap()
    a, b = h.alloc(10), h.alloc(0)
    assert a % 16 == 0 and b - a >= 16 + 32                  # redzone between chunks
    assert h.check(a, 10, "read") is None
    assert h.check(a + 9, 2, "write")[0] == "heap-buffer-overflow"
    assert h.check(b, 1, "read")[0] == "heap-buffer-overflow"     # malloc(0): no usable byte
    assert h.check(a - 1, 1, "read")[0] == "heap-buffer-overflow"  # left redzone
    # an aligned 16-byte vector load over the chunk's own tail is not a report
    assert h.check(a, 16, "read") is None
    assert h.check(a, 16, "write")[0] == "heap-buffer-overflow"
    assert h.free(a) is None and h.check(a, 1, "read")[0] == "heap-use-after-free"
    assert h.free(a)[0] == "double-free"
    assert h.free(a + 3)[0] == "invalid-free"
    assert h.free(0) is None
    c = h.alloc(4)
    assert c > b                                              # freed memory is never reused


def test_uninitialised_static_libc_fault_is_an_artifact_not_a_finding():
    """A NULL-page fault at a PC inside a static binary's libc (no heap verdict) is the harness's
    missing libc initialisation; a redzone-heap fault inside glibc's own memcpy is a real one."""
    from types import SimpleNamespace as N

    from lykos.analyze.harness.harness_stage import _LibSet, _uninit_libc_artifact
    lib = _LibSet({0x42CD40})
    lib.ranges = [(0x42CD40, 0x42CE84)]                    # malloc
    lib.bound = 0x40FCF0                                    # stripped: everything above is library
    tls_null = N(fault_pc=0x42CD7D, fault_addr=0x178, heap_kind="", access="read")
    assert _uninit_libc_artifact(tls_null, lib)
    above = N(fault_pc=0x47E19D, fault_addr=0x308, heap_kind="", access="read")
    assert _uninit_libc_artifact(above, lib)                # above the layout boundary
    heap = N(fault_pc=0x432D90, fault_addr=0xCC0000000040, heap_kind="heap-buffer-overflow",
             access="write")
    assert not _uninit_libc_artifact(heap, lib)             # memcpy overflowing a redzone chunk
    prog = N(fault_pc=0x408B10, fault_addr=0x0, heap_kind="", access="read")
    assert not _uninit_libc_artifact(prog, lib)             # the program's own NULL deref
    wild = N(fault_pc=0x42CD7D, fault_addr=0x4141414141, heap_kind="", access="read")
    assert not _uninit_libc_artifact(wild, lib)             # input-driven wild pointer in libc
    assert not _uninit_libc_artifact(tls_null, _LibSet())   # dynamic binary: nothing scoped
