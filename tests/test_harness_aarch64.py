"""Doc 62 item 5: the emulated function harness on AARCH64 (dynamic and static glibc builds).

The same redzone-heap defects as test_harness_redzone, cross-compiled: arguments in x0/x1, the
return through the link register to the sentinel, PLT stubs at .plt+32+16*i, `bl` call sites,
`svc` syscalls, TPIDR_EL0 TLS -- and, statically linked, glibc's aarch64 IFUNC slots (IRELATIVE
1032) resolved so memcpy & co. run instead of jumping to 0."""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.analyze import ifunc
from lykos.analyze.harness.emulate import available, run_function

pytestmark = pytest.mark.skipif(not available() or not shutil.which("aarch64-linux-gnu-gcc"),
                                reason="needs unicorn and an aarch64 cross gcc")

_SRC = r"""
#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) int loop_copy(char *buf, int len){
  char *p = malloc(16);
  for (int i = 0; i < len; i++) p[i] = buf[i];
  int r = p[0]; free(p); return r;
}
__attribute__((noinline)) int stub_copy(char *buf, int len){
  char *p = malloc(16);
  memcpy(p, buf, len);
  p[15] = 0;
  int r = (int)strlen(p); free(p); return r;
}
__attribute__((noinline)) int uaf(char *buf, int len){
  char *p = malloc(16); p[0] = 1; free(p);
  if (len > 0 && buf[0] == 'U') return p[0];
  return 0;
}
__attribute__((noinline)) int dfree(char *buf, int len){
  char *p = malloc(16); free(p);
  if (len > 0 && buf[0] == 'D') free(p);
  return 0;
}
int main(int c, char **v){ return loop_copy(v[0],1)+stub_copy(v[0],1)+uaf(v[0],1)+dfree(v[0],c); }
"""
_FUNCS = ("loop_copy", "stub_copy", "uaf", "dfree")


def _build(tmp_path_factory, extra):
    d = tmp_path_factory.mktemp("a64")
    (d / "t.c").write_text(_SRC)
    exe = d / "t"
    r = subprocess.run(["aarch64-linux-gnu-gcc", "-no-pie", "-O0", "-w", "-fno-builtin", *extra,
                        str(d / "t.c"), "-o", str(exe)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("aarch64 build failed: " + r.stderr.decode()[-200:])
    syms = {}
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[2] in _FUNCS + ("malloc", "free"):
            syms[p[2]] = int(p[0], 16)
    return exe.read_bytes(), syms


@pytest.fixture(scope="module", params=["dynamic", "static"])
def a64(request, tmp_path_factory):
    return request.param, *_build(tmp_path_factory, ["-static"] if request.param == "static" else [])


def test_aarch64_heap_overflow_both_in_code_and_in_memcpy(a64):
    kind, blob, syms = a64
    for fn in ("loop_copy", "stub_copy"):
        ok = run_function(blob, syms[fn], b"A" * 15 + b"\x00")
        assert ok.returned and not ok.crashed, (kind, fn, ok.note)
        bad = run_function(blob, syms[fn], b"A" * 17)
        assert bad.crashed and bad.heap_kind == "heap-buffer-overflow" and bad.access == "write", (
            kind, fn, bad.note, bad.heap_detail)


def test_aarch64_use_after_free_and_double_free(a64):
    kind, blob, syms = a64
    assert run_function(blob, syms["uaf"], b"x").returned, kind
    assert run_function(blob, syms["uaf"], b"U").heap_kind == "heap-use-after-free", kind
    assert run_function(blob, syms["dfree"], b"x").returned, kind
    assert run_function(blob, syms["dfree"], b"D").heap_kind == "double-free", kind


def test_aarch64_static_ifunc_slots_resolve(a64):
    kind, blob, _syms = a64
    if kind != "static":
        pytest.skip("IFUNC slots are a static-binary property")
    relocs = ifunc.irelative_relocs(blob)
    assert relocs and len(ifunc.resolve(blob)) == len(relocs)
    assert "memcpy" in set(ifunc.slot_names(blob).values())


_STAGE_SRC = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((noinline)) void parse(const char *s, long n){
    char *p = malloc(16);
    if (!p) return;
    if (n > 0) memcpy(p, s, n < 40 ? n : 40);   /* past 16 bytes: a heap overflow */
    write(1, p, 1);
    free(p);
}
int main(void){ static char in[64]; long n = read(0, in, sizeof in); if (n > 0) parse(in, n); return 0; }
"""


def test_harness_stage_drives_an_aarch64_binary(store, case, tmp_path):
    from lykos.analyze import register
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.harness.harness_stage import enqueue_harness
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    c = tmp_path / "h.c"
    c.write_text(_STAGE_SRC)
    out = tmp_path / "h"
    if subprocess.run(["aarch64-linux-gnu-gcc", "-no-pie", "-O0", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the aarch64 fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        from lykos.db.dao import TargetDAO
        t = ingest(store, case.id, out, filename="h")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
        t = TargetDAO(store.conn).get(t.id)
        assert t.arch in ("aarch64", "arm64"), t.arch
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
        enqueue_harness(q, t, params={"input_mode": "stdin", "sequence": False, "replay": False},
                        force=True)
        assert pool.wait_idle(240)
    finally:
        pool.stop(grace=3.0)
    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "harness"]
    assert any(f.cwe == "CWE-122" for f in hits), [(f.cwe, f.title) for f in hits]
