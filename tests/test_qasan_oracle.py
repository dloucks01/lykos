"""QASan: the binary-only memory oracle. A heap over-read / small over-write that does NOT crash a
native run is reported (class, access, size, in-target site, alloc site), and a target that merely
PRINTS a sanitizer report -- echoing its input, or a canned banner, even followed by a real SIGSEGV
-- is never accepted (the nonce'd module name must appear in a frame, the report must not be in the
input, and a report followed by a clean exit is rejected)."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze.dynamic import qasan

pytestmark = pytest.mark.skipif(not qasan.available(), reason="needs afl-qemu-trace + libqasan")

_OVR = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
int main(void){ unsigned char h[4]; if(read(0,h,4)!=4) return 0;
  unsigned n=h[0]; char *b=malloc(16); memset(b,'x',16);
  unsigned long s=0; for(unsigned i=0;i<n;i++) s+=b[i];   /* silent heap over-read when n>16 */
  printf("sum %lu\n", s); free(b); return 0; }
"""
_UAF = r"""
#include <stdlib.h>
#include <unistd.h>
int main(void){ char c; if(read(0,&c,1)!=1) return 0; char *p=malloc(32); free(p);
  if(c=='U') return p[3]; return 0; }
"""
# canned report text: once with a clean exit, once followed by a REAL SIGSEGV
_FAKE = r"""
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
int main(int argc,char**argv){ char b[8]; read(0,b,8);
  fprintf(stderr,"==1==ERROR: QEMU-AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2 bp 0x3 sp 0x4\nREAD of size 1 at 0x1 thread T1\n    #0 0x2 (%s+0x1169)\n    #1 0x3 (/lib/libc.so.6+0x1)\n", argv[0]);
  if(b[0]=='S') raise(SIGSEGV); return 0; }
"""
_ECHO = r"""
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
int main(void){ char b[512]={0}; int n=read(0,b,511); fwrite(b,1,n>0?n:0,stderr); raise(SIGSEGV); }
"""


def _build(src, tmp_path, gcc, name):
    c = tmp_path / f"{name}.c"; c.write_text(src)
    exe = tmp_path / name
    if subprocess.run([gcc, "-O0", "-w", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build fixture")
    return exe


def test_silent_heap_overread_is_reported_and_located(tmp_path, gcc):
    exe = _build(_OVR, tmp_path, gcc, "ovr")
    native = subprocess.run([str(exe)], input=b"\x28AAA", capture_output=True)
    assert native.returncode == 0                      # the bug is invisible natively
    assert qasan.run(exe, b"\x08AAA", timeout=8) is None   # in-bounds input: clean
    r = qasan.run(exe, b"\x28AAA", timeout=8)
    assert r is not None and r.kind == "heap-buffer-overflow" and r.access == "READ"
    assert r.cwe == "CWE-125" and r.site_off is not None and r.alloc_off is not None
    assert "16-byte region" in (r.region or "")
    va = qasan.site_va(r, exe.read_bytes())
    nm = subprocess.run(["addr2line", "-f", "-e", str(exe), hex(va)], capture_output=True,
                        text=True).stdout.split()
    assert nm and nm[0] == "main"                      # the site maps back into the right function


def test_use_after_free_is_classified(tmp_path, gcc):
    exe = _build(_UAF, tmp_path, gcc, "uaf")
    assert qasan.run(exe, b"N", timeout=8) is None
    r = qasan.run(exe, b"U", timeout=8)
    assert r is not None and r.kind == "heap-use-after-free" and r.cwe == "CWE-416"


@pytest.mark.parametrize("inp", [b"clean000", b"SEGV0000"], ids=["clean-exit", "real-sigsegv"])
def test_a_canned_report_is_never_accepted(inp, tmp_path, gcc):
    """The fake names its own argv[0] in a frame -- but lykos stages the target under a nonce name
    in a fresh dir and checks the report against it, and the clean-exit variant fails the
    abnormal-end rule regardless."""
    exe = _build(_FAKE, tmp_path, gcc, "fake")
    r = qasan.run(exe, inp, timeout=8)
    if r is not None:
        # only acceptable if it is a GENUINE report from the instrumentation (none fires here)
        pytest.fail(f"accepted a canned report: {r.summary()}")


def test_an_echoed_report_is_rejected(tmp_path, gcc):
    exe = _build(_ECHO, tmp_path, gcc, "echo")
    fake = (b"==1==ERROR: QEMU-AddressSanitizer: heap-buffer-overflow on address 0x1 at pc 0x2 "
            b"bp 0x3 sp 0x4\nREAD of size 1 at 0x1 thread T1\n    #0 0x2 (/x/t_000000000000+0x10)\n")
    assert qasan.run(exe, fake, timeout=8) is None


def test_static_binaries_are_declined_with_a_reason(tmp_path, gcc):
    c = tmp_path / "s.c"; c.write_text("int main(void){return 0;}\n")
    exe = tmp_path / "s"
    if subprocess.run([gcc, "-static", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("no static libc")
    ok, why = qasan.applicable(exe.read_bytes(), "x86-64")
    assert not ok and "statically linked" in why
    ok, why = qasan.applicable(exe.read_bytes(), "aarch64")
    assert not ok and "x86-64" in why


_GATED = r"""
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
int main(void){ unsigned char h[8]; if(read(0,h,8)<2 || h[0]!='Q') return 0;
  unsigned n=h[1]; char *b=malloc(16); memset(b,'x',16);
  volatile unsigned long s=0; for(unsigned i=0;i<n;i++) s+=b[i];   /* silent over-read if n>16 */
  free(b); return 0; }
"""


def test_coverage_stage_files_a_qasan_demonstrated_overread(store, case, tmp_path, gcc):
    """End to end through the real coverage_fuzz stage: AFL -Q runs under QASan, the silent
    over-read never crashes natively, and the QASan replay pass files a CONFIRMED CWE-125 finding
    located in main -- kept out of the native prove loop (isolation 'qasan')."""
    import base64
    from lykos.analyze import register
    from lykos.analyze.fuzz import aflpp, enqueue_coverage_fuzz
    from lykos.analyze.ingest import ingest
    from lykos.db.dao import DynResultDAO, FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if aflpp.locate_afl() is None:
        pytest.skip("afl-fuzz not installed")
    exe = _build(_GATED, tmp_path, gcc, "gated")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, lease_seconds=180,
                                                              poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, exe)
        from lykos.analyze.ingest import enqueue_triage
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True)
        assert pool.wait_idle(120)
        run = enqueue_coverage_fuzz(q, t, params={
            "input_mode": "stdin", "max_seconds": 40, "exec_timeout": 1, "qemu": True,
            "seeds": [base64.b64encode(b"Q\x04AAAAAA").decode()]})
        assert pool.wait_idle(240)
        rec = q.runs.get(run.id)
        if rec.status != "done":
            pytest.skip("afl-fuzz could not run here: " + str(rec.error))
    finally:
        pool.stop(grace=3.0)
    q_f = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "qasan"]
    assert q_f, "QASan lane filed nothing"
    f = q_f[0]
    assert f.cwe == "CWE-125" and f.state == "confirmed" and "main" in f.title
    assert any(d.isolation == "qasan" for d in DynResultDAO(store.conn).list_by_target(t.id))
