"""finding_resolve: every unresolved finding gets a measured verdict from the inputs the run kept.

Fixture: `leak` over-reads a 12-byte heap chunk by up to 255 bytes -- silent natively, a fault
under the guard-page heap oracle -- and an input starting with 'L' reaches it; `never` is not
reached by any input. The resolver must FIRE the first (raise it to confirmed, record the crash
for the prove loop) and mark the second not reached, without touching its state."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.resolve_stage import enqueue_finding_resolve
from lykos.db.dao import DynResultDAO, FindingDAO, FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) int leak(const unsigned char *s, int n){
  char *p = malloc(12);
  memcpy(p, s, n < 12 ? n : 12);
  int r = p[12 + s[1]];                /* reads past the 12-byte chunk */
  free(p);
  return r;
}
__attribute__((noinline)) int never(int x){ volatile int a[4] = {0}; return a[x & 3]; }
int main(int c, char **v){
  FILE *f = fopen(v[1], "rb"); if (!f) return 2;
  unsigned char b[64]; int n = (int)fread(b, 1, sizeof b, f); fclose(f);
  if (n > 1 && b[0] == 'L') printf("%d\n", leak(b, n));
  if (c > 5) never(c);
  return 0;
}
"""


def test_resolver_fires_a_reached_site_and_marks_an_unreached_one(store, case, gcc, tmp_path):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the block tracer is native x86-64 here")
    c = tmp_path / "r.c"
    c.write_text(_SRC)
    exe = tmp_path / "r"
    if subprocess.run([gcc, "-no-pie", "-O0", "-w", str(c), "-o", str(exe)], capture_output=True).returncode:
        pytest.skip("cannot build the fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=1, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, exe, filename="r")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
        fns = {f.name: f.addr for f in FunctionDAO(store.conn).list_by_target(t.id)}
        leak_a = next(a for n, a in fns.items() if n and n.endswith("leak"))
        never_a = next(a for n, a in fns.items() if n and n.endswith("never"))
        fd = FindingDAO(store.conn)
        for name, addr in (("leak", leak_a), ("never", never_a)):
            fd.upsert(t.id, case.id, {"cwe": "CWE-125", "title": f"candidate read in {name}",
                                      "severity": "medium", "detector": "tainted_deref",
                                      "state": "candidate", "confidence": 0.4,
                                      "dedup_key": f"test:{name}", "function_addr": addr,
                                      "site_addr": addr, "evidence": []})
        sha, _, _ = store.content.put_bytes(b"L" + bytes([200]) + b"payload-bytes")
        DynResultDAO(store.conn).insert(t.id, case.id, input_sha=sha, input_mode="file",
                                        argv=["@@"], crashed=False, isolation="bwrap+netns")
        enqueue_finding_resolve(q, t); assert pool.wait_idle(240)
    finally:
        pool.stop(grace=3.0)
    by = {f.dedup_key: f for f in FindingDAO(store.conn).list_by_target(t.id)}
    leak_ev = [e["detail"] for e in by["test:leak"].evidence if e.get("channel") == "resolve"]
    never_ev = [e["detail"] for e in by["test:never"].evidence if e.get("channel") == "resolve"]
    assert leak_ev and leak_ev[-1].startswith("[fired]"), leak_ev
    assert by["test:leak"].state == "confirmed"
    assert never_ev and never_ev[-1].startswith("[not-reached]"), never_ev
    assert by["test:never"].state == "candidate"                     # a verdict never lowers/raises
    crash = [d for d in DynResultDAO(store.conn).list_by_target(t.id) if d.crashed]
    assert crash and "finding_resolve" in (crash[0].note or "")       # handed to the prove loop
