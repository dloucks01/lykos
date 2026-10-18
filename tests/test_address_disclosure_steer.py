"""The address-control disclosure must STEER a decimal index/length field toward zero.

A binary with an attacker-chosen index read (`dump=<N>`) is the shape that has no sanitizer
twin: the read is measured from the faulting address, and the disclosure from steering that
address back into mapped memory. The campaign finds a crash by pushing the index FAR out of
bounds (`dump=99` -> +0x63000), which faults with or without the guard page and, replayed on the
plain build, discloses nothing -- it is simply unmapped. The byte that chose the address is a
DECIMAL field, and `address_primitive` cannot isolate a decimal digit as a single-byte lever
(a flipped digit re-parses to a different number, not a linear stride), so `offset` is None.

Before the steer, that combination capped the case at L2: the disclosure experiment tried only
the crashing input, which crashes again and prints nothing. `_address_disclosure` now steers the
whole numeric field toward zero, and the SMALLEST index reads just off the end of the object into
the adjacent chunk -- the classic place a live pointer sits -- which is what defeats ASLR. This
test pins that: the disclosure is proved, a base is recovered, and the winning input is a SMALL
index, not the far-out-of-bounds crash the campaign started from.
"""
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import ingest
from lykos.analyze.poc import enqueue_primitive
from lykos.analyze.poc import primitive_stage as PS
from lykos.db.dao import DynResultDAO, EventDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# An attacker-chosen INDEX read with a pointer-bearing neighbour chunk. `dump=<N>` copies 128
# bytes from `buf + N*0x1000` into a local and prints them: a large N faults (unmapped), and N=0
# reads off the end of the 64-byte `buf` into `nb`, which holds live code/libc pointers.
_INDEX_READ_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void win(void){ setuid(0); execl("/bin/sh","sh",(char*)0); }
int main(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
  unsigned char *buf = (unsigned char*)malloc(64);
  void **nb = (void**)malloc(64);
  nb[0]=(void*)win; nb[1]=(void*)stdout; nb[2]=(void*)nb; nb[3]=(void*)win;
  memset(buf,'X',64);
  char line[512];
  for(;;){ ssize_t n = read(0,line,sizeof(line)-1); if(n<=0) return 0; line[n]=0;
    if(!strncmp(line,"dump=",5)){
      unsigned long i = strtoul(line+5,NULL,10);
      unsigned char tmp[128];
      memcpy(tmp, buf + i*0x1000, sizeof(tmp));
      fwrite(tmp, 1, sizeof(tmp), stdout); fflush(stdout); continue; }
    return 0; } }
"""


def test_digit_runs_finds_each_decimal_field():
    assert PS._digit_runs(b"dump=99") == [(5, 7)]
    assert PS._digit_runs(b"name=AAAA") == []
    assert PS._digit_runs(b"show=12x34") == [(5, 7), (8, 10)]
    assert PS._digit_runs(b"") == []


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content,
                   JobConfig(workers=1, lease_seconds=300, poll_interval=0.02,
                             heartbeat_interval=5.0))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.mark.skipif(sandbox.host_arch() != "x86-64", reason="native ptrace capture")
def test_a_decimal_index_read_discloses_by_steering_the_field(store, case, pool, tmp_path):
    import shutil
    gcc = shutil.which("gcc") or shutil.which("cc")
    if not gcc:
        pytest.skip("no C compiler")
    c = tmp_path / "idx.c"; c.write_text(_INDEX_READ_SRC)
    b = tmp_path / "idx"
    if subprocess.run([gcc, "-fno-stack-protector", "-w", str(c), "-o", str(b)],
                      capture_output=True).returncode:
        pytest.skip("build failed")
    target = ingest(store, case.id, b)
    # the campaign's crash: a FAR out-of-bounds index, found under the guard-page allocator.
    sha, _, _ = store.content.put_bytes(b"dump=99")
    DynResultDAO(store.conn).insert(target.id, case.id, input_sha=sha, input_mode="stdin",
                                    crashed=True, signal_name="SIGSEGV",
                                    isolation="bwrap+%s" % sandbox.GUARD_PAGE_TAG)
    q = JobQueue(store.conn)
    run = enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                               "timeout": 12})
    assert pool.wait_idle(300)
    rec = q.runs.get(run.id)
    if rec.status != "done":
        pytest.skip("ptrace unavailable here: " + str(rec.error))

    discs = [e.payload for e in EventDAO(store.conn).walk(case_id=case.id)
             if e.type == "primitive.disclosure"]
    assert discs, "the disclosure experiment never ran on a confirmed read primitive"
    proved = [d for d in discs if d.get("proved")]
    assert proved, ("the decimal index read disclosed nothing -- the field was not steered toward "
                    "zero, so only the far out-of-bounds crash was tried: %r" % discs)
    d = proved[0]
    assert d.get("pie_base"), "a leak was seen but no PIE base was resolved from it"
    # the winning input is a SMALL index, not the far-out-of-bounds crash we started from.
    won = store.content.get_bytes(d["input_sha"])
    assert won != b"dump=99", "the crashing input itself cannot disclose here; a steer was required"
    assert won.startswith(b"dump="), won
    idx = int(won[5:].split(b"\n")[0] or b"0")
    assert idx < 16, "the disclosing index must be small (reads into the adjacent chunk): %r" % won
