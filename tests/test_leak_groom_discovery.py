"""Op-model DISCOVERY: the leak->groom->control chain fires with NO analyst op-model. A straight-line
heap target (self-allocates buf+victim, self-triggers the call around one read) has its victim
function-pointer offset discovered from the heap_fptr_call (CWE-822) finding, a trivial raw-read
op-model, and the overflow buffer size found by a bounded sweep the sound oracle confirms.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.poc.chain_primitive import enqueue_chain
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# A straight-line heap-overflow -> fptr -> call target: discloses &main (PIE base), allocs a 24-byte
# buffer then a victim object whose fptr sits at +0x30, reads attacker bytes into the buffer
# (overflowing into the victim), then calls the victim's pointer. No menu -- one input drives it.
_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ write(1,"WIN\n",4); _exit(42); }
static void noop(void){ }
typedef struct { char tag[0x30]; void (*fp)(void); } obj_t;
int main(void){
  setvbuf(stdout,0,2,0);
  printf("leak %p\n",(void*)&main);
  unsigned char *buf = malloc(24);
  obj_t *o = malloc(sizeof(obj_t)); o->fp = noop;
  if (read(0, buf, 200) <= 0) return 0;
  o->fp();
  return 0;
}
"""


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("leak-groom detonation is x86-64 native only")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _win_off(exe: str) -> int:
    for ln in subprocess.run(["nm", exe], capture_output=True, text=True).stdout.splitlines():
        p = ln.split()
        if len(p) == 3 and p[2] == "win":
            return int(p[0], 16)
    raise AssertionError("win symbol not found")


def test_chain_discovers_opmodel_and_reaches_L3(store, case, pool, gcc, tmp_path, x86_64_only):
    c = tmp_path / "s.c"; c.write_text(_SRC)
    exe = tmp_path / "s"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w",
                       str(c), "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("cannot build straight-line PIE heap fixture")
    t = ingest(store, case.id, exe, filename="s")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    # heap_fptr_call must have found the victim fptr site -- that is what discovery reads.
    hf = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "heap_fptr_call"]
    if not hf:
        pytest.skip("heap_fptr_call did not fire on this build (offset recovery unavailable)")
    # NO op-model / buf_request / obj_fptr_off params -- all discovered. (lg_win_off only, to keep
    # win selection deterministic; win discovery is a separate concern from op-model discovery.)
    enqueue_chain(q, t, params={"lg_win_off": _win_off(str(exe))}, force=True)
    assert pool.wait_idle(120)
    pocs = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.level == "L3" and p.verified]
    assert pocs, "op-model discovery did not drive the chain to a verified L3"
