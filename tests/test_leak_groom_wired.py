"""End-to-end: the leak->groom->control chain WIRED into the chain_primitive stage. A confirmed
heap OOB-write lead on a PIE target that discloses a pointer, plus the groom op-model, drives the
stage to file a poc-backed L3 (ASLR defeated) -- the auto-wiring of heap_groom.detonate_leak_groom.
"""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.poc.chain_primitive import enqueue_chain
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ write(1,"WIN\n",4); _exit(42); }
static void noop(void){ }
typedef struct { void (*fp)(void); char pad[8]; } obj_t;
static unsigned char *slot0; static obj_t *slot1;
int main(void){
  setvbuf(stdout,0,2,0);
  printf("leak %p\n", (void*)&main);
  for(;;){
    int c = getchar();
    if (c==EOF || c=='Q') break;
    if (c=='A'){ unsigned int sz=0; if(fread(&sz,4,1,stdin)!=1) break; slot0=malloc(sz); }
    else if (c=='O'){ slot1=malloc(sizeof(obj_t)); slot1->fp=noop; }
    else if (c=='E'){ unsigned int n=0; if(fread(&n,4,1,stdin)!=1) break; if(fread(slot0,1,n,stdin)!=n) break; }
    else if (c=='T'){ slot1->fp(); }
  }
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


def test_chain_stage_fires_leak_groom_to_L3(store, case, pool, gcc, tmp_path, x86_64_only):
    c = tmp_path / "h.c"; c.write_text(_SRC)
    exe = tmp_path / "h"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w",
                       str(c), "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("cannot build PIE heap fixture")
    t = ingest(store, case.id, exe, filename="h")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    # A confirmed heap OOB-write lead (what a detector/fuzzer would hand the chain stage).
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, {"cwe": "CWE-787", "title": "heap OOB write (overflow into next chunk)",
                              "detector": "oob_index", "severity": "high", "state": "corroborated",
                              "confidence": 0.9, "dedup_key": "lead:oob_write:leakgroom"})
    # Drive the chain stage with the declarative groom op-model (the analyst-supplied op-model path;
    # op-model discovery for the victim-fptr object is the named next step).
    params = {
        "lg_opmodel": {
            "alloc_buf": {"prefix_hex": "41", "size": "u32le"},
            "alloc_obj": {"prefix_hex": "4f"},
            "edit_buf":  {"prefix_hex": "45", "len": "u32le", "data": True},
            "trigger":   {"prefix_hex": "54"},
        },
        "lg_buf_request": 24,
        "lg_win_off": _win_off(str(exe)),
        "lg_obj_fptr_off": 0,
    }
    enqueue_chain(q, t, params=params, force=True)
    assert pool.wait_idle(90)
    pocs = [p for p in PocDAO(store.conn).list_by_target(t.id) if p.level == "L3" and p.verified]
    assert pocs, "leak-groom chain did not file a verified L3 poc"
