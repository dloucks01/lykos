"""Staged detonation of the attack path: a leak edge + a write edge compose to RCE, and the
attack_path stage DRIVES the leak->groom->control chain to a demonstrated L3 (not just a plan)."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.attack_path_stage import enqueue_attack_path
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

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


def test_attack_path_detonates_leak_plus_write_to_L3(store, case, pool, gcc, tmp_path, x86_64_only):
    c = tmp_path / "s.c"; c.write_text(_SRC)
    exe = tmp_path / "s"
    if subprocess.run([gcc, "-fPIE", "-pie", "-fno-stack-protector", "-O0", "-w",
                       str(c), "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("cannot build fixture")
    t = ingest(store, case.id, exe, filename="s")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    fd = FindingDAO(store.conn)
    if not [f for f in fd.list_by_target(t.id) if f.detector == "heap_fptr_call"]:
        pytest.skip("heap_fptr_call did not fire")
    # the pointer the target discloses is the leak edge -- represent it as a finding so the path
    # composes leak + write -> RCE (the write edge is the detected heap_fptr_call / CWE-822).
    fd.upsert(t.id, case.id, {"cwe": "CWE-125", "title": "address disclosure (leak)",
                              "detector": "oob_read", "severity": "medium", "state": "corroborated",
                              "confidence": 0.8, "dedup_key": "leak:disclosure:ap"})
    enqueue_attack_path(q, t, force=True); assert pool.wait_idle(120)
    ap_find = [f for f in fd.list_by_target(t.id) if f.detector == "attack_path"]
    assert ap_find, "attack_path filed no path"
    assert ap_find[0].state == "poc-backed", f"path not detonated: state={ap_find[0].state}"
    assert [p for p in PocDAO(store.conn).list_by_target(t.id) if p.level == "L3" and p.verified], \
        "no verified L3 from the staged detonation"


def test_attack_path_constructs_injection_objective(store, case, pool, gcc, tmp_path):
    """A command-injection objective path is demonstrated by a CONSTRUCTED payload (L1), not a
    memory detonation -- the generalized dispatch beyond leak->groom."""
    c = tmp_path / "t.c"; c.write_text("int main(void){return 0;}\n")
    exe = tmp_path / "t"
    if subprocess.run([gcc, "-O0", str(c), "-o", str(exe)], capture_output=True).returncode != 0:
        pytest.skip("cannot build trivial target")
    t = ingest(store, case.id, exe, filename="t")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    FindingDAO(store.conn).upsert(t.id, case.id, {
        "cwe": "CWE-78", "title": "os command injection (system with tainted arg)",
        "detector": "source_sink", "severity": "high", "state": "corroborated",
        "confidence": 0.9, "dedup_key": "cmdi:ap"})
    enqueue_attack_path(q, t, force=True); assert pool.wait_idle(60)
    ap_find = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "attack_path"]
    assert ap_find and ap_find[0].state == "poc-backed"
    assert any("cmd_exec" in (ev.get("detail") or "") or "constructed" in (ev.get("detail") or "")
               for ev in (ap_find[0].evidence or []))
    assert [p for p in PocDAO(store.conn).list_by_target(t.id)
            if p.provenance == "constructed" and p.level == "L1"]


def test_attack_path_detonates_data_only_dop(store, case, pool, gcc, tmp_path, x86_64_only):
    """A write + a post-auth sink compose to a DOP path (write->auth data-only); the attack_path
    stage demonstrates it on the binary by flipping a decision variable -- no PC control."""
    # the flag-flip fixture: a global `authed` flipped by an overflow -> privileged SECRET path.
    src = ("#include <stdio.h>\n#include <unistd.h>\n"
           "static char name[16]; static int authed=0;\n"
           "int main(void){setvbuf(stdout,0,2,0); int n=read(0,name,64); if(n<=0) return 0;\n"
           " if(authed){write(1,\"SECRET{dop}\\n\",11);} else {write(1,\"denied\\n\",7);} return 0;}\n")
    c = tmp_path / "d.c"; c.write_text(src)
    exe = tmp_path / "d"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(exe)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build dop fixture")
    t = ingest(store, case.id, exe, filename="d")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    fd = FindingDAO(store.conn)
    fd.upsert(t.id, case.id, {"cwe": "CWE-787", "title": "oob write into .bss", "detector": "oob_index",
                              "severity": "high", "state": "corroborated", "confidence": 0.9,
                              "dedup_key": "w:dop"})
    fd.upsert(t.id, case.id, {"cwe": "CWE-78", "title": "admin_exec command", "detector": "source_sink",
                              "severity": "high", "state": "corroborated", "confidence": 0.9,
                              "dedup_key": "c:dop"})
    enqueue_attack_path(q, t, force=True); assert pool.wait_idle(90)
    ap = [f for f in fd.list_by_target(t.id) if f.detector == "attack_path"]
    assert ap and ap[0].state == "poc-backed"
    assert any("data-only" in (e.get("detail") or "") for e in (ap[0].evidence or []))
    # the DOP detonator itself must have fired (not merely the path label saying "data-only")
    assert any("flipping a decision variable" in (e.get("detail") or "")
               for e in (ap[0].evidence or [])), ap[0].evidence
