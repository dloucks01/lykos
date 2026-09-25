"""L3 magic-value stack overwrite: a local checked against a magic constant gates a flag-print
path (jeeves' `if (local==0x1337bab3)`). A stack overflow that writes the magic into that local
takes the protected branch WITHOUT touching the return -- no leak, no gadgets, PIE-safe. The stage
recovers the overflow distance empirically and confirms with a planted marker + a negative control
(a wrong magic at the same offset must NOT print it)."""
from __future__ import annotations

import struct
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.poc import enqueue_exploit
from lykos.analyze.poc.rop import find_magic_gates
from lykos.analyze.dynamic import sandbox
from lykos.db.dao import FindingDAO, PocDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool

# A `volatile` local -> gcc emits `mov eax,[rbp-X]; cmp eax,IMM32; jne` (the load-then-compare
# shape, distinct from jeeves' direct `cmp [rbp-X],IMM32`). On the magic, open flag.txt (relative,
# like the real challenge) and print it.
_MAGIC = r"""
#include <stdio.h>
#include <unistd.h>
int main(void){
    volatile unsigned int magic = 0xdeadbeef;
    char buf[64];
    (void)read(0, buf, 256);
    if (magic == 0x1337c0de) {
        char fb[160]; FILE *f = fopen("flag.txt", "r");
        if (f) { size_t k = fread(fb, 1, 159, f); fb[k] = 0; printf("gift: %s\n", fb); fclose(f); }
    }
    return 0;
}
"""

# No gate: the flag prints unconditionally -- there is nothing for a magic overwrite to satisfy.
_NOGATE = r"""
#include <stdio.h>
#include <unistd.h>
int main(void){
    char buf[64];
    (void)read(0, buf, 256);
    FILE *f = fopen("flag.txt", "r");
    if (f) { char fb[160]; size_t k = fread(fb, 1, 159, f); fb[k] = 0; printf("%s\n", fb); fclose(f); }
    return 0;
}
"""


@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("magic-overwrite detonation is x86-64 native only")


def _build(gcc, d, src, name):
    c = d / f"{name}.c"; c.write_text(src)
    out = d / name
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-pie", "-fPIE", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build PIE magic-gate target")
    return out


@pytest.fixture
def magic_bin(gcc, tmp_path_factory, x86_64_only):
    return _build(gcc, tmp_path_factory.mktemp("magic"), _MAGIC, "magic")


@pytest.fixture
def nogate_bin(gcc, tmp_path_factory, x86_64_only):
    return _build(gcc, tmp_path_factory.mktemp("nogate"), _NOGATE, "nogate")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_find_magic_gates_load_then_compare(magic_bin):
    gates = find_magic_gates(magic_bin.read_bytes())
    assert any(g["magic"] == 0x1337C0DE and g["disp"] < 0 for g in gates)


def test_find_magic_gates_direct_compare_bytes():
    # A hand-built exec segment with `cmp dword [rbp-4], 0x1337bab3; je +2` (jeeves' direct shape).
    # find_magic_gates scans PT_LOAD exec segments; feed a minimal ELF-free path via the raw matcher
    # by checking both encodings are recognised on real bytes above -- here assert the direct form
    # is picked out of a buffer embedded in an executable segment of the compiled binary is covered
    # by the load-then-compare test; this asserts the opcode matcher on the direct immediate form.
    from lykos.analyze.poc import rop
    seg = b"\x90" * 4 + b"\x81\x7d\xfc\xb3\xba\x37\x13\x74\x02" + b"\x90" * 4
    # emulate a single exec load segment by monkeypatching _loads
    import types
    orig = rop._loads
    rop._loads = lambda data: [(0, len(seg), 0x1000, 1)]
    try:
        gates = rop.find_magic_gates(seg)
    finally:
        rop._loads = orig
    assert gates and gates[0]["magic"] == 0x1337BAB3 and gates[0]["disp"] == -4


def test_no_gate_when_flag_is_unconditional(nogate_bin):
    assert find_magic_gates(nogate_bin.read_bytes()) == []


def test_build_exploit_confirms_magic_overwrite(store, case, pool, magic_bin):
    t = ingest(store, case.id, magic_bin, filename="magic")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(30)
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "auto"})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"

    pocs = PocDAO(store.conn).list_by_target(t.id)
    assert any(pc.level == "L3" and pc.verified for pc in pocs)
    pb = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.state == "poc-backed"]
    assert any("magic-value" in e.get("detail", "") for f in pb for e in f.evidence)
    l3 = next(pc for pc in pocs if pc.level == "L3")
    assert l3.finding_id


def test_explicit_magic_strategy(store, case, pool, magic_bin):
    t = ingest(store, case.id, magic_bin, filename="magic")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(30)
    run = enqueue_exploit(q, t, params={"input_mode": "stdin", "strategy": "magic"})
    assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    assert any(pc.level == "L3" and pc.verified for pc in PocDAO(store.conn).list_by_target(t.id))
