"""Indirect call through a function pointer stored in an object field (CWE-822): `call *[obj+off]`
invokes a fptr read from writable memory. When the object is a corruptible heap allocation (a UAF,
a heap overflow, HTB auth-or-out's print_author calling author->fptr), the corruption redirects
control flow directly. The detector flags the SURFACE from the recovered IR; it is precise about
the call shape (object-field load, not a stack-local fptr and not an ordinary RIP-relative PLT/GOT
call)."""
from __future__ import annotations

import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect.detectors import DetectContext, heap_fptr_call, _reg_defined_by_mem_load
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.detect import enqueue_detect
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _ir(instrs):
    return {"blocks": [{"instructions": [{"addr": a, "text": t} for a, t in instrs]}]}


def _edge(dst, src=0x1000):
    return types.SimpleNamespace(dst_name=dst, src_addr=src, site_addr=src)


def _ctx(ir, edges=()):
    return DetectContext(target_id="t", case_id="c", call_edges=list(edges), strings=[],
                         functions=[], frames={}, func_irs={0x1000: ir}, bits=64, arch="x86-64")


# auth-or-out's print_author shape: obj ptr from a slot, fptr field at +0x30, then call it.
_AUTH = _ir([(0x1758, "mov rax, qword [rbp - 0x8]"), (0x175c, "mov rax, qword [rax + 0x30]"),
             (0x1760, "mov rdx, qword [rbp - 0x8]"), (0x1764, "mov rdx, qword [rdx + 0x20]"),
             (0x1768, "mov rdi, rdx"), (0x176b, "call rax")])


def test_reg_defined_by_mem_load():
    texts = ["mov rax, qword [rbp - 0x8]", "mov rdx, qword [rax + 0x30]"]
    assert _reg_defined_by_mem_load(texts, "rdx") == ("rax", "+0x30", 1)   # base, disp, def index
    assert _reg_defined_by_mem_load(["mov rax, rdi"], "rax") is None       # reg move, not a load


def test_fires_on_auth_shape_and_is_heap_when_allocator_present():
    hits = heap_fptr_call(_ctx(_AUTH, [_edge("malloc")]))
    assert len(hits) == 1 and hits[0]["cwe"] == "CWE-822" and hits[0]["severity"] == "medium"
    assert "rax+0x30" in hits[0]["evidence"][0]["detail"]


def test_low_severity_without_a_heap_allocator():
    hits = heap_fptr_call(_ctx(_AUTH, []))
    assert len(hits) == 1 and hits[0]["severity"] == "low"


def test_direct_memory_indirect_call_fires():
    ir = _ir([(0x10, "mov rax, qword [rbp - 0x8]"), (0x14, "call qword [rax + 0x30]")])
    assert len(heap_fptr_call(_ctx(ir, [_edge("calloc")]))) == 1


def test_plt_indirect_call_is_ignored():
    # ordinary RIP-relative PLT/GOT indirect call -- base is rip, not an object
    ir = _ir([(0x10, "call qword [rip + 0x2fc0]")])
    assert heap_fptr_call(_ctx(ir, [_edge("malloc")])) == []


def test_stack_local_fptr_is_ignored():
    # a function pointer held in a stack slot, called directly -- base is rbp, not a heap object
    ir = _ir([(0x10, "call qword [rbp - 0x18]")])
    assert heap_fptr_call(_ctx(ir, [_edge("malloc")])) == []


def test_base_must_come_from_memory():
    # the object base arrives in a register (arg), never loaded from memory in-frame -> not flagged
    ir = _ir([(0x10, "mov rax, rdi"), (0x14, "mov rax, qword [rax + 0x30]"), (0x18, "call rax")])
    assert heap_fptr_call(_ctx(ir, [_edge("malloc")])) == []


def test_one_finding_per_function():
    ir = _ir([(0x10, "mov rax, qword [rbp - 0x8]"), (0x14, "call qword [rax + 0x30]"),
              (0x18, "mov rcx, qword [rbp - 0x8]"), (0x1c, "call qword [rcx + 0x40]")])
    assert len(heap_fptr_call(_ctx(ir, [_edge("malloc")]))) == 1


# ---------------------------------------------------------------- end-to-end (compiled) --------
@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("heap_fptr_call arg-reg logic is x86-64 only")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def test_detect_heap_fptr_call_e2e(store, case, pool, gcc, tmp_path, x86_64_only):
    c = tmp_path / "o.c"
    c.write_text("#include <stdio.h>\n#include <stdlib.h>\n"
                 "struct obj { char buf[16]; void (*fn)(char*); };\n"
                 "void hello(char*s){ puts(s); }\n"
                 "int main(void){ struct obj*o=malloc(sizeof*o); o->fn=hello;"
                 " fgets(o->buf,64,stdin); o->fn(o->buf); return 0; }\n")
    out = tmp_path / "hfp"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build heap-fptr target")
    t = ingest(store, case.id, out, filename="hfp")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "heap_fptr_call"]
    assert hits and hits[0].cwe == "CWE-822"
