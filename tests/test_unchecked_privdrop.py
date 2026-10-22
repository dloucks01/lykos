"""Avenue #4 (logic/auth): unchecked privilege-management return (CWE-252 / CWE-273).

A privileged daemon that calls setuid()/setgid()/chroot() and ignores the result keeps its
privileges when the call fails -- a logic bug that never crashes. The detector reads the
disassembly after the call: a return value that is TESTED or KEPT is fine; one that is REDEFINED
(or clobbered by the next call) before any read is discarded -> a candidate finding."""
from __future__ import annotations

import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.detect.detectors import (
    DetectContext,
    _return_discarded,
    _touches_return,
    unchecked_privdrop,
)
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _ir(instrs):
    return {"blocks": [{"instructions": [{"addr": a, "text": t} for a, t in instrs]}]}


def _ctx(ir, edges):
    return DetectContext(target_id="t", case_id="c", call_edges=edges, strings=[],
                         functions=[], func_irs={0x1000: ir}, bits=64, arch="x86-64")


def _edge(dst="setuid", site=0x1010):
    # the detector only reads .dst_name / .src_addr / .site_addr
    return types.SimpleNamespace(src_addr=0x1000, site_addr=site, dst_name=dst)


# -------------------------------------------------------------------- operand analysis
def test_touches_return_read_vs_write():
    assert _touches_return("test", ["eax", "eax"]) == "read"     # explicit check
    assert _touches_return("mov", ["edi", "eax"]) == "read"      # passed to the next call as arg
    assert _touches_return("mov", ["qword [rbp - 8]", "rax"]) == "read"   # stored (kept)
    assert _touches_return("mov", ["eax", "0"]) == "write"       # `return 0;` tail -> discarded
    assert _touches_return("xor", ["eax", "eax"]) == "write"     # self-zero -> discarded
    assert _touches_return("lea", ["rax", "[rip + 0x20]"]) == "write"
    assert _touches_return("call", []) == "write"                # a later call clobbers rax
    assert _touches_return("mov", ["rbx", "rcx"]) is None        # unrelated
    assert _touches_return("mov", ["[rax]", "rbx"]) == "read"    # rax used as a pointer base


# -------------------------------------------------------------------- the detector
def test_discarded_return_is_flagged():
    # setuid(0); <next call clobbers rax, never checked>
    ir = _ir([(0x1010, "call sym.imp.setuid"),
              (0x1015, "mov edi, 0"), (0x101a, "call sym.imp.listen")])
    hits = unchecked_privdrop(_ctx(ir, [_edge("setuid")]))
    assert len(hits) == 1
    assert hits[0]["cwe"] == "CWE-252" and hits[0]["detector"] == "unchecked_privdrop"
    assert hits[0]["severity"] == "high"


def test_return_zero_tail_is_flagged():
    # setuid(0); return 0;  ->  `mov eax, 0` redefines the return reg before any read
    ir = _ir([(0x1010, "call sym.imp.setuid"), (0x1015, "mov eax, 0"), (0x101a, "ret")])
    assert len(unchecked_privdrop(_ctx(ir, [_edge("setuid")]))) == 1


def test_checked_return_is_not_flagged():
    # if (setuid(0) != 0) exit();  ->  test eax,eax; jne ...
    ir = _ir([(0x1010, "call sym.imp.setuid"), (0x1015, "test eax, eax"),
              (0x1017, "jne 0x1100"), (0x1019, "mov edi, 0")])
    assert unchecked_privdrop(_ctx(ir, [_edge("setuid")])) == []


def test_stored_return_is_not_flagged():
    # rc = setuid(0); ... (stored for a later check) -> kept
    ir = _ir([(0x1010, "call sym.imp.setuid"), (0x1015, "mov dword [rbp - 4], eax"),
              (0x1019, "cmp dword [rbp - 4], 0")])
    assert unchecked_privdrop(_ctx(ir, [_edge("setuid")])) == []


def test_non_priv_call_is_ignored():
    ir = _ir([(0x1010, "call sym.imp.printf"), (0x1015, "mov eax, 0"), (0x101a, "ret")])
    assert unchecked_privdrop(_ctx(ir, [_edge("printf")])) == []


def test_versioned_and_chroot_names_match():
    ir = _ir([(0x1010, "call setgid@GLIBC_2.2.5"), (0x1015, "call sym.imp.bind")])
    assert len(unchecked_privdrop(_ctx(ir, [_edge("setgid@GLIBC_2.2.5")]))) == 1
    ir2 = _ir([(0x1010, "call sym.imp.chroot"), (0x1015, "xor eax, eax"), (0x1017, "ret")])
    assert len(unchecked_privdrop(_ctx(ir2, [_edge("chroot")]))) == 1


def test_unknown_when_rax_untouched_then_ret_is_not_flagged():
    # `call setuid; ret` -> the result propagates to the caller; do NOT flag (conservative)
    ir = _ir([(0x1010, "call sym.imp.setuid"), (0x1015, "ret")])
    assert _return_discarded(ir, 0x1010) is False


# ---------------------------------------------------------------- end-to-end (compiled) --------
@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.mark.parametrize("src,expect", [
    # ignores setuid's return and carries on -> flagged
    ("#include <unistd.h>\nint main(void){ setuid(0); return 0; }\n", True),
    # checks it and exits on failure -> not flagged
    ("#include <unistd.h>\n#include <stdlib.h>\n"
     "int main(void){ if(setuid(0)!=0) return 1; return 0; }\n", False),
])
def test_unchecked_privdrop_e2e(store, case, pool, gcc, tmp_path, src, expect):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the rax/eax return-register scan is x86-64 only")
    c = tmp_path / "p.c"; c.write_text(src)
    out = tmp_path / "p"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="p")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "unchecked_privdrop"]
    assert bool(hits) is expect
