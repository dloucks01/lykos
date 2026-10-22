"""Avenue #4 (logic/access-control): privilege-drop ORDER (CWE-696, CERT POS36-C).

Dropping the user id before the group id is a revocation-order bug: once setuid() gives up root the
process may lack the privilege to setgid(), which then fails silently, leaving it in the privileged
group. Per function, flag when the first uid-drop precedes the first gid-drop."""
from __future__ import annotations

import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.detect.detectors import DetectContext, privilege_drop_order
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _edge(dst, site, fn=0x1000):
    return types.SimpleNamespace(src_addr=fn, site_addr=site, dst_name=dst)


def _ctx(edges):
    return DetectContext(target_id="t", case_id="c", call_edges=edges, strings=[],
                         functions=[], func_irs={}, bits=64, arch="x86-64")


def test_setuid_before_setgid_is_flagged():
    hits = privilege_drop_order(_ctx([_edge("setuid", 0x1100), _edge("setgid", 0x1200)]))
    assert len(hits) == 1
    assert hits[0]["cwe"] == "CWE-696" and hits[0]["detector"] == "privilege_drop_order"


def test_correct_order_not_flagged():
    assert privilege_drop_order(_ctx([_edge("setgid", 0x1100), _edge("setuid", 0x1200)])) == []


def test_only_setuid_not_flagged():
    assert privilege_drop_order(_ctx([_edge("setuid", 0x1100)])) == []


def test_setgroups_counts_as_a_group_drop():
    # setgroups is part of the group-drop family; uid before it is still the wrong order
    assert len(privilege_drop_order(_ctx([_edge("setresuid", 0x1100),
                                          _edge("setgroups", 0x1200)]))) == 1


def test_per_function_scoping():
    # uid-drop in one function, gid-drop in ANOTHER -> not a single-function ordering bug
    edges = [_edge("setuid", 0x1100, fn=0x1000), _edge("setgid", 0x2200, fn=0x2000)]
    assert privilege_drop_order(_ctx(edges)) == []


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


@pytest.mark.parametrize("body,expect", [
    ("setuid(0); setgid(0);", True),    # wrong order
    ("setgid(0); setuid(0);", False),   # correct order
])
def test_privilege_drop_order_e2e(store, case, pool, gcc, tmp_path, body, expect):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("e2e disassembly backend is host-arch bound here")
    c = tmp_path / "p.c"
    c.write_text(f"#include <unistd.h>\nint main(void){{ {body} return 0; }}\n")
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
            if f.detector == "privilege_drop_order"]
    assert bool(hits) is expect
