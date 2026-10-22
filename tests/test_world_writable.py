"""Avenue #4 (logic/access-control): world-writable file permissions (CWE-732).

A chmod()/fchmod() with an others-writable mode leaves a file any local user can rewrite -- an
access-control contract broken with a constant, not a crash. umask does not apply to chmod/fchmod,
so a literal mode is the file's final permission, which makes the detector precise: it reads the
mode immediate from the arg register and flags only the others-writable ones."""
from __future__ import annotations

import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.detect.detectors import (
    DetectContext,
    _imm_into_reg,
    world_writable_perms,
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


def _edge(dst="chmod", site=0x1010):
    return types.SimpleNamespace(src_addr=0x1000, site_addr=site, dst_name=dst)


# -------------------------------------------------------------------- immediate reader
def test_imm_into_reg_reads_mode_and_bails_on_computed():
    ir = _ir([(0x1000, "lea rdi, str.f"), (0x1008, "mov esi, 0x1ff"), (0x100e, "call sym.imp.chmod")])
    assert _imm_into_reg(ir, 0x100e, ("rsi", "esi")) == 0o777
    # a computed mode (mov esi, eax) is not a literal -> None (never guessed)
    ir2 = _ir([(0x1000, "mov esi, eax"), (0x1008, "call sym.imp.chmod")])
    assert _imm_into_reg(ir2, 0x1008, ("rsi", "esi")) is None


# -------------------------------------------------------------------- the detector
@pytest.mark.parametrize("mov,flagged", [
    ("mov esi, 0x1ff", True),    # 0777 rwxrwxrwx -> others-writable
    ("mov esi, 0x1b6", True),    # 0666 rw-rw-rw- -> others-writable
    ("mov esi, 0x1a4", False),   # 0644 rw-r--r-- -> NOT others-writable
    ("mov esi, 0x1ed", False),   # 0755 rwxr-xr-x -> NOT others-writable
])
def test_chmod_mode_gate(mov, flagged):
    ir = _ir([(0x1008, mov), (0x1010, "call sym.imp.chmod")])
    hits = world_writable_perms(_ctx(ir, [_edge("chmod")]))
    assert bool(hits) is flagged
    if flagged:
        assert hits[0]["cwe"] == "CWE-732" and hits[0]["detector"] == "world_writable_perms"


def test_fchmodat_uses_edx():
    ir = _ir([(0x1008, "mov edx, 0x1ff"), (0x1010, "call sym.imp.fchmodat")])
    assert len(world_writable_perms(_ctx(ir, [_edge("fchmodat")]))) == 1


def test_computed_mode_not_flagged():
    ir = _ir([(0x1008, "mov esi, eax"), (0x1010, "call sym.imp.fchmod")])
    assert world_writable_perms(_ctx(ir, [_edge("fchmod")])) == []


def test_non_perms_call_ignored():
    ir = _ir([(0x1008, "mov esi, 0x1ff"), (0x1010, "call sym.imp.memset")])
    assert world_writable_perms(_ctx(ir, [_edge("memset")])) == []


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


@pytest.mark.parametrize("mode,expect", [("0777", True), ("0644", False)])
def test_world_writable_e2e(store, case, pool, gcc, tmp_path, mode, expect):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the mode-register scan is x86-64 only")
    c = tmp_path / "p.c"
    c.write_text(f'#include <sys/stat.h>\nint main(void){{ chmod("/tmp/lykos_demo", {mode}); return 0; }}\n')
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
            if f.detector == "world_writable_perms"]
    assert bool(hits) is expect
