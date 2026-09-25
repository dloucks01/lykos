"""Width-bounded scanf that STILL overflows: `scanf("%16s", buf16)` writes 16 chars + a NUL = 17
bytes into 16, a single-NUL off-by-one (HTB scanner's real bug -- a poison-null-byte on the saved
frame pointer). The coarse stack-overflow detector suppresses any width-bounded `%Ns` as safe;
this one reads the specific width against the specific destination buffer size and fires only when
`width + 1 > size`."""
from __future__ import annotations

import subprocess
import types

import pytest
from lykos.analyze import register
from lykos.analyze.detect.detectors import (DetectContext, scanf_bounded_overflow,
                                            _norm_call, _str_flag_for_reg, _stack_slot_for_reg)
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.detect import enqueue_detect
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _S(v):
    return types.SimpleNamespace(value=v)


def _ir(instrs):
    return {"blocks": [{"instructions": [{"addr": a, "text": t} for a, t in instrs]}]}


# scanner's exact shape: memset(-0x10,0,0x10); scanf("%16s %u", &buf, &size).
_SCANNER_IR = _ir([
    (0x14eb, "lea rax, [rbp - 0x10]"), (0x14ef, "mov edx, 0x10"), (0x14f4, "mov esi, 0"),
    (0x14f9, "mov rdi, rax"), (0x14fc, "call sym.imp.memset"),
    (0x1512, "mov rdx, qword [rbp - 0x28]"), (0x1516, "lea rax, [rbp - 0x10]"),
    (0x151a, "mov rsi, rax"), (0x151d, "lea rdi, str._16s__u"),
    (0x1529, "call sym.imp.__isoc99_scanf"),
])


def _ctx(ir, vars_, strings):
    return DetectContext(target_id="t", case_id="c", call_edges=[], strings=[_S(s) for s in strings],
                         functions=[], frames={0x1000: {"vars": vars_}},
                         func_irs={0x1000: ir}, bits=64, arch="x86-64")


def test_norm_call_variants():
    assert _norm_call("call sym.imp.__isoc99_scanf") == "scanf"
    assert _norm_call("call sym.imp.__isoc23_scanf") == "scanf"
    assert _norm_call("call sym.imp.memset") == "memset"
    assert _norm_call("mov rax, rbx") is None


def test_reg_tracers_follow_one_hop():
    # lea rdx,str; mov rdi,rdx  -> the format flag reaches rdi through a hop
    texts = ["lea rdx, str._16s__u", "mov rdi, rdx"]
    assert _str_flag_for_reg(texts, "rdi") == "_16s__u"
    texts2 = ["lea rax, [rbp - 0x10]", "mov rsi, rax"]
    assert _stack_slot_for_reg(texts2, "rsi") == -16


def test_offbyone_fires_on_scanner_shape():
    # frame did NOT size the local -> the memset(...,0x10) supplies the 16-byte size
    ctx = _ctx(_SCANNER_IR, [{"name": "s", "offset": -16, "size": 0, "is_buffer": True}],
               ["%16s %u", "Enter parameters: "])
    hits = scanf_bounded_overflow(ctx)
    assert len(hits) == 1 and hits[0]["cwe"] == "CWE-787"
    assert "off-by-one" in hits[0]["title"]


def test_offbyone_uses_frame_size_when_present():
    ctx = _ctx(_SCANNER_IR, [{"name": "s", "offset": -16, "size": 16, "is_buffer": True}], ["%16s %u"])
    assert len(scanf_bounded_overflow(ctx)) == 1


def test_safe_width_does_not_fire():
    ir = _ir([(0x10, "lea rax, [rbp - 0x10]"), (0x14, "mov rsi, rax"),
              (0x18, "lea rdi, str._15s"), (0x1c, "call sym.imp.__isoc99_scanf")])
    ctx = _ctx(ir, [{"name": "s", "offset": -16, "size": 16, "is_buffer": True}], ["%15s"])
    assert scanf_bounded_overflow(ctx) == []       # 15 + NUL = 16 fits exactly


def test_unbounded_does_not_fire_here():
    # a widthless %s carries no width -> this detector stays silent (the coarse one handles it)
    ir = _ir([(0x10, "lea rax, [rbp - 0x10]"), (0x14, "mov rsi, rax"),
              (0x18, "lea rdi, str._s"), (0x1c, "call sym.imp.__isoc99_scanf")])
    ctx = _ctx(ir, [{"name": "s", "offset": -16, "size": 16, "is_buffer": True}], ["%s"])
    assert scanf_bounded_overflow(ctx) == []


def test_width_must_be_corroborated_by_a_real_format():
    # a coincidental "16s" in a symbol with NO %16s format string in the binary must NOT fire
    ctx = _ctx(_SCANNER_IR, [{"name": "s", "offset": -16, "size": 16, "is_buffer": True}],
               ["Enter parameters: "])
    assert scanf_bounded_overflow(ctx) == []


# ---------------------------------------------------------------- end-to-end (compiled) --------
@pytest.fixture
def x86_64_only():
    if sandbox.host_arch() != "x86-64":
        pytest.skip("scanf off-by-one detector arg-reg logic is x86-64 only")


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.mark.parametrize("fmt,size,expect", [("%16s", 16, True), ("%15s", 16, False),
                                             ("%32s", 16, True), ("%s", 16, False)])
def test_detect_scanf_offbyone_e2e(store, case, pool, gcc, tmp_path, x86_64_only, fmt, size, expect):
    c = tmp_path / "s.c"
    c.write_text(f'#include <stdio.h>\nint main(void){{char b[{size}];scanf("{fmt}",b);'
                 f'printf("%s",b);return 0;}}\n')
    out = tmp_path / "sf"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build scanf target")
    t = ingest(store, case.id, out, filename="sf")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "scanf_bounded_overflow"]
    assert bool(hits) is expect
