"""Avenue #4 (logic/misuse): non-literal format string, no arguments (CWE-134).

`printf(buf)` instead of `printf("%s", buf)` is the GCC -Wformat-security shape: a variadic
format function whose format is a run-time value and that passes zero format arguments. If that
value is attacker-influenced the %n/%s/%p conversions give an arbitrary read/write. The detector
is precise WITHOUT taint because it keys on two structural facts: the format register is fed by a
run-time value (a memory load, or a stack-buffer address) rather than a .rodata constant (a lea of
a str./rip operand), and no format-argument register is set up in the call's argument window. The
`cond ? "a" : "b"` case -- the one false positive of the naive rule -- is a lea of a rodata string,
so it classifies as literal and is never flagged."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.detect.detectors import (
    DetectContext,
    _fmt_source_class,
    _writes_arg_reg,
    format_string,
)
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _ir(instrs):
    return {"blocks": [{"instructions": [{"addr": a, "text": t} for a, t in instrs]}]}


def _ctx(ir):
    return DetectContext(target_id="t", case_id="c", call_edges=[], strings=[],
                         functions=[], func_irs={0x1000: ir}, bits=64, arch="x86-64")


# ------------------------------------------------------------- the format-source classifier
def test_source_class_literal_vs_dynamic():
    # lea of a rodata string -> literal (safe)
    assert _fmt_source_class(["lea rdi, str.hello"], "rdi") == "literal"
    assert _fmt_source_class(["lea rdi, qword [rip + 0x2004]"], "rdi") == "literal"
    # pointer loaded from memory -> dynamic (the bug shape)
    assert _fmt_source_class(["mov rax, qword [rbp - 8]", "mov rdi, rax"], "rdi") == "dynamic"
    # address of a stack buffer -> dynamic
    assert _fmt_source_class(["lea rax, [rbp - 0x40]", "mov rdi, rax"], "rdi") == "dynamic"
    # a function return feeding the format, never spilled -> indeterminate (not guessed)
    assert _fmt_source_class(["call sym.imp.get", "mov rdi, rax"], "rdi") is None


def test_ternary_of_two_literals_is_not_dynamic():
    # printf(c ? "a" : "b") selects between two rodata leas -> literal, never flagged
    pre = ["lea rax, str.a", "jmp 0x1020", "lea rax, str.b", "mov rdi, rax"]
    assert _fmt_source_class(pre, "rdi") == "literal"


def test_writes_arg_reg():
    assert _writes_arg_reg(["mov esi, 0x5", "mov eax, 0"], ("rsi", "rdx")) is True
    assert _writes_arg_reg(["lea rsi, [rbp-8]"], ("rsi",)) is True
    assert _writes_arg_reg(["mov eax, 0", "lea rdi, str.x"], ("rsi", "rdx")) is False


# ------------------------------------------------------------- the detector (synthetic IR)
def test_printf_of_memory_pointer_is_flagged():
    ir = _ir([(0x1000, "mov rax, qword [rbp - 8]"),
              (0x1004, "mov rdi, rax"),
              (0x1007, "mov eax, 0"),
              (0x100c, "call sym.imp.printf")])
    hits = format_string(_ctx(ir))
    assert len(hits) == 1
    assert hits[0]["cwe"] == "CWE-134" and hits[0]["detector"] == "format_string"
    assert hits[0]["site_addr"] == 0x100c


def test_printf_of_literal_is_not_flagged():
    ir = _ir([(0x1000, "lea rdi, str.hello"), (0x1007, "mov eax, 0"),
              (0x100c, "call sym.imp.printf")])
    assert format_string(_ctx(ir)) == []


def test_printf_with_a_format_argument_is_not_flagged():
    # printf("%d", x): rsi (a format argument) is set up -> the correct, safe shape
    ir = _ir([(0x1000, "mov esi, dword [rbp - 4]"),
              (0x1004, "lea rdi, str.d_fmt"),
              (0x100b, "mov eax, 0"),
              (0x1010, "call sym.imp.printf")])
    assert format_string(_ctx(ir)) == []


def test_ternary_format_is_not_flagged():
    ir = _ir([(0x1000, "lea rax, str.a"), (0x1007, "lea rax, str.b"),
              (0x100e, "mov rdi, rax"), (0x1011, "mov eax, 0"),
              (0x1016, "call sym.imp.printf")])
    assert format_string(_ctx(ir)) == []


def test_fprintf_format_in_rsi():
    # fprintf(stderr, buf): format is the SECOND arg (rsi); stream in rdi is not a format arg
    ir = _ir([(0x1000, "mov rdi, qword [rip + stderr]"),
              (0x1007, "mov rax, qword [rbp - 8]"),
              (0x100b, "mov rsi, rax"),
              (0x100e, "mov eax, 0"),
              (0x1013, "call sym.imp.fprintf")])
    hits = format_string(_ctx(ir))
    assert len(hits) == 1 and "fprintf" in hits[0]["title"]


def test_snprintf_format_in_rdx():
    # snprintf(buf, n, fmt): format is the THIRD arg (rdx)
    ir = _ir([(0x1000, "lea rdi, [rbp - 0x40]"),
              (0x1004, "mov esi, 0x40"),
              (0x1009, "mov rax, qword [rbp - 8]"),
              (0x100d, "mov rdx, rax"),
              (0x1010, "mov eax, 0"),
              (0x1015, "call sym.imp.snprintf")])
    hits = format_string(_ctx(ir))
    assert len(hits) == 1 and "snprintf" in hits[0]["title"]


def test_vprintf_family_excluded():
    # vprintf(fmt, ap) always carries a va_list; the wrapper pattern must not fire
    ir = _ir([(0x1000, "mov rax, qword [rbp - 8]"), (0x1004, "mov rdi, rax"),
              (0x1007, "mov rsi, qword [rbp - 0x10]"), (0x100b, "call sym.imp.vprintf")])
    assert format_string(_ctx(ir)) == []


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


# printf(buf) is the bug; printf("%s", buf) is the fix. The source feeds the SAME runtime buffer to
# both so the only difference under test is the format/argument shape, not reachability.
_SRC = r"""
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv){
    char buf[128];
    snprintf(buf, sizeof buf, "%s", argc > 1 ? argv[1] : "x");
    FMT ;
    return 0;
}
"""


@pytest.mark.parametrize("call,expect", [
    ("printf(buf)", True),           # non-literal format, zero args -> CWE-134
    ('printf("%s", buf)', False),    # the correct call -> clean
])
def test_format_string_e2e(store, case, pool, gcc, tmp_path, call, expect):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("the format-provenance scan is x86-64 only")
    c = tmp_path / "p.c"
    c.write_text(_SRC.replace("FMT", call))
    out = tmp_path / "p"
    # -Wno-format-security so the deliberately-vulnerable fixture still compiles cleanly
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-Wno-format-security",
                       str(c), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="p")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(60)
    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id)
            if f.detector == "format_string"]
    assert bool(hits) is expect
