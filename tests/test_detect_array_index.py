"""Static CWE-129 (improper validation of an array index): `array_index`.

An attacker-supplied integer (atoi/strtol of input, scanf("%d"), a raw read()) indexes a FIXED-SIZE
array with no dominating check that keeps it in bounds. Three verdicts, each true whatever the input
is: `unchecked` (no upper bound on some path), `signed` (only a signed upper bound -> -1 reaches the
array), `bound` (the bound admits an index past a GLOBAL array's st_size). Everything that could make
the claim false -- a validator call, a variable bound, a clamp that rewrites the index, an escaping
&index, a constant atoi("3") -- is a skip, never a guess."""
from __future__ import annotations

import shutil
import subprocess

import pytest
from lykos.analyze import register
from lykos.analyze.detect import enqueue_detect
from lykos.analyze.detect.detectors import (
    DetectContext,
    _mem_terms,
    _scanf_conversions,
    array_index,
)
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.db.dao import FindingDAO, FunctionDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _ctx(blocks, frames=None):
    return DetectContext(target_id="t", case_id="c", call_edges=[], strings=[], functions=[],
                         frames=frames or {}, func_irs={"0x1000": {"blocks": blocks}}, bits=64,
                         arch="x86-64")


def _blk(addr, ins, succ=()):
    return {"addr": addr, "succ": list(succ),
            "instructions": [{"addr": a, "text": t, "pcode": []} for a, t in ins]}


# ------------------------------------------------------------------------------- units --------
def test_mem_terms_parses_scaled_index_and_named_slot():
    assert _mem_terms("dword [rbp + rax*4 - 0x60]") == ("dword", [("rbp", 1), ("rax", 4)], -0x60, [])
    assert _mem_terms("qword [rdx + rax]")[1] == [("rdx", 1), ("rax", 1)]
    assert _mem_terms("dword [var_14h]", {"var_14h": -20})[1:3] == ([("rbp", 1)], -20)
    assert _mem_terms("rax") is None


def test_scanf_conversions_order_and_suppression():
    assert _scanf_conversions("%d %*s %16s%%%u") == [(0, None, "d", False), (1, 16, "s", False),
                                                    (2, None, "u", False)]
    assert _scanf_conversions("%2$d %1$s") is None             # positional: not mapped


def test_same_block_register_index_is_unchecked():
    # -O2: `call strtol; movsxd rbx, eax; mov [rsp + rbx*4 + 0x10], 5` -- no branch in between
    ctx = _ctx([_blk("0x1000", [
        ("0x1000", "mov rdi, qword [rsi + 8]"), ("0x1004", "call sym.imp.__isoc23_strtol"),
        ("0x1009", "movsxd rbx, eax"), ("0x100c", "xor eax, eax"),
        ("0x100e", "mov dword [rsp + rbx*4 + 0x10], 5")])])
    hits = array_index(ctx)
    assert len(hits) == 1
    h = hits[0]
    assert h["cwe"] == "CWE-129" and h["detector"] == "array_index" and h["severity"] == "high"
    data = h["evidence"][0]["array_index"]
    assert data["array"] == {"kind": "stack", "frame_base": "rsp", "frame_offset": 0x10,
                             "size": None, "elements": None, "element_size": 4}
    assert data["index"]["source"] == "strtol" and data["check"]["verdict"] == "unchecked"
    assert data["access"] == "write" and data["oob_index"] == [-1]


def test_constant_parser_argument_is_not_input():
    # atoi("3") parses a literal -- not attacker data
    ctx = _ctx([_blk("0x1000", [
        ("0x1000", "lea rdi, [0x00402004]"), ("0x1007", "call sym.imp.atoi"),
        ("0x100c", "cdqe"), ("0x100e", "mov dword [rsp + rax*4 + 0x10], 5")])])
    assert array_index(ctx) == []


def test_index_rewritten_in_register_is_dropped():
    # `and eax, 0xf` bounds the value -- the tracker drops it rather than guess
    ctx = _ctx([_blk("0x1000", [
        ("0x1000", "mov rdi, qword [rsi + 8]"), ("0x1004", "call sym.imp.atoi"),
        ("0x1009", "and eax, 0xf"), ("0x100c", "cdqe"),
        ("0x100e", "mov dword [rsp + rax*4 + 0x10], 5")])])
    assert array_index(ctx) == []


def test_unreadable_dominating_check_suppresses_the_claim():
    # -O0 slot index with a dominating compare whose condition cannot be evaluated (no P-Code):
    # a check exists, so "unchecked" would be a fabrication -> skipped
    ctx = _ctx([
        _blk("0x1000", [("0x1000", "mov rdi, qword [rbp - 0x20]"), ("0x1004", "call sym.imp.atoi"),
                        ("0x1009", "mov dword [rbp - 0x14], eax"),
                        ("0x100c", "cmp dword [rbp - 0x14], 9"), ("0x1010", "jg 0x1020")],
             succ=("0x1012", "0x1020")),
        _blk("0x1012", [("0x1012", "mov eax, dword [rbp - 0x14]"), ("0x1015", "cdqe"),
                        ("0x1017", "mov dword [rbp + rax*4 - 0x60], 5")], succ=("0x1020",)),
        _blk("0x1020", [("0x1020", "leave"), ("0x1021", "ret")])])
    assert array_index(ctx) == []


def test_slot_index_with_no_check_anywhere_is_unchecked():
    ctx = _ctx([
        _blk("0x1000", [("0x1000", "mov rdi, qword [rbp - 0x20]"), ("0x1004", "call sym.imp.atoi"),
                        ("0x1009", "mov dword [rbp - 0x14], eax"), ("0x100c", "jmp 0x1012")],
             succ=("0x1012",)),
        _blk("0x1012", [("0x1012", "mov eax, dword [rbp - 0x14]"), ("0x1015", "cdqe"),
                        ("0x1017", "mov eax, dword [rbp + rax*4 - 0x60]")])])
    hits = array_index(ctx)
    assert len(hits) == 1 and hits[0]["severity"] == "medium"          # a read
    assert hits[0]["evidence"][0]["array_index"]["index"]["slot"] == "rbp-0x14"


def test_slot_written_twice_is_not_an_input_index():
    # `i = atoi(s); ... i = 3;` -- the second writer may bound it; skipped
    ctx = _ctx([_blk("0x1000", [
        ("0x1000", "mov rdi, qword [rbp - 0x20]"), ("0x1004", "call sym.imp.atoi"),
        ("0x1009", "mov dword [rbp - 0x14], eax"), ("0x100c", "mov dword [rbp - 0x14], 3"),
        ("0x1010", "mov eax, dword [rbp - 0x14]"), ("0x1013", "cdqe"),
        ("0x1015", "mov dword [rbp + rax*4 - 0x60], 5")])])
    assert array_index(ctx) == []


@pytest.mark.parametrize("irs", [{}, {"0x1": None}, {"0x1": {}}, {"0x1": {"blocks": [{}]}},
                                 {"0x1": {"blocks": [{"addr": "0x1", "instructions": [
                                     {"addr": None, "text": None}, {"text": "call"},
                                     {"addr": "0x2", "text": "mov dword [rbp + rax*4], 1"}]}]}}])
def test_degenerate_ir_never_raises(irs):
    ctx = DetectContext(target_id="t", case_id="c", call_edges=[], strings=[], func_irs=irs,
                        frames={"0x1": {"vars": [{"name": "x", "offset": "bogus"}]}},
                        bits=64, arch="x86-64")
    assert array_index(ctx) == []


def test_unsupported_isa_is_silent():
    # aarch64 is now handled (below); an ISA with no tracker (mips) returns nothing, never guesses.
    ctx = _ctx([_blk("0x1000", [("0x1000", "lw $a0, 0($sp)")])])
    ctx.arch = "mips"
    assert array_index(ctx) == []
    ctx.arch = "aarch64"                                   # no resolvable access here -> still silent
    assert array_index(ctx) == []


# --------------------------------------------------------------------- end-to-end (compiled) ----
_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int table[10];
long big[10];
int valid(int i);
void fix(int *i);
__attribute__((noinline)) void off_by_one(char *s) { int k = atoi(s); if (k >= 0 && k <= 10) table[k] = 1; }
__attribute__((noinline)) void signed_only(char *s) { int k = atoi(s); if (k < 10) table[k] = 1; }
__attribute__((noinline)) void validator(char *s) { int i = atoi(s); if (!valid(i)) return; table[i] = 2; }
__attribute__((noinline)) void varbound(char *s, int n) { int i = atoi(s); if (i < 0 || i >= n) return; table[i] = 3; }
__attribute__((noinline)) void clamp(char *s) { int i = atoi(s); if (i > 9) i = 9; if (i < 0) i = 0; table[i] = 4; }
__attribute__((noinline)) void escape(void) { int i; if (scanf("%d", &i) != 1) return; fix(&i); table[i] = 5; }
__attribute__((noinline)) void constant(void) { int c = atoi("3"); table[c] = 6; }
__attribute__((noinline)) void readraw(int fd) { int i; if (read(fd, &i, 4) != 4) return; big[i] = 7; }
__attribute__((noinline)) void in_bounds(char *s) { int i = atoi(s); if (i >= 0 && i < 10) table[i] = 8; }
__attribute__((noinline)) void unsigned_ok(char *s) { unsigned i = strtoul(s, 0, 10); if (i < 10) table[i] = 8; }
__attribute__((noinline)) int readidx(char *s) { int i = atoi(s); return table[i]; }
int valid(int i) { return i >= 0 && i < 10; }
void fix(int *i) { if (*i < 0 || *i > 9) *i = 0; }
int main(int argc, char **argv) {
    off_by_one(argv[1]); signed_only(argv[1]); validator(argv[1]); varbound(argv[1], argc);
    clamp(argv[1]); escape(); constant(); readraw(0); in_bounds(argv[1]); unsigned_ok(argv[1]);
    return readidx(argv[1]);
}
"""

# function -> the verdict the detector must reach; any function not listed must stay silent
_EXPECT = {"off_by_one": "bound", "signed_only": "signed", "readraw": "unchecked",
           "readidx": "unchecked"}


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
@pytest.mark.parametrize("pie", [False, True])
def test_array_index_e2e(store, case, pool, gcc, tmp_path, opt, pie):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "ai.c"
    c.write_text(_SRC)
    out = tmp_path / "ai"
    flags = [opt, "-fno-stack-protector"] + ([] if pie else ["-no-pie"])
    if subprocess.run([gcc, *flags, str(c), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="ai")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        assert f.cwe == "CWE-129" and f.state == "candidate"
        for e in f.evidence:
            d = e.get("array_index")
            if d:
                got.setdefault(names.get(f.function_addr), set()).add(d["check"]["verdict"])
                assert d["array"]["kind"] == "global" and d["array"]["name"] in ("table", "big")
                assert d["array"]["elements"] == 10
    assert {k: v for k, v in got.items()} == {k: {v} for k, v in _EXPECT.items()}, got


def test_division_replaces_the_index_value():
    # `arr[idx / n]`: idiv writes rdx:rax implicitly -- the tracked value is gone
    ctx = _ctx([_blk("0x1000", [
        ("0x1000", "mov rdi, qword [rsi + 8]"), ("0x1004", "call sym.imp.atoi"),
        ("0x1009", "cdq"), ("0x100a", "idiv ecx"), ("0x100c", "cdqe"),
        ("0x100e", "mov dword [rsp + rax*4 + 0x10], 5")])])
    assert array_index(ctx) == []


# ------------------------------------------------------- an index handed to another function ----
_PARAM_SRC = r"""
#include <stdlib.h>
int table[10];
#define CALLEE __attribute__((noipa))
CALLEE void set_unchecked(int i, int v) { table[i] = v; }
CALLEE void set_checked(int i) { if (i < 0 || i >= 10) return; table[i] = 1; }
CALLEE void set_raw(int i) { table[i] = 2; }
CALLEE void put(int i) { table[i] = 3; }
CALLEE void sgn(int i) { if (i < 10) table[i] = 4; }
CALLEE void set_const(int i) { table[i] = 5; }
CALLEE void clampi(int i) { if (i > 9) i = 9; if (i < 0) i = 0; table[i] = 6; }
CALLEE void second(int v, int i) { table[i] = v; }
CALLEE void inner(int i) { table[i] = 7; }
CALLEE void outer(int i) { inner(i); }
int main(int argc, char **argv) {
    set_unchecked(atoi(argv[1]), 9);
    set_checked(atoi(argv[1]));
    int j = atoi(argv[2]);
    if (j >= 0 && j < 10) set_raw(j);           /* the CALLER bounds it: in range */
    int k = atoi(argv[3]);
    if (k >= 0 && k <= 10) put(k);              /* the caller's bound admits 10 */
    sgn(atoi(argv[1]));
    set_const(3);
    clampi(atoi(argv[1]));
    second(1, atoi(argv[1]));
    outer(atoi(argv[1]));                       /* two calls deep: forwarded param, now followed */
    return 0;
}
"""
# callee -> the verdict the detector must reach; every other function must stay silent
_PARAM_EXPECT = {"set_unchecked": "unchecked", "put": "bound", "sgn": "signed",
                 "second": "unchecked", "inner": "unchecked"}


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
@pytest.mark.parametrize("pie", [False, True])
def test_an_input_index_passed_to_another_function(store, case, pool, gcc, tmp_path, opt, pie):
    """`set(atoi(argv[1]), v)` with `set` writing `table[i]`: the index is parsed in one function
    and used in another. The caller's check and the callee's check both count; anything the
    detector cannot follow (a constant argument, a clamped parameter, a second call level) stays
    silent."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "pi.c"
    c.write_text(_PARAM_SRC)
    out = tmp_path / "pi"
    flags = [opt, "-fno-stack-protector"] + ([] if pie else ["-no-pie"])
    if subprocess.run([gcc, *flags, str(c), "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="pi")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if not d:
                continue
            via = d["index"].get("via_call")
            fn = names.get(d["function"])        # findings on one array merge: read each record
            got.setdefault(fn, set()).add(d["check"]["verdict"])
            if via:
                assert names.get(via["caller"]) == "main" and "passed as argument" in e["detail"]
    assert got == {k: {v} for k, v in _PARAM_EXPECT.items()}, got


_DEEP_SRC = r"""
#include <stdlib.h>
int table[10];
#define CALLEE __attribute__((noipa))
CALLEE void leaf(int i) { table[i] = 1; }          /* indexes the forwarded param */
CALLEE void mid(int i)  { leaf(i); }               /* forwards it on (hop 2) */
CALLEE void top(int i)  { mid(i); }                /* forwards it on (hop 1) */
CALLEE void safe_leaf(int i) { table[i] = 2; }
CALLEE void safe_top(int i) { if (i >= 0 && i < 10) safe_leaf(i); }   /* a bound on the way */
int main(int argc, char **argv) {
    top(atoi(argv[1]));            /* main -> top -> mid -> leaf: three edges, unchecked */
    safe_top(atoi(argv[2]));       /* bounded before the forward: must stay silent */
    return 0;
}
"""


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_an_input_index_forwarded_across_several_calls(store, case, pool, gcc, tmp_path, opt):
    """main parses an index and it is forwarded top -> mid -> leaf (three call edges) before it
    indexes `table`. The join follows the parameter across every edge; `leaf` is flagged unchecked.
    `safe_top` bounds the index before forwarding it to `safe_leaf`, which must stay silent."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "deep.c"
    c.write_text(_DEEP_SRC)
    out = tmp_path / "deep"
    if subprocess.run([gcc, opt, "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="deep")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if not d:
                continue
            fn = names.get(d["function"])
            got.setdefault(fn, set()).add(d["check"]["verdict"])
            via = d["index"].get("via_call")
            if fn == "leaf":
                assert via and names.get(via["caller"]) == "main" and via.get("hops", 1) >= 2, via
    assert got == {"leaf": {"unchecked"}}, got


# ------------------------------------------------------------------- aarch64 (cross-compiled) ----
_A64_SRC = r"""
#include <stdlib.h>
int table[10];
#define NI __attribute__((noinline))
NI void unchk(char*s){ int k=atoi(s); table[k]=1; }                         /* unchecked */
NI void sgn(char*s){ int k=atoi(s); if(k<10) table[k]=2; }                  /* signed only */
NI void bnd(char*s){ int k=atoi(s); if(k>=0&&k<=10) table[k]=3; }           /* bound admits 10 */
NI void okc(char*s){ int k=atoi(s); if(k>=0&&k<10) table[k]=4; }            /* in bounds -> silent */
NI void clmp(char*s){ int k=atoi(s); if(k>9)k=9; if(k<0)k=0; table[k]=5; }  /* clamped -> silent */
NI void param_unchk(int i){ table[i]=6; }                                   /* param, unchecked */
NI void param_chk(int i){ if(i<0||i>=10)return; table[i]=7; }               /* param, checked -> silent */
int main(int c,char**v){ unchk(v[1]); sgn(v[1]); bnd(v[1]); okc(v[1]); clmp(v[1]);
                         param_unchk(atoi(v[1])); param_chk(atoi(v[1])); return 0; }
"""
_A64_EXPECT = {"unchk": "unchecked", "sgn": "signed", "bnd": "bound", "param_unchk": "unchecked"}


@pytest.fixture
def a64_gcc():
    cc = shutil.which("aarch64-linux-gnu-gcc")
    if not cc:
        pytest.skip("no aarch64 cross-compiler (aarch64-linux-gnu-gcc)")
    return cc


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_aarch64_array_index_single_function(store, case, pool, a64_gcc, tmp_path, opt):
    """CWE-129 on aarch64 (single function): an input/parameter index into a GLOBAL array via
    `str/ldr wN,[xB,xI,lsl #s]`. The P-Code dominating-check analysis (reused unchanged) reads the
    aarch64 `cmp;b.cond` guards, so a checked/clamped/in-bounds access stays silent while unchecked,
    signed-only and past-the-end ones are flagged. Both the -O0 slot-spilled index and the -O2
    register-only index (the strtol result / a parameter in w0, carried across the check edge)."""
    c = tmp_path / "a.c"; c.write_text(_A64_SRC)
    out = tmp_path / "a"
    if subprocess.run([a64_gcc, opt, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o",
                       str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile the aarch64 fixture")
    t = ingest(store, case.id, out, filename="a")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "aarch64":
        pytest.skip("backend did not identify the target as aarch64")
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if not d:
                continue
            got.setdefault(names.get(d["function"]), set()).add(d["check"]["verdict"])
    assert got == {k: {v} for k, v in _A64_EXPECT.items()}, got


# ------------------------------------------------------------------- arm32 (cross-compiled) ------
@pytest.fixture
def arm32_gcc():
    cc = shutil.which("arm-linux-gnueabihf-gcc")
    if not cc:
        pytest.skip("no arm32 cross-compiler (arm-linux-gnueabihf-gcc)")
    return cc


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_arm32_array_index_single_function(store, case, pool, arm32_gcc, tmp_path, monkeypatch, opt):
    """CWE-129 on 32-bit ARM (single function). Same conservative shape as aarch64, but the global
    base comes from a PC-relative literal pool and the frame base is fp/r11. arm32 needs P-Code
    (the ghidra backend), so force it; a function using ARM conditional execution for the bound
    (the -O2 `cmp;popls` idiom) is skipped -- SILENT, never a false finding. Every flagged function
    must carry its correct verdict (no false positive); -O0 gets all four."""
    monkeypatch.setenv("LYKOS_DECOMPILER", "ghidra")
    c = tmp_path / "a.c"; c.write_text(_A64_SRC)                # same fixture, cross-compiled to arm
    out = tmp_path / "a"
    if subprocess.run([arm32_gcc, opt, "-marm", "-fno-stack-protector", "-no-pie", "-w", str(c),
                       "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile the arm32 fixture")
    t = ingest(store, case.id, out, filename="a")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "arm" or store.targets.get(t.id).bits != 32:
        pytest.skip("backend did not identify the target as arm32")
    irs = {f.addr: f for f in FunctionDAO(store.conn).list_by_target(t.id)}
    from lykos.db.dao import FunctionDAO as _FD
    one = _FD(store.conn).get(next(iter(irs.values())).id)
    if not any(i.get("pcode") for b in (one.ir or {}).get("blocks", []) for i in b.get("instructions", [])):
        pytest.skip("this backend emits no P-Code for arm32 (the check analysis would be blind)")
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if d:
                got.setdefault(names.get(d["function"]), set()).add(d["check"]["verdict"])
    expected = {"unchk": "unchecked", "sgn": "signed", "bnd": "bound", "param_unchk": "unchecked"}
    for fn, verdicts in got.items():                          # no false positive, no wrong verdict
        assert fn in expected and verdicts == {expected[fn]}, (opt, fn, verdicts, got)
    assert {"unchk", "param_unchk"} <= set(got), (opt, got)   # these reproduce whatever the opt
    if opt == "-O0":
        assert set(got) == set(expected), got                # -O0 (plain branches) gets all four


# ----------------------------------------------------------------- ARM stack arrays (compiled) ---
_STACK_SRC = r"""
#include <stdlib.h>
#define NI __attribute__((noinline))
NI int unchk_local(char *s){ int b[16]; int k = atoi(s); b[k] = 1; return b[0]; }  /* unchecked */
NI int chk_local(char *s){ int b[16]; int k = atoi(s); if (k>=0 && k<16) b[k]=2; return b[0]; }  /* safe */
int main(int c, char **v){ return unchk_local(v[1]) + chk_local(v[1]); }
"""


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_aarch64_stack_array_index(store, case, pool, a64_gcc, tmp_path, opt):
    """CWE-129 into a STACK array on aarch64: `add xB, sp, #off; str wN, [xB, xI, lsl #s]` (the
    index scaled by `lsl`). Extent is unknown, so only unchecked/signed are claimed -- the
    bounds-checked local stays silent. No false positive on the checked case."""
    c = tmp_path / "s.c"; c.write_text(_STACK_SRC)
    out = tmp_path / "s"
    if subprocess.run([a64_gcc, opt, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o",
                       str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="s")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "aarch64":
        pytest.skip("backend did not identify aarch64")
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if d:
                got.setdefault(names.get(d["function"]), set()).add((d["check"]["verdict"],
                                                                     d["array"]["kind"]))
    assert got == {"unchk_local": {("unchecked", "stack")}}, got      # chk_local must stay silent


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_arm32_stack_array_index(store, case, pool, arm32_gcc, tmp_path, monkeypatch, opt):
    """CWE-129 into a STACK array on arm32, where the element pointer is built explicitly
    (`mov r3,r3,lsl #2; add r3,r3,fp; str r2,[r3,#-off]` at -O0; `add r0,sp,r0,lsl #2; str [r0]`
    at -O2) -- a `ptr` value the scanner folds into a stack base. Checked local stays silent."""
    monkeypatch.setenv("LYKOS_DECOMPILER", "ghidra")
    c = tmp_path / "s.c"; c.write_text(_STACK_SRC)
    out = tmp_path / "s"
    if subprocess.run([arm32_gcc, opt, "-marm", "-fno-stack-protector", "-no-pie", "-w", str(c),
                       "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="s")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "arm" or store.targets.get(t.id).bits != 32:
        pytest.skip("backend did not identify arm32")
    one = FunctionDAO(store.conn).get(next(iter(FunctionDAO(store.conn).list_by_target(t.id))).id)
    if not any(i.get("pcode") for b in (one.ir or {}).get("blocks", []) for i in b.get("instructions", [])):
        pytest.skip("this backend emits no P-Code for arm32")
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if d:
                got.setdefault(names.get(d["function"]), set()).add((d["check"]["verdict"],
                                                                     d["array"]["kind"]))
    assert got == {"unchk_local": {("unchecked", "stack")}}, got


# --------------------------------------------------------- ARM cross-function join (compiled) ----
_XFN_SRC = r"""
#include <stdlib.h>
int table[10];
#define NX __attribute__((noipa))
NX void leaf(int i){ table[i]=1; }                      /* indexes the forwarded param */
NX void mid(int i){ leaf(i); }                          /* forwards it on (tail call at -O2) */
NX void top(int i){ mid(i); }                           /* forwards it on (tail call at -O2) */
NX void safe_leaf(int i){ table[i]=2; }
NX void safe_top(int i){ if(i>=0&&i<10) safe_leaf(i); } /* CALLER bounds it before the forward */
NX void uncalled(int i){ table[i]=9; }                  /* bare param fed only a constant */
int main(int c,char**v){
    top(atoi(v[1]));        /* main -> top -> mid -> leaf: three edges, unchecked */
    safe_top(atoi(v[2]));   /* bounded before the forward -> must stay silent */
    uncalled(3);            /* a constant, not input -> must stay silent */
    return 0;
}
"""


def _xfn_findings(store, t, pool, q):
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in FunctionDAO(store.conn).list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if not d:
                continue
            fn = names.get(d["function"])
            got.setdefault(fn, set()).add(d["check"]["verdict"])
            via = d["index"].get("via_call")
            if fn == "leaf":                             # reached only across the forwarding chain
                assert via and names.get(via["caller"]) == "main" and via.get("hops", 1) >= 2, via
    return got


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_aarch64_cross_function_join(store, case, pool, a64_gcc, tmp_path, opt):
    """CWE-129 across functions on aarch64: an index parsed in `main` is forwarded top -> mid ->
    leaf (three edges; `bl` at -O0, tail-call `b` at -O2) before it indexes `table`. The shared join
    follows it; `leaf` is flagged unchecked with the chain attributed to main. Precision: `safe_top`
    bounds the index before forwarding (safe_leaf silent) and `uncalled` indexes a bare parameter
    fed only a constant (silent) -- a bare parameter is no longer a finding on its own."""
    c = tmp_path / "x.c"; c.write_text(_XFN_SRC)
    out = tmp_path / "x"
    if subprocess.run([a64_gcc, opt, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o",
                       str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="x")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "aarch64":
        pytest.skip("backend did not identify aarch64")
    assert _xfn_findings(store, t, pool, q) == {"leaf": {"unchecked"}}


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_arm32_cross_function_join(store, case, pool, arm32_gcc, tmp_path, monkeypatch, opt):
    """CWE-129 across functions on arm32 (ghidra backend for the P-Code the check analysis needs).
    Same three-edge forward as aarch64; `leaf` is flagged unchecked via the chain, while the
    caller-bounded forward and the constant-fed bare parameter stay silent. A function using ARM
    predication for its bound is skipped (sound), so safe_leaf stays silent whichever way -O2 emits
    safe_top's check."""
    monkeypatch.setenv("LYKOS_DECOMPILER", "ghidra")
    c = tmp_path / "x.c"; c.write_text(_XFN_SRC)
    out = tmp_path / "x"
    if subprocess.run([arm32_gcc, opt, "-marm", "-fno-stack-protector", "-no-pie", "-w", str(c),
                       "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="x")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "arm" or store.targets.get(t.id).bits != 32:
        pytest.skip("backend did not identify arm32")
    one = FunctionDAO(store.conn).get(next(iter(FunctionDAO(store.conn).list_by_target(t.id))).id)
    if not any(i.get("pcode") for b in (one.ir or {}).get("blocks", []) for i in b.get("instructions", [])):
        pytest.skip("this backend emits no P-Code for arm32")
    assert _xfn_findings(store, t, pool, q) == {"leaf": {"unchecked"}}
