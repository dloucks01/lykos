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


# ---------------------------------------------------- arm32 -O2 predicated-check recall (compiled) --
_PRED_SRC = r"""
#include <stdlib.h>
int table[10];
#define NX __attribute__((noipa))
/* branch-checked -> SAFE (silent) */
NX int chk(char*s){ int k=atoi(s); if(k>=0&&k<10) table[k]=1; return table[0]; }
/* unchecked -> FLAG */
NX int unchk(char*s){ int k=atoi(s); table[k]=1; return table[0]; }
/* a predicated CLAMP of the INDEX itself -> SAFE, must stay silent (no false positive) */
NX int clamp_idx(char*s){ int k=atoi(s); if(k>9)k=9; if(k<0)k=0; table[k]=2; return table[0]; }
/* a predicated clamp on an UNRELATED value (the -O2 return-value idiom); table[k] is still
   unchecked and straight-line -> FLAG. This is the recall the whole-function skip used to drop. */
NX int clamp_ret(char*s){ int k=atoi(s); int r=k+1; if(r>100) r=100; table[k]=1; return r; }
int main(int c,char**v){ return chk(v[1])+unchk(v[1])+clamp_idx(v[1])+clamp_ret(v[1]); }
"""


def test_arm32_O2_predicated_check_recall(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    """At -O2 gcc uses ARM conditional execution (`movgt`/`movlt`) for clamps. The scanner used to
    skip ANY function containing a predicated instruction -- sound, but it threw away a genuinely
    unchecked access whenever the function also held an unrelated predicated op. Now only a
    predicated RETURN/branch or multi-register transfer skips the function; a predicated single-dest
    DATA op poisons just its destination. So `clamp_ret` (predicated clamp on the return value, index
    untouched) is FLAGGED, while `clamp_idx` (predicated clamp of the index) and `chk` stay silent --
    recall recovered with no false positive."""
    monkeypatch.setenv("LYKOS_DECOMPILER", "ghidra")
    c = tmp_path / "pr.c"; c.write_text(_PRED_SRC)
    out = tmp_path / "pr"
    if subprocess.run([arm32_gcc, "-O2", "-marm", "-fno-stack-protector", "-no-pie", "-w", str(c),
                       "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="pr")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "arm" or store.targets.get(t.id).bits != 32:
        pytest.skip("backend did not identify arm32")
    dao = FunctionDAO(store.conn)
    funcs = {f.name: dao.get(f.id) for f in dao.list_by_target(t.id)}
    cr = funcs.get("clamp_ret")
    if not cr or not any(i.get("pcode") for b in (cr.ir or {}).get("blocks", [])
                         for i in b.get("instructions", [])):
        pytest.skip("this backend emits no P-Code for arm32")
    # the test only guards the predication path when gcc actually emitted a predicated op here
    from lykos.analyze.detect.detectors import _ARM32_PRED_RE
    preds = [i.get("text") for b in (cr.ir or {}).get("blocks", [])
             for i in b.get("instructions", [])
             if _ARM32_PRED_RE.fullmatch((i.get("text") or "").split()[0].split(";")[0]
                                         if i.get("text") else "")]
    if not preds:
        pytest.skip("gcc did not use ARM predication for clamp_ret on this toolchain")
    enqueue_detect(q, t, force=True); assert pool.wait_idle(120)
    names = {f.addr: f.name for f in dao.list_by_target(t.id)}
    got = {}
    for f in FindingDAO(store.conn).list_by_target(t.id):
        if f.detector != "array_index":
            continue
        for e in f.evidence:
            d = e.get("array_index")
            if d:
                got.setdefault(names.get(d["function"]), set()).add(d["check"]["verdict"])
    expected = {"unchk": "unchecked", "clamp_ret": "unchecked"}
    for fn, verdicts in got.items():                           # no false positive, no wrong verdict
        assert fn in expected and verdicts == {expected[fn]}, (fn, verdicts, got)
    assert "clamp_ret" in got, got                             # the recall the skip used to drop
    assert "clamp_idx" not in got and "chk" not in got, got    # predicated index clamp / branch-safe


# ------------------------------------------- register-held index across a merge (all ISAs) -------
# An index kept in a register (never spilled) that reaches an access through a control-flow MERGE.
# `mixed`: a guarded read then an UNCHECKED write at a 2-pred join -> unchecked. `bothchk`: both arms
# bound only from above -> signed (a negative index still reaches). `safe2`: both arms bound [0,10)
# -> SILENT (the no-false-positive case). `varbnd`: a variable bound `i>=n` -> SILENT (undecidable).
_MERGE_SRC = r"""
#include <stdlib.h>
int table[10];
void sink(int);
#define NX __attribute__((noipa))
NX int mixed(char*s){ int k=atoi(s); int r=0; if(k>=0&&k<10) r=table[k]; table[k]=2; return r; }
NX int bothchk(char*s,int c){ int k=atoi(s);
  if(c){ if(k>=10)return 0; } else { if(k>=10)return 0; } table[k]=1; return 0; }
NX int safe2(char*s,int c){ int k=atoi(s);
  if(c){ if(k<0||k>=10)return 0; } else { if(k<0||k>=10)return 0; } table[k]=1; return 0; }
NX int varbnd(char*s,int n){ int k=atoi(s); if(k<0||k>=n) return 0; table[k]=1; return 0; }
int main(int c,char**v){ return mixed(v[1])+bothchk(v[1],c)+safe2(v[1],c)+varbnd(v[1],c); }
"""
_MERGE_EXPECT = {"mixed": "unchecked", "bothchk": "signed"}   # safe2 + varbnd must stay silent


def _merge_verdicts(store, t, pool, q):
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
    return got


@pytest.mark.parametrize("opt", ["-O2"])
def test_x86_merge_register_index(store, case, pool, gcc, tmp_path, opt):
    """x86-64: a register-held input index used past a control-flow merge is now analysed (it used to
    be dropped at the join). mixed -> unchecked, bothchk -> signed; safe2 and the variable-bound
    varbnd stay silent (no false positive)."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "mg.c"; c.write_text(_MERGE_SRC)
    out = tmp_path / "mg"
    if subprocess.run([gcc, opt, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="mg")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {k: {v} for k, v in _MERGE_EXPECT.items()}


def test_aarch64_merge_register_index(store, case, pool, a64_gcc, tmp_path):
    """Same register-held-index-across-a-merge recovery on aarch64 (native backend)."""
    c = tmp_path / "mg.c"; c.write_text(_MERGE_SRC)
    out = tmp_path / "mg"
    if subprocess.run([a64_gcc, "-O2", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o",
                       str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="mg")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "aarch64":
        pytest.skip("backend did not identify aarch64")
    assert _merge_verdicts(store, t, pool, q) == {k: {v} for k, v in _MERGE_EXPECT.items()}


def test_arm32_merge_register_index(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    """Same register-held-index-across-a-merge recovery on arm32 (ghidra backend for P-Code)."""
    monkeypatch.setenv("LYKOS_DECOMPILER", "ghidra")
    c = tmp_path / "mg.c"; c.write_text(_MERGE_SRC)
    out = tmp_path / "mg"
    if subprocess.run([arm32_gcc, "-O2", "-marm", "-fno-stack-protector", "-no-pie", "-w", str(c),
                       "-o", str(out)], capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="mg")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    if store.targets.get(t.id).arch != "arm" or store.targets.get(t.id).bits != 32:
        pytest.skip("backend did not identify arm32")
    one = FunctionDAO(store.conn).get(next(iter(FunctionDAO(store.conn).list_by_target(t.id))).id)
    if not any(i.get("pcode") for b in (one.ir or {}).get("blocks", []) for i in b.get("instructions", [])):
        pytest.skip("this backend emits no P-Code for arm32")
    assert _merge_verdicts(store, t, pool, q) == {k: {v} for k, v in _MERGE_EXPECT.items()}


# ---------------------------------------- input index guarded by an UNRELATED branch (all ISAs) ---
# An input index reaching an access past a conditional branch that tests an UNRELATED value (a loop
# trip count `if(n<=0)`, a flag) is unchecked -- the branch adds no bound on the index. It must be
# told apart from a branch that tests the index itself with a VARIABLE bound (`if(i>=n)`), which is
# undecidable (no claim), so neither becomes a false positive and the real one is still found.
_UNREL_SRC = r"""
#include <stdlib.h>
int table[10];
void sink(int);
#define NX __attribute__((noipa))
NX void unrel_guard(char*s,int n){ int i=atoi(s); if(n<=0) return; sink(table[i]); }
NX void var_guard(char*s,int n){ int i=atoi(s); if(i<0||i>=n) return; table[i]=1; }
void sink(int x){ volatile int y=x; (void)y; }
int main(int c,char**v){ unrel_guard(v[1],c); var_guard(v[1],c); return 0; }
"""


def test_x86_unrelated_guard_index(store, case, pool, gcc, tmp_path):
    """An input index (register-held at -O2) guarded by a branch on an UNRELATED value (`if(n<=0)`)
    is unchecked; a branch that tests the index against a VARIABLE bound (`if(i>=n)`) stays silent
    (undecidable, no FP). -O2, the register path (-O0 indices are slot-based, a separate path)."""
    opt = "-O2"
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "ug.c"; c.write_text(_UNREL_SRC)
    out = tmp_path / "ug"
    if subprocess.run([gcc, opt, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="ug")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {"unrel_guard": {"unchecked"}}   # var_guard silent


# ------------------------------------------------- loop induction variable overrunning an array ---
# A counted loop whose induction variable walks off a fixed array. The variable is recognised by its
# constant init + single constant step; its reachable max comes from the loop's own exit bound, read
# WITHOUT guard_bound's increment-store bail; and it is flagged only inside a SINGLE-EXIT loop (an
# early break could stop short). -O0, where the induction variable is a stack slot.
_IV_SRC = r"""
#include <stdlib.h>
int table[10];
#define NX __attribute__((noipa))
NX void c_over(void){ for(int i=0;i<=10;i++) table[i]=i; }                 /* reaches 10 -> bound */
NX void c_safe(void){ for(int i=0;i<10;i++) table[i]=i; }                  /* 0..9 -> silent */
NX void c_break(void){ for(int i=0;i<=10;i++){ if(i==5)break; table[i]=i; } }  /* break -> silent */
NX void c_inner(void){ for(int i=0;i<=20;i++){ if(i<10) table[i]=i; } }    /* inner guard -> silent */
int main(int c,char**v){ c_over(); c_safe(); c_break(); c_inner(); return 0; }
"""


def test_x86_loop_induction_overrun(store, case, pool, gcc, tmp_path):
    """A constant-trip-count loop that indexes past a fixed array is flagged `bound`; a safe loop, a
    loop with an early break, and one with an inner bound all stay silent (no false positive). -O0,
    induction variable in a stack slot."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "iv.c"; c.write_text(_IV_SRC)
    out = tmp_path / "iv"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="iv")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {"c_over": {"bound"}}


# --------------------------------------------- loop length from unvalidated input (CWE-787) --------
# `for(i=0;i<n;i++) table[i]=...` with n an unvalidated input value writes past a fixed array when n
# exceeds it -- the classic input-controlled-length overflow. Flagged ONLY when the length has no
# dominating bound: a re-assigned clamp (`if(n>10)n=10`) drops n as an input source, and a guard
# around the loop (`if(n<=10)`) bounds it -- both stay silent (no false positive).
_IVN_SRC = r"""
#include <stdlib.h>
int table[10];
#define NX __attribute__((noipa))
NX void n_over(char*s){ int n=atoi(s); for(int i=0;i<n;i++) table[i]=i; }                 /* unchecked */
NX void n_clamp(char*s){ int n=atoi(s); if(n>10)n=10; for(int i=0;i<n;i++) table[i]=i; }  /* clamp -> silent */
NX void n_guard(char*s){ int n=atoi(s); if(n>=0&&n<=10) for(int i=0;i<n;i++) table[i]=i; } /* guard -> silent */
int main(int c,char**v){ n_over(v[1]); n_clamp(v[1]); n_guard(v[1]); return 0; }
"""


def test_x86_loop_input_length_overflow(store, case, pool, gcc, tmp_path):
    """A loop whose trip count is an UNVALIDATED input value overruns a fixed array -> `unchecked`;
    a re-assigned clamp and a dominating guard on the length both stay silent (no false positive).
    -O0, where the length is a stack slot."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "ivn.c"; c.write_text(_IVN_SRC)
    out = tmp_path / "ivn"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="ivn")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {"n_over": {"unchecked"}}


# ------------------------------------------- loop induction variable on ARM (-O0, cross-compiled) --
def _run_iv(store, case, pool, cc, tmp_path, src, flags, ghidra, monkeypatch, want_arch, want_bits=None):
    if monkeypatch is not None and ghidra:
        monkeypatch.setenv("LYKOS_DECOMPILER", "ghidra")
    c = tmp_path / "iv.c"; c.write_text(src)
    out = tmp_path / "iv"
    if subprocess.run([cc, *flags, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot cross-compile")
    t = ingest(store, case.id, out, filename="iv")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(240)
    tgt = store.targets.get(t.id)
    if tgt.arch != want_arch or (want_bits and tgt.bits != want_bits):
        pytest.skip(f"backend did not identify {want_arch}")
    if ghidra:
        one = FunctionDAO(store.conn).get(next(iter(FunctionDAO(store.conn).list_by_target(t.id))).id)
        if not any(i.get("pcode") for b in (one.ir or {}).get("blocks", [])
                   for i in b.get("instructions", [])):
            pytest.skip("this backend emits no P-Code")
    return _merge_verdicts(store, t, pool, q)


def test_aarch64_loop_induction(store, case, pool, a64_gcc, tmp_path):
    """Loop induction overrun + input-length overflow on aarch64 -O0 (native backend)."""
    assert _run_iv(store, case, pool, a64_gcc, tmp_path, _IV_SRC, ["-O0"], False, None,
                   "aarch64") == {"c_over": {"bound"}}


def test_aarch64_loop_input_length(store, case, pool, a64_gcc, tmp_path):
    assert _run_iv(store, case, pool, a64_gcc, tmp_path, _IVN_SRC, ["-O0"], False, None,
                   "aarch64") == {"n_over": {"unchecked"}}


def test_arm32_loop_induction(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    """Loop induction overrun + input-length overflow on arm32 -O0 (ghidra backend for P-Code)."""
    assert _run_iv(store, case, pool, arm32_gcc, tmp_path, _IV_SRC, ["-O0", "-marm"], True,
                   monkeypatch, "arm", 32) == {"c_over": {"bound"}}


def test_arm32_loop_input_length(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    assert _run_iv(store, case, pool, arm32_gcc, tmp_path, _IVN_SRC, ["-O0", "-marm"], True,
                   monkeypatch, "arm", 32) == {"n_over": {"unchecked"}}


# ----------------------------------------------- loop induction at -O2 (register counter) ----------
# At -O2 the induction variable is promoted out of its stack slot into a register, and gcc unrolls /
# vectorises. Three distinct shapes result (verified per arch): x86 keeps a 2x-unrolled register-
# counter loop with a derived index (`t[i]; t[i+1]`) and a `cmp reg,C; jne` equality exit; aarch64
# FULLY vectorises the constant overrun into straight-line SIMD plus a constant out-of-bounds store
# (`str w1,[x0,#40]`), so there is no loop at all; and the input-length loop survives on aarch64 as a
# clean register counter. Each is handled without a single false positive on the safe companions.
def test_x86_loop_induction_overrun_O2(store, case, pool, gcc, tmp_path):
    """x86-64 -O2: the register-counter + 2x-unroll form of the counted overrun. The derived access
    `t[i+1]` reaches index 10 past the 10-int array -> bound; c_safe/c_break (vectorised away) and
    c_inner (register inner guard) stay silent."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "iv.c"; c.write_text(_IV_SRC)
    out = tmp_path / "iv"
    if subprocess.run([gcc, "-O2", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="iv")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {"c_over": {"bound"}}


def test_x86_loop_input_length_O2(store, case, pool, gcc, tmp_path):
    """x86-64 -O2: an input-length loop overruns a fixed array -> unchecked, even though gcc peels the
    remainder (a parity split `and edx,1; jne` and a peeled `if(1==n)` check). The DOMINATOR-only
    length scan skips those peel branches (neither dominates the loop) while still honouring a real
    dominating guard: n_clamp (a cmov clamp that rewrites n into an opaque register) and n_guard (a
    dominating `cmp eax,0xa; ja`) both stay silent -- no false positive."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "ivn.c"; c.write_text(_IVN_SRC)
    out = tmp_path / "ivn"
    if subprocess.run([gcc, "-O2", "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="ivn")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {"n_over": {"unchecked"}}


def test_aarch64_const_oob_store_O2(store, case, pool, a64_gcc, tmp_path):
    """aarch64 -O2: the constant overrun is fully unrolled/vectorised into a constant out-of-bounds
    store (`str w1,[x0,#40]` into a 10-int array) -- the induction loop is gone. The constant-offset
    OOB-store detector flags it as bound; c_safe/c_break (in-bounds SIMD) and c_inner stay silent."""
    assert _run_iv(store, case, pool, a64_gcc, tmp_path, _IV_SRC, ["-O2"], False, None,
                   "aarch64") == {"c_over": {"bound"}}


def test_aarch64_loop_input_length_O2(store, case, pool, a64_gcc, tmp_path):
    """aarch64 -O2: the input-length loop survives as a clean register counter (`str w1,[x2,x1,lsl
    #2]; add x1,x1,#1; cmp w0,w1; b.gt`) with no remainder peeling, so the length value traces to
    the strtol result with no dominating bound -> unchecked; n_clamp/n_guard stay silent."""
    assert _run_iv(store, case, pool, a64_gcc, tmp_path, _IVN_SRC, ["-O2"], False, None,
                   "aarch64") == {"n_over": {"unchecked"}}


def test_arm32_walking_pointer_overrun_O2(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    """arm32 -O2: the counted overrun compiles to a WALKING-POINTER loop (`str r3,[r2,#4]!` with
    r2 = &table - 4) plus a separate trip-count counter (`cmp r3,#11; bne`); no index register
    appears in the store. The pointer's stride x constant trip count reaches table[10] past the
    10-int array -> bound. c_safe/c_break/c_inner stay silent (no false positive)."""
    assert _run_iv(store, case, pool, arm32_gcc, tmp_path, _IV_SRC, ["-O2", "-marm"], True,
                   monkeypatch, "arm", 32) == {"c_over": {"bound"}}


def test_arm32_walking_pointer_input_length_O2_silent(store, case, pool, arm32_gcc, tmp_path,
                                                      monkeypatch):
    """arm32 -O2 input-length loops carry a predicated return (`if(n<=0)return` -> `pople {..,pc}`),
    which the conservative `_arm32_pred_unsound` gate cannot model and so skips the whole function.
    The result is a sound MISS, never a false positive -- n_over/n_clamp/n_guard all stay silent."""
    assert _run_iv(store, case, pool, arm32_gcc, tmp_path, _IVN_SRC, ["-O2", "-marm"], True,
                   monkeypatch, "arm", 32) == {}


# ----------------------------------------- UNBOUNDED write: table[i++] until EOF (CWE-787) ----------
# A loop that walks a fixed array with NO bound on the write position, driven by an input-reading call
# (`while((c=getchar())!=EOF) table[i++]=c;`): the position is input-controlled and overruns. Flagged
# `unchecked`. The companions are all safe and must stay silent: s_bound bounds i with `i<10` (two
# exits), s_guard guards the write with `if(i<10)`, and s_par's loop is bounded by a parallel counter
# `j<5` (and is not input-driven). -O0 keeps a slot counter; -O2 x86/aarch64 emit a walking pointer
# (no counter); arm32 -O2 carries a predicated return and is soundly skipped.
_UNB_SRC = r"""
#include <stdio.h>
int table[10];
#define NX __attribute__((noipa))
NX void u_copy(void){ int c,i=0; while((c=getchar())!=EOF) table[i++]=c; }           /* unbounded */
NX void s_bound(void){ int c,i=0; while(i<10 && (c=getchar())!=EOF) table[i++]=c; }  /* i<10 -> silent */
NX void s_guard(void){ int c,i=0; while((c=getchar())!=EOF){ if(i<10) table[i]=c; i++; } } /* guard */
NX void s_par(void){ int i=0; for(int j=0;j<5;j++){ table[i]=j; i++; } }             /* bounded -> silent */
int main(int c,char**v){ u_copy(); s_bound(); s_guard(); s_par(); return 0; }
"""


@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_x86_unbounded_input_copy(store, case, pool, gcc, tmp_path, opt):
    """x86-64: `while((c=getchar())!=EOF) table[i++]=c;` walks a fixed array an INPUT-controlled number
    of times -> unchecked (CWE-787). -O0 keeps a slot counter (the `arr[i++]` lea-increment form), -O2
    a walking pointer (`mov [rbx],eax; add rbx,4`); both exit on the getchar/getc result, so neither
    bounds the write. s_bound/s_guard/s_par stay silent (no false positive)."""
    if sandbox.host_arch() != "x86-64":
        pytest.skip("array_index reads x86-64 operands; the e2e backend is host-arch bound")
    c = tmp_path / "unb.c"; c.write_text(_UNB_SRC)
    out = tmp_path / "unb"
    if subprocess.run([gcc, opt, "-fno-stack-protector", "-no-pie", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    t = ingest(store, case.id, out, filename="unb")
    q = JobQueue(store.conn)
    enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
    enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    assert _merge_verdicts(store, t, pool, q) == {"u_copy": {"unchecked"}}


def test_aarch64_unbounded_input_copy_O0(store, case, pool, a64_gcc, tmp_path):
    """aarch64 -O0: a getchar-until-EOF copy into a fixed array -> unchecked. Slot counter
    (load-add-store step, sign-extended index); exit on the getchar result (input-driven)."""
    assert _run_iv(store, case, pool, a64_gcc, tmp_path, _UNB_SRC, ["-O0"], False, None,
                   "aarch64") == {"u_copy": {"unchecked"}}


def test_aarch64_unbounded_input_copy_O2(store, case, pool, a64_gcc, tmp_path, monkeypatch):
    """aarch64 -O2: the copy becomes a walking pointer (`adrp/add x19,table; str w0,[x19],#4`) with a
    getc-driven exit -> unchecked. Uses the ghidra backend: the native (rizin) backend is
    pathologically slow on this getc/stdin binary (it recovers no functions within budget)."""
    assert _run_iv(store, case, pool, a64_gcc, tmp_path, _UNB_SRC, ["-O2"], True, monkeypatch,
                   "aarch64") == {"u_copy": {"unchecked"}}


def test_arm32_unbounded_input_copy_O0(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    """arm32 -O0: a getchar-until-EOF copy into a fixed array -> unchecked (ghidra backend)."""
    assert _run_iv(store, case, pool, arm32_gcc, tmp_path, _UNB_SRC, ["-O0", "-marm"], True,
                   monkeypatch, "arm", 32) == {"u_copy": {"unchecked"}}


def test_arm32_unbounded_input_copy_O2_silent(store, case, pool, arm32_gcc, tmp_path, monkeypatch):
    """arm32 -O2: the walking-pointer copy carries a predicated return (`popeq {..,pc}`), so the
    `_arm32_pred_unsound` gate skips the function -- a sound MISS, never a false positive (silent)."""
    assert _run_iv(store, case, pool, arm32_gcc, tmp_path, _UNB_SRC, ["-O2", "-marm"], True,
                   monkeypatch, "arm", 32) == {}
