"""Regression tests for the static-detector precision follow-ups of the 2026-10-22 audit (doc 48):

* scanf_bounded_overflow -- each width bounds ITS OWN destination (`%4s %63s` is not a 64-byte
  write into the 5-byte first buffer); the register tracers resume after a mov hop; each memset is
  read at its own call with the size that reaches it.
* privilege_drop_order -- `seteuid(0)` is a RAISE, not a drop; ordering is decided per CFG path
  (a correct branch no longer masks a wrong-order one).
* uaf -- a one-line `if (err) { free(p); return; }` ends the freeing path.
* cve_corroborate -- CWE-20 / CWE-369 are not "memory corruption".
"""
from __future__ import annotations

import types

from lykos.analyze.detect.detectors import (
    DetectContext,
    _memset_size_for_slot,
    _stack_slot_for_reg,
    _str_flag_for_reg,
    privilege_drop_order,
    scanf_bounded_overflow,
    stack_buffer_overflow,
)
from lykos.analyze.fingerprint import corroborate
from lykos.analyze.fingerprint.uaf import _scan_text


def _ir(instrs):
    return {"blocks": [{"addr": "0x1000", "succ": [],
                        "instructions": [{"addr": hex(a), "text": t} for a, t in instrs]}]}


def _sctx(ir, strings, vars_=None):
    return DetectContext(target_id="t", case_id="c", call_edges=[],
                         strings=[types.SimpleNamespace(value=s, addr=None) for s in strings],
                         functions=[], frames={0x1000: {"vars": vars_ or []}},
                         func_irs={0x1000: ir}, bits=64, arch="x86-64")


def _two_buffer_scanf(fmt_flag):
    # memset(small,0,5); memset(big,0,64); scanf(fmt, small, big)
    return _ir([
        (0x10, "lea rax, [rbp - 5]"), (0x14, "mov edx, 5"), (0x18, "mov esi, 0"),
        (0x1c, "mov rdi, rax"), (0x20, "call sym.imp.memset"),
        (0x24, "lea rax, [rbp - 0x50]"), (0x28, "mov edx, 0x40"), (0x2c, "mov esi, 0"),
        (0x30, "mov rdi, rax"), (0x34, "call sym.imp.memset"),
        (0x38, "lea rdx, [rbp - 0x50]"), (0x3c, "lea rax, [rbp - 5]"),
        (0x40, f"lea rcx, str.{fmt_flag}"), (0x44, "mov rsi, rax"), (0x48, "mov rdi, rcx"),
        (0x4c, "call sym.imp.__isoc99_scanf")])


# ------------------------------------------------------------------------ scanf widths --------
def test_scanf_width_is_matched_to_its_own_buffer():
    # %4s -> small[5] fits; %63s -> big[64] fits. The old max(widths)-on-first-buffer read this as
    # a 64-byte write into the 5-byte `small` -- a fabricated HIGH CWE-787.
    assert scanf_bounded_overflow(_sctx(_two_buffer_scanf("_4s__63s"), ["%4s %63s"])) == []


def test_scanf_overflow_is_reported_on_the_buffer_that_overflows():
    hits = scanf_bounded_overflow(_sctx(_two_buffer_scanf("_4s__64s"), ["%4s %64s"]))
    assert len(hits) == 1
    assert "%64s" in hits[0]["site_detail"] and "64-byte buffer (rbp-80)" in hits[0]["site_detail"]
    assert "off-by-one" in hits[0]["title"]


def test_scanf_non_string_conversion_shifts_the_argument_registers():
    # "%d %16s": the %16s destination is the SECOND variadic argument (rdx), not rsi
    ir = _ir([(0x10, "lea rax, [rbp - 0x14]"), (0x14, "lea rdx, [rbp - 0x10]"),
              (0x18, "mov rsi, rax"), (0x1c, "lea rdi, str._d__16s"),
              (0x20, "call sym.imp.__isoc99_scanf")])
    vars_ = [{"name": "n", "offset": -20, "size": 4}, {"name": "b", "offset": -16, "size": 16}]
    hits = scanf_bounded_overflow(_sctx(ir, ["%d %16s"], vars_))
    assert len(hits) == 1 and "rbp-16" in hits[0]["site_detail"]


def test_scanf_unresolved_format_only_maps_a_leading_width():
    # no real string matches the flag -> nothing can be mapped beyond a leading %Ns
    ir = _ir([(0x10, "lea rax, [rbp - 0x10]"), (0x14, "mov rsi, rax"),
              (0x18, "lea rdi, str._d__16s"), (0x1c, "call sym.imp.__isoc99_scanf")])
    vars_ = [{"name": "n", "offset": -16, "size": 4}]
    assert scanf_bounded_overflow(_sctx(ir, ["%16s"], vars_)) == []


def test_reg_tracer_resumes_after_the_hop():
    # rcx <- rdx at the copy; the LATER `mov rdx, rax` must not be read as rcx's source
    texts = ["lea rdx, [rbp - 0x80]", "lea rax, [rbp - 0x58]", "lea rdi, str._d__7s__32s",
             "mov rcx, rdx", "mov rdx, rax"]
    assert _stack_slot_for_reg(texts, "rcx") == -0x80
    assert _stack_slot_for_reg(texts, "rdx") == -0x58
    assert _str_flag_for_reg(texts, "rdi") == "_d__7s__32s"
    # a 32-bit write to the register is a redefinition too
    assert _stack_slot_for_reg(["lea rsi, [rbp - 0x10]", "mov esi, 5"], "rsi") is None


def test_memset_size_is_read_at_each_call():
    texts = ["lea rax, [rbp - 5]", "mov edx, 5", "mov rdi, rax", "call sym.imp.memset",
             "lea rax, [rbp - 0x50]", "mov edx, elf_phdr", "mov rdi, rax", "call sym.imp.memset",
             "lea rax, [rbp - 0x80]", "mov edx, 0x20", "mov rdi, rax", "call sym.imp.memset"]
    assert _memset_size_for_slot(texts, -5) == 5
    assert _memset_size_for_slot(texts, -0x80) == 0x20          # was None: index() hit call #1
    # a size r2 renders as a symbol is unknown -- NOT the previous memset's 5
    assert _memset_size_for_slot(texts, -0x50) is None


def test_stack_frame_survives_a_degenerate_frame_record():
    e = types.SimpleNamespace(src_addr=0x1000, site_addr="0x1010", dst_name="strcpy")
    ctx = DetectContext(target_id="t", case_id="c", call_edges=[e], strings=[], functions=[],
                        frames={0x1000: {"vars": [{"name": "b", "offset": None, "size": None,
                                                   "is_buffer": True}]}},
                        func_irs={}, bits=64, arch="x86-64")
    hits = stack_buffer_overflow(ctx)
    assert len(hits) == 1 and "distance to the saved return address unknown" in hits[0]["site_detail"]


# ------------------------------------------------------------------ privilege drop order ------
def _pctx(edges, blocks):
    es = [types.SimpleNamespace(src_addr=0x1000, site_addr=s, dst_name=n) for n, s in edges]
    return DetectContext(target_id="t", case_id="c", call_edges=es, strings=[], functions=[],
                         func_irs={"0x1000": {"blocks": blocks}}, bits=64, arch="x86-64")


def _b(addr, ins, succ=()):
    return {"addr": hex(addr), "succ": [hex(s) for s in succ],
            "instructions": [{"addr": hex(a), "text": t} for a, t in ins]}


def test_seteuid_zero_is_a_raise_not_a_drop():
    # seteuid(0); setgid(1000); setuid(1000) -- restore root, then drop correctly
    blk = _b(0x1000, [(0x1000, "mov edi, 0"), (0x1005, "call sym.imp.seteuid"),
                      (0x100a, "mov edi, 0x3e8"), (0x100f, "call sym.imp.setgid"),
                      (0x1014, "mov edi, 0x3e8"), (0x1019, "call sym.imp.setuid")])
    edges = [("seteuid", 0x1005), ("setgid", 0x100f), ("setuid", 0x1019)]
    assert privilege_drop_order(_pctx(edges, [blk])) == []
    # the -O2 zeroing idiom is the same raise
    blk2 = _b(0x1000, [(0x1000, "xor edi, edi"), (0x1005, "call sym.imp.seteuid"),
                       (0x100a, "mov edi, 0x3e8"), (0x100f, "call sym.imp.setgid"),
                       (0x1014, "mov edi, 0x3e8"), (0x1019, "call sym.imp.setuid")])
    assert privilege_drop_order(_pctx(edges, [blk2])) == []


def test_a_correct_branch_no_longer_masks_a_wrong_order_branch():
    # if (a) { setgid; setuid; } else { setuid; setgid; } -- the function-wide min() hid the else
    blocks = [_b(0x1000, [(0x1000, "test edi, edi"), (0x1002, "je 0x1200")], (0x1100, 0x1200)),
              _b(0x1100, [(0x1100, "mov edi, ebx"), (0x1104, "call sym.imp.setgid"),
                          (0x1108, "mov edi, ebx"), (0x110c, "call sym.imp.setuid"),
                          (0x1110, "jmp 0x1300")], (0x1300,)),
              _b(0x1200, [(0x1200, "mov edi, ebx"), (0x1204, "call sym.imp.setuid"),
                          (0x1208, "mov edi, ebx"), (0x120c, "call sym.imp.setgid")], (0x1300,)),
              _b(0x1300, [(0x1300, "ret")])]
    edges = [("setgid", 0x1104), ("setuid", 0x110c), ("setuid", 0x1204), ("setgid", 0x120c)]
    hits = privilege_drop_order(_pctx(edges, blocks))
    assert len(hits) == 1 and hits[0]["site_addr"] == "0x1204"


def test_gid_call_after_an_earlier_gid_drop_is_not_flagged():
    # setgid; setuid; setgid -- the gid was dropped first on this path
    blk = _b(0x1000, [(0x1000, "mov edi, ebx"), (0x1004, "call sym.imp.setgid"),
                      (0x1008, "mov edi, ebx"), (0x100c, "call sym.imp.setuid"),
                      (0x1010, "mov edi, ebx"), (0x1014, "call sym.imp.setgid")])
    edges = [("setgid", 0x1004), ("setuid", 0x100c), ("setgid", 0x1014)]
    assert privilege_drop_order(_pctx(edges, [blk])) == []


def test_a_loop_back_edge_is_not_a_path():
    # for (;;) { setgid; setuid; } -- the back-edge must not make setgid "follow" setuid
    blocks = [_b(0x1000, [(0x1000, "mov edi, ebx"), (0x1004, "call sym.imp.setgid"),
                          (0x1008, "mov edi, ebx"), (0x100c, "call sym.imp.setuid"),
                          (0x1010, "jne 0x1000")], (0x1000, 0x1020)),
              _b(0x1020, [(0x1020, "ret")])]
    assert privilege_drop_order(_pctx([("setgid", 0x1004), ("setuid", 0x100c)], blocks)) == []


def test_computed_seteuid_argument_stays_a_drop():
    # seteuid(getuid()) then setgid -- a temporary drop before the gid change: still wrong order
    blk = _b(0x1000, [(0x1000, "mov edi, eax"), (0x1005, "call sym.imp.seteuid"),
                      (0x100a, "mov edi, ebx"), (0x100f, "call sym.imp.setgid")])
    assert len(privilege_drop_order(_pctx([("seteuid", 0x1005), ("setgid", 0x100f)], [blk]))) == 1


# -------------------------------------------------------------------------------- uaf ---------
def test_one_line_guarded_free_with_return_is_not_a_uaf():
    lines = ["void f(char *p, int err) {", "    if (err) { free(p); return; }", "    use(p);", "}"]
    assert _scan_text("a.c", lines) == []
    lines = ["int f(char *p, int err) {", "    if (err) { free(p); return -1; }", "    p[0] = 1;",
             "    return 0;", "}"]
    assert _scan_text("a.c", lines) == []


def test_conditional_return_after_free_still_flags():
    # `free(p); if (x) return;` -- the free still reaches the fall-through
    lines = ["void f(char *p, int x) {", "    free(p); if (x) return;", "    use(p);", "}"]
    assert [f["cwe"] for f in _scan_text("a.c", lines)] == ["CWE-416"]
    # the return is in a sibling block, not the free's
    lines = ["void f(char *p, int x) {", "    if (x) { free(p); } else { return; }", "    use(p);",
             "}"]
    assert [f["cwe"] for f in _scan_text("a.c", lines)] == ["CWE-416"]


def test_one_line_break_does_not_end_the_freeing_path():
    # a loop exit lands on the use -- a real UAF
    lines = ["void f(char *p, int n) {", "    for (;;) { if (n) { free(p); break; } }",
             "    use(p);", "}"]
    assert [f["cwe"] for f in _scan_text("a.c", lines)] == ["CWE-416"]


# --------------------------------------------------------------------- cve corroboration ------
def test_input_validation_and_div_by_zero_are_not_memory_corruption():
    assert corroborate._family("CWE-20") == "CWE-20"
    assert corroborate._family("CWE-369") == "CWE-369"
    assert corroborate._family("CWE-787") == corroborate._family("CWE-129") == "memory"
    assert corroborate._family("CWE-20") != corroborate._family("CWE-787")


# ------------------------------------------- bounds: a guard on a value later overwritten -----
_STALE_SRC = r"""
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((noinline)) void stale(const char *src, char **argv) {
  char buf[64]; memset(buf, 0, sizeof buf);
  int n = atoi(argv[1]);
  if (n < 0 || n > 64) return;
  n = atoi(argv[2]);
  memcpy(buf, src, n);
  write(1, buf, 1);
}
__attribute__((noinline)) void fresh(const char *src, char **argv) {
  char buf[64]; memset(buf, 0, sizeof buf);
  int n = atoi(argv[1]);
  if (n < 0 || n > 64) return;
  memcpy(buf, src, n);
  write(1, buf, 1);
}
int main(int argc, char **argv) { stale(argv[0], argv); fresh(argv[0], argv); return 0; }
"""


def test_a_guard_on_a_since_overwritten_length_does_not_bound_the_copy(store, case, gcc, tmp_path):
    """`n = a(); if (n > 64) return; n = b(); memcpy(buf, s, n)` -- the check bounded the OLD n.
    Trusting it demoted a real overflow to "bounded"; the stale guard is now ignored."""
    import subprocess

    import pytest
    from lykos.analyze import register
    from lykos.analyze.detect import bounds
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.dynamic import sandbox
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if sandbox.host_arch() != "x86-64":
        pytest.skip("host-arch bound e2e")
    c = tmp_path / "g.c"
    c.write_text(_STALE_SRC)
    out = tmp_path / "g"
    if subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, out, filename="g")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
    finally:
        pool.stop(grace=3.0)
    fdao = FunctionDAO(store.conn)
    irs, frames, names = {}, {}, {}
    for f in fdao.list_by_target(t.id):
        full = fdao.get(f.id)
        names[f.addr] = f.name
        if full and full.ir:
            irs[f.addr] = full.ir
        frames[f.addr] = (full.frame if full else None) or {}
    v = bounds.classify_program(irs, CallEdgeDAO(store.conn).list_by_target(t.id), frames,
                                TargetDAO(store.conn).get(t.id).arch, bits=64)
    by_fn = {names.get(i["function_addr"]): i["verdict"] for i in v.values() if i["sink"] == "memcpy"}
    if by_fn.get("fresh") != bounds.SAFE:
        pytest.skip(f"toolchain did not give the guarded control a verdict: {by_fn}")
    assert by_fn.get("stale") != bounds.SAFE, by_fn


# ----------------------------------------- int_overflow_alloc: a stale narrow product ---------
def _alloc_ir(pcodes):
    ins = [{"addr": hex(0x10 + 4 * k), "text": "", "pcode": p} for k, p in enumerate(pcodes)]
    return {"0x1000": {"blocks": [{"addr": "0x10", "succ": [], "instructions": ins}]}}


def test_alloc_wrap_needs_the_product_to_still_be_in_the_size_register():
    from lykos.analyze.detect.stage import _intover_candidates
    from lykos.analyze.detect.taint import ARCH_ABI
    argregs = ARCH_ABI["x86-64"]["args"]
    prod = ["INT_MULT reg:EDI:4 reg:ESI:4 -> reg:EDI:4"]
    call = ["CALL ram:0x401030:8"]
    site = hex(0x10 + 4 * 2)
    # control: the narrow product reaches malloc's size register -> flagged
    hits = _intover_candidates(_alloc_ir([prod, ["COPY reg:EAX:4 -> reg:EBX:4"], call]), [],
                               alloc_sites={site: "malloc"}, argregs=argregs)
    assert [h["detector"] for h in hits] == ["int_overflow_alloc"]
    # the size register is RELOADED before the call -> the product is gone
    reload = ["LOAD const:0x1:8 reg:RAX:8 -> reg:EDI:4"]
    assert _intover_candidates(_alloc_ir([prod, reload, call]), [],
                               alloc_sites={site: "malloc"}, argregs=argregs) == []
    # a narrow product in the SECOND argument register is not malloc's size
    prod_rsi = ["INT_MULT reg:ESI:4 reg:EDX:4 -> reg:ESI:4"]
    assert _intover_candidates(_alloc_ir([prod_rsi, ["COPY reg:EAX:4 -> reg:EBX:4"], call]), [],
                               alloc_sites={site: "malloc"}, argregs=argregs) == []


# ----------------------------------------------------------- source-level detectors -----------
def test_int_overflow_source_ignores_sizeof_deref_macros_and_comments(tmp_path):
    from lykos.analyze.fingerprint import int_overflow
    (tmp_path / "a.c").write_text(
        "void *f(struct s *p, unsigned a, unsigned b){\n"
        "  struct s *q = malloc(sizeof *p);\n"                # the canonical safe size
        "  char *t = malloc(COUNT * ELEM_SIZE);\n"             # compile-time constants
        "  /* old: x = malloc(a * b); */\n"                    # not code
        "  return malloc(a * b);\n}\n")                       # the one real shape
    hits = int_overflow.scan_source(tmp_path)
    assert [h["dedup_key"].split(":")[2] for h in hits] == ["5"], hits


def test_source_sinks_skip_prototypes_macro_bodies_and_va_list_wrappers(tmp_path):
    from lykos.analyze.fingerprint import source_sinks
    (tmp_path / "a.c").write_text(
        "int printf(const char *fmt, ...);\n"
        "static void logf_(const char *fmt, ...) { va_list ap; vfprintf(stderr, fmt, ap); }\n"
        "#define DBG(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)\n"
        "void f(char *buf, char *cmd) { printf(buf); if (buf) return (void)system(cmd); }\n")
    got = sorted((h["cwe"], h["evidence"][0]["detail"].split(":")[1]) for h in
                 source_sinks.scan_source(tmp_path))
    assert got == [("CWE-134", "4"), ("CWE-78", "4")], got


def test_scriptscan_parameterised_query_and_literal_send_are_not_findings():
    from lykos.analyze.detect import scriptscan
    py = b'cur.execute("SELECT * FROM t WHERE id = %s", (request.args["id"],))\n'
    assert not any(f["cwe"] == "CWE-89" for f in scriptscan.scan(py, "python"))
    fmt = b'cur.execute("SELECT * FROM t WHERE id = %s" % request.args["id"])\n'
    assert ("CWE-89", "corroborated") in {(f["cwe"], f["state"]) for f in scriptscan.scan(fmt, "python")}
    assert scriptscan.scan(b"obj.send(:save)\n", "ruby") == []
    assert any(f["cwe"] == "CWE-95" for f in scriptscan.scan(b"obj.send(params[:m])\n", "ruby"))


def test_testing_a_freed_pointers_value_is_not_a_use():
    # `if (p == NULL)` / `while (p)` / `sizeof(p)` read the pointer VALUE, never the freed memory
    for use in ("if (p == NULL) return;", "while (p) break;", "n = sizeof(p);"):
        lines = ["void f(char *p) {", "    free(p);", f"    {use}", "}"]
        assert _scan_text("a.c", lines) == [], use
    # a real call argument still is
    lines = ["void f(char *p) {", "    free(p);", "    if (x) puts(p);", "}"]
    assert [f["cwe"] for f in _scan_text("a.c", lines)] == ["CWE-416"]


def test_over_the_taint_cap_the_stage_runs_ranked_and_reports_it(store, case, gcc, tmp_path):
    """Past `max_taint_functions` taint runs on the ranked top-N instead of being dropped whole;
    the stage reports the selection (`detect.taint_ranked`) and still files findings, and the
    image constants (here: the global array's st_size) come through the mapped view."""
    import json
    import subprocess

    import pytest
    from lykos.analyze import register
    from lykos.analyze.detect.stage import DETECT_STAGE
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.dynamic import sandbox
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    if sandbox.host_arch() != "x86-64":
        pytest.skip("host-arch bound e2e")
    c = tmp_path / "r.c"
    c.write_text("#include <stdlib.h>\nint table[10];\n"
                 "__attribute__((noinline)) int a(char *s){ return table[atoi(s)]; }\n"
                 "__attribute__((noinline)) int b(int x){ return x + 1; }\n"
                 "int main(int c, char **v){ return a(v[1]) + b(c); }\n")
    out = tmp_path / "r"
    if subprocess.run([gcc, "-O0", "-no-pie", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    try:
        t = ingest(store, case.id, out, filename="r")
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(120)
        run = q.enqueue(case.id, DETECT_STAGE, target_id=t.id, force=True,
                        params={"max_taint_functions": 1})
        assert pool.wait_idle(120) and q.runs.get(run.id).status == "done"
    finally:
        pool.stop(grace=3.0)
    events = [(r["type"], json.loads(r["payload_json"] or "{}"))
              for r in store.conn.execute("SELECT type, payload_json FROM event").fetchall()]
    ranked = [p for ty, p in events if ty == "detect.taint_ranked"]
    assert ranked and ranked[0]["cap"] == 1 and ranked[0].get("analyzed") is not None
    hits = [f for f in FindingDAO(store.conn).list_by_target(t.id) if f.detector == "array_index"]
    assert hits and any(e.get("array_index", {}).get("array", {}).get("elements") == 10
                        for f in hits for e in f.evidence)
