"""P-Code allocation-size integer overflow (CWE-190 -> CWE-122/787): `pcode_guards.alloc_overflow_sites`.

The detector reports an allocator call whose size is an INT_MULT / INT_ADD / INT_LEFT that can wrap
GIVEN THE OPERANDS' TRUE SOURCE WIDTHS, with attacker-tainted operands and no guard -- one record per
allocation site. Precision is the contract, so every true positive here has a twin true negative that
differs only in the property the detector must read:

  u32 * 16 in 32 bits (wraps)            vs  (size_t)u32 * 16 (zero-extended BEFORE: cannot wrap)
  u32 + u32 in 32 bits (wraps)           vs  the same sum checked `t < a` (the wrap check)
  u32 * u32 (wraps)                      vs  u16 * u16 in 32 bits (cannot wrap)
  u32 * 16 (wraps)                       vs  `n > 1000` / `n >> 28` / `n & 0xffff` / a clamp first
  u32 * u32 (wraps)                      vs  `x > UINT32_MAX / y`, __builtin_mul_overflow
  int * 16 in 32 bits from atoi(argv)    vs  int * sizeof(...) (sign-extended to 64 first)

Two layers: synthetic P-Code (pins the width rule, no toolchain), and real compiled fixtures lifted
through the project's own path (ingest -> disassemble -> FunctionDAO.ir) at -O0 and -O2, on x86-64
and -- when a cross compiler is installed -- aarch64.
"""
import shutil
import subprocess
from collections import namedtuple

import pytest
from lykos.analyze.detect import pcode_guards as pg

# =============================================================================== synthetic IR
_Edge = namedtuple("_Edge", "src_addr site_addr dst_addr dst_name external")


def _x86_read_then_alloc(load_size: int, combine: list, *, guard_k=None) -> tuple:
    """x86-64 low P-Code for:   read(0, &buf, 8);  [if (a > guard_k) return;]  malloc(<combine>)

    `combine` is the P-Code that computes the size into RDI from EAX (= buf[0]) and EDX (= buf[1]),
    each loaded with `load_size` bytes and zero-extended to 32 bits."""
    def ld(reg32, disp):
        ins = [f"INT_ADD reg:RSP:8 const:{hex(disp)}:8 -> unique:0x100:8",
               f"LOAD const:0x1:8 unique:0x100:8 -> unique:0x200:{load_size}"]
        if load_size < 4:
            ins.append(f"INT_ZEXT unique:0x200:{load_size} -> reg:{reg32}:4")
        else:
            ins.append(f"COPY unique:0x200:4 -> reg:{reg32}:4")
        return ins
    call = ["INT_SUB reg:RSP:8 const:0x8:8 -> reg:RSP:8",
            "STORE const:0x1:8 reg:RSP:8 const:0x0:8"]
    b0 = [
        {"addr": "0x1000", "pcode": ["INT_SUB reg:RSP:8 const:0x20:8 -> reg:RSP:8"]},
        {"addr": "0x1004", "pcode": ["INT_ADD reg:RSP:8 const:0x8:8 -> unique:0x100:8",
                                     "COPY unique:0x100:8 -> reg:RSI:8",
                                     "COPY const:0x0:8 -> reg:RDI:8",
                                     "COPY const:0x8:8 -> reg:RDX:8"]},
        {"addr": "0x1010", "pcode": call + ["CALL ram:0x2000:8"]},
        {"addr": "0x1015", "pcode": ld("EAX", 8)},
        {"addr": "0x1019", "pcode": ld("EDX", 0xC)},
    ]
    blocks = []
    alloc_block = {"addr": "0x1030", "succ": [], "instructions": [
        {"addr": "0x1030", "pcode": combine + ["COPY reg:RAX:8 -> reg:RDI:8"]},
        {"addr": "0x1040", "pcode": call + ["CALL ram:0x3000:8"]},
        {"addr": "0x1045", "pcode": ["RETURN reg:RIP:8"]}]}
    if guard_k is None:
        b0.append({"addr": "0x101d", "pcode": ["BRANCH ram:0x1030:8"]})
        blocks.append({"addr": "0x1000", "succ": ["0x1030"], "instructions": b0})
    else:
        # cmp eax, K ; ja exit       (unsigned: exit when a > K)
        b0.append({"addr": "0x101d", "pcode": [
            f"INT_LESS reg:EAX:4 const:{hex(guard_k)}:4 -> reg:CF:1",
            f"INT_SUB reg:EAX:4 const:{hex(guard_k)}:4 -> unique:0x300:4",
            "INT_EQUAL unique:0x300:4 const:0x0:4 -> reg:ZF:1"]})
        b0.append({"addr": "0x1022", "pcode": [
            "BOOL_NEGATE reg:CF:1 -> unique:0x400:1",
            "BOOL_NEGATE reg:ZF:1 -> unique:0x401:1",
            "BOOL_AND unique:0x400:1 unique:0x401:1 -> unique:0x402:1",
            "CBRANCH ram:0x1050:8 unique:0x402:1"]})
        blocks.append({"addr": "0x1000", "succ": ["0x1050", "0x1030"], "instructions": b0})
        blocks.append({"addr": "0x1050", "succ": [], "instructions": [
            {"addr": "0x1050", "pcode": ["COPY const:0x0:8 -> reg:RAX:8", "RETURN reg:RIP:8"]}]})
    blocks.append(alloc_block)
    edges = [_Edge("0x1000", "0x1010", "0x2000", "read", True),
             _Edge("0x1000", "0x1040", "0x3000", "malloc", True)]
    return {"0x1000": {"blocks": blocks}}, edges


_MUL32 = ["INT_MULT reg:EAX:4 reg:EDX:4 -> reg:EAX:4", "INT_ZEXT reg:EAX:4 -> reg:RAX:8"]
_ADD32 = ["INT_ADD reg:EAX:4 reg:EDX:4 -> reg:EAX:4", "INT_ZEXT reg:EAX:4 -> reg:RAX:8"]
_SHL32 = ["INT_LEFT reg:EAX:4 const:0x4:4 -> reg:EAX:4", "INT_ZEXT reg:EAX:4 -> reg:RAX:8"]
_ZEXT_THEN_SHL64 = ["INT_ZEXT reg:EAX:4 -> reg:RAX:8", "INT_LEFT reg:RAX:8 const:0x4:8 -> reg:RAX:8"]
_SHL32_ZEXT_AFTER = _SHL32


def _sites(irs, edges, **kw):
    return pg.alloc_overflow_sites(irs, edges, "x86-64", bits=64, names={"0x1000": "f"}, **kw)


def test_u32_times_u32_in_32_bits_is_reported():
    irs, edges = _x86_read_then_alloc(4, _MUL32)
    (r,) = _sites(irs, edges)
    assert r["site_addr"] == "0x1040" and r["allocator"] == "malloc" and r["cwe"] == "CWE-190"
    assert r["op"] == "INT_MULT" and r["width_bits"] == 32 and r["guard_status"] == "unguarded"
    assert all(o["tainted"] and o["range"] == [0, 0xFFFFFFFF] for o in r["operands"])
    assert r["max_value"] == 0xFFFFFFFF * 0xFFFFFFFF


def test_u16_times_u16_in_32_bits_cannot_wrap():
    irs, edges = _x86_read_then_alloc(2, _MUL32)
    st = {}
    assert _sites(irs, edges, stats_out=st) == []
    assert st["alloc_sites"] == 1 and st["suppressed"] == {"no-tainted-wrap": 1}


def test_u8_plus_u8_cannot_wrap_but_u32_plus_u32_can():
    assert _sites(*_x86_read_then_alloc(1, _ADD32)) == []
    (r,) = _sites(*_x86_read_then_alloc(4, _ADD32))
    assert r["op"] == "INT_ADD" and r["max_value"] == 2 * 0xFFFFFFFF


def test_zero_extension_before_vs_after_the_shift():
    # (size_t)n << 4: zero-extended BEFORE the arithmetic -> 36 bits in a 64-bit register, no wrap
    assert _sites(*_x86_read_then_alloc(4, _ZEXT_THEN_SHL64)) == []
    # (n << 4) in 32 bits, zero-extended AFTER -> the product wrapped before it was widened
    (r,) = _sites(*_x86_read_then_alloc(4, _SHL32_ZEXT_AFTER))
    assert r["op"] == "INT_LEFT" and r["width_bits"] == 32


def test_dominating_constant_bound_is_applied_exactly():
    # n <= 0x0fffffff: n << 4 fits in 32 bits -> suppressed;  n <= 0x10000000: one too many -> reported
    assert _sites(*_x86_read_then_alloc(4, _SHL32, guard_k=0x0FFFFFFF)) == []
    (r,) = _sites(*_x86_read_then_alloc(4, _SHL32, guard_k=0x10000000))
    assert r["operands"][0]["range"] == [0, 0x10000000]


def test_untainted_operands_are_not_reported():
    irs, edges = _x86_read_then_alloc(4, _MUL32)
    edges = [e if e.dst_name != "read" else e._replace(dst_name="memset") for e in edges]
    assert _sites(irs, edges) == []


def test_unknown_arch_is_an_honest_empty_result():
    irs, edges = _x86_read_then_alloc(4, _MUL32)
    st = {}
    assert pg.alloc_overflow_sites(irs, edges, "z80", stats_out=st) == []
    assert "no calling convention" in st["note"]


# ========================================================================= compiled fixtures
_SRC = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define NI __attribute__((noinline))
struct rec { uint32_t a, b, c, d; };
struct hdr { uint32_t w, h; };

/* ---- true positives ---- */
NI struct rec *tp_count32(int fd) {          /* u32 * sizeof(struct) computed in 32 bits */
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    uint32_t sz = n * (uint32_t)sizeof(struct rec);
    struct rec *r = malloc(sz);
    if (!r) return 0;
    for (uint32_t i = 0; i < n; i++) if (read(fd, &r[i], sizeof r[i]) <= 0) break;
    return r;
}
NI char *tp_add(int fd) {                    /* a + b, both tainted u32 */
    uint32_t h[2];
    if (read(fd, h, 8) != 8) return 0;
    char *p = malloc(h[0] + h[1]);
    if (p && read(fd, p, h[0]) < 0) { free(p); return 0; }
    return p;
}
NI void *tp_u64(int fd) {                    /* u64 * 24 in 64 bits */
    uint64_t n;
    if (read(fd, &n, 8) != 8) return 0;
    return malloc(n * 24);
}
NI void *alloc_items(uint32_t n) {           /* wraps on a caller's tainted count */
    return malloc(n * 12u);
}
NI void *tp_interproc(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    return alloc_items(n);
}
NI void *tp_fread_struct(FILE *f) {          /* w * h * 4 from an fread header */
    struct hdr hd;
    if (fread(&hd, sizeof hd, 1, f) != 1) return 0;
    return malloc(hd.w * hd.h * 4u);
}
NI void *tp_atoi(const char *s) {            /* int * 16 in 32 bits, from argv */
    int n = atoi(s);
    return malloc(n * 16);
}
NI void *tp_sscanf(const char *line) {       /* two scanf outputs multiplied */
    unsigned w, h;
    if (sscanf(line, "%u %u", &w, &h) != 2) return 0;
    return malloc(w * h);
}
NI int hdr_ok(const struct hdr *h) { return h->w != 0 && h->h != 0; }
NI void *tp_validated(int fd) {              /* a read-only validator does not launder taint */
    struct hdr hd;
    if (read(fd, &hd, sizeof hd) != sizeof hd || !hdr_ok(&hd)) return 0;
    return malloc(hd.w * hd.h * 4u);
}

/* ---- true negatives ---- */
NI void *tn_u16(int fd) {
    uint16_t h[2];
    if (read(fd, h, 4) != 4) return 0;
    return malloc(h[0] * h[1]);
}
NI void *tn_zext64(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    return malloc(n * sizeof(struct rec));
}
NI void *tn_const_bound(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    if (n > 1000) return 0;
    return malloc(n * 16u);
}
NI void *tn_div(int fd) {
    uint32_t v[2];
    if (read(fd, v, 8) != 8) return 0;
    if (v[1] == 0 || v[0] > UINT32_MAX / v[1]) return 0;
    return malloc(v[0] * v[1]);
}
NI void *tn_builtin(int fd) {
    uint32_t n, t;
    if (read(fd, &n, 4) != 4) return 0;
    if (__builtin_mul_overflow(n, 16u, &t)) return 0;
    return malloc(t);
}
NI void *tn_builtin64(int fd) {
    uint64_t v[2], t;
    if (read(fd, v, 16) != 16) return 0;
    if (__builtin_mul_overflow(v[0], v[1], &t)) return 0;
    return malloc(t);
}
NI void *tn_result_check(int fd) {
    uint32_t h[2];
    if (read(fd, h, 8) != 8) return 0;
    uint32_t t = h[0] + h[1];
    if (t < h[0]) return 0;
    return malloc(t);
}
NI void *tn_clamp(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    if (n > 4096) n = 4096;
    return malloc(n * 16u);
}
NI void *tn_mask(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    return malloc((n & 0xffff) * 16u);
}
NI void *tn_shift_check(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    if (n >> 28) return 0;
    return malloc(n << 4);
}
NI void *tn_calloc(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return 0;
    return calloc(n, 16);
}
NI void *tn_strlen(const char *s) { return malloc(strlen(s) + 1); }
NI void *tn_int_sizeof(const char *s) {
    int n = atoi(s);
    return malloc(n * sizeof(struct rec));
}
NI void *tn_untainted(int k) { return malloc(k * 64); }
NI void *tn_const(void) { return malloc(4096); }

int main(int argc, char **argv) {
    FILE *f = fopen(argc > 1 ? argv[1] : "/dev/null", "rb");
    int fd = f ? fileno(f) : 0;
    void *keep[32]; int i = 0;
    keep[i++] = tp_count32(fd); keep[i++] = tp_add(fd); keep[i++] = tp_u64(fd);
    keep[i++] = tp_interproc(fd); keep[i++] = tp_fread_struct(f);
    keep[i++] = tp_atoi(argc > 2 ? argv[2] : "1");
    keep[i++] = tp_sscanf(argc > 4 ? argv[4] : "1 1"); keep[i++] = tp_validated(fd);
    keep[i++] = tn_u16(fd); keep[i++] = tn_zext64(fd); keep[i++] = tn_const_bound(fd);
    keep[i++] = tn_div(fd); keep[i++] = tn_builtin(fd); keep[i++] = tn_builtin64(fd);
    keep[i++] = tn_result_check(fd); keep[i++] = tn_clamp(fd); keep[i++] = tn_mask(fd);
    keep[i++] = tn_shift_check(fd); keep[i++] = tn_calloc(fd);
    keep[i++] = tn_strlen(argc > 2 ? argv[2] : "x");
    keep[i++] = tn_int_sizeof(argc > 3 ? argv[3] : "1");
    keep[i++] = tn_untainted(3); keep[i++] = tn_const();
    for (int j = 0; j < i; j++) free(keep[j]);
    return 0;
}
"""

# function holding the allocation -> the arithmetic width the wrap happens at
_TP = {"tp_count32": 32, "tp_add": 32, "tp_u64": 64, "alloc_items": 32, "tp_fread_struct": 32,
       "tp_atoi": 32, "tp_sscanf": 32, "tp_validated": 32}
_TN = ["tn_u16", "tn_zext64", "tn_const_bound", "tn_div", "tn_builtin", "tn_builtin64",
       "tn_result_check", "tn_clamp", "tn_mask", "tn_shift_check", "tn_calloc", "tn_strlen",
       "tn_int_sizeof", "tn_untainted", "tn_const"]

_BUILDS = [("x86-64", "gcc", "-O0"), ("x86-64", "gcc", "-O2"),
           ("aarch64", "aarch64-linux-gnu-gcc", "-O0"), ("aarch64", "aarch64-linux-gnu-gcc", "-O2")]


@pytest.fixture(scope="module")
def lifted(tmp_path_factory):
    """Compile every available build and lift it through the real pipeline once per module:
    ingest -> triage -> disassemble, then read the stored IR back through the DAOs exactly as a
    stage would."""
    from lykos.analyze import native_re
    if not native_re.locate_native():
        pytest.skip("needs the native RE backend (rizin + pypcode)")
    from lykos.analyze import register
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.casestore import CaseStore
    from lykos.db.dao import CallEdgeDAO, FunctionDAO, TargetDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    d = tmp_path_factory.mktemp("pcode_alloc")
    src = d / "alloc.c"
    src.write_text(_SRC)
    binaries = {}
    for arch, cc, opt in _BUILDS:
        exe = shutil.which(cc)
        if not exe:
            continue
        out = d / f"alloc_{arch}_{opt[1:]}"
        r = subprocess.run([exe, opt, "-fno-inline", str(src), "-o", str(out)],
                           capture_output=True)
        if r.returncode == 0:
            binaries[(arch, opt)] = out
    if not binaries:
        pytest.skip("cannot build the fixtures")

    store = CaseStore.open(d / "case")
    case = store.cases.create("pcode-alloc")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    pool.start()
    out = {}
    try:
        q = JobQueue(store.conn)
        targets = {}
        for key, exe in binaries.items():
            t = ingest(store, case.id, exe, filename=exe.name)
            targets[key] = t
            enqueue_triage(q, t, force=True)
        assert pool.wait_idle(120)
        for t in targets.values():
            enqueue_disassemble(q, t, force=True)
        assert pool.wait_idle(600)
        fdao, edao, tdao = FunctionDAO(store.conn), CallEdgeDAO(store.conn), TargetDAO(store.conn)
        for key, t in targets.items():
            tgt = tdao.get(t.id)
            fns = fdao.list_by_target(t.id)
            irs = {f.addr: fdao.get(f.id).ir for f in fns}
            irs = {a: ir for a, ir in irs.items() if ir}
            if not irs:
                continue
            out[key] = {"irs": irs, "edges": edao.list_by_target(t.id), "arch": tgt.arch,
                        "bits": tgt.bits or 64, "names": {f.addr: f.name for f in fns}}
    finally:
        pool.stop(grace=3.0)
        store.close()
    if not out:
        pytest.skip("the lifter produced no IR for the fixtures")
    return out


def _run(lifted, key):
    if key not in lifted:
        pytest.skip(f"no {key[0]} {key[1]} build (compiler or lifter unavailable)")
    L = lifted[key]
    st = {}
    recs = pg.alloc_overflow_sites(L["irs"], L["edges"], L["arch"], bits=L["bits"],
                                   names=L["names"], include_suppressed=True, stats_out=st)
    by_fn: dict = {}
    for r in recs:
        by_fn.setdefault(r["function"], []).append(r)
    return recs, by_fn, st


_KEYS = [(a, o) for a, _cc, o in _BUILDS]
_IDS = [f"{a}{o}" for a, o in _KEYS]


@pytest.mark.parametrize("key", _KEYS, ids=_IDS)
def test_true_positives_are_reported_one_record_per_site(lifted, key):
    recs, by_fn, _st = _run(lifted, key)
    for fn, width in _TP.items():
        got = [r for r in by_fn.get(fn, []) if not r["guard_status"].startswith("guarded")]
        assert len(got) == 1, (fn, by_fn.get(fn))
        r = got[0]
        assert r["cwe"] == "CWE-190" and r["allocator"] == "malloc", r
        assert r["guard_status"] in ("unguarded", "post-wrap-check"), r
        assert r["width_bits"] == width, (fn, r["width_bits"], r["expr"])
        assert r["max_value"] >= 1 << width, r
        assert any(o["tainted"] for o in r["operands"]), r
        assert r["confidence"] >= 0.6, r
    # the inter-procedural one: the tainted count arrives as a parameter from tp_interproc's read()
    org = [o["origin"] for o in by_fn["alloc_items"][0]["operands"] if o["tainted"]]
    assert org and all("read" in o for o in org), org
    sites = [r["site_addr"] for r in recs]
    assert len(sites) == len(set(sites)), "one record per allocation site, never a roll-up"


@pytest.mark.parametrize("key", _KEYS, ids=_IDS)
def test_true_negatives_are_not_reported(lifted, key):
    recs, by_fn, st = _run(lifted, key)
    for fn in _TN:
        reported = [r for r in by_fn.get(fn, []) if not r["guard_status"].startswith("guarded")]
        assert not reported, (fn, reported)
    assert st["reported"] == len(_TP), st


@pytest.mark.parametrize("key", _KEYS, ids=_IDS)
def test_guards_are_recognised_for_the_right_reason(lifted, key):
    _recs, by_fn, st = _run(lifted, key)

    def status(fn):
        rs = by_fn.get(fn, [])
        return rs[0]["guard_status"] if rs else None
    # -O0 keeps the source's division; -O2 strength-reduces `x > MAX / y` into a widening
    # multiply whose high half is tested -- either way the wrap is checked, and it is recognised
    assert status("tn_div") in ("guarded-division", "guarded-overflow-flag")
    assert status("tn_builtin64") == "guarded-overflow-flag"
    assert status("tn_result_check") in ("guarded-result-check", "guarded-overflow-flag")
    # exact constant bounds are applied as value ranges: nothing left to suppress
    for fn in ("tn_const_bound", "tn_clamp", "tn_mask", "tn_shift_check", "tn_builtin"):
        assert status(fn) is None, (fn, by_fn.get(fn))
    assert st["alloc_sites"] >= len(_TP) + len(_TN)


def test_write_with_the_unwrapped_length_raises_confidence(lifted):
    _recs, by_fn, _st = _run(lifted, ("x86-64", "-O0"))
    (r,) = by_fn["tp_add"]
    # read(fd, p, h[0]) into malloc(h[0] + h[1]): the copy length is the un-wrapped operand
    assert r["written_after"] and r["written_after"]["sink"] == "read", r
    assert r["consequence"] == "CWE-787" and r["confidence"] > 0.8
    (c,) = by_fn["tp_count32"]
    # the row loop is bounded by the un-wrapped count n, not by the wrapped size
    assert c["written_after"] and "loop" in c["written_after"]["detail"], c


def test_detect_stage_files_one_pcode_alloc_overflow_per_site(store, case, tmp_path, gcc):
    """Wired: the detect stage files the precise detector's records as per-SITE candidates and
    drops the untainted int_overflow_alloc roll-up (Tier-0 i01_mul_wrap: rows*rowsize wraps)."""
    import subprocess
    from pathlib import Path
    from lykos.analyze import register
    from lykos.analyze.disassemble import enqueue_disassemble
    from lykos.analyze.detect.stage import enqueue_detect
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.db.dao import FindingDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool
    src = Path(__file__).resolve().parents[1] / "bench" / "tier0" / "i01_mul_wrap" / "prog.c"
    exe = tmp_path / "i01"
    if subprocess.run([gcc, "-O0", "-w", "-no-pie", str(src), "-o", str(exe)],
                      capture_output=True).returncode:
        pytest.skip("cannot build i01")
    register()
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2, lease_seconds=300,
                                                              poll_interval=0.05))
    pool.start()
    try:
        t = ingest(store, case.id, exe)
        q = JobQueue(store.conn)
        enqueue_triage(q, t, force=True); assert pool.wait_idle(120)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(300)
        enqueue_detect(q, t, force=True); assert pool.wait_idle(300)
    finally:
        pool.stop(grace=3.0)
    fs = FindingDAO(store.conn).list_by_target(t.id)
    pg = [f for f in fs if f.detector == "pcode_alloc_overflow"]
    assert pg and all(":pcode_alloc_overflow:" in f.dedup_key for f in pg)
    assert any("load_table" in f.title for f in pg), [f.title for f in pg]
    assert not [f for f in fs if f.detector == "int_overflow_alloc"]
