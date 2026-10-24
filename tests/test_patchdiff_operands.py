"""Patch-diff operand blindness: an IMMEDIATE-only patch (`cmp 64 -> 32`, the classic bounds fix)
must read as a change, while a relink/rebase (every address moved) must still read as unchanged."""
from __future__ import annotations

import subprocess

import pytest
from lykos.analyze import patchdiff, register
from lykos.analyze.disassemble import enqueue_disassemble
from lykos.analyze.dynamic import sandbox
from lykos.analyze.ingest import enqueue_triage, ingest
from lykos.analyze.patch_diff_stage import enqueue_patch_diff
from lykos.db.dao import FindingDAO
from lykos.jobs import JobConfig, JobQueue, WorkerPool


def _fn(name, texts, callees=()):
    return {"name": name, "addr": "0x1000",
            "cfg": {"blocks": [{"instructions": [{"text": t} for t in texts]}], "edges": 1},
            "calls": [{"dst_name": c} for c in callees]}


def test_an_immediate_only_bounds_fix_is_a_change():
    old = [_fn("check", ["push rbp", "cmp eax, 0x40", "jbe 0x401136", "ret"])]
    new = [_fn("check", ["push rbp", "cmp eax, 0x20", "jbe 0x401136", "ret"])]
    d = patchdiff.diff(old, new)
    assert [c["name"] for c in d["changed"]] == ["check"]
    c = d["changed"][0]
    assert c["dropped_consts"] == ["cmp:0x40"] and c["new_consts"] == ["cmp:0x20"]
    assert c["moved"] > 0


@pytest.mark.parametrize("a,b", [
    ("call 0x401020", "call 0x401520"),                       # call target moved
    ("jne 0x1149", "jne 0x1179"),                             # branch target moved
    ("lea rdi, [rip + 0x2edf]", "lea rdi, [rip + 0x2fa3]"),   # rip-relative data
    ("mov edi, 0x402010", "mov edi, 0x403010"),               # non-PIE absolute address
    ("mov eax, dword [rbp - 0x14]", "mov eax, dword [rbp - 0x1c]"),   # frame slot moved
    ("sw ra, 0x1c(sp)", "sw ra, 0x24(sp)"),                   # MIPS displacement
    ("bne a0, v0, 0x400a10", "bne a0, v0, 0x400b30"),         # MIPS branch
    ("bl 0x8124", "bl 0x8168"),                               # small firmware branch target
    ("mov edi, str.hello", "mov edi, str.hello_1"),           # symbolic operand
])
def test_layout_noise_is_not_a_change(a, b):
    assert patchdiff.diff([_fn("f", ["push rbp", a, "ret"])],
                          [_fn("f", ["push rbp", b, "ret"])])["changed"] == []


def test_an_address_pair_low_half_is_not_a_constant():
    """aarch64 adrp+add / mips lui+addiu: the second instruction's immediate is an address's low
    bits and moves with layout."""
    for pair_a, pair_b in ((["adrp x0, 0x411000", "add x0, x0, 0x8c8"],
                            ["adrp x0, 0x412000", "add x0, x0, 0x1f0"]),
                           (["lui v0, 0x41", "addiu v0, v0, 0x1234"],
                            ["lui v0, 0x42", "addiu v0, v0, 0x5678"])):
        assert patchdiff.diff([_fn("f", pair_a + ["ret"])],
                              [_fn("f", pair_b + ["ret"])])["changed"] == []


def test_is_patched_distinguishes_an_immediate_only_fix():
    vuln = _fn("check", ["cmp eax, 0x40", "ret"])
    fixed = _fn("check", ["cmp eax, 0x20", "ret"])
    assert patchdiff.is_patched([fixed], vuln, fixed) == "patched"
    assert patchdiff.is_patched([vuln], vuln, fixed) == "vulnerable"


# ---- end to end through the real disassembler -------------------------------------------------

_SRC = r"""
#include <stdio.h>
#include <string.h>
%(extra)s
int check(const char *s){ return strlen(s) > %(bound)d; }
void banner(void){ puts("lykos banner text"); }
int main(int c, char **v){ banner(); return c > 1 ? check(v[1]) : 0; }
"""


@pytest.fixture
def pool(store):
    register()
    p = WorkerPool(store.db_path, store.content, JobConfig(workers=2, poll_interval=0.02))
    p.start()
    try:
        yield p
    finally:
        p.stop(grace=3.0)


def _build(gcc, tmp_path, name, bound, extra=""):
    c = tmp_path / f"{name}.c"
    c.write_text(_SRC % {"bound": bound, "extra": extra})
    out = tmp_path / name
    if subprocess.run([gcc, "-no-pie", "-fno-stack-protector", "-O0", "-w", str(c), "-o", str(out)],
                      capture_output=True).returncode != 0:
        pytest.skip("cannot build the fixture")
    return out


def test_stage_files_the_immediate_only_fix_and_not_the_relinked_neighbours(
        store, case, pool, gcc, tmp_path):
    if sandbox.host_arch() != "x86-64":
        pytest.skip("disassembly backend is host-arch bound here")
    old = _build(gcc, tmp_path, "old", 64)
    # the patched build ALSO grows an unrelated function placed first, so every other function and
    # string moves address: banner()/main() must still read unchanged.
    new = _build(gcc, tmp_path, "new", 32,
                 extra="int pad(int x){ int a[8]; for(int i=0;i<8;i++) a[i]=x*i; return a[3]+a[5]; }")
    a = ingest(store, case.id, old, filename="old")
    b = ingest(store, case.id, new, filename="new")
    q = JobQueue(store.conn)
    for t in (a, b):
        enqueue_triage(q, t, force=True); assert pool.wait_idle(60)
        enqueue_disassemble(q, t, force=True); assert pool.wait_idle(180)
    enqueue_patch_diff(q, b, params={"baseline_target_id": a.id}, force=True)
    assert pool.wait_idle(120)
    leads = [f for f in FindingDAO(store.conn).list_by_target(b.id) if f.detector == "patch_diff"]
    titles = " ".join(f.title or "" for f in leads)
    assert "'check'" in titles, f"the immediate-only fix was not localized: {titles!r}"
    assert "'banner'" not in titles and "'main'" not in titles, titles
    chk = next(f for f in leads if "'check'" in (f.title or ""))
    assert any("immediates" in (e.get("detail") or "") for e in chk.evidence)
