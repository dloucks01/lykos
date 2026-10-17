"""Architecture coverage gate: prove each supported ISA still reaches its PoC level.

`eval-gate` measures detection quality on x86-64 only, so every architecture-specific
regression found in the September 2026 sweep -- a missing qemu mapping, endianness dropped on
the way to the sandbox, the isolation tier silently downgrading, a payload that cannot travel
via argv, an absent gdbstub register layout -- would have tripped nothing.

This gate closes that. For each architecture it compiles a deliberately vulnerable program
with the cross toolchain, detonates it through the REAL sandbox, and drives the real PoC
stages, asserting the level it is expected to reach:

    L1  a verified crash reproducer      (needs qemu-user for the ISA)
    L2  instruction-pointer control      (additionally needs a gdbstub register layout,
                                          hard-coded or derived from the stub)
    L3  a confirmed control-flow hijack  (ret2win: redirect to a chosen function and prove
                                          arrival with a breakpoint)

Deliberately does NOT run Ghidra: decompilation is the slow part, and nearly every
architecture regression lives in the dynamic path. That keeps this cheap enough to gate on.

An architecture whose cross-compiler is absent SKIPs rather than fails -- the same rule the
static gate uses for Ghidra -- so the gate is honest on a machine that cannot build for it.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from lykos.db.dao import EventDAO

# The source buffer is deliberately oversized (64 KiB): SPARC keeps the return address in %i7,
# a register window, so a stack-buffer overflow does NOT corrupt control flow there and a copy
# that stays mapped never faults at all. Only a copy long enough to run off the end of the
# stack produces a fault on SPARC -- which is why the ladder below tries a large payload too.
#
# The overflow is delivered over stdin with read()+memcpy rather than fgets()+strcpy on
# purpose: read() is not length-capped and memcpy is NUL-transparent, so one program works for
# every ISA. fgets caps at its buffer size, which cannot reach SPARC's saved %i7 (~2KB away,
# because the SysV SPARC frame puts the register save area BELOW the locals), and strcpy stops
# at the first NUL, which an L2 confirmation payload always contains once it embeds an address.
_SRC = r"""
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
/* never called: the L3 ret2win target. __attribute__((used)) keeps it past the linker. */
__attribute__((used)) void win(void){ write(1, "LYKOS-L3-WIN\n", 13); _exit(7); }
static void sink(const char *s, long n){ char b[64]; memcpy(b, s, n); write(1, b, 1); }
int main(void){ static char in[1<<16]; long n = read(0, in, sizeof in);
                if(n > 0) sink(in, n); return 0; }
"""

_CFLAGS = ["-O0", "-fno-stack-protector", "-static", "-w"]


@dataclass(frozen=True)
class ArchCase:
    label: str
    cc: str                      # compiler (or prefix-gcc) that builds this ISA
    expect: str                  # highest PoC level this architecture should reach
    flags: tuple = ()
    note: str = ""


# Expected level per architecture. Lower it only with a recorded reason -- a drop here is the
# regression this gate exists to catch.
MATRIX = [
    ArchCase("x86-64", "gcc", "L3"),
    ArchCase("x86", "gcc", "L3", flags=("-m32",),
             note="cross-arch on an x86-64 host: takes the qemu path, layout from the stub"),
    ArchCase("aarch64", "aarch64-linux-gnu-gcc", "L3"),
    ArchCase("arm", "arm-linux-gnueabihf-gcc", "L3",
             note="Thumb: the win symbol is odd, the breakpoint goes at the even address"),
    ArchCase("ppc", "powerpc-linux-gnu-gcc", "L3"),
    ArchCase("ppc64", "powerpc64-linux-gnu-gcc", "L3"),
    ArchCase("ppc64le", "powerpc64le-linux-gnu-gcc", "L3",
             note="regression canary for endianness reaching the sandbox"),
    ArchCase("riscv", "riscv64-linux-gnu-gcc", "L3"),
    ArchCase("s390", "s390x-linux-gnu-gcc", "L3",
             note="Ghidra ships no SystemZ processor, yet the whole dynamic ladder works: "
                  "r14 is its link register and the PC reads big-endian"),
    ArchCase("loongarch", "loongarch64-linux-gnu-gcc", "L3", note="layout derived from the stub"),
    ArchCase("m68k", "m68k-linux-gnu-gcc", "L3", note="layout derived from the stub"),
    ArchCase("sh", "sh4-linux-gnu-gcc", "L3",
             note="qemu-sh4 serves no target description, so its layout is the one that stays "
                  "hand-written (verified against a live g-packet)"),
    # Two ISAs whose qemu-user emulators ship on a stock host and whose cross compilers are a
    # package away, so the ONLY reason they were uncovered is that nobody had asked. `_QEMU`
    # has carried both since the xtensa/microblaze round; what no case asserted is that the
    # ladder -- fault capture, the gdbstub layout, IP control, the redirect -- reaches them.
    # Added 2026-10-16 at L1 (no gdbstub layout for either), and re-measured the same day once
    # both had one. They went opposite ways, and the gate now records what each MEASURED.
    ArchCase("alpha", "alpha-linux-gnu-gcc", "L3",
             note="layout DERIVED from qemu-alpha's own target description (66 registers, named "
                  "symbolically); its fetch unit clears the low 2 bits of a branch target, so "
                  "the captured pc is `ra & ~3` and the control offset has to come from `ra` -- "
                  "the pc's window matches the cyclic sequence 4 bytes early, exactly"),
    ArchCase("hppa", "hppa-linux-gnu-gcc", "L1",
             note="layout HAND-WRITTEN (qemu-hppa serves no target description at all) and "
                  "verified against a live g-packet. The ladder stops at L1 for an architectural "
                  "reason, measured: the cyclic reaches r21 and r28 but never the program "
                  "counter, because PA-RISC keeps the return address in the frame marker and "
                  "the stack grows UP -- a bounded forward overflow of a local does not touch "
                  "it. Same shape as sparcv9's register windows, one ISA over"),
    ArchCase("sparcv9", "sparc64-linux-gnu-gcc", "L1",
             note="register windows keep the return address in %i7, not on the stack: a "
                  "bounded overflow never corrupts control flow, so only a copy that runs off "
                  "the end of the stack faults (write fault, not IP control)"),
]

_RANK = {"": 0, "L0": 1, "L1": 2, "L2": 3, "L3": 4}


def _all_events(store, run_id) -> list:
    """Every event of a run, paged to the end.

    `store.events.list` is `ORDER BY id ASC LIMIT ?`, so a fixed `limit=` reads only a run's
    OLDEST events -- and the `.done` event these notes want is the second-to-last of ~131. The
    gate's verdict comes from PocDAO and was never wrong, but `l2_note`/`l3_note` -- the reason
    an operator reads to find out why an architecture stalled -- were always None.
    """
    return list(EventDAO(store.conn).walk(run_id=run_id))


def compile_case(case: ArchCase, outdir: Path) -> Optional[Path]:
    if not shutil.which(case.cc):
        return None
    src = outdir / f"{case.label}.c"
    src.write_text(_SRC)
    out = outdir / f"vuln_{case.label}"
    r = subprocess.run([case.cc, *case.flags, *_CFLAGS, str(src), "-o", str(out)],
                       capture_output=True)
    return out if r.returncode == 0 and out.exists() else None


def run_case(case: ArchCase, exe: Path, *, timeout: float = 30.0,
             progress=None) -> dict:
    """Drive one architecture through the real stages. Returns a result dict."""
    from ..analyze import register as register_stages
    from ..analyze.ingest import enqueue_triage, ingest
    from ..analyze.poc.exploit_stage import enqueue_exploit
    from ..analyze.poc.primitive_stage import enqueue_primitive
    from ..analyze.poc.stage import enqueue_build_poc
    from ..casestore import CaseStore
    from ..db.dao import PocDAO
    from ..jobs import JobConfig, JobQueue, WorkerPool

    register_stages()
    res: dict = {"label": case.label, "expect": case.expect, "reached": "", "note": case.note}
    d = Path(tempfile.mkdtemp(prefix=f"lykos-archgate-{case.label}-"))
    store = CaseStore.open(d / "case")
    try:
        cid = store.cases.create(case.label).id
        target = ingest(store, cid, exe, filename=exe.name)

        crash = b"A" * 600                       # reaches the saved return address on most ISAs
        big = b"A" * 65536                       # runs the copy off the end of the stack
        pool = WorkerPool(store.db_path, store.content, JobConfig(workers=2))
        pool.start()
        try:
            q = JobQueue(store.conn)
            enqueue_triage(q, target)          # arch/bits/endianness route qemu downstream
            pool.wait_idle(timeout * 4)
            target = store.targets.get(target.id)
            res["arch"], res["bits"] = target.arch, target.bits
            res["endianness"] = target.endianness
            for payload in (crash, big):
                sha = store.put_artifact(cid, "archgate-seed", data=payload).sha256
                enqueue_build_poc(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                     "timeout": timeout}, force=True)
                pool.wait_idle(timeout * 20)
                if any(p.verified and p.level == "L1"
                       for p in PocDAO(store.conn).list_by_target(target.id)):
                    res["crash_len"] = len(payload)
                    break
            pocs = PocDAO(store.conn).list_by_target(target.id)
            if any(p.verified and p.level == "L1" for p in pocs):
                res["reached"] = "L1"
            # ALWAYS escalate, whatever this case EXPECTS. Gating the attempt on the
            # expectation makes the gate blind in the one direction that matters: alpha and hppa
            # were recorded at L1 the day they were added, and when both later got a
            # qemu-gdbstub layout -- the exact thing their notes said was missing -- the gate
            # kept reporting L1 because `expect` was L1 and the L2 attempt was never made. An
            # expectation is a BAR to clear, not a budget; the same trap capped
            # `addr_leak_pie_ret2win` at L2 on the conformance side.
            if res["reached"] == "L1":
                sha = store.put_artifact(cid, "archgate-seed",
                                         data=b"A" * res.get("crash_len", 600)).sha256
                enqueue_primitive(q, target, params={"input_sha": sha, "input_mode": "stdin",
                                                     "timeout": timeout}, force=True)
                pool.wait_idle(timeout * 60)
                pocs = PocDAO(store.conn).list_by_target(target.id)
                if any(p.verified and p.level == "L2" for p in pocs):
                    res["reached"] = "L2"
                else:
                    runs = [r for r in store.runs.list_by_case(cid)
                            if r.stage == "poc_primitive"]
                    evs = [e for r in runs
                           for e in _all_events(store, r.id)
                           if e.type == "primitive.done"]
                    res["l2_note"] = (str(evs[-1].payload)[:160] if evs
                                      else (runs[-1].error if runs else None))
            if res["reached"] == "L2":
                # L3 reads the offset L2 just confirmed (see exploit_stage._l2_offset), so it
                # must run after it -- which is the documented ladder order anyway.
                enqueue_exploit(q, target, params={"input_mode": "stdin",
                                                   "timeout": timeout}, force=True)
                pool.wait_idle(timeout * 80)
                pocs = PocDAO(store.conn).list_by_target(target.id)
                if any(p.verified and p.level == "L3" for p in pocs):
                    res["reached"] = "L3"
                else:
                    runs = [r for r in store.runs.list_by_case(cid)
                            if r.stage == "build_exploit"]
                    evs = [e for r in runs
                           for e in _all_events(store, r.id)
                           if e.type == "exploit.done"]
                    res["l3_note"] = (str(evs[-1].payload)[:160] if evs
                                      else (runs[-1].error if runs else None))
        finally:
            pool.stop()
    finally:
        store.close()
        shutil.rmtree(d, ignore_errors=True)
    res["ok"] = _RANK[res["reached"]] >= _RANK[case.expect]
    return res


def run(cases=None, *, timeout: float = 30.0, progress=None) -> dict:
    """Build and drive every architecture. Returns {"results": [...], "skipped": [...]}"""
    cases = list(cases if cases is not None else MATRIX)
    out, skipped = [], []
    workdir = Path(tempfile.mkdtemp(prefix="lykos-archgate-"))
    try:
        for i, case in enumerate(cases, 1):
            if progress:
                progress(f"[{i}/{len(cases)}] {case.label}")
            exe = compile_case(case, workdir)
            if exe is None:
                skipped.append({"label": case.label, "reason": f"no {case.cc}"})
                continue
            out.append(run_case(case, exe, timeout=timeout, progress=progress))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return {"results": out, "skipped": skipped}


def gate(report: dict):
    """(passed, verdict, reason) over an arch-matrix report."""
    res = report.get("results") or []
    if not res:
        return True, "SKIP", "no cross toolchain available for any architecture"
    bad = [r for r in res if not r["ok"]]
    if bad:
        detail = ", ".join(f"{r['label']} reached {r['reached'] or 'nothing'} "
                           f"(expected {r['expect']})" for r in bad)
        return False, "FAIL", f"{len(bad)}/{len(res)} regressed: {detail}"
    lv = {}
    for r in res:
        lv[r["reached"]] = lv.get(r["reached"], 0) + 1
    return True, "PASS", f"{len(res)} architectures at expected level ({lv})"


def table(report: dict) -> str:
    rows = [f"{'arch':11} {'built':>6} {'crash@':>7} {'expect':>7} {'reached':>8}  note"]
    rows.append("-" * 78)
    for r in report.get("results", []):
        mark = "" if r["ok"] else "   <-- REGRESSED"
        rows.append(f"{r['label']:11} {str(r.get('bits') or '?'):>6} "
                    f"{str(r.get('crash_len') or '-'):>7} {r['expect']:>7} "
                    f"{(r['reached'] or '-'):>8}  {r.get('note','')}{mark}")
        # WHY it stopped where it did, on the line under it. The reason was recorded in the
        # JSON and printed nowhere, so the table said "L1" next to a static note that could
        # be months out of date -- which is how alpha and hppa went on claiming "no
        # qemu-gdbstub layout yet" after both had one.
        for key, label in (("l2_note", "L2"), ("l3_note", "L3")):
            if r.get(key) and _RANK.get(r.get("reached") or "", 0) < _RANK[label]:
                rows.append(f"{'':11} {'':>6} {'':>7} {'':>7} {'':>8}  {label} stopped: "
                            f"{str(r[key])[:150]}")
    for s in report.get("skipped", []):
        rows.append(f"{s['label']:11} {'SKIP':>6} {'':>7} {'':>7} {'':>8}  {s['reason']}")
    return "\n".join(rows)
