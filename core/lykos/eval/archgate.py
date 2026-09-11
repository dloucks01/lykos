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
    ArchCase("x86-64", "gcc", "L2"),
    ArchCase("x86", "gcc", "L2", flags=("-m32",),
             note="cross-arch on an x86-64 host: takes the qemu path, layout from the stub"),
    ArchCase("aarch64", "aarch64-linux-gnu-gcc", "L2"),
    ArchCase("arm", "arm-linux-gnueabihf-gcc", "L2"),
    ArchCase("ppc", "powerpc-linux-gnu-gcc", "L2"),
    ArchCase("ppc64", "powerpc64-linux-gnu-gcc", "L1",
             note="big-endian ppc64 does not confirm IP control on this program"),
    ArchCase("ppc64le", "powerpc64le-linux-gnu-gcc", "L2",
             note="regression canary for endianness reaching the sandbox"),
    ArchCase("riscv", "riscv64-linux-gnu-gcc", "L2"),
    ArchCase("s390", "s390x-linux-gnu-gcc", "L1",
             note="Ghidra ships no SystemZ processor; the dynamic ladder still works"),
    ArchCase("loongarch", "loongarch64-linux-gnu-gcc", "L2", note="layout derived from the stub"),
    ArchCase("m68k", "m68k-linux-gnu-gcc", "L2", note="layout derived from the stub"),
    ArchCase("sh", "sh4-linux-gnu-gcc", "L1", note="qemu-sh4 serves no target description"),
    ArchCase("sparcv9", "sparc64-linux-gnu-gcc", "L1",
             note="register windows keep the return address in %i7, not on the stack: a "
                  "bounded overflow never corrupts control flow, so only a copy that runs off "
                  "the end of the stack faults (write fault, not IP control)"),
]

_RANK = {"": 0, "L0": 1, "L1": 2, "L2": 3, "L3": 4}


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
            if _RANK[case.expect] >= _RANK["L2"] and res["reached"] == "L1":
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
                           for e in store.events.list(run_id=r.id, limit=40)
                           if e.type == "primitive.done"]
                    res["l2_note"] = (str(evs[-1].payload)[:160] if evs
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
    for s in report.get("skipped", []):
        rows.append(f"{s['label']:11} {'SKIP':>6} {'':>7} {'':>7} {'':>8}  {s['reason']}")
    return "\n".join(rows)
