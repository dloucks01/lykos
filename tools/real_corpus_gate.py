#!/usr/bin/env python3
"""Plumbing health on REAL binaries, which is the thing that decides whether this tool survives
first contact with a target nobody prepared for us.

Why this exists, stated plainly: every new target in the last two sessions exposed a new defect,
and not one of them was an analysis failure. They were integration failures -- a libtool wrapper
script analysed instead of the ELF, a project typedef in a synthesized declaration, one `.cxx`
file forcing a C project through clang++, a generated config header missing, `examples/` code
linked against symbols that do not exist, a sanitizer fault that exits with a code rather than a
signal. Each was found by pointing the tool at one more binary, by hand, one at a time.

`pipeline_conformance.py` cannot catch this class: every fixture it builds is a 2-8 KB file it
compiled itself with a planted bug, so the plumbing it exercises is the plumbing it created.
`breadth_probe.py` reports WORK on arbitrary binaries but has no pass mark and does not look at
whether a capability refused for a reason that is our fault.

This gate asserts the invariants that have ACTUALLY broken:

  1. the target ran at all (or there is an honest recorded reason);
  2. no stage ERRORED -- an error is never an acceptable outcome, a decline is;
  3. no capability declined for a reason that is OUR plumbing rather than the target's nature
     ("libFuzzer build failed: 'tiffio.h' not found" is a bug; "no source for this target" is
     not);
  4. a target that runs executes the program more than zero times;
  5. a recorded crash produces a VERIFIED PoC -- or the run says why not.

It is not a bug-finding benchmark. A target with no findings passes. A target with a found crash
and an unverified PoC fails, because that is the shape of every "it worked on my machine" defect
this project has had.

Usage:
    python3 tools/real_corpus_gate.py --budget 300 /usr/bin/xxd ~/Downloads/libs/tiff-4.0.3.tar.gz
    python3 tools/real_corpus_gate.py --budget 300          # the default corpus, if present
"""
from __future__ import annotations

import argparse
import shutil
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
import sys

if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

#: A decline whose reason is OURS. These are substrings of the note a stage emits when it refuses;
#: each one here has been a real defect, so the list is evidence rather than imagination.
_OUR_FAULT = (
    "build failed", "did not compile", "file not found", "no such file",
    "undefined reference", "could not build", "failed to build", "not installed",
    "no clang", "loader refused", "did not link", "no harness",
)
#: Checked BEFORE `_OUR_FAULT`: a capability boundary stated honestly is not a plumbing defect,
#: however much its wording resembles one. `mem_oracle` saying "memcheck is a host-architecture
#: dynamic translator and cannot run a non-host-architecture target" is the tool knowing its own
#: limits -- the first version of this gate called it OUR fault on the strength of "cannot run",
#: which would have trained us to ignore the gate.
_BOUNDARY = (
    "host-architecture", "host architecture", "cannot run a non-host",
    "incompatible with afl", "shadow memory", "only supports", "x86-64 only",
    "x86-64 native only", "needs native", "no gdbstub", "not supported for this",
    "cross-arch", "the clr owns", "owns the instruction pointer",
)
#: A decline that describes the TARGET, not us. Allowed, and the gate must not punish it or every
#: honest refusal becomes a failure and the gate gets ignored.
_NOT_APPLICABLE = (
    "no source for this target", "no archived source tree", "no ipc channel",
    "nothing here reads the environment", "no distinct custom allocator",
    "no matched cve", "no heap", "not applicable", "the clr", "managed",
    "no primitive", "needs params", "no crash", "not fuzzed under afl",
)


#: The stages that constitute the search. Their combined wall time is what a "0 crashes" row is
#: actually worth: libtiff at a 200s budget reported 6 capabilities working and no crashes -- a row
#: that reads exactly like a clean library -- and the same target at 900s produced a heap overflow
#: and a verified PoC. The build had eaten the budget. The number that distinguishes those two runs
#: was never printed, so the gate could not tell a clean target from a starved one.
_ENGINES = ("fuzz", "coverage_fuzz", "directed_fuzz", "libfuzzer", "net_fuzz", "env_fuzz",
            "concolic")
#: Below this many seconds of combined engine time, a source project has not been searched. The
#: floor is measurement, not taste: the libtiff crash arrived 6 executions into the SGILog seed,
#: but the in-process harness needed ~200s of that run to configure, build and link before the
#: first execution happened at all.
_SEARCH_FLOOR = 150.0


@dataclass
class Row:
    name: str
    ok: bool = True
    ran: str = "?"
    execs: int = 0
    rate: float = 0.0
    worked: int = 0
    declined: int = 0
    errored: list = field(default_factory=list)
    never: int = 0
    crashes: int = 0
    level: int = 0
    demonstrated: int = 0
    detected: int = 0
    problems: list = field(default_factory=list)
    elapsed: int = 0
    #: Seconds the search engines actually held. A clean row is only evidence next to this.
    search: float = 0.0
    #: Set when the budget was too small for this target's shape to be scored at all. Distinct
    #: from `ok`: the tool did not fail, the MEASUREMENT did, and the two must not print alike.
    invalid: str = ""


def _classify_decline(note: str) -> str:
    low = (note or "").lower()
    for s in _BOUNDARY:
        if s in low:
            return "target"
    for s in _NOT_APPLICABLE:
        if s in low:
            return "target"
    for s in _OUR_FAULT:
        if s in low:
            return "ours"
    return "unknown"


def _stage_target(src: Path, work: Path) -> Path | None:
    """A tarball becomes an unpacked source tree; anything else is used as-is."""
    if src.is_dir() or src.suffix not in (".gz", ".tgz", ".bz2", ".xz"):
        return src
    try:
        with tarfile.open(src) as tf:
            tf.extractall(work)
    except Exception:                                    # noqa: BLE001
        return None
    tops = [d for d in work.iterdir() if d.is_dir()]
    return tops[0] if len(tops) == 1 else work


def _is_source_project(src: Path) -> bool:
    """A tarball or a directory has to be CONFIGURED, BUILT and LINKED before a single execution
    happens. That work comes out of the same budget as the search, which is why a source target
    needs a floor and a prebuilt binary does not."""
    return src.is_dir() or src.suffix in (".gz", ".tgz", ".bz2", ".xz")


def unscoreable(src: Path, search: float, budget: float, crashes: int) -> str:
    """Why this run cannot be scored, or "" if it can.

    Pure so it can be tested without a 900s campaign.
    """
    if crashes or not _is_source_project(src) or search >= _SEARCH_FLOOR:
        return ""
    return (f"search starved: the engines held {search:.0f}s of a {budget:.0f}s budget, under the "
            f"{_SEARCH_FLOOR:.0f}s floor a source project needs after it is built. A clean row "
            f"here is not evidence -- re-run with a larger --budget.")


def run_one(src: Path, budget: float) -> Row:
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.orchestrate import run_case_autopilot
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, FindingDAO, PocDAO, TargetDAO
    from lykos.db.models import STATIC_DETECTORS
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    row = Row(name=src.name)
    wd = Path(tempfile.mkdtemp(prefix="rcgate-"))
    t0 = time.time()
    register()
    store = CaseStore.open(wd / "case")
    case = store.cases.create(src.name)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=3, poll_interval=0.02))
    pool.start()
    try:
        staged = _stage_target(src, wd / "src")
        if staged is None:
            row.ok, row.problems = False, ["could not unpack"]
            return row
        t = ingest(store, case.id, staged, filename=staged.name)
        enqueue_triage(JobQueue(store.conn), t, force=True)
        pool.wait_idle(180)
        status, stop = {}, threading.Event()
        th = threading.Thread(target=run_case_autopilot,
                              args=(wd / "case", case.id, [t.id], status, stop, budget),
                              daemon=True)
        th.start()
        while th.is_alive() and time.time() - t0 < budget * 2 + 300:
            time.sleep(5)
        if th.is_alive():
            stop.set(); th.join(timeout=120)

        card = (status or {}).get("scorecard") or {}
        cap = card.get("capability") or {}
        base = card.get("baseline") or {}
        ex = card.get("executions") or {}
        row.ran = "yes" if base.get("ran") else ("FAULTED" if base.get("crashed") else "NO")
        row.execs = int(ex.get("total") or 0)
        row.rate = float(ex.get("per_second") or 0.0)
        row.worked = len(cap.get("worked") or [])
        row.declined = len(cap.get("declined") or [])
        row.errored = list(cap.get("errored") or [])
        row.never = len(cap.get("never_scheduled") or [])

        tids = [x.id for x in TargetDAO(store.conn).list_by_case(case.id)]
        row.crashes = sum(1 for tid in tids
                          for d in DynResultDAO(store.conn).list_by_target(tid) if d.crashed)
        pocs = [pc for tid in tids for pc in PocDAO(store.conn).list_by_target(tid)]
        row.level = max((int(pc.level[1]) for pc in pocs
                         if getattr(pc, "verified", False) and (pc.level or "").startswith("L")),
                        default=0)
        fs = FindingDAO(store.conn).list_by_case(case.id)
        row.demonstrated = sum(1 for f in fs if f.state in ("poc-backed", "confirmed")
                               and f.detector not in STATIC_DETECTORS)
        row.detected = len(fs) - row.demonstrated

        # --- the invariants
        if row.ran == "NO" and not (base.get("note") or ""):
            row.problems.append("did not run, and no reason recorded")
        if row.errored:
            row.problems.append("stage errored: " + ",".join(row.errored[:4]))
        for stage, why in (card.get("declined") or {}).items():
            kind = _classify_decline(why)
            if kind == "ours":
                row.problems.append(f"{stage} declined for OUR reason: {why[:70]}")
            elif kind == "unknown":
                row.problems.append(f"{stage} declined, unclassified: {why[:60]}")
        if row.ran == "yes" and row.execs == 0:
            row.problems.append("ran once but the campaigns executed it zero times")
        if row.crashes and row.level == 0:
            row.problems.append(f"{row.crashes} crash(es) recorded but NO verified PoC")
        row.ok = not row.problems

        # Was this run SCOREABLE? Separate question from whether it passed, and asked last so a
        # starved run still reports every plumbing defect it did manage to expose.
        by_stage = ((card.get("budget") or {}).get("by_stage") or {})
        row.search = round(sum(float(v) for k, v in by_stage.items() if k in _ENGINES), 1)
        row.invalid = unscoreable(src, row.search, budget, row.crashes)
        return row
    finally:
        row.elapsed = int(time.time() - t0)
        pool.stop(grace=5.0)
        store.close()
        # KEEP a failing target's case store. Deleting it meant every failure cost a full re-run
        # to investigate -- and a gate whose failures are expensive to read is a gate that gets
        # ignored. A clean target leaves nothing behind.
        if row.ok:
            shutil.rmtree(wd, ignore_errors=True)
        else:
            row.problems.append(f"case kept for diagnosis: {wd}")


def default_corpus() -> list:
    """Real material that is present on this machine, newest-shaped first. Nothing synthetic."""
    out = []
    for p in ("/usr/bin/xxd", "/usr/bin/readelf", "/usr/bin/jpegtran"):
        if Path(p).exists():
            out.append(Path(p))
    libs = Path.home() / "Downloads/libs"
    out += sorted(libs.glob("*.tar.gz")) if libs.is_dir() else []
    htb = Path.home() / "Downloads/htb_pwn_challenges"
    if htb.is_dir():
        out += [p for p in sorted(htb.rglob("*")) if p.is_file() and p.stat().st_mode & 0o111
                and p.suffix == ""][:3]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("targets", nargs="*", help="binaries, source dirs or source tarballs")
    ap.add_argument("--budget", type=float, default=300.0, help="seconds per target")
    a = ap.parse_args()
    targets = [Path(x) for x in a.targets] or default_corpus()
    if not targets:
        print("no targets given and no default corpus on this machine"); return 2
    print(f"{'TARGET':26s} {'RAN':8s} {'EXECS':>8s} {'RATE':>7s} {'SRCH':>6s} "
          f"{'WORK':>4s} {'DECL':>4s} {'ERR':>3s} {'CR':>3s} {'L':>2s} {'DEMO':>4s}  VERDICT")
    print("-" * 126)
    rows = []
    for src in targets:
        row = run_one(src, a.budget)
        rows.append(row)
        if not row.ok:
            verdict = "FAIL: " + "; ".join(row.problems[:2])
        elif row.invalid:
            verdict = "INVALID: budget too small to score"
        else:
            verdict = "PASS"
        print(f"{row.name[:26]:26s} {row.ran:8s} {row.execs:8,d} {row.rate:7.1f} "
              f"{row.search:6.0f} {row.worked:4d} {row.declined:4d} {len(row.errored):3d} "
              f"{row.crashes:3d} {row.level:2d} {row.demonstrated:4d}  {verdict}")
    print("-" * 126)
    bad = [r for r in rows if not r.ok]
    starved = [r for r in rows if r.ok and r.invalid]
    print(f"PLUMBING: {len(rows) - len(bad)}/{len(rows)} targets clean "
          f"({sum(r.elapsed for r in rows)}s total)")
    for r in bad:
        print(f"  {r.name}:")
        for pr in r.problems:
            print(f"     - {pr}")
    # An unscoreable run is not a pass. Exiting 0 on a starved corpus is the false clean this
    # whole gate exists to prevent, so it is reported as loudly as a defect and fails the run.
    for r in starved:
        print(f"  {r.name}: NOT SCORED")
        print(f"     - {r.invalid}")
    return 1 if (bad or starved) else 0


if __name__ == "__main__":
    raise SystemExit(main())
