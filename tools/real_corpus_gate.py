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

# The classifier lives in the ENGINE (`analyze.capabilities`), not here. It used to live only
# here, which meant the gate drew a distinction -- "this capability refused because of OUR
# defect" vs "because of the target" -- that the operator running `lykos analyze` never saw. One
# definition, read by both.
from lykos.analyze.capabilities import classify_decline as _classify_decline  # noqa: E402

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
    #: Entry points fuzzed IN-PROCESS, and how many the plan held. A library is not one function:
    #: this is the reach the run actually had, where `execs` is only its volume.
    doors: int = 0
    doors_planned: int = 0
    #: Facts worth printing that are not defects: a synthesized entry point the linker rejected.
    notes: list = field(default_factory=list)


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
        try:
            t = ingest(store, case.id, staged, filename=staged.name)
        except Exception as e:                           # noqa: BLE001 -- any ingest failure
            # A target that cannot be ingested is a RESULT, not a reason to stop measuring. The
            # zlib tarball raised NotAnalysable out of here ("source project did not build"),
            # the exception left `main`, and the gate died with expat and bzip2 unmeasured --
            # so one target's failure cost the rest of the corpus. The whole point of a gate is
            # the table at the end.
            row.ok = False
            row.problems = [f"{type(e).__name__}: {str(e).splitlines()[0][:160]}"]
            return row
        enqueue_triage(JobQueue(store.conn), t, force=True)
        pool.wait_idle(180)
        status, stop = {}, threading.Event()
        th = threading.Thread(target=run_case_autopilot,
                              args=(wd / "case", case.id, [t.id], status, stop, budget),
                              daemon=True)
        th.start()
        # `budget` is PER TARGET, and a source project registers one target per executable it
        # built -- libtiff builds six under the current ceiling. A fixed `budget * 2 + 300` wall
        # clock therefore cut the run off a third of the way through and set `stop`, so the later
        # targets were never analysed and the row reported a truncated pass as a whole one. The
        # deadline scales with the targets the case actually has, counted as they appear (the
        # extras are registered during ingest, the firmware/packed ones mid-run).
        while th.is_alive():
            n = max(1, len(TargetDAO(store.conn).list_by_case(case.id)))
            if time.time() - t0 >= budget * n * 1.3 + 300:
                break
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

        # REACH, not just volume. In-process fuzzing goes through one harness at a time, so a
        # library fuzzed through one of its six doors and one fuzzed through all six report the
        # same execution count. A door the plan held, built, and then could not run is a defect
        # worth failing on; a door that did not BUILD is ours to fix and says so.
        ip = card.get("in_process") or {}
        row.doors = int(ip.get("entry_points") or 0)
        row.doors_planned = int(ip.get("planned") or 0)
        # A SYNTHESIZED door may simply not be one: `z_error` is declared in zlib's internal
        # header and not exported, so the harness for it does not link -- the linker answering
        # "that is not a door" is the check working, and it costs 0.2 s because the library's
        # objects are already compiled. That is reported, not failed. The FIRST door is
        # different: it is the harness the pipeline would have built when it built only one, so
        # its failure is the whole engine failing on this target.
        doors = list(ip.get("doors") or [])
        for i, d in enumerate(doors):
            if d.get("built") or "no budget" in (d.get("why") or ""):
                continue
            msg = f"entry point {d.get('entry')} did not build: {(d.get('why') or '')[:70]}"
            (row.problems if i == 0 else row.notes).append(msg)
        row.ok = not row.problems
        return row
    finally:
        row.elapsed = int(time.time() - t0)
        pool.stop(grace=5.0)
        store.close()
        # KEEP a failing target's case store. Deleting it meant every failure cost a full re-run
        # to investigate -- and a gate whose failures are expensive to read is a gate that gets
        # ignored. A clean target leaves nothing behind.
        if row.ok:
            # Twice, because once is not enough: a worker thread winding down after `pool.stop`
            # recreates the content store's directory, so the first sweep left an empty
            # `case/artifacts` behind on every clean target. `ignore_errors` hid it.
            shutil.rmtree(wd, ignore_errors=True)
            if wd.exists():
                time.sleep(0.5)
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
    ap.add_argument("--max-entry-points", type=int, default=None,
                    help="how many of a source project's executables one case carries "
                         "(default: the pipeline's own ceiling). Each is a full target with its "
                         "own budget, so this multiplies the wall clock")
    a = ap.parse_args()
    if a.max_entry_points:
        # `from lykos.analyze import ingest` gives the ingest FUNCTION, not the module: the
        # package re-exports it and the name shadows the submodule. Setting MAX_ENTRY_POINTS on
        # that function object is a silent no-op -- measured: the run went on registering six
        # targets per library while the flag said two, and nothing anywhere said otherwise.
        # Import the module by name, and assert the value actually moved, because a measurement
        # tool whose knob quietly does nothing is worse than one without the knob.
        from importlib import import_module
        _ingest = import_module("lykos.analyze.ingest")
        _ingest.MAX_ENTRY_POINTS = max(1, a.max_entry_points)
        assert _ingest.MAX_ENTRY_POINTS == max(1, a.max_entry_points), \
            "--max-entry-points did not take effect"
    targets = [Path(x) for x in a.targets] or default_corpus()
    if not targets:
        print("no targets given and no default corpus on this machine"); return 2
    print(f"{'TARGET':26s} {'RAN':8s} {'EXECS':>8s} {'RATE':>7s} {'SRCH':>6s} {'DOOR':>5s} "
          f"{'WORK':>4s} {'DECL':>4s} {'ERR':>3s} {'CR':>3s} {'L':>2s} {'DEMO':>4s}  VERDICT")
    print("-" * 132)
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
        _doors = (f"{row.doors}/{row.doors_planned}" if row.doors_planned else "-")
        print(f"{row.name[:26]:26s} {row.ran:8s} {row.execs:8,d} {row.rate:7.1f} "
              f"{row.search:6.0f} {_doors:>5s} {row.worked:4d} {row.declined:4d} "
              f"{len(row.errored):3d} {row.crashes:3d} {row.level:2d} {row.demonstrated:4d}"
              f"  {verdict}")
    print("-" * 132)
    bad = [r for r in rows if not r.ok]
    starved = [r for r in rows if r.ok and r.invalid]
    print(f"PLUMBING: {len(rows) - len(bad)}/{len(rows)} targets clean "
          f"({sum(r.elapsed for r in rows)}s total)")
    for r in rows:
        for n in r.notes:
            print(f"  note  {r.name}: {n}")
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
