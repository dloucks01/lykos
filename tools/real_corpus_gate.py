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

Because a target with no findings passes, this gate cannot see a REGRESSION in what we find:
a harness planner that offers one door instead of six errors nowhere, declines nothing, and
reports a clean library. That is `corpus_regression.py`, which scores the same campaigns against
ground truth per library. The two share one runner (`corpus_run.py`) and nothing else.

Usage:
    python3 tools/real_corpus_gate.py --budget 300 /usr/bin/xxd ~/Downloads/libs/tiff-4.0.3.tar.gz
    python3 tools/real_corpus_gate.py --budget 300          # the default corpus, if present
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
TOOLS = Path(__file__).resolve().parent

if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

# The CAMPAIGN -- ingest, autopilot, evidence -- is shared with `corpus_regression.py`, which
# asks a different question about the same run. Two scorers, one runner: see corpus_run.py for
# why the project does not keep two copies of a thing like this.
from corpus_run import ENGINES as _ENGINES  # noqa: E402

# `unscoreable` is re-exported rather than defined here: the gate is where the search floor was
# first needed, and the gate's own tests call it on this module.
from corpus_run import (  # noqa: E402,F401
    Evidence,
    run_campaign,
    set_max_entry_points,
    unscoreable,
)
from lykos import observe  # noqa: E402

# The classifier lives in the ENGINE (`analyze.capabilities`), not here. It used to live only
# here, which meant the gate drew a distinction -- "this capability refused because of OUR
# defect" vs "because of the target" -- that the operator running `lykos analyze` never saw. One
# definition, read by both.
from lykos.analyze.capabilities import classify_decline as _classify_decline  # noqa: E402


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
    #: Errors the run absorbed on purpose, and at how many distinct sites. This gate already
    #: separates "declined for the target's reason" from "declined for OURS"; absorption is the
    #: third case it could not see -- a step that neither ran nor declined, it just failed and
    #: was allowed to. A real binary absorbs some (a parser that does not apply to this format),
    #: so this is REPORTED, not failed. What makes it worth printing is the delta: the same
    #: target absorbing twice as much as last round is our plumbing degrading, and nothing else
    #: in this table would move.
    absorbed: int = 0
    absorbed_sites: int = 0
    absorbed_top: list = field(default_factory=list)


def score_run(ev: Evidence, src: Path, budget: float) -> Row:
    """Turn one campaign's evidence into a gate row. PURE -- no campaign, no I/O.

    Split out of `run_one` so the invariants can be tested without a 900 s run against a real
    library. Every check below was added because the thing it checks actually went wrong.
    """
    row = Row(name=ev.name, elapsed=ev.elapsed)
    if ev.error:
        row.ok, row.problems = False, [ev.error]
        return row
    card = ev.scorecard
    cap = card.get("capability") or {}
    base = card.get("baseline") or {}
    row.ran = ev.ran
    row.execs = ev.execs
    row.rate = ev.rate
    row.worked = len(cap.get("worked") or [])
    row.declined = len(cap.get("declined") or [])
    row.errored = list(cap.get("errored") or [])
    row.never = len(cap.get("never_scheduled") or [])
    row.crashes = ev.n_crashes
    row.level = ev.verified_level
    row.demonstrated = sum(1 for d in ev.defects if d.demonstrated)
    row.detected = len(ev.defects) - row.demonstrated

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

    # Was this run SCOREABLE? Separate question from whether it passed, and asked last so a
    # starved run still reports every plumbing defect it did manage to expose.
    row.search = ev.search_seconds(_ENGINES)
    row.invalid = unscoreable(src, row.search, budget, row.crashes)

    # REACH, not just volume. In-process fuzzing goes through one harness at a time, so a
    # library fuzzed through one of its six doors and one fuzzed through all six report the
    # same execution count. A door the plan held, built, and then could not run is a defect
    # worth failing on; a door that did not BUILD is ours to fix and says so.
    row.doors = ev.doors_built
    row.doors_planned = ev.doors_planned
    # A SYNTHESIZED door may simply not be one: `z_error` is declared in zlib's internal
    # header and not exported, so the harness for it does not link -- the linker answering
    # "that is not a door" is the check working, and it costs 0.2 s because the library's
    # objects are already compiled. That is reported, not failed. The FIRST door is
    # different: it is the harness the pipeline would have built when it built only one, so
    # its failure is the whole engine failing on this target.
    for i, d in enumerate(ev.doors):
        if d.get("built") or "no budget" in (d.get("why") or ""):
            continue
        msg = f"entry point {d.get('entry')} did not build: {(d.get('why') or '')[:70]}"
        (row.problems if i == 0 else row.notes).append(msg)
    _ab = card.get("absorbed") or {}
    row.absorbed = int(_ab.get("total") or 0)
    row.absorbed_sites = int(_ab.get("sites") or 0)
    row.absorbed_top = list(_ab.get("top") or [])
    row.ok = not row.problems
    return row


def run_one(src: Path, budget: float, keep: bool = False) -> Row:
    ev = run_campaign(src, budget)
    row = score_run(ev, src, budget)
    # KEEP a failing target's case store. Deleting it meant every failure cost a full re-run to
    # investigate -- and a gate whose failures are expensive to read is a gate that gets
    # ignored. A clean target leaves nothing behind.
    #
    # `keep` overrides that for a target that PASSED, which is what you want when the gate is
    # being used as evidence rather than as a tripwire: a passing run still holds the absorbed
    # counts, the scorecard and the L2/L3 handoff record, and re-running a real library to look
    # at them costs ten minutes.
    if row.ok and not keep:
        ev.discard()
    elif row.ok:
        row.notes.append(f"case kept: {ev.workdir}")
    else:
        row.problems.append(f"case kept for diagnosis: {ev.workdir}")
    return row


def default_corpus() -> list:
    """Real material that is present on this machine, newest-shaped first. Nothing synthetic."""
    out = []
    for p in ("/usr/bin/xxd", "/usr/bin/readelf", "/usr/bin/jpegtran"):
        if Path(p).exists():
            out.append(Path(p))
    libs = Path.home() / "Downloads/libs"
    out += sorted(libs.glob("*.tar.gz")) if libs.is_dir() else []
    # FOREIGN ARCHITECTURES, as real binaries rather than fixtures we compiled. Every cross-arch
    # case this project had was a 2-8 KB file built by `archgate`/`pipeline_conformance` from
    # one planted-bug source, for the ISAs a cross compiler happens to package -- which excludes
    # MIPS entirely on a Kali host. These are upstream busybox builds: static, stripped, ~1 MB,
    # real code for 16 arch/endianness/word-size combinations. The first one ever run (MIPS BE)
    # failed the gate on two defects, neither about MIPS: `coverage_fuzz` ERRORED where it should
    # have declined, and four honest cross-arch declines were unclassified because each site
    # worded its own sentence. Both are fixed; this is what keeps them fixed.
    ma = Path.home() / "Downloads/multiarch/corpus"
    out += [p for p in sorted(ma.glob("busybox-*")) if p.is_file()] if ma.is_dir() else []
    htb = Path.home() / "Downloads/htb_pwn_challenges"
    if htb.is_dir():
        out += [p for p in sorted(htb.rglob("*")) if p.is_file() and p.stat().st_mode & 0o111
                and p.suffix == ""][:3]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("targets", nargs="*", help="binaries, source dirs or source tarballs")
    ap.add_argument("--budget", type=float, default=300.0, help="seconds per target")
    ap.add_argument("--keep", action="store_true",
                    help="keep the case store even for a target that PASSED (a failing one is "
                         "always kept). For using a run as evidence -- the absorbed counts, the "
                         "scorecard and the L2->L3 record all live in it")
    ap.add_argument("--max-entry-points", type=int, default=None,
                    help="how many of a source project's executables one case carries "
                         "(default: the pipeline's own ceiling). Each is a full target with its "
                         "own budget, so this multiplies the wall clock")
    a = ap.parse_args()
    # These harnesses are diagnostic instruments, so their diagnostics have to be readable. With
    # nothing configured, a `_log.warning` from inside the engine reaches stderr through
    # `logging.lastResort` -- no timestamp, no module, no line -- which is how a gate run prints
    # "run <uuid> is past its deadline" with no indication of which stage said it. `LYKOS_LOG`
    # still selects the level, so the default stays quiet.
    observe.configure()

    if a.max_entry_points:
        set_max_entry_points(a.max_entry_points)
    targets = [Path(x) for x in a.targets] or default_corpus()
    if not targets:
        print("no targets given and no default corpus on this machine"); return 2
    print(f"{'TARGET':26s} {'RAN':8s} {'EXECS':>8s} {'RATE':>7s} {'SRCH':>6s} {'DOOR':>5s} "
          f"{'WORK':>4s} {'DECL':>4s} {'ERR':>3s} {'ABS':>5s} {'CR':>3s} {'L':>2s} "
          f"{'DEMO':>4s}  VERDICT")
    print("-" * 140)
    rows = []
    for src in targets:
        row = run_one(src, a.budget, keep=a.keep)
        rows.append(row)
        if not row.ok:
            verdict = "FAIL: " + "; ".join(row.problems[:2])
        elif row.invalid:
            verdict = "INVALID: budget too small to score"
        else:
            verdict = "PASS"
        _doors = (f"{row.doors}/{row.doors_planned}" if row.doors_planned else "-")
        _abs = (f"{row.absorbed}/{row.absorbed_sites}" if row.absorbed else "-")
        print(f"{row.name[:26]:26s} {row.ran:8s} {row.execs:8,d} {row.rate:7.1f} "
              f"{row.search:6.0f} {_doors:>5s} {row.worked:4d} {row.declined:4d} "
              f"{len(row.errored):3d} {_abs:>5s} {row.crashes:3d} {row.level:2d} "
              f"{row.demonstrated:4d}  {verdict}")
    print("-" * 140)
    # The absorbed sites, named. A count alone says "something degraded"; the site says which
    # handler, and `--log debug` then prints its traceback.
    _noisy = [r for r in rows if r.absorbed_top]
    if _noisy:
        print("absorbed (steps that failed quietly and were allowed to):")
        for r in _noisy:
            for e in r.absorbed_top[:4]:
                print(f"  {r.name[:24]:24s} {e.get('count'):>4}x {e.get('site')}")
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
