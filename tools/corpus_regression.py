#!/usr/bin/env python3
"""Regression benchmark over the REAL library corpus: did we still find the bugs we found before,
and did we still DEMONSTRATE them?

The three instruments that already existed each miss this:

  * the unit suite asserts each link's logic in isolation and cannot see whether the links
    compose on a real target;
  * `pipeline_conformance.py` asks "can it find THIS planted bug" -- but every fixture is a 2-8 KB
    file the gate compiled itself, so the plumbing it exercises is the plumbing it created;
  * `real_corpus_gate.py` asks whether the PLUMBING held on real material, and says so plainly:
    "a target with no findings passes". That is the right contract for a plumbing gate and the
    wrong one here. A harness regression that turns libtiff's six doors into one, or the expat
    build back into a link against Debian's copy of the library, leaves every plumbing invariant
    satisfied and the findings gone.
  * `recall_benchmark.py` is this tool's shape, on the planted `examples/vuln-targets/` corpus:
    binaries with a known CVE, scored for recall AND precision. What it does not have is a real
    library, built from source with sanitizers, searched in-process.

So this is the recall benchmark for the real corpus. Ground truth is what the 2026-10-14 round
MEASURED, not what the libraries are believed to contain, and every entry says how it was
reached. Three verdicts matter and they are deliberately distinct:

    DEMONSTRATED    the defect was found AND a verified PoC reproduces it     <- the only PASS
    IDENTIFIED      the defect was found and nothing proved it                <- counts as a MISS
    MISS            the defect was not found at all

"Identified but not demonstrated" has its own word because it is this project's characteristic
failure -- `we identify, we don't demonstrate` is written into the notes of three separate
rounds -- and a benchmark that scored it as a catch would launder exactly the regression it
exists to catch.

Two further verdicts protect the measurement itself:

    FALSE-POSITIVE  a library the baseline runs CLEAN produced a demonstrated defect
    INVALID         the run cannot be scored: the search was starved, or REACH collapsed

INVALID is the one that took a scar to learn. zlib and bzip2 are precision controls: they are
expected to run clean, so a findings-only benchmark would pass them even if the harness builder
broke completely and the campaign fuzzed nothing at all. A clean row is evidence only next to
the doors it opened and the seconds it searched, so both are asserted here. And FALSE-POSITIVE
is not hypothetical either: teaching the planner K&R C while `fn_params` kept its own ANSI-only
copy of the regex produced a harness that called zlib's two-parameter `gzopen` with one
argument, and the campaign reported an ASan SEGV in zlib on execution one. This benchmark is the
instrument that would have caught it.

Usage:
    PYTHONPATH=core python3 tools/corpus_regression.py                      # the whole corpus
    PYTHONPATH=core python3 tools/corpus_regression.py --only expat-2.1.0
    PYTHONPATH=core python3 tools/corpus_regression.py --budget 900 --json out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
TOOLS = Path(__file__).resolve().parent
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from corpus_run import (  # noqa: E402
    ENGINES,
    Evidence,
    run_campaign,
    set_max_entry_points,
    unscoreable,
)
from lykos import observe  # noqa: E402

#: Where the corpus tarballs live. Not in the repo: they are upstream releases, several MB each,
#: and an absent one is reported as SKIP rather than silently passing.
CORPUS = Path.home() / "Downloads" / "libs"

#: The memory-safety classes a precision control must not produce. A `CWE-400` (libFuzzer's
#: `oom-` artifact, filed as uncontrolled allocation) or a `CWE-835` timeout on zlib is a real
#: resource observation about a real library, not a fabricated memory fault, and it is reported
#: without failing the run. Corruption is different: it is the claim that gets a CVE written.
CORRUPTION_CWES = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
    "CWE-134", "CWE-415", "CWE-416", "CWE-457", "CWE-476", "CWE-787", "CWE-788",
})


# --------------------------------------------------------------------------------------------
# GROUND TRUTH
#
# Every `site` here is a source location a sanitizer named in a run that happened; `note` says
# which. A `site` may be a LIST, and a file without a line is a legitimate entry, because the
# exact line is a fact about which input arrived first and not about the library: expat's
# namingBitmap shift reported `xmltok_impl.c:694` on 2026-10-14 and `xmltok.c:147` on 2026-10-15
# -- the same family of bit test, a different expansion, whichever input the fuzzer found first.
# Pinning one line would make this instrument flaky, and a flaky instrument gets ignored.
#
# `through` is the entry point the campaign reached it by, and is ADVISORY: a defect reachable
# through two doors is filed once, under whichever door got there first, so requiring a
# particular door would fail on a legitimate re-ordering. Set `require_through` when the door is
# the point of the test.
#
# `tier` decides what a MISS costs:
#   * `anchor` (the default) -- measured as a verified PoC and expected every run. A miss FAILS.
#   * `reach`  -- measured once, behind a door a second pass opens, so whether it appears is the
#     budget's decision. A miss is printed as a WATCH line and does not fail. Promote an entry to
#     `anchor` when it holds across runs; that is the only honest way to raise the bar.
#
# `min_level` is the verified PoC level the chain must reach. It is 1 everywhere: an L2 on a heap
# out-of-bounds READ needs the distance experiment in `poc_primitive` to find a MOVING distance,
# which it does for these defects but not within every budget. Raise an entry to 2 when it holds
# across runs -- the observed level is in the JSON either way, so a rise is visible before it is
# demanded.
# --------------------------------------------------------------------------------------------
GROUND_TRUTH: dict[str, dict] = {
    "tiff-4.0.3": {
        "archive": "tiff-4.0.3.tar.gz",
        # 6/6 measured at a 600s budget. The floor is 3 rather than 6 because the later doors are
        # taken in a second pass whose slice the budget decides -- but a run that opens ONE door
        # is the single-harness pipeline again, and that is a regression whatever it finds.
        "min_doors": 3,
        "defects": [
            {"id": "tiff-getimage-oob-read", "cwe": "CWE-125", "site": "tif_getimage.c",
             "through": "TIFFReadRGBAImageOriented", "min_level": 1,
             "note": "heap out-of-bounds READ in putRGBcontig8bittile, reached through the "
                     "RGBA image path; the SGILog per-codec seed triggers it unmutated"},
            # The UBSan sites that only exist because the harness stopped being one harness.
            # They are the regression test for `plan_harnesses`: every one is behind a door the
            # single-harness pipeline never opened.
            #
            # Two of them carry NO `cwe`, and that is deliberate: the 2026-10-14 round recorded
            # the SITE and not the check that fired, and inventing a class here would be a claim
            # with no evidence behind it -- the thing this project's rule forbids. An entry with
            # no CWE matches on its site alone, and gains a class the first time a run measures
            # one. Pinning a guess is how `tif_read.c:460` was written down as CWE-758 and then
            # found, on 2026-10-15, to be CWE-476: `bytecount = td->td_stripbytecount[strip]`
            # with a NULL byte-count array, which is a null pointer use and not a bad shift.
            {"id": "tiff-read-460-null", "cwe": "CWE-476", "site": "tif_read.c:460",
             "through": "TIFFReadRawStrip", "min_level": 1, "tier": "reach",
             "note": "UBSan null pointer use reading td_stripbytecount, reachable only through "
                     "TIFFReadRawStrip/TIFFReadEncodedStrip. Site measured 2026-10-14, class "
                     "measured 2026-10-15"},
            {"id": "tiff-read-545", "cwe": "CWE-476", "site": "tif_read.c:545",
             "through": "TIFFReadEncodedStrip", "min_level": 1, "tier": "reach",
             "note": "null-pointer dereference. Site measured 2026-10-14 behind the same pair "
                     "of doors with the check unrecorded; the CLASS measured 2026-10-16, "
                     "confirmed through TIFFOpen -> TIFFReadEncodedStrip -> TIFFClose. Recording "
                     "it closes the hole an empty `cwe` leaves: an entry that names no class "
                     "matches any class, so a detector that regressed from CWE-476 to something "
                     "else here would still have scored a hit"},
            {"id": "tiff-dirread-3766", "cwe": "", "site": "tif_dirread.c:3766",
             "through": "", "min_level": 1, "tier": "reach",
             "note": "site measured 2026-10-14 in directory reading; class not recorded"},
            {"id": "tiff-unix-284-memcpy", "cwe": "CWE-758", "site": "tif_unix.c:284",
             "through": "", "min_level": 1, "tier": "reach",
             "note": "UBSan in _TIFFmemcpy -- a null pointer passed to memcpy. Measured "
                     "2026-10-15, one observation, so it is reach-tier until it holds"},
        ],
    },
    "expat-2.1.0": {
        "archive": "expat-2.1.0.tar.gz",
        "min_doors": 1,
        "defects": [
            {"id": "expat-namingbitmap-shift", "cwe": "CWE-758",
             "site": ["xmltok_impl.c:694", "xmltok.c:147", "xmltok.c:133"],
             "through": "XML_Parse", "min_level": 1,
             "note": "signed left shift of 1 by 31 places in the namingBitmap bit test. "
                     "xmltok_impl.c:694 measured 2026-10-14, xmltok.c:147 measured 2026-10-15, "
                     "xmltok.c:133 measured 2026-10-16 "
                     "(xmltok.c includes xmltok_impl.c, and the three lines are the same macro "
                     "family reached by different inputs). :133 and :147 are BOTH the body of "
                     "UTF8_GET_NAMING2 -- `namingBitmap[...] & (1 << (byte[1] & 0x1F))`, "
                     "xmltok.c:55 -- expanded in utf8_isName2 (namePages) and utf8_isNmstrt2 "
                     "(nmstrtPages); which one UBSan names depends only on whether the input "
                     "reaches a name character or a name-start character first, so a list that "
                     "held only one of them scored the same defect as a MISS. Unreachable until "
                     "the harness could "
                     "be synthesized for a handle-first API (XML_ParserCreate -> XML_Parse -> "
                     "XML_ParserFree) AND the build stopped resolving XML_Parse from -lexpat, "
                     "which had the campaign fuzzing Debian's copy of the library"},
        ],
    },
    "libsndfile-1.0.28": {
        "archive": "libsndfile-1.0.28.tar.gz",
        # 1/6 measured at a 600s budget, and 1 is the floor rather than 2 because the five
        # behind it are opened by a second pass whose slice the budget decides -- the first
        # door alone compiles 188 translation units under ASan+UBSan. The door that matters is
        # the one in the floor: a run that opens NONE of them is the state this library was in
        # before, when the planner chose `psf_allocate()` -> `psf_fopen()` out of the internal
        # `src/common.h` and the harness did not compile at all.
        "min_doors": 1,
        "defects": [
            {"id": "sndfile-common-174-negate", "cwe": "CWE-190", "site": "common.c:174",
             "through": "sndfile", "require_through": True, "min_level": 1,
             "note": "UBSan: negation of -2147483648 cannot be represented in type 'int', in "
                     "psf_log_printf's integer formatter. Measured 2026-10-17 through the "
                     "libsndfile known harness (sf_open_virtual -> sf_readf_short -> sf_close) "
                     "seeded with a valid 44-byte RIFF/WAVE header: 11,545 executions at "
                     "57.7/s, filed confirmed and verified to L1. `require_through` because "
                     "this entry point IS the point of the test -- libsndfile's decoders sit "
                     "behind an open that wants a path, so no synthesized harness reaches them, "
                     "and the virtual-IO door is the only honest way in"},
        ],
    },
    # --- precision controls. Clean is the expected answer for code this heavily fuzzed, which is
    # exactly why they need a REACH floor: without one, a broken harness builder passes here.
    "zlib-1.2.11": {
        "archive": "zlib-1.2.11.tar.gz",
        "clean": True,
        # 4/6 measured; the best door is gzopen -> gzread -> gzclose (cov 407 vs 293 for the
        # known harness). Two were the budget's decision. A run that opens none of them is not a
        # clean library, it is a broken builder -- and zlib is the library that defeated the
        # definition scanner four ways at once (K&R defs, `#define local static`, `voidp`, and
        # `gzopen OF((...))`), so this floor guards the scanner as much as the builder.
        "min_doors": 2,
        "note": "a demonstrated memory-safety defect here is EITHER a new find worth recording "
                "in ground truth OR a fabricated crash -- the `gzopen(path)` one-argument call "
                "reported an ASan SEGV on execution one. Both need a human; neither is a pass.",
    },
    "bzip2-1.0.6": {
        "archive": "bzip2-1.0.6.tar.gz",
        "clean": True,
        # 1/1: the streaming API passes everything inside a `bz_stream` and
        # `BZ2_bzBuffToBuffDecompress` takes its input as parameter 3 with an OUT buffer first,
        # so neither is synthesizable from a signature. The one door is the _KNOWN_HARNESSES
        # entry, gated on the symbols being present.
        "min_doors": 1,
    },
}


@dataclass
class DefectResult:
    id: str
    cwe: str
    site: str
    #: `anchor` (a miss FAILS) or `reach` (a miss is a WATCH line -- see GROUND TRUTH).
    tier: str = "anchor"
    verdict: str = "MISS"
    level: int = 0
    state: str = ""
    through: str = ""                 # the entry point the run actually reached it by
    why: str = ""


@dataclass
class LibResult:
    name: str
    verdict: str = "PASS"
    doors: int = 0
    doors_planned: int = 0
    execs: int = 0
    search: float = 0.0
    crashes: int = 0
    level: int = 0
    elapsed: int = 0
    defects: list = field(default_factory=list)
    #: Demonstrated defects that ground truth does not list. On a positive library that is a
    #: NEW CATCH to record; on a precision control it is the whole point of the control.
    unexpected: list = field(default_factory=list)
    #: Reach-tier defects this run did not demonstrate. Printed, not failed.
    watch: list = field(default_factory=list)
    #: Errors the run absorbed on purpose. This benchmark scores WHAT WAS FOUND against ground
    #: truth, so the interesting correlation is a miss next to a rise here: a library that went
    #: from 6 demonstrated to 3 while absorbing twice as much did not get harder, our plumbing
    #: got worse. Reported, never gated -- a real library legitimately absorbs some.
    absorbed: int = 0
    absorbed_sites: int = 0
    problems: list = field(default_factory=list)
    kept: str = ""


def _sites(spec: dict) -> list:
    """The site(s) a ground-truth entry accepts, as a list. See GROUND TRUTH for why a `site` may
    be several measured locations, or a file with no line."""
    want = spec.get("site") or ""
    return [want] if isinstance(want, str) else list(want)


def match_defect(spec: dict, defects: list) -> object | None:
    """The finding that corresponds to this ground-truth entry, or None.

    Matched on (CWE, source site), because that pair is the only stable identity a defect in a
    real library has. An address moves with every rebuild; a title is the sanitizer's class name,
    shared by every bug of that class; a dedup key is ours and says nothing about the library.
    Static findings are excluded outright -- `cve_fingerprint` files 108 candidate CVEs on
    libtiff 4.0.3 from a version match, none of them reached, and matching those would score a
    version string as a reproduced bug.
    """
    for d in defects:
        if not d.dynamic:
            continue
        if spec.get("cwe") and d.cwe != spec["cwe"]:
            continue
        sites = _sites(spec)
        if any(sites):
            hay = list(d.sites) + [d.title or ""] + list(d.evidence)
            if not any(s and s in (h or "") for s in sites for h in hay):
                continue
        if spec.get("require_through") and spec.get("through"):
            if not any(spec["through"] in (e or "") for e in d.evidence):
                continue
        return d
    return None


def demonstrated_level(ev: Evidence, defect) -> int:
    """The verified PoC level that proves THIS defect, 0 if nothing proved it.

    Three routes, because one defect legitimately wears two finding rows. A libFuzzer artifact is
    filed under its sanitizer SITE; the verified PoC that replays it promotes the CRASH finding,
    keyed on signal and fault pc. Attribution therefore runs through the crashing INPUT, which is
    the same bytes in both rows:

      1. a PoC whose `finding_id` is this finding (the direct link, when it exists);
      2. a PoC whose input is the input of a recorded crash carrying this defect's site -- the
         libFuzzer stage writes `defect_key=libfuzzer:<site>` and names the site in the note;
      3. the finding's own state: `poc-backed` is only ever set BY a verified PoC, so a defect
         carrying it was demonstrated even if the rows cannot be joined.

    Route 3 is last and floors at L1 rather than claiming more: the state says a reproducer
    verified, not how far up the ladder it got.
    """
    best = max((p.level for p in ev.pocs if p.verified and p.finding_id == defect.finding_id),
               default=0)
    sites = [s for s in defect.sites if s]
    if sites:
        keys = {f"libfuzzer:{s}" for s in sites}
        inputs = {c.input_sha for c in ev.crashes if c.input_sha
                  and (c.defect_key in keys or any(s in (c.note or "") for s in sites))}
        best = max([best] + [p.level for p in ev.pocs if p.verified and p.input_sha in inputs])
    if not best and defect.state == "poc-backed":
        best = 1
    return best


def score_library(name: str, spec: dict, ev: Evidence) -> LibResult:
    """Score one campaign against ground truth. PURE -- no campaign, no I/O.

    The order matters: REACH and the search floor are checked FIRST, because they decide whether
    the findings (or their absence) mean anything at all.
    """
    r = LibResult(name=name, elapsed=ev.elapsed)
    if ev.error:
        r.verdict, r.problems = "ERROR", [ev.error]
        return r
    r.doors, r.doors_planned = ev.doors_built, ev.doors_planned
    r.execs, r.crashes, r.level = ev.execs, ev.n_crashes, ev.verified_level
    r.search = ev.search_seconds(ENGINES)
    _ab = (ev.scorecard or {}).get("absorbed") or {}
    r.absorbed, r.absorbed_sites = int(_ab.get("total") or 0), int(_ab.get("sites") or 0)

    # --- is this run scoreable at all? Two ways it is not.
    starved = unscoreable(ev.src, r.search, ev.budget, r.crashes)
    if starved:
        r.verdict, r.problems = "INVALID", [starved]
    floor = int(spec.get("min_doors") or 0)
    if floor and r.doors < floor:
        # REACH collapsed. Said separately from a plumbing failure because the plumbing may be
        # perfectly healthy: a planner that offers one door instead of six errors nowhere,
        # declines nothing, and reports a clean library.
        r.verdict = "INVALID"
        r.problems.append(
            f"REACH: {r.doors} of the {floor} doors this library is known to open were fuzzed "
            f"({r.doors_planned} planned). Neither the findings nor their absence is evidence.")

    # --- the defects ground truth expects
    for d_spec in spec.get("defects") or []:
        dr = DefectResult(id=d_spec["id"], cwe=d_spec.get("cwe", ""),
                          site="|".join(_sites(d_spec)),
                          tier=d_spec.get("tier") or "anchor")
        found = match_defect(d_spec, ev.defects)
        if found is None:
            dr.verdict = "XFAIL" if d_spec.get("known_gap") else "MISS"
            dr.why = "no dynamic finding with this CWE at this site"
        else:
            dr.state = found.state
            dr.through = next((e.split(" through ", 1)[1].split(" (")[0]
                               for e in found.evidence if " through " in e), "")
            dr.level = demonstrated_level(ev, found)
            want = int(d_spec.get("min_level") or 1)
            if dr.level >= want:
                dr.verdict = "DEMONSTRATED"
            elif d_spec.get("known_gap"):
                dr.verdict = "XFAIL"
                dr.why = f"identified, no verified PoC (documented gap), state={found.state}"
            else:
                # The failure this benchmark was built for: the defect is in the report and
                # nothing reproduces it.
                dr.verdict = "IDENTIFIED"
                dr.why = (f"found (state={found.state}) but no verified PoC at L{want}: "
                          f"reached L{dr.level}")
        r.defects.append(dr)

    # --- demonstrated defects ground truth does NOT list
    known = [(g.get("cwe"), _sites(g)) for g in (spec.get("defects") or [])]
    counted = any(d.verdict == "DEMONSTRATED" for d in r.defects)
    for d in ev.defects:
        if not d.demonstrated:
            continue
        hay = list(d.sites) + [d.title or ""]
        if any(cw == d.cwe and any(st and st in (h or "") for st in sts for h in hay)
               for cw, sts in known):
            continue
        if counted and not [s for s in d.sites if s]:
            # One defect legitimately wears two finding rows, and the second has no site: the
            # verified replay files a CRASH finding keyed on signal and fault pc, whose class is
            # the generic signal-derived one (CWE-119/787). On a library where a ground-truth
            # defect was already counted, reporting that row as a NEW defect is noise about the
            # same bug. On a precision control nothing is counted, so the row is still reported
            # -- which is the case that matters, since a fabricated crash arrives exactly here.
            continue
        r.unexpected.append({"cwe": d.cwe, "title": d.title, "state": d.state,
                             "sites": d.sites[:3], "severity": d.severity})

    # --- the verdict
    if r.verdict == "INVALID":
        return r
    if spec.get("clean"):
        # A precision control. Only CORRUPTION counts against it: an oom or a non-terminating
        # input is a real observation about a real library and is reported, not failed.
        fabricated = [u for u in r.unexpected if u["cwe"] in CORRUPTION_CWES]
        if fabricated:
            r.verdict = "FALSE-POSITIVE"
            r.problems.append(
                f"{len(fabricated)} demonstrated memory-safety defect(s) on a library the "
                f"baseline runs clean: " + ", ".join(
                    f"{u['cwe']} {(u['sites'] or ['?'])[0]}" for u in fabricated[:3])
                + ". " + (spec.get("note") or ""))
        return r
    lost = [d for d in r.defects if d.verdict not in ("DEMONSTRATED", "XFAIL")]
    r.watch = [f"{d.id}: {d.verdict} -- {d.why}" for d in lost if d.tier == "reach"]
    anchors = [d for d in lost if d.tier == "anchor"]
    if anchors:
        # IDENTIFIED-ONLY and MISS are kept apart because they call for different work: one is a
        # broken reproducer, the other a search that no longer reaches the code.
        r.verdict = "IDENTIFIED-ONLY" if all(d.verdict == "IDENTIFIED" for d in anchors) \
            else "MISS"
        for d in anchors:
            r.problems.append(f"{d.id}: {d.verdict} -- {d.why}")
    return r


def run_library(name: str, spec: dict, budget: float, *, log=print) -> LibResult:
    tar = CORPUS / spec["archive"]
    if not tar.exists():
        r = LibResult(name=name, verdict="SKIP")
        r.problems.append(f"not present: {tar}")
        return r
    ev = run_campaign(tar, budget, log=log)
    r = score_library(name, spec, ev)
    # Keep the case store for anything that is not a clean pass, for the same reason the gate
    # does: an instrument whose failures cost a full re-run to investigate gets ignored.
    if r.verdict == "PASS":
        ev.discard()
    else:
        r.kept = str(ev.workdir)
    return r


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="lykos real-corpus regression benchmark")
    ap.add_argument("--only", help="comma-separated library names (default: all present)")
    ap.add_argument("--budget", type=float, default=600.0,
                    help="seconds per target (default 600, the budget ground truth was "
                         "measured at)")
    ap.add_argument("--max-entry-points", type=int, default=1,
                    help="how many of a project's executables one case carries. The default is "
                         "1: the in-process doors come from the SOURCE TREE, so the library is "
                         "searched either way, and each extra executable costs a full budget "
                         "slice of wall clock")
    ap.add_argument("--json", help="write the scoreboard here")
    a = ap.parse_args(argv)
    # These harnesses are diagnostic instruments, so their diagnostics have to be readable. With
    # nothing configured, a `_log.warning` from inside the engine reaches stderr through
    # `logging.lastResort` -- no timestamp, no module, no line -- which is how a gate run prints
    # "run <uuid> is past its deadline" with no indication of which stage said it. `LYKOS_LOG`
    # still selects the level, so the default stays quiet.
    observe.configure()

    set_max_entry_points(a.max_entry_points)

    names = a.only.split(",") if a.only else list(GROUND_TRUTH)
    rows = []
    for name in names:
        spec = GROUND_TRUTH.get(name)
        if spec is None:
            print(f"  ?? {name}: no ground truth entry -- skipping")
            continue
        kind = "CLEAN control" if spec.get("clean") else \
            f"{len(spec.get('defects') or [])} known defect(s)"
        print(f"  .. {name}  [{kind}, budget {a.budget:.0f}s]")
        r = run_library(name, spec, a.budget)
        rows.append(r)
        print(f"     {r.verdict:<16} doors={r.doors}/{r.doors_planned} execs={r.execs:,} "
              f"search={r.search:.0f}s crashes={r.crashes} L{r.level} ({r.elapsed}s)")
        for d in r.defects:
            mark = d.verdict if d.verdict == "DEMONSTRATED" or d.tier == "anchor" \
                else f"WATCH/{d.verdict}"
            print(f"       {mark:<20} {d.id} ({d.cwe} {d.site})"
                  + (f" L{d.level}" if d.level else "")
                  + (f" via {d.through}" if d.through else ""))
        for u in r.unexpected:
            print(f"       NEW                  {u['cwe']} {u['state']} "
                  f"{(u['sites'] or ['no site'])[0]}")

    print("\n" + "=" * 100)
    print(f"{'LIBRARY':<16}{'DOORS':<8}{'EXECS':>12}{'SRCH':>7}{'CR':>4}{'L':>3}{'ABS':>7}  "
          f"{'DEFECTS':<16}VERDICT")
    print("-" * 108)
    want = got = reach_want = reach_got = 0
    for r in rows:
        shown = [d for d in r.defects if d.verdict != "XFAIL" and d.tier == "anchor"]
        reach = [d for d in r.defects if d.verdict != "XFAIL" and d.tier == "reach"]
        dem = sum(1 for d in shown if d.verdict == "DEMONSTRATED")
        want += len(shown)
        got += dem
        reach_want += len(reach)
        reach_got += sum(1 for d in reach if d.verdict == "DEMONSTRATED")
        tally = f"{dem}/{len(shown)} demo" if shown else "clean control"
        if reach:
            tally += f" +{sum(1 for d in reach if d.verdict == 'DEMONSTRATED')}/{len(reach)}"
        _abs = (f"{r.absorbed}/{r.absorbed_sites}" if r.absorbed else "-")
        print(f"{r.name:<16}{f'{r.doors}/{r.doors_planned}':<8}{r.execs:>12,}{r.search:>7.0f}"
              f"{r.crashes:>4}{r.level:>3}{_abs:>7}  {tally:<16}{r.verdict}")
    print("-" * 108)
    print(f"REAL-CORPUS SCORE: {got}/{want} anchor defects DEMONSTRATED on "
          f"{len(rows)} librar{'y' if len(rows) == 1 else 'ies'}"
          + (f", {reach_got}/{reach_want} of the reach-tier defects (budget-dependent, "
             f"not gated)" if reach_want else ""))
    bad = [r for r in rows if r.verdict not in ("PASS", "SKIP")]
    for r in bad:
        print(f"\n  {r.name}: {r.verdict}")
        for p in r.problems:
            print(f"     - {p}")
        if r.kept:
            print(f"     - case kept for diagnosis: {r.kept}")
    for r in rows:
        for w in r.watch:
            print(f"  watch {r.name}: {w}")
    for r in rows:
        for u in r.unexpected:
            if r.verdict == "PASS":
                print(f"  note  {r.name}: demonstrated defect not in ground truth -- "
                      f"{u['cwe']} {u['severity']} {(u['sites'] or ['?'])[0]}. If it is real, "
                      f"record it in GROUND_TRUTH so it cannot regress silently.")
    if a.json:
        Path(a.json).write_text(json.dumps(
            {"score": f"{got}/{want}", "demonstrated": got, "expected": want,
             "reach_score": f"{reach_got}/{reach_want}", "budget": a.budget,
             "libraries": [{"name": r.name, "verdict": r.verdict, "doors": r.doors,
                            "doors_planned": r.doors_planned, "execs": r.execs,
                            "search_seconds": r.search, "crashes": r.crashes,
                            "verified_level": r.level, "elapsed": r.elapsed,
                            "problems": r.problems, "unexpected": r.unexpected,
                            "watch": r.watch,
                            "defects": [vars(d) for d in r.defects]} for r in rows]},
            indent=2))
        print(f"wrote {a.json}")
    # A SKIP never fails the run -- the corpus is not in the repo. Everything else does,
    # INVALID included: a run that could not be scored is not a pass, and exiting 0 on one is
    # the false clean this whole instrument exists to prevent.
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
