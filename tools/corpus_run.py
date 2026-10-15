#!/usr/bin/env python3
"""Drive ONE real target through the real autopilot and collect what it produced.

This exists because two instruments need the same thing and must not keep their own copies of
it. `real_corpus_gate.py` asks "did the PLUMBING hold" and `corpus_regression.py` asks "did we
still find the bugs we found last time" -- different questions about the same campaign, and the
campaign is the part that is easy to get subtly wrong: the triage wait, the deadline that has to
scale with the targets a source project registers, keeping a failed case for diagnosis, the
double rmtree a winding-down worker makes necessary.

The project has already paid for duplicating one piece of logic across callers: the planner and
the caller each had a copy of the C definition regex, they drifted by one dialect, and the
mismatch synthesized a harness that called `gzopen(path, mode)` with one argument -- reported as
an ASan SEGV in zlib on execution one. A fabricated crash in a real library is the worst thing
this tool can emit. One runner, two scorers.

Nothing here renders a VERDICT. It gathers evidence (the scorecard, the findings and their
sites, the recorded crashes, the PoCs) and leaves the judging to the caller, because the two
callers judge the same evidence against different standards.
"""
from __future__ import annotations

import shutil
import sys
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


#: The stages that constitute the search. Their combined wall time is what a "0 crashes" row is
#: actually worth: libtiff at a 200s budget reported 6 capabilities working and no crashes -- a row
#: that reads exactly like a clean library -- and the same target at 900s produced a heap overflow
#: and a verified PoC. The build had eaten the budget. The number that distinguishes those two runs
#: was never printed, so neither instrument could tell a clean target from a starved one.
ENGINES = ("fuzz", "coverage_fuzz", "directed_fuzz", "libfuzzer", "net_fuzz", "env_fuzz",
           "concolic")
#: Below this many seconds of combined engine time, a source project has not been searched. The
#: floor is measurement, not taste: the libtiff crash arrived 6 executions into the SGILog seed,
#: but the in-process harness needed ~200s of that run to configure, build and link before the
#: first execution happened at all.
SEARCH_FLOOR = 150.0


def unscoreable(src: Path, search: float, budget: float, crashes: int) -> str:
    """Why this run cannot be scored, or "" if it can.

    Pure so it can be tested without a 900s campaign. Both instruments need it and neither owns
    it: "a clean row is not evidence when the search never ran" is as true of a regression
    benchmark as of a plumbing gate.
    """
    if crashes or not is_source_project(src) or search >= SEARCH_FLOOR:
        return ""
    return (f"search starved: the engines held {search:.0f}s of a {budget:.0f}s budget, under the "
            f"{SEARCH_FLOOR:.0f}s floor a source project needs after it is built. A clean row "
            f"here is not evidence -- re-run with a larger --budget.")


@dataclass
class Defect:
    """A finding, with the two fields that say WHERE and HOW IT WAS REACHED.

    `sites` carries `finding_site.detail`, which for a sanitizer-reported defect is the source
    line the report named (`tif_read.c:460`). That string is the only stable identity a defect
    in a real library has: an address moves with every rebuild, a title is the sanitizer's class
    name shared by hundreds of bugs, and a dedup key is ours.
    """
    finding_id: str
    target_id: str
    cwe: str = ""
    title: str = ""
    state: str = "candidate"
    severity: str = "info"
    detector: str = ""
    sites: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    @property
    def dynamic(self) -> bool:
        """Did something EXECUTE to produce this, or did a static detector infer it?"""
        from lykos.db.models import STATIC_DETECTORS
        return self.detector not in STATIC_DETECTORS

    @property
    def demonstrated(self) -> bool:
        """The report's own definition, so the two instruments and the report agree."""
        return self.state in ("poc-backed", "confirmed") and self.dynamic


@dataclass
class Crash:
    """A recorded execution that faulted. `defect_key` is what ties it to a Defect's site."""
    input_sha: str = ""
    defect_key: str = ""
    signal_name: str = ""
    note: str = ""
    isolation: str = ""
    crashed: bool = False


@dataclass
class PocRow:
    level: int = 0
    verified: bool = False
    input_sha: str = ""
    finding_id: str = ""
    bundle_sha: str = ""


@dataclass
class Evidence:
    """Everything one campaign left behind, plus where its case store is."""
    name: str
    src: Path
    budget: float
    workdir: Path
    elapsed: int = 0
    #: Set when the target never got as far as a campaign (could not unpack, would not ingest).
    error: str = ""
    scorecard: dict = field(default_factory=dict)
    defects: list = field(default_factory=list)
    crashes: list = field(default_factory=list)
    pocs: list = field(default_factory=list)
    #: How many targets the case ended up with. A source project registers one per executable it
    #: built, and each costs a full budget slice -- which is why the deadline scales with it.
    targets: int = 0

    # --- the readings both scorers take, named once so they are taken the same way

    @property
    def ran(self) -> str:
        base = self.scorecard.get("baseline") or {}
        return "yes" if base.get("ran") else ("FAULTED" if base.get("crashed") else "NO")

    @property
    def execs(self) -> int:
        return int((self.scorecard.get("executions") or {}).get("total") or 0)

    @property
    def rate(self) -> float:
        return float((self.scorecard.get("executions") or {}).get("per_second") or 0.0)

    @property
    def doors(self) -> list:
        return list((self.scorecard.get("in_process") or {}).get("doors") or [])

    @property
    def doors_built(self) -> int:
        return int((self.scorecard.get("in_process") or {}).get("entry_points") or 0)

    @property
    def doors_planned(self) -> int:
        return int((self.scorecard.get("in_process") or {}).get("planned") or 0)

    def search_seconds(self, engines) -> float:
        by_stage = ((self.scorecard.get("budget") or {}).get("by_stage") or {})
        return round(sum(float(v) for k, v in by_stage.items() if k in engines), 1)

    @property
    def verified_level(self) -> int:
        return max((p.level for p in self.pocs if p.verified), default=0)

    @property
    def n_crashes(self) -> int:
        return sum(1 for c in self.crashes if c.crashed)

    def discard(self) -> None:
        """Delete the case store, retrying while a worker is still winding down.

        A worker thread that outlives `pool.stop` recreates the content store's directory, so one
        sweep leaves an empty `case/artifacts` behind and `ignore_errors` hides it. Two sweeps
        0.5 s apart were enough for a 90 s target and NOT for zlib after a 449 s campaign
        **[measured]**: `/tmp/corpus-hcy408m7/case/artifacts` outlived a passing run. Retry until
        the directory stays gone, and give up quietly rather than block the next library.
        """
        for attempt in range(6):
            shutil.rmtree(self.workdir, ignore_errors=True)
            if not self.workdir.exists():
                return
            time.sleep(0.5 * (attempt + 1))
        shutil.rmtree(self.workdir, ignore_errors=True)


def stage_target(src: Path, work: Path) -> Path | None:
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


def is_source_project(src: Path) -> bool:
    """A tarball or a directory has to be CONFIGURED, BUILT and LINKED before a single execution
    happens. That work comes out of the same budget as the search, which is why a source target
    needs a search floor and a prebuilt binary does not."""
    return src.is_dir() or src.suffix in (".gz", ".tgz", ".bz2", ".xz")


def set_max_entry_points(n: int) -> None:
    """Cap how many of a source project's executables one case carries.

    `from lykos.analyze import ingest` gives the ingest FUNCTION, not the module: the package
    re-exports it and the name shadows the submodule, so setting MAX_ENTRY_POINTS on that object
    is a silent no-op -- measured, the run went on registering six targets per library while the
    flag said two and nothing anywhere said otherwise. Import the module by name, and assert the
    value moved, because a measurement tool whose knob quietly does nothing is worse than one
    without the knob.
    """
    from importlib import import_module
    mod = import_module("lykos.analyze.ingest")
    mod.MAX_ENTRY_POINTS = max(1, n)
    assert mod.MAX_ENTRY_POINTS == max(1, n), "--max-entry-points did not take effect"


def run_campaign(src: Path, budget: float, *, workers: int = 3,
                 triage_wait: float = 180.0, log=lambda *_: None) -> Evidence:
    """Ingest `src`, run the autopilot on it with `budget` seconds per target, collect evidence.

    The case store is LEFT ON DISK at `ev.workdir`; the caller calls `ev.discard()` when it has
    decided it does not need it. Deleting it here cost a full re-run to investigate any failure,
    and an instrument whose failures are expensive to read is an instrument that gets ignored.
    """
    from lykos.analyze import register
    from lykos.analyze.ingest import enqueue_triage, ingest
    from lykos.analyze.orchestrate import run_case_autopilot
    from lykos.casestore import CaseStore
    from lykos.db.dao import DynResultDAO, FindingDAO, PocDAO, TargetDAO
    from lykos.jobs import JobConfig, JobQueue, WorkerPool

    wd = Path(tempfile.mkdtemp(prefix="corpus-"))
    ev = Evidence(name=src.name, src=src, budget=budget, workdir=wd)
    t0 = time.time()
    register()
    store = CaseStore.open(wd / "case")
    case = store.cases.create(src.name)
    pool = WorkerPool(store.db_path, store.content, JobConfig(workers=workers,
                                                             poll_interval=0.02))
    pool.start()
    try:
        staged = stage_target(src, wd / "src")
        if staged is None:
            ev.error = "could not unpack"
            return ev
        try:
            t = ingest(store, case.id, staged, filename=staged.name)
        except Exception as e:                           # noqa: BLE001 -- any ingest failure
            # A target that cannot be ingested is a RESULT, not a reason to stop measuring. The
            # zlib tarball raised NotAnalysable out of here ("source project did not build"),
            # the exception left `main`, and the run died with expat and bzip2 unmeasured -- so
            # one target's failure cost the rest of the corpus. The whole point is the table at
            # the end.
            ev.error = f"{type(e).__name__}: {str(e).splitlines()[0][:160]}"
            return ev
        enqueue_triage(JobQueue(store.conn), t, force=True)
        pool.wait_idle(triage_wait)
        status, stop = {}, threading.Event()
        th = threading.Thread(target=run_case_autopilot,
                              args=(wd / "case", case.id, [t.id], status, stop, budget),
                              daemon=True)
        th.start()
        # `budget` is PER TARGET, and a source project registers one target per executable it
        # built -- libtiff builds six under the default ceiling. A fixed `budget * 2 + 300` wall
        # clock therefore cut the run off a third of the way through and set `stop`, so the later
        # targets were never analysed and a truncated pass was reported as a whole one. The
        # deadline scales with the targets the case actually has, counted as they appear (the
        # extras are registered during ingest, the firmware/packed ones mid-run).
        while th.is_alive():
            n = max(1, len(TargetDAO(store.conn).list_by_case(case.id)))
            if time.time() - t0 >= budget * n * 1.3 + 300:
                log(f"     deadline reached ({n} targets)")
                break
            time.sleep(5)
        if th.is_alive():
            stop.set()
            th.join(timeout=120)

        ev.scorecard = (status or {}).get("scorecard") or {}
        tids = [x.id for x in TargetDAO(store.conn).list_by_case(case.id)]
        ev.targets = len(tids)
        fdao = FindingDAO(store.conn)
        for f in fdao.list_by_case(case.id):
            ev.defects.append(Defect(
                finding_id=f.id, target_id=f.target_id, cwe=f.cwe or "",
                title=f.title or "", state=f.state or "candidate",
                severity=f.severity or "info", detector=f.detector or "",
                sites=[s["detail"] for s in fdao.sites(f.id) if s.get("detail")],
                evidence=[str(e.get("detail") or "") for e in (f.evidence or [])
                          if isinstance(e, dict)]))
        for tid in tids:
            for d in DynResultDAO(store.conn).list_by_target(tid):
                ev.crashes.append(Crash(
                    input_sha=d.input_sha or "", defect_key=d.defect_key or "",
                    signal_name=d.signal_name or "", note=d.note or "",
                    isolation=d.isolation or "", crashed=bool(d.crashed)))
            for p in PocDAO(store.conn).list_by_target(tid):
                lvl = int(str(p.level)[1]) if str(p.level or "").startswith("L") else 0
                ev.pocs.append(PocRow(level=lvl, verified=bool(getattr(p, "verified", False)),
                                      input_sha=p.input_sha or "",
                                      finding_id=p.finding_id or "",
                                      bundle_sha=getattr(p, "bundle_sha", "") or ""))
        return ev
    finally:
        ev.elapsed = int(time.time() - t0)
        pool.stop(grace=5.0)
        store.close()
