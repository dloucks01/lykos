"""Run the labeled corpus through the real pipeline and score detection quality (doc 14).

For each `Case`: compile it, ingest it, run triage -> disassemble (Ghidra) -> detect_cwe, and
read back the CWEs the platform flagged. Match against ground truth to produce an `Outcome`,
then score the whole set. Uses the same job engine the product uses, so the numbers reflect
the real detectors, not a mock.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..analyze import register as register_stages
from ..analyze.detect.stage import enqueue_detect
from ..analyze.disassemble import enqueue_disassemble
from ..analyze.fuzz.stage import enqueue_fuzz
from ..analyze.ghidra import locate_ghidra
from ..analyze.ingest import enqueue_triage, ingest
from ..casestore import CaseStore
from ..db.dao import FindingDAO
from ..jobs import JobConfig, JobQueue, WorkerPool
from .corpus import bundled, bundled_dynamic
from .metrics import Outcome, Report, score

_CONFIRMED = ("confirmed", "poc-backed")

# finding-state lifecycle order, for reporting the strongest state reached per class
_STATE_RANK = {"candidate": 0, "corroborated": 1, "confirmed": 2, "poc-backed": 3}


def compile_case(case, outdir: Path, gcc: str = "gcc"):
    """Compile one case to an ELF; return the path, or None if compilation failed.

    The source is written under a NEUTRAL filename (``unit.c``), because gcc embeds the
    source path as an ELF FILE symbol -- a descriptive name like ``CWE-798__..._secret.c``
    would leak the ground-truth label into the binary's strings and cause a false detection.
    The output binary keeps a descriptive name (never embedded as a string).
    """
    stem = f"{case.cwe}__{case.name}__{case.verdict}"
    build = outdir / stem
    build.mkdir(parents=True, exist_ok=True)
    src = build / "unit.c"
    src.write_text(case.source)
    out = build / "prog"
    r = subprocess.run([gcc, *case.cflags, str(src), "-o", str(out)],
                       capture_output=True)
    return out if r.returncode == 0 and out.exists() else None


def _best_state(findings, cwe):
    states = [f.state for f in findings if f.cwe == cwe and f.state]
    return max(states, key=lambda s: _STATE_RANK.get(s, -1)) if states else ""


def run_corpus(cases=None, *, workdir=None, gcc="gcc", workers=2, stage_timeout=180,
               progress=None) -> Report:
    """Compile + analyze every case and return a scored `Report`.

    `progress(msg)` is an optional callback for a live readout. Requires gcc; Ghidra is
    strongly recommended (the call-graph detectors are dark without it) and its presence is
    recorded in the report meta.
    """
    cases = list(cases if cases is not None else bundled())
    gcc_path = shutil.which(gcc)
    ghidra = locate_ghidra()
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="lykos-eval-"))
    tmp.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda _m: None)

    meta = {
        "n_cases": len(cases), "gcc": bool(gcc_path),
        "ghidra": str(ghidra) if ghidra else None,
        "warnings": [],
    }
    if not gcc_path:
        meta["warnings"].append("gcc not found: cannot compile the corpus")
        return Report(outcomes=[], metrics=score([]), meta=meta)
    if not ghidra:
        meta["warnings"].append(
            "Ghidra not located: call-graph detectors are inactive, so recall will be ~0. "
            "Set LYKOS_GHIDRA or install Ghidra for a meaningful run.")

    store = CaseStore.open(tmp / "eval-store")
    register_stages()
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=workers, lease_seconds=stage_timeout,
                                poll_interval=0.02, heartbeat_interval=5.0))
    pool.start()
    outcomes: list[Outcome] = []
    try:
        case_row = store.cases.create("benchmark")
        q = JobQueue(store.conn)
        for i, c in enumerate(cases, 1):
            say(f"[{i}/{len(cases)}] {c.cwe} {c.name} ({c.verdict})")
            exe = compile_case(c, tmp, gcc)
            if exe is None:
                outcomes.append(Outcome(c.name, c.cwe, c.verdict, set(),
                                        note="compile failed (skipped)"))
                continue
            label = f"{c.cwe}__{c.name}__{c.verdict}"     # store label only, not embedded
            target = ingest(store, case_row.id, exe, filename=label)
            enqueue_triage(q, target, force=True)
            pool.wait_idle(stage_timeout)
            if ghidra:
                enqueue_disassemble(q, target, force=True)
                pool.wait_idle(stage_timeout)
            enqueue_detect(q, target, force=True)
            pool.wait_idle(stage_timeout)
            findings = FindingDAO(store.conn).list_by_target(target.id)
            found = {f.cwe for f in findings}
            outcomes.append(Outcome(c.name, c.cwe, c.verdict, found,
                                    state=_best_state(findings, c.cwe), note=c.note))
    finally:
        pool.stop(grace=3.0)
        store.close()

    meta["elapsed_s"] = None
    return Report(outcomes=outcomes, metrics=score(outcomes), meta=meta)


def run_dynamic_corpus(cases=None, *, workdir=None, gcc="gcc", workers=2, max_execs=2500,
                       max_seconds=25, stage_timeout=90, progress=None) -> Report:
    """Confirmed-stage recall (doc 14): compile each crash case and FUZZ it, measuring whether
    the pipeline reproduces the bug as a *Confirmed* finding.

    Recall = fraction of `bad` cases the fuzzer crashed and confirmed; the FP-rate is the
    fraction of `good` cases that produced a false confirmed crash (should be ~0 -- the point
    of the confidence pipeline). No Ghidra needed: fuzzing runs the binary in the sandbox.
    """
    cases = list(cases if cases is not None else bundled_dynamic())
    gcc_path = shutil.which(gcc)
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="lykos-eval-dyn-"))
    tmp.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda _m: None)
    meta = {"n_cases": len(cases), "gcc": bool(gcc_path), "stage": "dynamic",
            "max_execs": max_execs, "max_seconds": max_seconds, "warnings": []}
    if not gcc_path:
        meta["warnings"].append("gcc not found: cannot compile the crash corpus")
        return Report(outcomes=[], metrics=score([]), meta=meta)

    store = CaseStore.open(tmp / "eval-store")
    register_stages()
    pool = WorkerPool(store.db_path, store.content,
                      JobConfig(workers=workers, lease_seconds=stage_timeout,
                                poll_interval=0.02, heartbeat_interval=5.0))
    pool.start()
    outcomes: list[Outcome] = []
    try:
        case_row = store.cases.create("benchmark-dynamic")
        q = JobQueue(store.conn)
        for i, c in enumerate(cases, 1):
            say(f"[{i}/{len(cases)}] {c.cwe} {c.name} ({c.verdict}) -- fuzzing")
            exe = compile_case(c, tmp, gcc)
            if exe is None:
                outcomes.append(Outcome(c.name, c.cwe, c.verdict, set(),
                                        note="compile failed (skipped)"))
                continue
            target = ingest(store, case_row.id, exe, filename=f"{c.cwe}__{c.name}__{c.verdict}")
            enqueue_triage(q, target, force=True)
            pool.wait_idle(stage_timeout)
            enqueue_fuzz(q, target, params={"input_mode": "stdin", "max_execs": max_execs,
                                            "max_seconds": max_seconds, "exec_timeout": 1})
            pool.wait_idle(stage_timeout)
            findings = FindingDAO(store.conn).list_by_target(target.id)
            confirmed = [f for f in findings if f.state in _CONFIRMED]
            # confirmed-stage: "reproduced a real bug here" -> credit the ground-truth class
            found = {c.cwe} if confirmed else set()
            state = confirmed[0].state if confirmed else ""
            note = f"reproduced -> {confirmed[0].cwe} ({state})" if confirmed else c.note
            outcomes.append(Outcome(c.name, c.cwe, c.verdict, found, state=state, note=note))
    finally:
        pool.stop(grace=3.0)
        store.close()
    return Report(outcomes=outcomes, metrics=score(outcomes), meta=meta)


def run(cases=None, *, stage="static", **kw) -> Report:
    """Timed convenience wrapper. `stage`: "static" (candidate detection) or "dynamic"
    (confirmed-stage crash reproduction via fuzzing)."""
    t0 = time.time()
    runner = run_dynamic_corpus if stage == "dynamic" else run_corpus
    rep = runner(cases, **kw)
    rep.meta["elapsed_s"] = round(time.time() - t0, 1)
    return rep
