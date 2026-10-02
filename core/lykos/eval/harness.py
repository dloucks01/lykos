"""Run the labeled corpus through the real pipeline and score detection quality (doc 14).

For each `Case`: compile it, ingest it, run triage -> disassemble (Ghidra) -> detect_cwe, and
read back the CWEs the platform flagged. Match against ground truth to produce an `Outcome`,
then score the whole set. Uses the same job engine the product uses, so the numbers reflect
the real detectors, not a mock.
"""
from __future__ import annotations

import random
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..analyze import register as register_stages
from ..analyze.detect.stage import enqueue_detect
from ..analyze.disassemble import enqueue_disassemble
from ..analyze.fuzz.stage import enqueue_fuzz
from ..analyze.ingest import enqueue_triage
from ..analyze.ghidra import locate_ghidra
from ..analyze.ingest import ingest
from ..casestore import CaseStore
from ..db.dao import FindingDAO
from ..jobs import JobConfig, JobQueue, WorkerPool
from .corpus import Case, bundled, bundled_dynamic, bundled_lava
from .metrics import Outcome, Report, matches, same_family, score

_CONFIRMED = ("confirmed", "poc-backed")
_LAVA_MARKER = re.compile(rb"Successfully triggered bug (\d+)")

# finding-state lifecycle order, for reporting the strongest state reached per class
_STATE_RANK = {"candidate": 0, "corroborated": 1, "confirmed": 2, "poc-backed": 3}

# Classes whose detector has NO call site, so neither corroboration channel (reachability /
# data-flow) can apply -- a hard-coded credential/key/password is a string in the binary, not a
# sink reached by input. They are promoted straight to poc-backed by `synthesize_secret` (the
# secret itself is the reproducer), never through `corroborated`. Counting them as a
# corroborated-stage miss reads as a recall gap that is really a structural mismatch (doc 20 §G),
# so at the corroborated+ gate they count as detected at the candidate state they do reach.
_CORROBORATION_EXEMPT = {"CWE-798", "CWE-321", "CWE-259"}


# Cross toolchains for per-architecture static scoring. `eval-gate` measures x86-64 only, so an
# arch-specific regression in the recovery/bounds/taint passes (which run on the decompiler's
# P-Code, the same IR on every ISA) never trips it. STATIC detection does not RUN the binary --
# it disassembles it -- so this needs only a cross-compiler, no qemu. An arch whose compiler is
# absent SKIPs, the same rule arch-gate uses for the dynamic path.
CROSS_TOOLCHAINS = {
    "aarch64": "aarch64-linux-gnu-gcc", "arm": "arm-linux-gnueabihf-gcc",
    "ppc64": "powerpc64-linux-gnu-gcc", "ppc64le": "powerpc64le-linux-gnu-gcc",
    "riscv64": "riscv64-linux-gnu-gcc", "mips": "mips-linux-gnu-gcc",
    "mipsel": "mipsel-linux-gnu-gcc", "m68k": "m68k-linux-gnu-gcc",
    "s390x": "s390x-linux-gnu-gcc", "sh4": "sh4-linux-gnu-gcc",
}


def available_arches(arches=None):
    """(arch, cross-gcc) for each requested arch whose compiler is installed. `arches=None` or
    'all' means every toolchain in CROSS_TOOLCHAINS that is present."""
    want = list(CROSS_TOOLCHAINS) if (arches is None or arches == ["all"]) else list(arches)
    return [(a, CROSS_TOOLCHAINS[a]) for a in want
            if a in CROSS_TOOLCHAINS and shutil.which(CROSS_TOOLCHAINS[a])]


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
    out = build / "prog"
    srcs: list[str] = []
    if case.source:                                    # inline (bundled) source
        u = build / "unit.c"
        u.write_text(case.source)
        srcs.append(str(u))
    srcs += list(case.files)                            # extra/multi-file (Juliet) sources
    cmd = [gcc, *case.cflags]
    cmd += [f"-I{d}" for d in case.include_dirs]
    cmd += [f"-D{d}" for d in case.defines]
    cmd += srcs + ["-o", str(out)]
    r = subprocess.run(cmd, capture_output=True)
    return out if r.returncode == 0 and out.exists() else None


def _best_state(findings, cwe):
    states = [f.state for f in findings if same_family(cwe, f.cwe) and f.state]
    return max(states, key=lambda s: _STATE_RANK.get(s, -1)) if states else ""


def run_corpus(cases=None, *, workdir=None, gcc="gcc", workers=2, stage_timeout=180,
               min_state="candidate", progress=None) -> Report:
    """Compile + analyze every case and return a scored `Report`.

    `min_state` sets the finding state a case must reach to count as detected: "candidate"
    scores the raw rule/sink channel (flags any dangerous-API use), "corroborated" scores the
    taint-discriminated channel (a tainted source actually reaches the sink) -- the confidence
    pipeline's precision lever. `progress(msg)` is an optional live-readout callback. Requires
    gcc; Ghidra is strongly recommended (the call-graph detectors are dark without it).
    """
    cases = list(cases if cases is not None else bundled())
    gcc_path = shutil.which(gcc)
    ghidra = locate_ghidra()
    from ..analyze import native_re
    native = native_re.locate_native()
    decompiler = ghidra or native          # the detect pass runs with EITHER backend (per LYKOS_DECOMPILER)
    rank_min = _STATE_RANK.get(min_state, 0)
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="lykos-eval-"))
    tmp.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda _m: None)

    meta = {
        "n_cases": len(cases), "gcc": bool(gcc_path),
        # `ghidra` kept for back-compat; `decompiler` is the backend-presence signal the gate
        # reads, so a native-only host (rizin + pypcode, no JVM) is not treated as backend-absent.
        "ghidra": str(ghidra) if ghidra else None, "native": str(native) if native else None,
        "decompiler": str(decompiler) if decompiler else None, "min_state": min_state,
        "warnings": [],
    }
    if not gcc_path:
        meta["warnings"].append("gcc not found: cannot compile the corpus")
        return Report(outcomes=[], metrics=score([]), meta=meta)
    if not decompiler:
        meta["warnings"].append(
            "No RE backend located (neither Ghidra nor rizin+pypcode): call-graph detectors are "
            "inactive, so recall will be ~0. Install rizin+pypcode or set LYKOS_GHIDRA.")

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
            # ingest() only stores the blob + creates the target row; triage is a separate stage
            # and nothing else enqueues it. Without it the target's arch/bits/language stay null,
            # so the taint/bounds corroboration channel is dark and every bad case tops out at
            # `candidate` -- the corroborated-stage gate then reads recall 0.0. Run it explicitly.
            enqueue_triage(q, target, force=True)
            timed_out = not pool.wait_idle(stage_timeout)
            # Disassemble under EITHER backend: the stage picks native (rizin+pypcode) or Ghidra
            # via LYKOS_DECOMPILER/_select_backend(). Gating this on Ghidra alone left a native-only
            # host (the shipped default, and the CI eval-gate runner) with no IR -- every call-graph
            # and bounds detector dark, so recall read 0.0. Run it whenever any backend is present.
            if decompiler:
                enqueue_disassemble(q, target, force=True)
                timed_out |= not pool.wait_idle(stage_timeout)
            enqueue_detect(q, target, force=True)
            timed_out |= not pool.wait_idle(stage_timeout)
            findings = FindingDAO(store.conn).list_by_target(target.id)
            found = {f.cwe for f in findings
                     if _STATE_RANK.get(f.state, 0) >= rank_min
                     or f.cwe in _CORROBORATION_EXEMPT}
            # A False return means a stage never went idle within stage_timeout, so `found` is
            # read from an UNFINISHED pipeline. Flag the outcome as indeterminate rather than let
            # a slow-but-correct run score as a clean miss.
            note = (f"{c.note}; " if c.note else "") + "stage timed out (indeterminate)" \
                if timed_out else c.note
            outcomes.append(Outcome(c.name, c.cwe, c.verdict, found,
                                    state=_best_state(findings, c.cwe),
                                    matched=matches(c.cwe, found), note=note))
    finally:
        pool.stop(grace=3.0)
        store.close()

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
            timed_out = not pool.wait_idle(stage_timeout)
            enqueue_fuzz(q, target, params={"input_mode": "stdin", "max_execs": max_execs,
                                            "max_seconds": max_seconds, "exec_timeout": 1})
            timed_out |= not pool.wait_idle(stage_timeout)
            findings = FindingDAO(store.conn).list_by_target(target.id)
            confirmed = [f for f in findings if f.state in _CONFIRMED]
            # confirmed-stage: "reproduced a real bug here" -> credit the ground-truth class
            found = {c.cwe} if confirmed else set()
            state = confirmed[0].state if confirmed else ""
            if confirmed:
                note = f"reproduced -> {confirmed[0].cwe} ({state})"
            elif timed_out:
                # Fuzzing never went idle within stage_timeout: a non-reproduction here is
                # unfinished, not a clean negative -- mark it indeterminate.
                note = (f"{c.note}; " if c.note else "") + "stage timed out (indeterminate)"
            else:
                note = c.note
            outcomes.append(Outcome(c.name, c.cwe, c.verdict, found, state=state, note=note))
    finally:
        pool.stop(grace=3.0)
        store.close()
    return Report(outcomes=outcomes, metrics=score(outcomes), meta=meta)


def _lava_deliver(prog, workfile: Path, data: bytes):
    """Map a fuzz input onto a program's vector -> (argv, stdin)."""
    if prog.input_mode == "stdin":
        return [], data
    workfile.write_bytes(data)                          # file / arg: "@@" -> the input path
    argv = [str(workfile) if a == "@@" else a for a in prog.argv]
    return (argv, b"") if prog.input_mode != "arg" else ([data.decode("latin-1", "ignore")], b"")


def run_lava_corpus(programs=None, *, workdir=None, gcc="gcc", max_execs=4000, max_seconds=30,
                    exec_timeout=2, progress=None) -> Report:
    """LAVA-M bug-finding recall (doc 14): fuzz each program and count the unique injected
    bugs triggered (each self-reports "Successfully triggered bug N"). Recall = found / total.

    LAVA-M is built to defeat coverage-blind fuzzers, so a black-box mutator finds the easy
    (single-byte) gates and misses the 4-byte-magic ones -- partial recall is the honest,
    expected result, not a defect. Each bug becomes one scored `bad` case (found or missed).
    """
    from ..analyze.dynamic import sandbox
    from ..analyze.fuzz.mutator import Mutator
    programs = list(programs if programs is not None else bundled_lava())
    gcc_path = shutil.which(gcc)
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="lykos-eval-lava-"))
    tmp.mkdir(parents=True, exist_ok=True)
    say = progress or (lambda _m: None)
    meta = {"n_programs": len(programs), "gcc": bool(gcc_path), "stage": "lava",
            "max_execs": max_execs, "max_seconds": max_seconds, "programs": [], "warnings": []}
    outcomes: list[Outcome] = []
    for prog in programs:
        exe = prog.binary
        if not exe:
            if not gcc_path:
                meta["warnings"].append(f"{prog.name}: no gcc, skipped")
                continue
            built = compile_case(Case(prog.name, "lava", "bad", source=prog.source,
                                      cflags=prog.cflags), tmp, gcc)
            if built is None:
                meta["warnings"].append(f"{prog.name}: compile failed")
                continue
            exe = str(built)
        rng = random.Random(1337)
        mut = Mutator(rng, prog.dictionary)
        corpus = [bytes(s) for s in (prog.seeds or [b"\n"])]
        wf = tmp / f"{prog.name}.in"
        found: set = set()
        execs = 0
        deadline = time.time() + max_seconds
        say(f"{prog.name}: fuzzing for {len(prog.bug_ids)} injected bugs")
        while execs < max_execs and time.time() < deadline:
            data = mut.mutate(rng.choice(corpus), corpus)
            argv, stdin = _lava_deliver(prog, wf, data)
            res = sandbox.run(str(exe), argv=argv, stdin=stdin, timeout=exec_timeout)
            execs += 1
            new = False
            for m in _LAVA_MARKER.findall(res.stdout + res.stderr):
                bid = int(m)
                if bid not in found:
                    found.add(bid)
                    new = True
            if new or res.crashed:
                corpus.append(data)                     # explore near interesting inputs
        gt = set(prog.bug_ids)
        for bid in prog.bug_ids:
            hit = bid in found
            outcomes.append(Outcome(f"{prog.name}#{bid}", prog.name, "bad",
                                    {prog.name} if hit else set(), matched=hit))
        meta["programs"].append({"program": prog.name, "found": len(found & gt),
                                 "total": len(gt), "execs": execs})
        say(f"{prog.name}: {len(found & gt)}/{len(gt)} bugs in {execs} execs")
    return Report(outcomes=outcomes, metrics=score(outcomes), meta=meta)


def run(cases=None, *, stage="static", **kw) -> Report:
    """Timed convenience wrapper. `stage`: "static" (candidate detection), "dynamic"
    (confirmed-stage crash reproduction), or "lava" (LAVA-M bug-finding recall)."""
    t0 = time.time()
    runner = {"dynamic": run_dynamic_corpus, "lava": run_lava_corpus}.get(stage, run_corpus)
    rep = runner(cases, **kw)
    rep.meta["elapsed_s"] = round(time.time() - t0, 1)
    return rep
