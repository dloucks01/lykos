"""Phase 5 (coverage-guided) — the `coverage_fuzz` stage.

AFL++ in qemu-mode drives the target under edge-coverage feedback, which reaches crashes a
black-box mutator misses. AFL++ is an optional bundled tool: the locator checks
LYKOS_AFL/AFL_PATH/PATH and the stage fails clearly when it is absent (the built-in `fuzz`
stage remains the zero-dependency fallback). Each unique crashing input AFL saves is replayed
in our own sandbox, minimized, de-duplicated by signal, recorded as a dyn_result, and turned
into a Confirmed finding -- the same confirm pipeline the `fuzz` and `dynamic_run` stages use.
"""
from __future__ import annotations

import base64
import os

from ...db.dao import DynResultDAO, FindingDAO, TargetDAO
from ...hashing import canonical_json
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.minimize import minimize
from ..dynamic.stage import asan_defect_key, crash_finding_candidate
from . import aflpp
from .runner import invocation, run_input
from .stage import _DEFAULT_SEEDS, _recovered_blocks

COVERAGE_STAGE = "coverage_fuzz"
TOOL = "aflpp"
TOOL_VERSION = "aflpp-1"


def toolchain_missing():
    """Why coverage-guided fuzzing cannot run on this MACHINE, or None if it can.

    Separate from `_unsupported`, which answers about the TARGET. The distinction matters:
    "this jar has no machine code" is permanent and belongs in a decline, while "afl-qemu-trace
    is not installed" is an environment defect the operator can fix in ten minutes, and a
    stage that quietly reports zero crashes for it is the failure this codebase keeps hunting.
    """
    afl = aflpp.locate_afl(None)
    if afl is None:
        return ("AFL++ not found (looked at LYKOS_AFL, AFL_PATH, PATH). Install afl++ with "
                "afl-qemu, or use the built-in black-box `fuzz` stage instead.")
    if aflpp.locate_qemu_trace(afl) is None:
        return (f"AFL++ qemu-mode needs afl-qemu-trace, which is not installed next to {afl} "
                f"or on PATH. Build it with AFL++'s qemu_mode/build_qemu_support.sh, pass "
                f"params.qemu=false to fuzz an afl-instrumented build, or use the built-in "
                f"black-box `fuzz` stage.")
    return None


def _unsupported(target):
    """Why AFL++ cannot drive this target, or None if it can.

    Returning a REASON rather than silently producing an empty campaign is the whole point:
    the operator needs to know the difference between "nothing was found" and "nothing was
    run", and those two are otherwise identical on screen.
    """
    ftype = (target.file_type or "").lower()
    if ftype in ("jar", "class"):
        return ("AFL++ instruments native code and cannot drive a JVM target. Use the "
                "black-box `fuzz` stage, which runs the JVM directly (~36 exec/s measured) "
                "and reads uncaught exceptions as faults.")
    if ftype == "pe":
        return ("AFL++ cannot instrument a Windows PE here, and the Wine path runs at about "
                "one execution a second. Use `synthesize_poc`, which derives the overflow "
                "from the recovered stack frame without executing at all.")
    # Which guest can the installed afl-qemu-trace actually run? Not "the host": it is an
    # EMULATOR, always built for the host and targeting one guest chosen at build time. This
    # check previously assumed host == guest, which blocked coverage-guided fuzzing on the one
    # architecture the installed trace binary could drive (aarch64 here) and permitted it on
    # the one that aborts at the fork-server handshake (x86-64, the host).
    afl = aflpp.locate_afl(None)
    if afl is not None and target.arch:
        # an emulator for THIS guest, wherever it lives -- an arch-suffixed neighbour or a
        # LYKOS_AFL_QEMU_<ARCH> override. One machine can hold several.
        if aflpp.locate_qemu_trace_for(afl, target.arch) is not None:
            return None
    trace = aflpp.locate_qemu_trace(afl) if afl else None
    if trace is None:
        # Missing TOOLING is not a property of the target -- it is a fixable defect in this
        # machine, and the stage still raises for it so it stays loud. Reported here only so
        # the workbench can grey the control with a reason instead of offering it.
        return toolchain_missing()
    guest = aflpp.qemu_trace_arch(trace)
    if guest and target.arch and guest != target.arch:
        cpu = {"x86-64": "x86_64", "x86": "i386"}.get(target.arch, target.arch)
        return (f"the installed afl-qemu-trace emulates {guest}, and this target is "
                f"{target.arch} -- it would abort at the fork-server handshake. Build a "
                f"matching one (CPU_TARGET={cpu} ./qemu_mode/build_qemu_support.sh in "
                f"AFL++) and point LYKOS_AFL at it, or use the black-box `fuzz` stage, "
                f"which routes through qemu-user for any architecture and takes coverage "
                f"from qemu's own block log.")
    return None


def coverage_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("coverage_fuzz requires a target_id")

    p = ctx.params or {}
    # Can AFL++ drive this target AT ALL? afl-qemu-trace is built for the HOST architecture
    # and AFL++ instruments native code, so a cross-architecture ELF, a Windows PE and a jar
    # are all outside what this backend can execute -- and the failure is the quiet kind:
    # measured on an aarch64 target, the campaign ran to completion and reported
    # `crash_inputs: 0, unique: 0, confirmed: 0` with status `done`, which reads exactly like
    # a thorough campaign that found nothing. The `advise` endpoint recommended it first for
    # every one of the eleven non-host architectures in the corpus.
    why = _unsupported(target)
    if why and why == toolchain_missing():
        # environment, not target: raise so the run is visibly broken rather than a clean zero
        raise RuntimeError(why)
    if why:
        ctx.emit("coverage.done", payload={"supported": False, "backend": "aflpp",
                                           "crash_inputs": 0, "unique": 0, "confirmed": 0,
                                           "note": why})
        ctx.progress(pct=100, msg=why[:90])
        return {}
    afl = aflpp.locate_afl(p.get("afl_path"))
    if afl is None:
        raise RuntimeError(
            "AFL++ not found (looked at LYKOS_AFL, AFL_PATH, PATH). Install afl++ with "
            "afl-qemu, or use the built-in black-box `fuzz` stage instead.")

    mode = p.get("input_mode", "file")                # file (@@) | stdin | arg
    if mode not in ("file", "stdin"):
        # AFL++ qemu-mode delivers input as a file (@@) or over stdin ONLY -- it cannot inject
        # into argv. `run_campaign` passes no @@ for a non-file mode, so an "arg" request is
        # actually fuzzed over stdin. Replaying it through argv would then never reproduce, and
        # every real crash would be dropped as a clean zero. Normalise it, and say so, so the
        # crash is found and replayed the same way.
        ctx.emit("coverage.mode", payload={"requested": mode, "used": "stdin", "why": (
            "AFL++ delivers input as a file (@@) or over stdin only; it cannot inject into "
            "argv, so this campaign fuzzes and replays over stdin")})
        mode = "stdin"
    seconds = int(p.get("max_seconds", 30))
    exec_timeout = float(p.get("exec_timeout", 2))
    use_qemu = bool(p.get("qemu", True))              # qemu-mode: fuzz an uninstrumented bin
    trace = aflpp.locate_qemu_trace_for(afl, target.arch) if target.arch else None
    afl_path = None
    if use_qemu and trace is not None:
        afl_path = aflpp.stage_qemu_trace(trace, ctx.scratch())
        ctx.emit("coverage.backend", payload={
            "afl_qemu_trace": str(trace), "guest": aflpp.qemu_trace_arch(trace),
            "target_arch": target.arch})
    if use_qemu and trace is None and aflpp.locate_qemu_trace(afl) is None:
        # Checking only for afl-fuzz is not enough: -Q needs afl-qemu-trace, which ships
        # separately (Ubuntu's afl++ package omits it). Without this check the campaign
        # aborts at the fork-server handshake and still reports a clean "0 crashes" run.
        raise RuntimeError(
            "AFL++ qemu-mode needs afl-qemu-trace, which is not installed next to "
            f"{afl} or on PATH. Build it with AFL++'s qemu_mode/build_qemu_support.sh, pass "
            "params.qemu=false to fuzz an afl-instrumented build, or use the built-in "
            "black-box `fuzz` stage.")

    exe = ctx.scratch() / "target.bin"
    _blob = ctx.content.path(target.sha256).read_bytes()
    # A sanitizer build (the source-code path compiles one) reserves a ~20 TB shadow mapping.
    # AFL cannot run it under its memory cap, and running it UNCAPPED (-m none) lets the target
    # allocate without bound and OOM the host -- observed here. So AFL does not fuzz sanitizer
    # builds at all: the sandbox `fuzz`/`directed_fuzz` stages run them under rlimits (memory
    # bounded, crashes still caught as the sanitizer's SIGABRT), which is safe and effective.
    if aflpp.is_sanitizer_build(_blob):
        note = ("sanitizer build: not fuzzed under AFL (its shadow memory is incompatible with "
                "AFL's memory model). The sandbox fuzzers cover it under rlimits.")
        ctx.emit("coverage.done", payload={"supported": False, "backend": "aflpp",
                                           "crash_inputs": 0, "unique": 0, "confirmed": 0,
                                           "sanitizer": True, "note": note})
        ctx.progress(pct=100, msg="sanitizer build — fuzzed by the sandbox path instead")
        return {}
    exe.write_bytes(_blob)
    os.chmod(exe, 0o755)

    # seed corpus for AFL's input dir
    seeds = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_DEFAULT_SEEDS)
    seeds_dir = ctx.scratch() / "afl-in"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    for i, s in enumerate(seeds):
        (seeds_dir / f"seed{i:04d}").write_bytes(s or b"\n")
    out_dir = ctx.scratch() / "afl-out"

    ctx.progress(msg=f"AFL++ qemu-mode, {seconds}s budget")
    ctx.emit("coverage.start", payload={"backend": "aflpp", "seconds": seconds,
                                        "afl": str(afl)})
    proc = aflpp.run_campaign(afl, exe, seeds_dir, out_dir, seconds=seconds, afl_path=afl_path,
                              mode=mode, qemu=use_qemu)
    if proc.returncode != 0 and not (out_dir / "default").exists() \
            and not (out_dir / "crashes").exists():
        tail = (proc.stderr or b"")[-800:].decode("latin-1", "ignore")
        raise RuntimeError(f"afl-fuzz failed (rc={proc.returncode}): {tail}")

    raw = aflpp.harvest_crashes(out_dir)
    failed = aflpp.campaign_failed(proc)
    if failed:
        raise RuntimeError(
            f"{failed}. No inputs were executed, so this is NOT a clean 'no crashes' result.")
    # What the campaign actually DID -- "0 crashes" after two million executions and "0
    # crashes" after none are opposite conclusions, and the event could not tell them apart.
    stats = aflpp.campaign_stats(out_dir)
    ctx.emit("coverage.harvest", payload={"crash_inputs": len(raw), **stats})
    if stats.get("execs_done", "").isdigit() and int(stats["execs_done"]) < 100:
        ctx.emit("coverage.starved", payload={
            "execs_done": stats.get("execs_done"),
            "note": ("the campaign executed almost nothing -- the seeds may be rejected by "
                     "this target, or each execution may be hitting the timeout. A clean "
                     "'0 crashes' from a campaign that never ran says nothing about the "
                     "binary.")})

    fd = FindingDAO(ctx.conn)
    dd = DynResultDAO(ctx.conn)
    workfile = ctx.scratch() / "input.bin"
    seen_crashes = set()
    confirmed = 0
    # Recover blocks once so a crash replay can capture a FAULT LOCUS. Without it every AFL crash
    # replayed here has fault_pc=None: they all bucket (signal, None) -> only the first is treated
    # as unique, and the finding is keyed by signal alone, which then differs from fuzz/directed's
    # located key and double-files one defect. run_batch traces native targets (ptrace fault_pc);
    # for an emulated target the blocks give qemu's fault log via run_input.
    cover_blocks = _recovered_blocks(ctx, target)

    def _replay(data):
        if cover_blocks:
            b = sandbox.run_batch(exe, [data], mode=mode, timeout=exec_timeout, blocks=cover_blocks)
            if b:
                return b[0]
        return run_input(exe, mode, workfile, exec_timeout, target.arch, data,
                         blocks=cover_blocks)[1]

    for data in raw:
        if ctx.should_cancel():
            break
        res = _replay(data)
        if not res.crashed:
            continue                                  # not reproducible in our sandbox
        sig = res.signal_name
        defect_key = asan_defect_key(res.stderr) if sig == "SIGABRT" else None
        # Bucket by (signal, fault site), not signal alone: every SIGSEGV in a program is the
        # same signal but not the same bug, and de-duping on the name collapsed distinct
        # defects into one finding. AFL's crashes/ are already coverage-unique.
        key = (sig, res.fault_pc)
        if key in seen_crashes:
            input_sha = ctx.put_artifact("afl-crash-input", data=data)
            dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                      # the flag prefix, which for an AFL replay is empty: the invocation
                      # is nothing but the carrier, and that is scratch
                      input_mode=mode, argv=[],
                      signal=res.signal, signal_name=sig, crashed=True,
                      isolation=res.isolation, duration_ms=res.duration_ms,
                      fault_pc=res.fault_pc, defect_key=defect_key)
            continue
        seen_crashes.add(key)

        def _same(d, _sig=sig):
            r = run_input(exe, mode, workfile, exec_timeout, target.arch, d)[1]
            return r.crashed and r.signal_name == _sig

        mdata, _ = minimize(_same, data, cap=200)
        note = (f"minimized {len(data)}->{len(mdata)}B" if len(mdata) < len(data) else None)
        margv = invocation(mode, workfile, mdata)[0]
        input_sha = ctx.put_artifact("afl-crash-input", data=mdata)
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                  input_mode=mode, argv=margv, signal=res.signal, signal_name=sig,
                  crashed=True, isolation=res.isolation, duration_ms=res.duration_ms,
                  note=note, fault_pc=res.fault_pc, defect_key=defect_key)
        fd.upsert(target.id, target.case_id, crash_finding_candidate(
            sig, input_sha, res.isolation, "coverage_fuzz",
            "(found by AFL++ coverage-guided fuzzing"
            + ("; " + note if note else "") + ")",
            fault_pc=res.fault_pc, discriminator=defect_key))
        confirmed += 1

    ctx.emit("coverage.done", payload={"crash_inputs": len(raw),
                                       "unique": len(seen_crashes), "confirmed": confirmed})
    ctx.progress(pct=100, msg=f"{len(raw)} crash inputs, {len(seen_crashes)} unique crashes")
    # Persist the campaign's own measure of how much it exercised, so the run's output carries
    # the coverage it achieved -- not just its crash count. `bitmap_cvg` is AFL's edge-map
    # fill percentage; a low number on a big binary means the fuzzer barely got past the door.
    def _num(k):
        v = stats.get(k)
        try:
            return float(str(v).rstrip("%")) if v not in (None, "") else None
        except ValueError:
            return None
    summary = {"backend": "aflpp", "execs": _num("execs_done"), "execs_per_sec": _num("execs_per_sec"),
               "corpus_count": _num("corpus_count"), "unique_crashes": len(seen_crashes),
               "coverage": {"kind": "edge", "bitmap_cvg_pct": _num("bitmap_cvg"),
                            "edges_found": _num("edges_found")}}
    # Persist as the run's output artifact so /runs/<id>/output carries the coverage achieved.
    sha = ctx.put_artifact("fuzz-summary", data=canonical_json(summary))
    return {"output_shas": [sha], "output_kind": "fuzz-summary"}


def register() -> None:
    register_stage(COVERAGE_STAGE, coverage_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=3600)


def enqueue_coverage_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, COVERAGE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
