"""Phase 5 — the `fuzz` stage: black-box mutational fuzzing over the sandbox executor.

Drives inputs through the Phase-4 sandbox, detects crashes, dedups them, saves the crashing
input as an artifact, records a dyn_result, and turns each unique crash into a Confirmed
finding (L1: crash + reproducible input). Budget-bounded (execs + wall-clock); cancellable.

The core loop is exposed as `fuzz_campaign()` so the directed-fuzzing stage can reuse it with
a targeted corpus/dictionary aimed at statically-flagged sinks.
"""
from __future__ import annotations

import base64
import hashlib
import os
import random
import re
import time

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.minimize import minimize
from ..dynamic.stage import crash_finding_candidate
from ..poc.capture import modes_for
from . import structure
from .mutator import Mutator
from .runner import invocation, run_input

FUZZ_STAGE = "fuzz"
TOOL = "fuzz"
TOOL_VERSION = "fuzz-1"
# Long seeds are not a luxury: a blind mutator keeps nothing, so without one the campaign can
# only reach a length-triggered bug by growing into it, and it never does. These put the
# overflow class in range from the first exec.
_DEFAULT_SEEDS = [b"", b"A" * 8, b"%s%s%s%n", b"0", b"-1", b"../../etc/passwd",
                  b"A" * 256, b"A" * 1024, b"A" * 4096]


def _mine_dictionary(strings):
    toks = []
    for s in strings:
        v = (s.value or "").strip()
        if v and len(v) <= 64:
            toks.append(v.encode("latin-1", "ignore"))
    return toks[:500]


# How many inputs the corpus may retain, and how big one may be. A blind campaign that keeps
# everything spends its budget re-running near-duplicates of one enormous input.
_MAX_CORPUS = 256
_MAX_KEEP = 16384


def behaviour_of(res, data: bytes = b""):
    """A coarse signature of what the program DID -- a coverage proxy with no instrumentation.

    The campaign was purely blind: the corpus only ever grew on a CRASH, so an input that
    reached new parser code without crashing was discarded and the search random-walked around
    its seeds forever. `unique: 0` on every jhead run was that, not bad luck.

    Real coverage needs instrumentation we do not have for an arbitrary binary, but a parser
    announces which path it took: jhead prints "Illegal subdirectory link", "Illegal value
    pointer", "Invalid Exif alignment marker" and so on. Exit status plus the SHAPE of the
    output is therefore a usable proxy -- digits are collapsed so that "Extraneous 16 padding
    bytes" and "Extraneous 56" count as the same path rather than two.
    """
    blob = (res.stderr or b"") + b"\x00" + (res.stdout or b"")
    shape = re.sub(rb"\d+", b"#", blob[:512])
    # Paths too: a program that echoes the file it was given would otherwise report a new
    # behaviour for every input, and a proxy that fires on everything is noise.
    shape = re.sub(rb"[/\\][^\s'\"]*", b"#PATH", shape)
    # Drop anything the program merely ECHOED back. A parser handed its input as a filename
    # prints that filename in the diagnostic, so every distinct payload looked like a distinct
    # path: 40% of inputs counted as new behaviour in argv mode, which is noise, not coverage.
    if data:
        shape = b" ".join(t for t in re.split(rb"[^A-Za-z#]+", shape)
                          if len(t) > 2 and t not in data)
    return (res.exit_code, res.signal_name,
            hashlib.blake2b(shape, digest_size=8).digest())


def fuzz_campaign(ctx, target, *, corpus, dictionary, mode, max_execs, max_seconds,
                  exec_timeout, rng, detector, event_prefix, note_prefix, run_fn=run_input,
                  mutator=None, cover_blocks=()):
    """Shared mutational campaign: mutate -> sandbox -> dedup-by-signal -> minimize ->
    dyn_result + Confirmed finding. Used by both the black-box `fuzz` stage and the directed
    stage (which supplies a corpus/dictionary aimed at specific sinks). Returns stats.

    `run_fn(exe, mode, workfile, timeout, arch, data) -> (argv, RunResult)` is the input
    delivery; boundary-driven harnessing (doc 17.4) swaps in a channel runner."""
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)
    workfile = ctx.scratch() / "input.bin"

    corpus = list(corpus) or list(_DEFAULT_SEEDS)
    mut = mutator or Mutator(rng, dictionary)          # structure-aware mutator when supplied
    fd = FindingDAO(ctx.conn)
    dd = DynResultDAO(ctx.conn)
    deadline = time.time() + max_seconds
    execs = crashes = 0
    seen_sigs = set()
    seen_behaviour, kept = set(), 0

    # Batching pays the sandbox namespace once per BATCH instead of once per input, which is
    # 3.18 ms of every 3.55 ms execution. Only for the plain runner: a stage that supplies its
    # own delivery (boundary harnessing) is not a series of independent executions.
    batchable = run_fn is run_input
    batch_n = 64
    # Real path coverage when the target has been disassembled. An output-shape proxy notices
    # that a parser printed something new; block coverage notices that it took a branch it has
    # never taken -- which is the difference between a few thousand distinct behaviours and
    # tens of thousands of distinct paths.
    all_blocks = set(cover_blocks or ())
    seen_blocks: set = set()
    ctx.progress(msg=f"{event_prefix} campaign")
    while execs < max_execs and time.time() < deadline and not ctx.should_cancel():
        want = min(batch_n if batchable else 1, max_execs - execs)
        inputs = [mut.mutate(rng.choice(corpus), corpus) for _ in range(max(1, want))]
        results = None
        if batchable:
            # Only ever arm blocks we have not reached: the breakpoints are one-shot, so
            # the cost decays as coverage saturates instead of being paid in full forever.
            arm = sorted(all_blocks - seen_blocks) if all_blocks else ()
            results = sandbox.run_batch(exe, inputs, mode=mode, timeout=exec_timeout,
                                        arch=target.arch, endianness=target.endianness,
                                        bits=target.bits, blocks=arm)
            if results is None:
                batchable = False                     # not available here; stay per-exec
        if results is None:
            inputs = inputs[:1]
            results = [run_fn(exe, mode, workfile, exec_timeout, target.arch, inputs[0],
                              endianness=target.endianness, bits=target.bits)[1]]
        for data, res in zip(inputs, results):
            argv = invocation(mode, workfile, data)[0]
            execs += 1
            # Keep anything that made the program behave in a way we have not seen. This is the
            # ratchet: without it the corpus never grows and a deeper path is reachable only by a
            # single lucky mutation from a seed.
            new_blocks = set()
            if all_blocks and res.note:
                try:
                    new_blocks = {int(x) for x in res.note.split(",") if x} - seen_blocks
                except ValueError:
                    new_blocks = set()
                seen_blocks |= new_blocks
            b = behaviour_of(res, data)
            novel = bool(new_blocks) if all_blocks else (b not in seen_behaviour)
            if b not in seen_behaviour:
                seen_behaviour.add(b)
            if novel:
                if not res.crashed and len(data) <= _MAX_KEEP:  # noqa: SIM102
                    if len(corpus) < _MAX_CORPUS:
                        corpus.append(data)
                    else:
                        # Full: ROTATE rather than stop learning. Capping without replacement
                        # freezes the corpus around whatever shallow behaviours were found first,
                        # which is most of them -- the interesting paths are discovered late.
                        corpus[rng.randrange(len(corpus))] = data
                    kept += 1
            if res.crashed:
                crashes += 1
                corpus.append(data)                        # explore near crashers
                if res.signal_name not in seen_sigs:
                    seen_sigs.add(res.signal_name)
                    sig = res.signal_name

                    def _same(d, _sig=sig):
                        r = run_fn(exe, mode, workfile, exec_timeout, target.arch, d,
                                  endianness=target.endianness, bits=target.bits)[1]
                        return r.crashed and r.signal_name == _sig

                    budget = min(200, max(20, max_execs - execs))
                    mdata, mexecs = minimize(_same, data, cap=budget)
                    execs += mexecs
                    note = (f"minimized {len(data)}->{len(mdata)}B"
                            if len(mdata) < len(data) else None)
                    margv = invocation(mode, workfile, mdata)[0]
                    input_sha = ctx.put_artifact("fuzz-crash-input", data=mdata)
                    dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                              input_mode=mode, argv=margv, signal=res.signal, signal_name=sig,
                              crashed=True, isolation=res.isolation,
                              duration_ms=res.duration_ms, note=note)
                    extra = "(" + note_prefix + ("; " + note if note else "") + ")"
                    fd.upsert(target.id, target.case_id, crash_finding_candidate(
                        sig, input_sha, res.isolation, detector, extra))
                else:
                    input_sha = ctx.put_artifact("fuzz-crash-input", data=data)
                    dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                              input_mode=mode, argv=argv, signal=res.signal,
                              signal_name=res.signal_name, crashed=True, isolation=res.isolation,
                              duration_ms=res.duration_ms)
        if execs % 250 == 0:
            ctx.emit(f"{event_prefix}.progress", payload={"execs": execs, "crashes": crashes,
                                                          "unique": len(seen_sigs),
                                                          "behaviours": len(seen_behaviour),
                                                          "corpus": len(corpus)})

    elapsed = max(1e-3, max_seconds - max(0.0, deadline - time.time()))
    stats = {"execs": execs, "crashes": crashes, "unique": len(seen_sigs),
             "behaviours": len(seen_behaviour), "corpus": len(corpus), "kept": kept,
             "execs_per_sec": round(execs / elapsed),
             "blocks_hit": len(seen_blocks), "blocks_known": len(all_blocks)}
    ctx.emit(f"{event_prefix}.done", payload=stats)
    ctx.progress(pct=100, msg=f"{execs} execs, {crashes} crashes, {len(seen_sigs)} unique, "
                             f"{len(seen_behaviour)} behaviours")
    return stats


def _recovered_blocks(ctx, target):
    """Basic-block addresses as FILE vaddrs, or () when the target has not been disassembled.

    The decompiler already walked this binary; its block list is coverage instrumentation we
    have already paid for. Addresses are shifted out of the decompiler's image base so the
    runner can place them whether the target is position-independent or not.
    """
    from ..debug import rootcause
    from ..elf import parse as parse_elf
    fd = FunctionDAO(ctx.conn)
    fns = fd.list_by_target(target.id)
    if not fns:
        return ()
    try:
        entry = parse_elf(ctx.content.path(target.sha256).read_bytes()).entry
    except Exception:
        entry = None
    base = rootcause.image_base(fns, entry) or 0
    out = set()
    for f in fns:
        if not f.blocks:
            continue
        full = fd.get(f.id)
        for b in ((full.ir or {}).get("blocks") or []):
            try:
                out.add(int(b["addr"], 16) - base)
            except (KeyError, TypeError, ValueError):
                continue
    return sorted(out)


def fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("fuzz requires a target_id")

    p = ctx.params or {}
    # Which channels to fuzz. Committing to one is wrong even when the inference is right
    # about what the program READS: ncompress genuinely parses files, and its overflow is in
    # the filename it was handed on the command line. A campaign aimed at the wrong channel
    # does no work and reports a clean zero.
    channels = ([p["input_mode"]] if p.get("input_mode")
                else modes_for(CallEdgeDAO(ctx.conn).list_by_target(target.id)))
    max_execs = int(p.get("max_execs", 3000))
    max_seconds = float(p.get("max_seconds", 30))
    exec_timeout = float(p.get("exec_timeout", 2))
    rng = random.Random(int(p.get("seed", 1337)))

    strings = StringDAO(ctx.conn).list_by_target(target.id)
    blocks = _recovered_blocks(ctx, target)
    corpus = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_DEFAULT_SEEDS)
    dictionary = _mine_dictionary(strings)
    mutator, note = _structure_mutator(p, rng, dictionary), "found by fuzzing"
    fmt = p.get("format_name") or ("custom" if p.get("format") else None)
    if mutator is None and not p.get("format"):
        # Nobody supplied a model, so ask the binary. A parser rejects random bytes before it
        # reaches any of its own logic -- jhead ran 98,500 executions for zero finds while
        # AFL++ reached the same bug in 60 seconds WITH a valid sample -- and the target's own
        # strings say which format it reads. The model then yields a seed that passes the gate,
        # so the campaign starts inside the parser instead of at its front door.
        fmt = structure.detect_format([x.value for x in strings])
        if fmt:
            model = structure.builtin(fmt)
            mutator = structure.StructMutator(rng, model, dictionary)
            seed = structure.seed_for_name(fmt)
            if seed:
                corpus = [seed] + list(corpus)
    if mutator:
        note = "found by structure-aware fuzzing"
        ctx.emit("fuzz.format", payload={"model": fmt or "custom", "auto": not (
            p.get("format") or p.get("format_name"))})
    # Split the budget across them, stopping early on a crash. A bug is usually reachable
    # through one channel only, and which one is not knowable in advance.
    share_execs = max(1, max_execs // len(channels))
    share_secs = max(1.0, max_seconds / len(channels))
    totals = {"execs": 0, "crashes": 0, "unique": 0, "behaviours": 0}
    for ch in channels:
        st = fuzz_campaign(ctx, target, corpus=list(corpus), dictionary=dictionary, mode=ch,
                           max_execs=share_execs, max_seconds=share_secs,
                           exec_timeout=exec_timeout, rng=rng, detector="fuzz",
                           event_prefix="fuzz", note_prefix=note, mutator=mutator,
                           cover_blocks=blocks)
        for k in totals:
            totals[k] += st.get(k, 0)
        if st.get("crashes"):
            break
    ctx.emit("fuzz.channels", payload={"channels": channels, **totals})
    return {}


def _structure_mutator(p, rng, dictionary):
    """Build a structure-aware mutator from params.format (a field spec) or params.format_name
    (a built-in model). params.magic overrides a built-in's placeholder magic. None otherwise."""
    from . import structure
    model = None
    if p.get("format"):
        model = structure.from_spec(p["format"])
    elif p.get("format_name"):
        model = structure.builtin(p["format_name"])
    if model is None:
        return None
    magic = p.get("magic")                             # override the model's magic (e.g. a gate)
    if magic and model.spec and model.spec[0].get("type") == "magic":
        model.spec[0]["value"] = base64.b64decode(magic) if p.get("magic_b64") else magic
    return structure.StructMutator(rng, model, dictionary)


def register() -> None:
    register_stage(FUZZ_STAGE, fuzz_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=3600)


def enqueue_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, FUZZ_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
