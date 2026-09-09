"""Phase 5 — the `fuzz` stage: black-box mutational fuzzing over the sandbox executor.

Drives inputs through the Phase-4 sandbox, detects crashes, dedups them, saves the crashing
input as an artifact, records a dyn_result, and turns each unique crash into a Confirmed
finding (L1: crash + reproducible input). Budget-bounded (execs + wall-clock); cancellable.

The core loop is exposed as `fuzz_campaign()` so the directed-fuzzing stage can reuse it with
a targeted corpus/dictionary aimed at statically-flagged sinks.
"""
from __future__ import annotations

import base64
import os
import random
import time

from ...db.dao import DynResultDAO, FindingDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic.minimize import minimize
from ..dynamic.stage import crash_finding_candidate
from .mutator import Mutator
from .runner import invocation, run_input

FUZZ_STAGE = "fuzz"
TOOL = "fuzz"
TOOL_VERSION = "fuzz-1"
_DEFAULT_SEEDS = [b"", b"A" * 8, b"%s%s%s%n", b"0", b"-1", b"../../etc/passwd"]


def _mine_dictionary(strings):
    toks = []
    for s in strings:
        v = (s.value or "").strip()
        if v and len(v) <= 64:
            toks.append(v.encode("latin-1", "ignore"))
    return toks[:500]


def fuzz_campaign(ctx, target, *, corpus, dictionary, mode, max_execs, max_seconds,
                  exec_timeout, rng, detector, event_prefix, note_prefix, run_fn=run_input):
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
    mut = Mutator(rng, dictionary)
    fd = FindingDAO(ctx.conn)
    dd = DynResultDAO(ctx.conn)
    deadline = time.time() + max_seconds
    execs = crashes = 0
    seen_sigs = set()

    ctx.progress(msg=f"{event_prefix} campaign")
    while execs < max_execs and time.time() < deadline and not ctx.should_cancel():
        data = mut.mutate(rng.choice(corpus), corpus)
        argv, res = run_fn(exe, mode, workfile, exec_timeout, target.arch, data,
                              endianness=target.endianness, bits=target.bits)
        execs += 1
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
                                                          "unique": len(seen_sigs)})

    ctx.emit(f"{event_prefix}.done", payload={"execs": execs, "crashes": crashes,
                                              "unique": len(seen_sigs)})
    ctx.progress(pct=100, msg=f"{execs} execs, {crashes} crashes, {len(seen_sigs)} unique")
    return {"execs": execs, "crashes": crashes, "unique": len(seen_sigs)}


def fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("fuzz requires a target_id")

    p = ctx.params or {}
    mode = p.get("input_mode", "stdin")               # stdin | arg | file
    max_execs = int(p.get("max_execs", 3000))
    max_seconds = float(p.get("max_seconds", 30))
    exec_timeout = float(p.get("exec_timeout", 2))
    rng = random.Random(int(p.get("seed", 1337)))

    corpus = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_DEFAULT_SEEDS)
    dictionary = _mine_dictionary(StringDAO(ctx.conn).list_by_target(target.id))
    fuzz_campaign(ctx, target, corpus=corpus, dictionary=dictionary, mode=mode,
                  max_execs=max_execs, max_seconds=max_seconds, exec_timeout=exec_timeout,
                  rng=rng, detector="fuzz", event_prefix="fuzz", note_prefix="found by fuzzing")
    return {}


def register() -> None:
    register_stage(FUZZ_STAGE, fuzz_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=3600)


def enqueue_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, FUZZ_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
