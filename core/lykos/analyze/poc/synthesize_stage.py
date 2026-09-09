"""Phase 6 — the `synthesize_poc` stage: turn a *static* stack-overflow finding into a
reproduced crash + verified PoC **without fuzzing**.

Fuzzing rediscovers, over thousands of executions, an input that the recovered stack frame
already tells us: a buffer of size N whose start sits `offset` bytes from the saved return
address. This stage synthesizes that input directly -- cyclic filler to the predicted offset
plus a sentinel at the return slot (`primitive.control_input`) -- delivers it over the input
channel the binary actually reads, and detonates once in the sandbox. On a crash it builds a
verified L1 PoC and promotes the finding, exactly like a fuzzer-found crash, and the crashing
input then feeds `poc_primitive` (L2) / `build_exploit` (L3) unchanged.

Deterministic and budget-free. Honest limit: it delivers the payload straight to the entry
channel, so it reproduces overflows the input reaches directly (parsers, argv/stdin handlers);
a bug gated behind menu navigation or a specific protocol still needs fuzzing/concolic to reach.
"""
from __future__ import annotations

import os

from ...db.dao import CallEdgeDAO, FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import bundle, primitive
from .primitive_stage import _hydrate_frames

SYNTH_STAGE = "synthesize_poc"
TOOL = "synth"
TOOL_VERSION = "synth-1"

# input-reading imports -> the channel that reaches a buffer (heuristic ordering only)
_STDIN_FUNCS = {"read", "fgets", "gets", "scanf", "__isoc99_scanf", "fread", "getchar",
                "getline", "fgetc"}
_FILE_FUNCS = {"fopen", "fopen64", "open", "open64", "freopen"}


def _modes_for(call_edges, given):
    """Order the input channels to try: honour an explicit mode, else rank by the input
    functions the binary imports, always ending with all three tried."""
    if given:
        return [given]
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    ordered = []
    if names & _FILE_FUNCS:
        ordered.append("file")
    if names & _STDIN_FUNCS:
        ordered.append("stdin")
    ordered.append("arg")
    for m in ("stdin", "arg", "file"):        # ensure every channel is attempted
        if m not in ordered:
            ordered.append(m)
    return ordered


def _deliver(mode, payload, argv_base, ctx):
    if mode == "stdin":
        return list(argv_base), payload
    if mode == "arg":
        return argv_base + [payload.decode("latin-1")], b""
    wf = ctx.scratch() / "input.bin"          # file
    wf.write_bytes(payload)
    return argv_base + [str(wf)], b""


def synthesize_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("synthesize_poc requires a target_id")
    p = ctx.params or {}
    word = 8 if (target.bits or 64) >= 64 else 4
    endian = "big" if target.endianness == "big" else "little"

    frames = _hydrate_frames(ctx, target.id)
    candidates = primitive.frame_offset_candidates(frames, word)
    if not candidates:
        ctx.emit("synth.done", payload={"ok": False, "crashed": False,
                 "note": "no stack buffers recovered -- run Decompile first (needs the frame)"})
        ctx.progress(pct=100, msg="no recovered stack buffers to synthesize from")
        return {}

    call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    modes = _modes_for(call_edges, p.get("input_mode"))
    argv_base = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 8))

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(target_bytes)
    os.chmod(exe, 0o755)

    ctx.emit("synth.start", payload={"candidates": candidates[:8], "modes": modes})
    tried, cap = 0, 48
    for c in candidates[:6]:                  # a few of the largest/tightest buffers
        for off, _c, slack in primitive.seed_offsets([c], word):   # predicted offset, +/- a word
            payload = primitive.control_input(off, off + word * 4 + 16, word, endian)
            for mode in modes:
                if tried >= cap:
                    break
                tried += 1
                run_argv, stdin = _deliver(mode, payload, argv_base, ctx)
                ctx.progress(msg=f"detonating synthesized overflow (buffer {c['buffer']}, "
                                 f"offset {off}, {mode})")
                res = sandbox.run(exe, argv=run_argv, stdin=stdin, timeout=timeout,
                                  arch=target.arch, endianness=target.endianness,
                                  bits=target.bits)
                if res.crashed:
                    return _finalize(ctx, target, target_bytes, payload, mode, run_argv,
                                     res, c, off, slack, tried)

    ctx.emit("synth.done", payload={"ok": True, "crashed": False, "tried": tried,
             "note": "synthesized overflow inputs did not reproduce a crash -- the buffer may "
                     "not be reachable directly (menu/protocol navigation); try fuzzing/concolic"})
    ctx.progress(pct=100, msg=f"no crash from {tried} synthesized inputs (buffer not reached)")
    return {}


def _finalize(ctx, target, target_bytes, payload, mode, run_argv, res, cand, off, slack, tried):
    input_sha = ctx.put_artifact("synth-crash-input", data=payload)
    detail = (f"synthesized from static CWE-121: {cand['size']}-byte buffer {cand['buffer']} at "
              f"offset {off}"
              + (f" (predicted {cand['offset']}{'+' if slack > 0 else ''}{slack if slack else ''})"
                 if slack else "") + "; no fuzzing")
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "argv": run_argv, "expected_signal": res.signal_name, "isolation": res.isolation,
            "verified": True, "level": "L1", "synthesized": True, "offset": off,
            "buffer": cand["buffer"], "buffer_size": cand["size"], "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, payload, meta, res.stderr, mode, run_argv,
                        res.signal_name or "SIGSEGV")
    bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                  meta={"verified": True, "level": "L1"})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L1", verified=True,
                                     signal_name=res.signal_name, input_sha=input_sha,
                                     bundle_sha=bundle_sha)
    fd = FindingDAO(ctx.conn)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        res.signal_name, input_sha, res.isolation, "synth_overflow", f"({detail})",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha))
    fid = fd.id_for_dedup(target.id, f"dynamic-crash:{res.signal_name}")
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)

    ctx.emit("synth.done", payload={"ok": True, "crashed": True, "offset": off,
             "buffer": cand["buffer"], "buffer_size": cand["size"], "mode": mode,
             "signal": res.signal_name, "level": "L1", "bundle": bundle_sha, "tried": tried,
             "input_sha": input_sha})
    ctx.progress(pct=100, msg=f"synthesized crash: {res.signal_name} via {cand['buffer']} "
                             f"overflow at offset {off} ({mode})")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def register() -> None:
    register_stage(SYNTH_STAGE, synthesize_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=180)


def enqueue_synthesize(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, SYNTH_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
