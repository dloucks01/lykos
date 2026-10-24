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

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, PocDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import asan_defect_key, crash_dedup_key, crash_finding_candidate, crash_key_parts
from . import bundle, primitive, recipe
from .capture import modes_for
from .primitive_stage import _hydrate_frames

SYNTH_STAGE = "synthesize_poc"
TOOL = "synth"
TOOL_VERSION = "synth-1"

from ..invocation import staged_name as _staged_name


def _deliver(mode, payload, argv_base, ctx):
    if mode == "stdin":
        return list(argv_base), payload
    if mode == "arg":
        # A synthesized payload always carries a sentinel address, and a sentinel always
        # contains NUL bytes. Handing that to subprocess raw raises "embedded null byte", so
        # every argv-reachable overflow reported "no crash from N synthesized inputs" -- on
        # ncompress, whose overflow is argv-only and already confirmed to L2.
        # execve truncates at the first NUL anyway, so this delivers what the kernel would.
        return argv_base + [sandbox.argv_arg(payload, truncate=True)], b""
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

    frames = _hydrate_frames(ctx, target.id, target)
    candidates = primitive.frame_offset_candidates(frames, word)
    if not candidates:
        ctx.emit("synth.done", payload={"ok": False, "crashed": False,
                 "note": "no stack buffers recovered -- run Decompile first (needs the frame)"})
        ctx.progress(pct=100, msg="no recovered stack buffers to synthesize from")
        return {}

    call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    modes = modes_for(call_edges, p.get("input_mode"), file_type=target.file_type)
    argv_base = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 8))

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    # Staged under the name the image dispatches on (busybox and any other multi-call
    # binary refuse every input as `target.bin`): see invocation.staged_name.
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)
    if not argv_base:
        # A PARAMETER-DRIVEN target refuses to run until its required option is supplied, and this
        # stage is enqueued without params, so argv was always empty: the synthesized overflow was
        # delivered to a program that printed its usage and exited, and the one stage that can prove
        # this bug class reported "no crash". The fuzz stage already mines the invocation for itself;
        # do the same here rather than leave the proof unreachable. Best-effort: an undiscoverable
        # invocation just leaves argv empty, exactly as before.
        try:
            from .. import invocation as _inv
            _strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                        if getattr(x, "value", None)]
            _found = _inv.discover(_strings, prog=getattr(target, "filename", None))
            _cand = _inv.materialize(_found, ctx.scratch())
            if _cand:
                _smp = ctx.scratch() / "inv-sample"
                _smp.write_bytes(b"# lykos\n")

                def _probe(a):
                    return sandbox.run(exe, argv=a, stdin=b"", timeout=max(4.0, timeout),
                                       arch=target.arch, endianness=target.endianness,
                                       bits=target.bits)
                _v = _inv.verify(_probe, exe, _cand, str(_smp))
                if _v.get("accepted") and _v.get("bare_rejected"):
                    argv_base = [str(a) for a in _cand]
                    ctx.progress(msg="required invocation discovered: " + " ".join(argv_base))
        except Exception:                                # noqa: BLE001 -- never block the synthesis
            pass                                 # discovery is an optimisation, not a gate

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

    # NON-EXECUTED RECIPE: the overflow input is DERIVED from the recovered frame, not from a
    # fuzzer -- the exact offset + sentinel-at-return-slot payload exists whether or not this one
    # detonation faulted (it may not have reached the buffer here: menu/protocol gating, wrong
    # channel, or the target could not be executed at all). Emit it as a corroborated recipe + the
    # concrete bytes rather than discarding a computed L1 just because confirmation was unavailable.
    top = candidates[0]
    rec_off = int(top.get("offset") or 0)
    lead, exact = _overflow_lead(ctx, target, target_bytes)
    where = f"{top['size']}-byte buffer {top['buffer']}"
    key = f"recipe:stack-overflow:{top['buffer']}:{target.id}"
    off_note = ""
    if exact is not None:
        # The COPY SITE says which buffer is written and where the return slot is: exact, where the
        # frame-based prediction above is the distance to the saved frame pointer on an rbp frame
        # (one word short) and names the tightest buffer, not necessarily the destination.
        rec_off = int(exact["payload_offset"])
        where = (f"the {exact['func']}() destination at rbp{exact['dest_disp']:+#x}"
                 if exact["dest_base"] == "rbp" else f"the {exact['func']}() destination")
        key = f"recipe:stack-overflow:{exact['site']:#x}:{target.id}"
        off_note = (f" (exact, from the copy site at {exact['site']:#x}"
                    + (f"; {'; '.join(exact['notes'])}" if exact["notes"] else "") + ")")
    rec_payload = primitive.control_input(rec_off, rec_off + word * 4 + 16, word, endian)
    why = (f"the {tried} synthesized input(s) did not fault in this sandbox -- the buffer may be "
           "gated behind menu/protocol navigation or the target could not be executed here")
    recipe.file_recipe(
        ctx, target, cwe=(lead.cwe if lead and lead.cwe else "CWE-121"),
        technique="stack-overflow return-address overwrite", target_level="L1",
        severity="high", detector="synth_overflow",
        dedup_key=key,
        title=f"Exploitation recipe: stack overflow of {top['buffer'] if exact is None else where}",
        summary=(f"{where}: write {rec_off} bytes of cyclic filler{off_note} then a sentinel at "
                 f"the saved return address (word {word}B, {endian}-endian) to take control of the "
                 f"return address"),
        why_not_executed=why,
        lead=lead, input_bytes=rec_payload, input_mode=(modes or ["stdin"])[0], argv=argv_base or None)
    # One rung further when the image allows it: a win function, no PIE, no canary in the frame ->
    # the return slot gets &win instead of a sentinel. A candidate L3, the payload carried over.
    if exact is not None:
        _file_ret2win_recipe(ctx, target, target_bytes, exact, lead, why, word, endian,
                             (modes or ["stdin"])[0], argv_base)
    ctx.emit("synth.done", payload={"ok": True, "crashed": False, "tried": tried,
             "recipe": True,
             "note": "synthesized overflow inputs did not reproduce a crash -- filed the computed "
                     "offset/payload as a corroborated recipe; the buffer may not be reachable "
                     "directly (menu/protocol navigation) or the target could not be executed"})
    ctx.progress(pct=100, msg=f"no crash from {tried} inputs -- filed overflow recipe for {top['buffer']}")
    return {}


#: Detectors whose CWE-121/120 finding names an unbounded copy SITE (function + call address).
_OVERFLOW_DETECTORS = ("stack_frame", "stack_buffer_overflow", "dangerous_api")
_OVERFLOW_CWES = ("CWE-121", "CWE-120", "CWE-787", "CWE-242")


def _overflow_lead(ctx, target, target_bytes):
    """(lead, exact layout or None): the overflow finding to annotate, and -- when its copy site is
    recoverable on an x86-64 rbp frame -- the exact geometry from `overflow_recipe`. The stack-frame
    detector's row is preferred (it is the one that correlated a buffer with the sink)."""
    from . import fmt_recipe, overflow_recipe, x64frame
    try:
        rows = [f for f in FindingDAO(ctx.conn).list_by_target(target.id)
                if f.cwe in _OVERFLOW_CWES and not (f.title or "").startswith("Exploitation recipe")]
    except Exception:                                    # noqa: BLE001 -- lead linkage is best-effort
        return None, None
    rows.sort(key=lambda f: ((f.detector or "") not in _OVERFLOW_DETECTORS,
                             (f.detector or "") != "stack_frame", -(f.confidence or 0)))
    lead = rows[0] if rows else None
    if not fmt_recipe._x86_64(target):
        return lead, None
    for f in rows[:8]:
        if not (f.function_addr and f.site_addr):
            continue
        try:
            ir = fmt_recipe._function_ir(ctx.conn, target.id, f.function_addr)
            if not ir:
                continue
            ins = x64frame.instructions(ir)
            k = x64frame.site_index(ins, f.site_addr)
            name = x64frame.call_target(ins[k][1]) if k is not None else None
            lay = overflow_recipe.overflow_layout(ir, f.site_addr, name or "", target_bytes)
        except Exception:                                # noqa: BLE001
            lay = None
        if lay:
            return f, lay
    return lead, None


def _file_ret2win_recipe(ctx, target, target_bytes, exact, lead, why, word, endian, mode,
                         argv_base) -> None:
    """File the ret2win candidate (L3 ceiling) for an exactly-placed overflow -- only when the
    image makes the address a literal fact (no PIE) and the frame has no canary."""
    from . import elfstatic, exploit, overflow_recipe
    try:
        if exact.get("canary") or elfstatic.is_pie(target_bytes):
            return
        edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        win = exploit.find_win(exploit.elf_functions(target_bytes), call_edges=edges)
        if not (win and win[0]):
            return
        payload = overflow_recipe.ret2win_payload(exact, int(win[1]), word=word, endian=endian)
        if payload is None:
            return
        alt = exploit.win_realign_entry(target_bytes, int(win[1]))
        recipe.file_recipe(
            ctx, target, cwe=(lead.cwe if lead and lead.cwe else "CWE-121"),
            technique=f"stack-overflow ret2win -> {win[0]}", target_level="L3", severity="high",
            detector="synth_overflow",
            dedup_key=f"recipe:ret2win:{exact['site']:#x}:{target.id}",
            title=f"Exploitation recipe: stack overflow ret2win -> {win[0]} (candidate)",
            summary=(f"{exact['func']}() at {exact['site']:#x}: {exact['payload_offset']} bytes of "
                     f"filler then &{win[0]} ({int(win[1]):#x}) over the saved return address -- "
                     "no PIE (fixed address), no stack canary in this frame"),
            steps=[f"send the {len(payload)}-byte payload over {mode}",
                   f"if {win[0]} faults on a misaligned stack (movaps in system()), use the "
                   f"realigned entry {alt:#x} in place of {int(win[1]):#x}"]
                  + list(exact.get("notes") or []),
            why_not_executed=why, lead=lead, input_bytes=payload, input_mode=mode,
            argv=argv_base or None)
    except Exception:                                    # noqa: BLE001 -- the L1 recipe stands
        pass


def _finalize(ctx, target, target_bytes, payload, mode, run_argv, res, cand, off, slack, tried):
    input_sha = ctx.put_artifact("synth-crash-input", data=payload)
    # Record the fault as a first-class crashing dyn_result, exactly like a fuzzer-found crash. The
    # autopilot's prove/exploit phase selects crashes from the dyn_result table (distinct_crashes),
    # so without this row the synthesized L1 crash is invisible to root_cause -> build_poc ->
    # build_exploit and the ladder stalls at L1 instead of climbing to L2/L3. Written before the
    # fault_pc lookup below so it resolves against this row.
    defect_key = asan_defect_key(res.stderr) if res.signal_name == "SIGABRT" else None
    DynResultDAO(ctx.conn).insert(
        target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha, input_mode=mode,
        argv=list(run_argv), signal=res.signal, signal_name=res.signal_name, crashed=True,
        isolation=res.isolation, duration_ms=res.duration_ms, fault_pc=res.fault_pc,
        defect_key=defect_key, note="synthesized from the static stack frame; no fuzzing")
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
    # With the discriminator, or a sanitizer abort is filed under the signal alone and does not
    # meet the per-defect finding the fuzz stage filed. See `crash_key_parts`.
    fault_pc, disc, _ = crash_key_parts(ctx.conn, target.id, input_sha)
    fd.upsert(target.id, target.case_id, crash_finding_candidate(
        res.signal_name, input_sha, res.isolation, "synth_overflow", f"({detail})",
        state="poc-backed", confidence=0.95, bundle_sha=bundle_sha, fault_pc=fault_pc,
        discriminator=disc))
    fid = fd.id_for_dedup(target.id, crash_dedup_key(res.signal_name, fault_pc, disc))
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
