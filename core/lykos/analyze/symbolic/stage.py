"""Phase 6 — the `concolic` stage: hybrid concolic execution with a selectable backend.

The fuzzer explores broadly but stalls at narrow checks (magic bytes, checksums, deep
branches). Concolic execution complements it by solving path constraints and emitting concrete
inputs. Two backends, chosen by params.backend ("auto" | "angr" | "symqemu"):

  * angr    -- symbolic exploration steered toward the statically-flagged sink sites; can
               report which sink an input reaches (corroborating the static finding).
  * symqemu -- QEMU-based concolic execution seeded by the fuzzer corpus; fast, source-free,
               generates new inputs by flipping branches along the concrete path.

Every generated input is replayed in the Phase-4 sandbox: a crash becomes a Confirmed finding,
a reached sink corroborates the static finding, and the rest become new seeds for the fuzzer.
Both backends are optional bundled tools; the stage fails clearly when the requested backend
is unavailable and the fuzzing stages remain the deterministic fallback.
"""
from __future__ import annotations

import base64
import json

from ...db.dao import DynResultDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from ..fuzz.directed import select_targets
from ..fuzz.runner import _sub_output, invocation
from ..poc.capture import how_to_feed
from . import concolic, symqemu

CONCOLIC_STAGE = "concolic"
TOOL = "concolic"
TOOL_VERSION = "concolic-1"


def _gather_seeds(conn, target_id, limit=16):
    seen, out = set(), []
    for d in DynResultDAO(conn).list_by_target(target_id):
        if d.input_sha and d.input_sha not in seen:
            seen.add(d.input_sha)
            out.append(d.input_sha)
        if len(out) >= limit:
            break
    return out


#: a reachability signal only touches a lead that is not already program-level demonstrated;
#: it must never revise a confirmed / poc-backed finding.
_REACH_STATES = ("candidate", "corroborated")


def _same_addr(a, b) -> bool:
    """Compare two addresses that may be hex strings ("0x2020"), decimal strings, or differ only
    in leading zeros / case. The driver emits "0x%x"; findings store whatever the detector wrote."""
    if not a or not b:
        return False
    if a == b:
        return True
    try:
        ia = int(a, 16) if str(a).lower().startswith("0x") else int(a)
        ib = int(b, 16) if str(b).lower().startswith("0x") else int(b)
        return ia == ib
    except (ValueError, TypeError):
        return False


def _corroborate_sink(conn, target, reached_addr, *, evidence_detail, confidence=0.75):
    """A symbolically-generated input that reaches a flagged site promotes that lead to
    `corroborated` -- a second channel now agrees it is reachable from the modeled entry. Matches
    by site OR function address and is detector-agnostic (a static dangerous-api sink, a taint sink
    and a harness function-level lead all qualify), but only RAISES a lead that is not already
    program-level demonstrated. Returns the number of findings promoted."""
    fd = FindingDAO(conn)
    n = 0
    for f in fd.list_by_target(target.id):
        if (f.state or "candidate") not in _REACH_STATES:
            continue
        if _same_addr(f.site_addr, reached_addr) or _same_addr(f.function_addr, reached_addr):
            fd.upsert(target.id, target.case_id, {
                "cwe": f.cwe, "title": f.title, "severity": f.severity,
                "state": "corroborated", "confidence": max(f.confidence or 0.0, confidence),
                "detector": f.detector, "function_addr": f.function_addr,
                "site_addr": f.site_addr, "dedup_key": f.dedup_key,
                "evidence": [{"channel": "symbolic", "detail": evidence_detail}]})
            n += 1
    return n


def _record_unreached(ctx, target, meta, reached) -> int:
    """T3: the honest half of a reachability certificate. When -- and ONLY when -- the search hit a
    natural fixpoint (`drained` and not `cutoff`), a flagged target the search never reached is a
    candidate false positive. We ANNOTATE it (so the operator can de-prioritize) but NEVER drop or
    downgrade it: the model is partial (libs unloaded, one modeled entry, bounded), so a real reach
    via another entry / argv / library path stays possible. The annotation goes on a SEPARATE
    `reachability` channel at zero confidence, so it can never revise down the `symbolic` channel
    that may have corroborated the same finding in another run."""
    if not (meta.get("drained") and not meta.get("cutoff")):
        return 0
    reached_set = list(reached or [])
    fd = FindingDAO(ctx.conn)
    findings = fd.list_by_target(target.id)
    n = 0
    for addr in meta.get("targets", []):
        if any(_same_addr(addr, r) for r in reached_set):
            continue
        for f in findings:
            if (f.state or "candidate") not in _REACH_STATES:
                continue
            if _same_addr(f.site_addr, addr) or _same_addr(f.function_addr, addr):
                fd.upsert(target.id, target.case_id, {
                    "cwe": f.cwe, "title": f.title, "severity": f.severity,
                    "state": "candidate", "confidence": 0.0,   # a zero-weight annotation channel
                    "detector": f.detector, "function_addr": f.function_addr,
                    "site_addr": f.site_addr, "dedup_key": f.dedup_key,
                    "evidence": [{"channel": "reachability", "detail": (
                        "concolic explored to a natural fixpoint from the modeled entry (libs "
                        "unloaded, bounded) and did NOT reach this site. It may be unreachable in "
                        "this invocation -- DE-PRIORITIZE -- but it is NOT dropped: the model is "
                        "partial, so a real path via another entry / argv / library is still "
                        "possible.")}]})
                n += 1
    return n


def _certificate(ctx, *, sink_addr, input_sha, input_len, mode, base_argv, meta):
    """Store a replayable REACHABILITY CERTIFICATE (T3): the concrete input, in the program's real
    invocation terms, that drives execution from the modeled entry to a flagged sink. Returns its
    content sha so the finding evidence can cite it."""
    explored = (meta or {}).get("argv")
    cert = {
        "kind": "reachability-certificate",
        "sink_addr": sink_addr,
        "input_mode": mode,                                  # stdin | file | arg
        # The invocation the model ACTUALLY explored (@@ = input). Only that argv is certified: a
        # cert naming flags the exploration never saw would vouch for a path nobody explored. When
        # the backend did not report it, keep the replay shape but SAY it was not the explored one.
        "argv": list(explored) if explored is not None else list(base_argv),
        "argv_explored": explored is not None,
        "input_sha": input_sha,                              # the concrete reaching input (artifact)
        "input_len": input_len,
        "angr_version": (meta or {}).get("angr_version"),
        "model": ("angr auto_load_libs=False; bounded symbolic exploration from full_init_state -- "
                  "reachability is relative to this model, not a whole-program proof"),
    }
    return ctx.put_artifact("reachability-certificate",
                            data=json.dumps(cert, sort_keys=True).encode())


def _validate(ctx, target, exe, mode, workfile, generated, exec_timeout, base_argv=(), meta=None):
    """Replay each generated input in the sandbox and record crashes / corroborations / seeds.
    `generated` items are dicts: {input_b64, reached?}. A non-crashing input that reaches a flagged
    sink promotes the lead to corroborated AND files a reachability certificate (T3). Returns
    (confirmed, corroborated, new_seeds, certified)."""
    fd = FindingDAO(ctx.conn)
    dd = DynResultDAO(ctx.conn)
    confirmed = corroborated = new_seeds = certified = 0
    seen_sigs = set()
    for g in generated:
        if ctx.should_cancel():
            break
        data = base64.b64decode(g["input_b64"])
        argv, stdin = invocation(mode, workfile, data, base_argv)   # honour the target's flags / `@@`
        r = sandbox.run(exe, argv=argv, stdin=(stdin if mode == "stdin" else b""),
                        timeout=exec_timeout, arch=target.arch,
                        endianness=target.endianness, bits=target.bits)
        input_sha = ctx.put_artifact("concolic-input", data=data)
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                  # the invocation prefix it ran under (`-c @@`), as the dynamic stage records it:
                  # a crash stored with argv=[] is replayed by root_cause/build_poc WITHOUT the
                  # flags and reads as "did not fault"
                  input_mode=mode, argv=list(base_argv), exit_code=r.exit_code, signal=r.signal,
                  signal_name=r.signal_name, crashed=r.crashed, isolation=r.isolation,
                  duration_ms=r.duration_ms,
                  note="concolic-generated" + (f"; reached {g['reached']}"
                                               if g.get("reached") else ""))
        if r.crashed:
            if r.signal_name not in seen_sigs:
                seen_sigs.add(r.signal_name)
                fd.upsert(target.id, target.case_id, crash_finding_candidate(
                    r.signal_name, input_sha, r.isolation, "concolic",
                    "(generated by concolic execution)"))
            confirmed += 1
        elif g.get("reached") and g["reached"] not in (None, "unconstrained-ip"):
            cert_sha = _certificate(ctx, sink_addr=g["reached"], input_sha=input_sha,
                                    input_len=len(data), mode=mode, base_argv=base_argv, meta=meta)
            detail = (f"a concolic-solved input reaches this site from the modeled program entry; "
                      f"reachability certificate {cert_sha[:12]} (input {input_sha[:12]}, {len(data)}"
                      f" B, mode {mode}) replays the path. Program-level reachability of the FLAGGED "
                      f"SITE demonstrated under the concolic model; not yet a crashing PoC.")
            promoted = _corroborate_sink(ctx.conn, target, g["reached"], evidence_detail=detail)
            if promoted:
                corroborated += promoted
                certified += 1
            else:
                new_seeds += 1                               # reached, but no matching flagged lead
        else:
            new_seeds += 1
    return confirmed, corroborated, new_seeds, certified


def _choose_backend(p, target):
    """Return (backend, angr_python, symqemu_path). Honors params.backend; auto prefers angr
    (directed, sink-aware) then symqemu."""
    want = p.get("backend", "auto")
    py = concolic.locate_angr_python(p.get("angr_python")) if want in ("auto", "angr") else None
    sq = (symqemu.locate_symqemu(p.get("symqemu_path"), target.arch or "x86-64")
          if want in ("auto", "symqemu") else None)
    if want == "angr":
        return ("angr", py, None) if py else (None, None, None)
    if want == "symqemu":
        return ("symqemu", None, sq) if sq else (None, None, None)
    if py:
        return "angr", py, None
    if sq:
        return "symqemu", None, sq
    return None, None, None


def _frame_sized_input(ctx, target, fallback=64, cap=4096):
    """How many symbolic input bytes concolic needs to EXPRESS a stack overflow on this target.

    A fixed 64-byte symbolic input can satisfy an input gate (a magic token) but can never
    generate a return-address-smashing input for a buffer larger than 64 bytes -- so concolic
    solved a `strstr(input,"TOKEN")` input gate yet stopped short of the overflow, because the
    vulnerable buffer sat 136 bytes from the saved return address and the symbolic input was 64.
    Size it from the largest recovered frame offset (buffer + saved regs + return slot) so the
    solved input can reach unconstrained-IP in one shot, bounded by `cap` to keep angr tractable.
    Best-effort: any failure (no frames recovered, not disassembled) falls back to the default."""
    try:
        from ..poc import primitive
        from ..poc.primitive_stage import _hydrate_frames
        word = 8 if (target.bits or 64) >= 64 else 4
        frames = _hydrate_frames(ctx, target.id, target)
        cands = primitive.frame_offset_candidates(frames, word)
        offs = [int(c["offset"]) for c in cands if isinstance(c, dict) and c.get("offset")]
        if not offs:
            return fallback
        # the offset is to the return slot; cover it plus the saved return address, with a little
        # slack so the smash lands past it rather than exactly on its first byte.
        need = max(offs) + 2 * word + 16
        return max(fallback, min(need, cap))
    except Exception:                                        # noqa: BLE001 -- sizing is an optimisation
        return fallback


def _run_angr(ctx, target, exe, mode, p, py, base_argv=()):
    input_size = int(p["input_size"]) if p.get("input_size") else _frame_sized_input(ctx, target)
    max_seconds = int(p.get("max_seconds", 120))
    if p.get("targets"):
        targets = list(p["targets"])
    else:
        ranked = select_targets(FindingDAO(ctx.conn).list_by_target(target.id))
        targets = []
        for t in ranked:
            a = t.get("site_addr") or t.get("function_addr")
            if a and a not in targets:
                targets.append(a)
        targets = targets[: int(p.get("max_targets", 8))]
    seed_shas = _gather_seeds(ctx.conn, target.id)
    seeds_b64 = [base64.b64encode(ctx.content.get_bytes(s)).decode() for s in seed_shas]
    seeds_b64 += list(p.get("seeds", []))
    spec = {"binary": str(exe), "input_mode": mode, "input_size": input_size,
            "targets": targets, "seeds": seeds_b64, "max_seconds": max_seconds,
            "num_find": int(p.get("num_find", 6)), "max_states": int(p.get("max_states", 800)),
            # arch hints let the driver fall back to angr's raw 'blob' loader when CLE cannot
            # identify the format (firmware / headerless dumps), instead of failing the stage.
            "arch": target.arch, "bits": target.bits,
            # the operator's flags (`-c @@`): explore the SAME invocation the replay runs, so a
            # flag-gated path is explorable and the certificate's argv is the one explored.
            # "@@out" (converter output) becomes the same relative scratch name the replay uses.
            "argv": _sub_output([str(a) for a in base_argv or []], None)}
    ctx.emit("concolic.start", payload={"backend": "angr", "targets": targets,
                                        "seeds": len(seeds_b64), "mode": mode})
    ctx.progress(msg=f"angr exploration toward {len(targets)} target(s)")
    res = concolic.run_explore(py, spec, ctx=ctx, timeout=max_seconds)
    meta = {"drained": bool(res.get("drained")), "cutoff": bool(res.get("cutoff")),
            "targets": targets, "angr_version": res.get("angr_version"),
            "argv": (list(res["argv"]) if isinstance(res.get("argv"), list) else None)}
    ctx.emit("concolic.explored", payload={"backend": "angr",
             "reached": res.get("reached_targets", []),
             "generated": len(res.get("generated", [])),
             "drained": meta["drained"], "cutoff": meta["cutoff"],
             "stats": res.get("stats", {}), "angr_version": res.get("angr_version")})
    return res.get("generated", []), res.get("reached_targets", []), meta


def _run_symqemu(ctx, target, exe, mode, base_argv, p, sq):
    max_seconds = int(p.get("max_seconds", 120))
    seed_shas = _gather_seeds(ctx.conn, target.id)
    seeds = [ctx.content.get_bytes(s) for s in seed_shas]
    seeds += [base64.b64decode(x) for x in p.get("seeds", [])]
    ctx.emit("concolic.start", payload={"backend": "symqemu", "seeds": len(seeds),
                                        "mode": mode})
    ctx.progress(msg=f"symqemu concolic from {len(seeds)} seed(s)")
    gen = symqemu.run_campaign(sq, exe, seeds, ctx.scratch(),
                               mode=("file" if mode != "stdin" else "stdin"),
                               base_argv=base_argv, rounds=int(p.get("rounds", 2)),
                               timeout=max(10, max_seconds // 4),
                               cap=int(p.get("num_find", 64)), ctx=ctx)
    generated = [{"input_b64": base64.b64encode(d).decode(), "reached": None} for d in gen]
    ctx.emit("concolic.explored", payload={"backend": "symqemu",
             "generated": len(generated), "reached": []})
    # symqemu is a branch-flipping corpus generator, not an exhaustive explorer: it NEVER licenses
    # an unreachable claim (drained=False) -- so a sink it did not reach stays untouched.
    return generated, [], {"drained": False, "cutoff": True, "targets": [], "angr_version": None,
                           "argv": list(base_argv)}


def concolic_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("concolic requires a target_id")
    p = ctx.params or {}
    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p, content=ctx.content)[0]
    base_argv = list(p.get("argv") or [])
    exec_timeout = float(p.get("exec_timeout", 2))

    backend, py, sq = _choose_backend(p, target)
    if backend is None:
        raise RuntimeError(
            "no concolic backend available: angr (LYKOS_ANGR_PYTHON / vendored venv / python3) "
            "and symqemu (LYKOS_SYMQEMU / vendored / PATH) were both not found. Install one, "
            "or use the fuzzing stages instead.")

    # Stage the binary WITH its bundled deps (a bundled ./glibc/ loader + libc), not a bare
    # write: a concolic-solved input that reaches unconstrained-IP still records "no crash" if the
    # detonation cannot load the binary, because a relative ELF interpreter needs its loader staged
    # beside it. stage_target lays the deps out at their relative paths (and patchelf's the interp
    # where available); the sandbox chdirs into this dir so ./glibc/ld-... resolves.
    exe = ctx.content.stage_target(target, ctx.scratch(), "target.bin")
    workfile = ctx.scratch() / "input.bin"

    # Exploration is best-effort: angr can time out (stuck deep in a single step) or a backend can
    # fail on an odd binary. That must NOT lose the run -- concolic is one corroborating channel,
    # not the case. On failure we record why, validate whatever inputs were produced (possibly
    # none), and finish cleanly so the fuzzing/static findings stand and the pipeline moves on.
    note = None
    # On any exploration failure, the model proved nothing: drained=False forbids unreachable claims.
    meta = {"drained": False, "cutoff": True, "targets": [], "angr_version": None}
    try:
        if backend == "angr":
            generated, reached, meta = _run_angr(ctx, target, exe, mode, p, py, base_argv)
        else:
            generated, reached, meta = _run_symqemu(ctx, target, exe, mode, base_argv, p, sq)
    except Exception as e:                                   # noqa: BLE001
        generated, reached = [], []
        note = f"{type(e).__name__}: {e}"[:300]
        ctx.emit("concolic.explored", payload={"backend": backend, "generated": 0,
                                               "reached": [], "incomplete": True, "note": note})
        ctx.progress(msg=f"[{backend}] exploration did not finish ({note}); "
                         f"keeping any inputs already generated")

    confirmed, corroborated, new_seeds, certified = _validate(
        ctx, target, exe, mode, workfile, generated, exec_timeout, base_argv, meta)
    unreachable = _record_unreached(ctx, target, meta, reached)
    ctx.emit("concolic.done", payload={"backend": backend, "confirmed": confirmed,
                                       "corroborated": corroborated, "new_seeds": new_seeds,
                                       "certified": certified, "unreachable": unreachable,
                                       "drained": bool(meta.get("drained")),
                                       "reached": reached, "incomplete": bool(note),
                                       "note": note})
    tail = (f"[{backend}] {confirmed} crashes, {corroborated} corroborated "
            f"({certified} certified reachable), {unreachable} unreachable, {new_seeds} new seeds")
    ctx.progress(pct=100, msg=(tail + " (exploration incomplete)") if note else tail)
    return {}


def register() -> None:
    register_stage(CONCOLIC_STAGE, concolic_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=3600)


def enqueue_concolic(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CONCOLIC_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
