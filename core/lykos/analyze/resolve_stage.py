"""finding_resolve -- drive every unresolved finding on a binary to a measured verdict.

Detectors file findings; nothing followed most of them up. On gif2rgb, 17 leads sat as
'candidate' with no evidence either way: nobody had checked whether any execution even reached
their site. This stage answers that from work the run already did, cheapest first:

  1. REACHED? Replay every input the case kept for this target -- the fuzz campaigns' corpora
     (fuzz/corpus_keep), every executed input (dyn_result), crash/concolic/PoC inputs -- under the
     sandbox block tracer with breakpoints on each finding's site block and its function's entry.
  2. FIRES? Replay the inputs that reach a site under the guard-page heap oracle (and QASan for a
     dynamically linked x86-64 target), with SITE attribution: a fault whose PC lies inside the
     finding's own function, on 3/3 runs. That is a demonstrated memory error at this finding: it
     becomes a crash row the prove loop takes (root_cause -> build_poc -> poc_primitive) and the
     finding is raised to 'confirmed' on the `resolve` channel. A channel can only RAISE a state.
  3. Otherwise the finding gets the verdict it earned, as evidence -- never a silent lead:
       reached, did not fire  (K of N inputs reach the site; no fault under any oracle)
       function entered, site not reached  (a guard keeps the site cold under N inputs)
       not reached  (neither the site nor its function ran under N inputs)
     These do NOT lower a state -- absence of a fault under these inputs is not proof of
     absence -- they say what was measured, so the operator (and the next technique) start from it.

Native-arch ELF only (the block tracer is ptrace-based); declines otherwise with the reason.
"""
from __future__ import annotations

import time
from typing import Optional

from ..db.dao import ArtifactDAO, DynResultDAO, FindingDAO, FunctionDAO, PocDAO, TargetDAO
from ..jobs.registry import register_stage

STAGE = "finding_resolve"
TOOL, TOOL_VERSION = "lykos-resolve", "resolve-1"

# Composite / meta findings that are resolved through the findings they are built from.
_SKIP_DETECTORS = {"attack_path", "chain_primitive", "harness"}
_INPUT_KINDS = {"fuzz-crash-input", "concolic-input", "poc-l2-input", "recipe-input",
                "afl-crash-input", "harness-replay-input"}
_MAX_INPUTS = 400
_ORACLE_INPUTS = 6
_REPLAYS = 3


def _int(a) -> Optional[int]:
    try:
        return int(str(a), 16) if a is not None else None
    except ValueError:
        return None


def _decline(ctx, why):
    ctx.emit("finding_resolve.done", payload={"supported": False, "note": why})
    ctx.progress(pct=100, msg=f"finding_resolve: {why}")
    return {"supported": False, "note": why}


def _unresolved(conn, target) -> list:
    proven = {p.finding_id for p in PocDAO(conn).list_by_target(target.id)
              if p.verified or (getattr(p, "provenance", None) == "detonated")}
    out = []
    for f in FindingDAO(conn).list_by_target(target.id):
        if f.state not in ("candidate", "corroborated", "confirmed") or f.id in proven:
            continue
        if (f.detector or "") in _SKIP_DETECTORS:
            continue
        out.append(f)
    return out


def _sites(conn, target, findings, image_base: int) -> dict:
    """finding id -> {fn, lo, hi, site_block, entry} in FILE vaddrs (decompiler - image base)."""
    fd = FunctionDAO(conn)
    fns = sorted(((_int(f.addr), f) for f in fd.list_by_target(target.id) if _int(f.addr) is not None),
                 key=lambda x: x[0])
    full_cache: dict = {}

    def owner(a):
        best = None
        for s, f in fns:
            if s <= a < s + max(1, int(f.size or 0)):
                best = (s, f)
        return best
    out = {}
    for f in findings:
        a = _int(f.site_addr) or _int(f.function_addr)
        if a is None:
            continue
        own = owner(a)
        if not own:
            continue
        s, fn = own
        if fn.id not in full_cache:
            full_cache[fn.id] = fd.get(fn.id)
        blocks = sorted(_int(b.get("addr")) for b in ((full_cache[fn.id].ir or {}).get("blocks") or [])
                        if _int(b.get("addr")) is not None)
        blk = max((b for b in blocks if b <= a), default=s)
        out[f.id] = {"fn": fn.name or hex(s), "lo": s - image_base, "hi": s + int(fn.size or 0) - image_base,
                     "entry": s - image_base, "block": blk - image_base,
                     "site": (_int(f.site_addr) - image_base) if _int(f.site_addr) is not None else None}
    return out


def _inputs(ctx, target) -> list:
    """[(bytes, mode, argv, origin)] -- distinct inputs this case kept for the target."""
    from .fuzz import corpus_keep
    rows = DynResultDAO(ctx.conn).list_by_target(target.id)
    crash_modes = [d.input_mode for d in rows if d.crashed and d.input_mode]
    default_mode = max(set(crash_modes), key=crash_modes.count) if crash_modes else None
    ref = next((d for d in rows if d.input_mode == default_mode and d.argv), None)
    default_argv = list(ref.argv) if ref else []
    single = len(TargetDAO(ctx.conn).list_by_case(target.case_id)) == 1
    seen, out = set(), []

    def add(data, mode, argv, origin):
        if not data or len(out) >= _MAX_INPUTS:
            return
        key = (bytes(data), mode, tuple(argv or ()))
        if key in seen:
            return
        seen.add(key)
        out.append((bytes(data), mode or default_mode or "stdin", list(argv or default_argv), origin))
    for d in rows:                                   # crashes first: the likeliest to reach deep
        if d.crashed and d.input_sha:
            try:
                add(ctx.content.get_bytes(d.input_sha), d.input_mode, d.argv, "crash input")
            except Exception:                        # noqa: BLE001 -- a pruned artifact
                pass
    for x, mode, argv, src in corpus_keep.load(ctx.conn, ctx.content, target.case_id, target.id):
        add(x, mode, argv, f"{src} corpus")
    for d in rows:
        if not d.crashed and d.input_sha:
            try:
                add(ctx.content.get_bytes(d.input_sha), d.input_mode, d.argv, "executed input")
            except Exception:                        # noqa: BLE001
                pass
    if single:                                       # untagged artifacts belong to the only target
        for a in ArtifactDAO(ctx.conn).list_by_case(target.case_id):
            if a.kind in _INPUT_KINDS:
                try:
                    add(ctx.content.get_bytes(a.sha256), None, None, a.kind)
                except Exception:                    # noqa: BLE001
                    pass
    return out


def _qasan_fires(exe, data, mode, argv, span, arch) -> Optional[str]:
    try:
        from pathlib import Path

        from .dynamic import qasan
        blob = Path(exe).read_bytes()
        if not qasan.applicable(blob, arch)[0] or mode not in ("file", "stdin"):
            return None
        rep = qasan.run(exe, data, argv=argv, mode=mode, timeout=10.0)
        site = qasan.site_va(rep, blob) if rep is not None else None
        if site is not None and span[0] <= site < span[1]:
            return f"{rep.summary()} at {site:#x}"
    except Exception:                                # noqa: BLE001 -- an extra oracle
        return None
    return None


def resolve_stage(ctx) -> dict:
    from . import elf
    from .debug.rootcause import image_base
    from .dynamic import sandbox
    from .fuzz import distill
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("finding_resolve requires a target_id")
    p = ctx.params or {}
    if (target.file_type or "").lower() != "elf":
        return _decline(ctx, "the block tracer drives native ELF executables")
    if target.arch and target.arch != sandbox.host_arch():
        return _decline(ctx, f"the block tracer is native-only ({target.arch} on a {sandbox.host_arch()} host)")
    findings = _unresolved(ctx.conn, target)
    if not findings:
        return _decline(ctx, "no unresolved findings on this target")
    blob = ctx.content.path(target.sha256).read_bytes()
    try:
        info = elf.parse(blob)
        base = image_base(FunctionDAO(ctx.conn).list_by_target(target.id), info.entry) or 0
    except Exception:                                # noqa: BLE001
        base = 0
    sites = _sites(ctx.conn, target, findings, base)
    inputs = _inputs(ctx, target)
    deadline = time.time() + float(p.get("max_seconds", 90))
    if not inputs:
        for f in findings:
            _verdict(ctx, target, f, "untested",
                     "no input was kept for this target, so reach could not be measured")
        return _decline(ctx, "no inputs kept for this target to replay")
    import os
    exe = ctx.content.stage_target(target, ctx.scratch(), "target.bin")
    os.chmod(exe, 0o755)
    blocks = sorted({v["block"] for v in sites.values()} | {v["entry"] for v in sites.values()})
    ctx.progress(msg=f"finding_resolve: {len(findings)} findings, {len(inputs)} inputs, {len(blocks)} breakpoints")

    # 1. reach: per (mode, argv) group, per-input reached-block sets
    groups: dict = {}
    for i, (_d, mode, argv, _o) in enumerate(inputs):
        groups.setdefault((mode, tuple(argv)), []).append(i)
    reached: dict = {b: [] for b in blocks}
    traced = 0
    for (mode, argv), idxs in groups.items():
        if ctx.should_cancel() or time.time() > deadline:
            break
        cov = distill.block_coverage(str(exe), [inputs[i][0] for i in idxs], blocks, mode=mode,
                                     base_argv=list(argv), timeout=2.0, arch=target.arch,
                                     endianness=target.endianness, bits=target.bits,
                                     cap=len(idxs), deadline=deadline)
        for i, hit in zip(idxs, cov):
            if hit:
                traced += 1
            for b in hit or ():
                if b in reached:
                    reached[b].append(i)

    # 2. fire: replay the site-reaching inputs under the guard-page oracle (+ QASan), attributed
    counts = {"fired": 0, "reached": 0, "entered": 0, "unreached": 0, "unmapped": 0}
    fd = FindingDAO(ctx.conn)
    for f in findings:
        if ctx.should_cancel():
            break
        s = sites.get(f.id)
        if s is None:
            counts["unmapped"] += 1
            _verdict(ctx, target, f, "unmapped", "its site maps to no recovered function, so reach "
                     "could not be measured")
            continue
        at_site = reached.get(s["block"], [])
        at_fn = reached.get(s["entry"], [])
        if at_site and time.time() < deadline:
            fired = _fire(ctx, target, exe, f, s, [inputs[i] for i in at_site[:_ORACLE_INPUTS]], sandbox)
            if fired:
                counts["fired"] += 1
                continue
            counts["reached"] += 1
            _verdict(ctx, target, f, "reached-did-not-fire",
                     f"{len(at_site)} of {len(inputs)} kept inputs execute the site block "
                     f"{s['block'] + base:#x} in {s['fn']}; replaying {min(len(at_site), _ORACLE_INPUTS)} of "
                     "them natively and under the guard-page heap oracle produced no fault there. "
                     "The site is reachable from input; what is unproven is the triggering value.",
                     reach_input=inputs[at_site[0]])
        elif at_fn:
            counts["entered"] += 1
            _verdict(ctx, target, f, "function-entered-site-cold",
                     f"{len(at_fn)} of {len(inputs)} kept inputs enter {s['fn']} but none executes the "
                     f"site block {s['block'] + base:#x}: a branch/guard keeps it cold under every "
                     "input this run produced. Next: a solve aimed at that block.")
        else:
            counts["unreached"] += 1
            _verdict(ctx, target, f, "not-reached",
                     f"neither the site nor {s['fn']} executed under any of {len(inputs)} kept inputs "
                     f"({_origins(inputs)}). Static reachability decides whether it is worth a "
                     "directed solve.")
    ctx.emit("finding_resolve.done", payload={"supported": True, "findings": len(findings),
             "inputs": len(inputs), "traced": traced, **counts})
    ctx.progress(pct=100, msg=(f"finding_resolve: {counts['fired']} fired at their site, "
                               f"{counts['reached']} reached but quiet, {counts['entered']} with a cold "
                               f"site, {counts['unreached']} not reached ({len(inputs)} inputs)"))
    _ = fd
    return {"metrics": {"findings": len(findings), "inputs": len(inputs), **counts}}


def _origins(inputs) -> str:
    from collections import Counter
    c = Counter(o for _d, _m, _a, o in inputs)
    return ", ".join(f"{n} {k}" for k, n in c.most_common(5))


def _fire(ctx, target, exe, f, s, cands, sandbox) -> bool:
    """Replay site-reaching inputs under the guard-page oracle (then QASan); a fault whose PC is in
    the finding's own function on 3/3 runs raises it to confirmed and records the crash row."""
    for data, mode, argv, origin in cands:
        rs = sandbox.run_batch(str(exe), [data] * _REPLAYS, mode=mode, base_argv=argv, timeout=4.0,
                               arch=target.arch, endianness=target.endianness, bits=target.bits,
                               guard_page=True, fault_pc=True) or []
        hits = [r for r in rs if r.crashed and r.fault_pc is not None and s["lo"] <= r.fault_pc < s["hi"]]
        if len(rs) == _REPLAYS and len(hits) == _REPLAYS:
            r = hits[0]
            sha = ctx.put_artifact("resolve-input", data=data)
            DynResultDAO(ctx.conn).insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=sha,
                                          input_mode=mode, argv=list(argv), crashed=True,
                                          signal_name=r.signal_name, isolation=r.isolation,
                                          duration_ms=r.duration_ms, fault_pc=r.fault_pc,
                                          note="finding_resolve: fault at the finding's own function")
            _verdict(ctx, target, f, "fired",
                     f"a kept input ({origin}, {len(data)} B, {sha[:12]}) reaches {s['fn']} and faults "
                     f"there natively under the guard-page heap oracle on {_REPLAYS}/{_REPLAYS} runs "
                     f"({r.signal_name} at pc {r.fault_pc:#x}). Recorded as a crash for the prove loop.",
                     raise_to="confirmed")
            return True
        q = _qasan_fires(exe, data, mode, argv, (s["lo"], s["hi"]), target.arch)
        if q:
            sha = ctx.put_artifact("resolve-input", data=data)
            _verdict(ctx, target, f, "fired",
                     f"a kept input ({origin}, {len(data)} B, {sha[:12]}) reaches {s['fn']} and QASan "
                     f"reports {q} inside it (no native fault).", raise_to="confirmed")
            return True
    return False


def _verdict(ctx, target, f, kind, detail, *, raise_to=None, reach_input=None) -> None:
    ev = [{"channel": "resolve", "detail": f"[{kind}] {detail}"}]
    if reach_input is not None:
        try:
            sha = ctx.put_artifact("resolve-reach-input", data=reach_input[0])
            ev.append({"channel": "resolve-reach", "detail":
                       f"reaching input {sha[:12]} ({reach_input[3]}, {reach_input[1]}) -- the seed a "
                       "directed solve for the triggering value starts from"})
        except Exception:                            # noqa: BLE001
            pass
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": f.cwe, "title": f.title, "severity": f.severity, "detector": f.detector,
        "dedup_key": f.dedup_key, "state": raise_to or f.state,
        "site_addr": f.site_addr, "function_addr": f.function_addr, "evidence": ev})


def enqueue_finding_resolve(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, STAGE, target_id=target.id, params=params or {}, force=force)


def register() -> None:
    register_stage(STAGE, resolve_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=240)


register()
