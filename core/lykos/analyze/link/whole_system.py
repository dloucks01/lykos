"""The `whole_system` stage (doc 17.3) — detonate a component set together and blame a
crash on the input that entered the entry component.

Builds a scenario (entry component + service components + channel) from params or auto-derives
a 2-component producer->consumer scenario from an `ipc` component edge. Runs one detonation, or
(fuzz=true) mutates the entry input over a budget until a service crashes. A crash in a
*service* becomes a Confirmed cross-component finding on that service, whose evidence records
the cross-boundary blame and a saved, reproducible whole-system input.
"""
from __future__ import annotations

import base64
import os
import random
import time

from ...db.dao import ComponentEdgeDAO, DynResultDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic.minimize import minimize
from ..dynamic.stage import crash_finding_candidate
from ..fuzz.mutator import Mutator
from .detonate import detonate

WHOLE_SYSTEM_STAGE = "whole_system"
TOOL = "lykos-system"
TOOL_VERSION = "system-1"
_SEEDS = [b"A" * 64, b"", b"MAGIC", b"%s%s%n", b"\xff" * 32]


def _materialize(ctx, target):
    exe = ctx.scratch() / f"comp-{target.id[:8]}"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)
    return exe


def _scenario_from_params(ctx, tdao, p):
    """Explicit scenario: {entry_target, services:[ids], channel:{family,key}, mode}."""
    entry_id = p.get("entry_target") or ctx.target_id
    service_ids = p.get("services") or []
    channel = p.get("channel")
    entry = tdao.get(entry_id) if entry_id else None
    services = [tdao.get(s) for s in service_ids]
    return entry, [s for s in services if s], channel


def _scenario_from_ipc(ctx, tdao):
    """Auto: first ipc edge -> producer (entry) sends to consumer (service) over its channel."""
    for e in ComponentEdgeDAO(ctx.conn).list_by_case(ctx.case_id):
        if e.kind == "ipc":
            fam = (e.detail or "").split(":", 1)[0] if e.detail else ""
            entry = tdao.get(e.src_target)
            svc = tdao.get(e.dst_target)
            if entry and svc:
                return entry, [svc], {"family": fam, "key": e.symbol}
    return None, [], None


def _components(ctx, entry, services):
    comps = []
    for s in services:
        comps.append({"exe": _materialize(ctx, s), "target_id": s.id,
                      "filename": s.filename, "role": "service"})
    comps.append({"exe": _materialize(ctx, entry), "target_id": entry.id,
                  "filename": entry.filename, "role": "entry"})
    return comps


def _record_crash(ctx, result, entry, entry_input, arch_of):
    """A service crash -> Confirmed cross-component finding on the service, with blame."""
    blame = result.blame
    victim_id = blame["crashed_target"]
    input_sha = ctx.put_artifact("system-crash-input", data=entry_input)
    note = (f"whole-system: input into {blame['entry']} crashed {blame['crashed']} "
            f"({blame['signal']})")
    DynResultDAO(ctx.conn).insert(
        victim_id, ctx.case_id, run_id=ctx.run_id, input_sha=input_sha,
        input_mode="whole-system", signal_name=blame["signal"], crashed=True,
        isolation=result.isolation, note=note)
    extra = f"(whole-system cross-boundary blame: input into {blame['entry']})"
    FindingDAO(ctx.conn).upsert(victim_id, ctx.case_id, crash_finding_candidate(
        blame["signal"], input_sha, result.isolation, "whole_system", extra))
    return input_sha


def whole_system_stage(ctx) -> dict:
    tdao = TargetDAO(ctx.conn)
    p = ctx.params or {}
    entry, services, channel = _scenario_from_params(ctx, tdao, p)
    if not entry or not services:
        entry, services, channel = _scenario_from_ipc(ctx, tdao)
    if not entry or not services:
        ctx.emit("system.done", payload={"error": "no scenario", "crashes": 0})
        ctx.progress(pct=100, msg="no whole-system scenario (need an entry + service or an "
                                  "IPC edge)")
        return {"metrics": {"error": "no scenario"}}

    comps = _components(ctx, entry, services)
    timeout = float(p.get("exec_timeout", 6))
    arch = entry.arch
    ctx.emit("system.start", payload={
        "entry": entry.filename, "services": [s.filename for s in services],
        "channel": channel})

    def _detonate(data):
        return detonate(comps, channel=channel, entry_input=data, timeout=timeout, arch=arch)

    if not p.get("fuzz"):
        data = base64.b64decode(p["input"]) if p.get("input") else _SEEDS[0]
        res = _detonate(data)
        crashes = _finish_single(ctx, res, entry, data)
        return {"metrics": {"execs": 1, "crashes": crashes,
                            "cross_boundary": bool(res.cross_boundary)}}

    # ---- whole-system fuzzing: mutate the entry input until a service crashes ----
    rng = random.Random(int(p.get("seed", 1337)))
    corpus = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_SEEDS)
    mut = Mutator(rng, [])
    max_execs = int(p.get("max_execs", 120))
    deadline = time.time() + float(p.get("max_seconds", 30))
    execs = crossb = 0
    seen = set()
    ctx.progress(msg="whole-system detonation campaign")
    while execs < max_execs and time.time() < deadline and not ctx.should_cancel():
        data = mut.mutate(rng.choice(corpus), corpus)
        res = _detonate(data)
        execs += 1
        if res.blame and res.cross_boundary and res.blame["signal"] not in seen:
            seen.add(res.blame["signal"])
            crossb += 1
            sig = res.blame["signal"]

            def _same(d, _sig=sig):
                r = _detonate(d)
                return bool(r.cross_boundary and r.blame and r.blame["signal"] == _sig)

            budget = min(60, max(10, max_execs - execs))
            mdata, mexecs = minimize(_same, data, cap=budget)
            execs += mexecs
            self_res = _detonate(mdata)
            if self_res.cross_boundary:
                _record_crash(ctx, self_res, entry, mdata, arch)
        if execs % 20 == 0:
            ctx.emit("system.progress", payload={"execs": execs, "cross_boundary": crossb})

    ctx.emit("system.done", payload={"execs": execs, "cross_boundary": crossb})
    ctx.progress(pct=100, msg=f"{execs} detonations, {crossb} cross-boundary crash(es)")
    return {"metrics": {"execs": execs, "cross_boundary": crossb}}


def _finish_single(ctx, res, entry, data) -> int:
    if res.note and "arch" in (res.note or ""):
        ctx.emit("system.done", payload={"error": res.note, "crashes": 0})
        ctx.progress(pct=100, msg=res.note)
        return 0
    n = 0
    if res.cross_boundary:
        _record_crash(ctx, res, entry, data, entry.arch)
        n = 1
    ctx.emit("system.done", payload={
        "crashes": n, "cross_boundary": bool(res.cross_boundary),
        "outcomes": [{"filename": o.filename, "role": o.role, "crashed": o.crashed,
                      "signal": o.signal_name} for o in res.outcomes],
        "blame": res.blame})
    ctx.progress(pct=100, msg=(f"cross-boundary crash: {res.blame['crashed']} "
                               f"<- {res.blame['entry']}") if res.cross_boundary
                 else "no cross-boundary crash")
    return n


def register() -> None:
    register_stage(WHOLE_SYSTEM_STAGE, whole_system_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=3600)


def enqueue_whole_system(queue, case_id: str, *, params=None, force: bool = True):
    return queue.enqueue(case_id, WHOLE_SYSTEM_STAGE, params=params or {}, tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
