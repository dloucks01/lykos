"""The `boundary_fuzz` stage (doc 17.4) — fuzz a consumer through its IPC endpoint.

Reuses the Phase-5 mutational campaign but delivers each input over the target's channel
(FIFO / Unix socket / TCP) instead of stdin/argv/file. The channel is taken from params
(`family`, `key`) or auto-derived from an `ipc` component edge whose consumer is this target.
A crash becomes a Confirmed finding whose evidence records the boundary it entered through
(cross-boundary blame, doc 17.4).
"""
from __future__ import annotations

import base64
import random

from ...db.dao import ComponentEdgeDAO, StringDAO, TargetDAO
from ...jobs.registry import register_stage
from ..fuzz.stage import _mine_dictionary, fuzz_campaign
from .harness import DRIVABLE, channel_run

BOUNDARY_STAGE = "boundary_fuzz"
TOOL = "lykos-harness"
TOOL_VERSION = "harness-1"
_SEEDS = [b"A" * 8, b"", b"%s%s%s%n", b"MAGIC", b"../../etc/passwd", b"\xff" * 16]


def _ipc_channel_for(conn, target):
    """Auto-derive (family, key) from an ipc edge whose consumer (dst) is this target."""
    for e in ComponentEdgeDAO(conn).list_by_case(target.case_id):
        if e.kind == "ipc" and e.dst_target == target.id:
            family = (e.detail or "").split(":", 1)[0] if e.detail else ""
            return family, e.symbol
    return None, None


def boundary_fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("boundary_fuzz requires a target_id")
    p = ctx.params or {}
    family = p.get("family")
    key = p.get("key")
    if not family or not key:
        family, key = _ipc_channel_for(ctx.conn, target)
    # normalise socket family alias
    if family == "socket":
        family = "tcp"

    if not family or not key:
        # Not applicable, not an error. A single binary has no IPC channel to drive, and
        # reporting that as an error makes a stage that correctly had nothing to do look like
        # a stage that broke -- the same conflation "no fault reproduced" made.
        ctx.emit("harness.done", payload={"applicable": False, "execs": 0, "crashes": 0,
                 "note": "no IPC channel on this target (supply family+key, or run ipc_model "
                         "on a linked case first)"})
        ctx.progress(pct=100, msg="not applicable: no IPC channel to drive")
        return {"metrics": {"applicable": False}}
    if family not in DRIVABLE:
        ctx.emit("harness.done", payload={"error": f"cannot drive {family}", "family": family,
                                          "execs": 0, "crashes": 0})
        ctx.progress(pct=100, msg=f"channel family {family!r} not drivable (fifo/unix/tcp)")
        return {"metrics": {"error": f"cannot drive {family}"}}

    readiness = float(p.get("readiness", 1.0))

    def run_fn(exe, mode, workfile, timeout, arch, data, *, endianness=None, bits=None):
        res = channel_run(exe, family, key, data, timeout=timeout, arch=arch,
                          readiness=readiness)
        return [], res

    rng = random.Random(int(p.get("seed", 1337)))
    corpus = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_SEEDS)
    dictionary = _mine_dictionary(StringDAO(ctx.conn).list_by_target(target.id))
    ctx.emit("harness.start", payload={"family": family, "key": key})
    stats = fuzz_campaign(
        ctx, target, corpus=corpus, dictionary=dictionary, mode="channel",
        max_execs=int(p.get("max_execs", 800)), max_seconds=float(p.get("max_seconds", 30)),
        exec_timeout=float(p.get("exec_timeout", 2)), rng=rng, detector="boundary",
        event_prefix="harness", note_prefix=f"found by boundary harness ({family} channel {key})",
        run_fn=run_fn)
    return {"metrics": {**stats, "family": family, "key": key}}


def register() -> None:
    register_stage(BOUNDARY_STAGE, boundary_fuzz_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=3600)


def enqueue_boundary(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, BOUNDARY_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
