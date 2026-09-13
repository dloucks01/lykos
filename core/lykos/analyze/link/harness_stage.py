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
from ..fuzz import structure
from ..fuzz.stage import _mine_dictionary, fuzz_campaign
from .harness import DRIVABLE, ChannelSession, channel_run

BOUNDARY_STAGE = "boundary_fuzz"
TOOL = "lykos-harness"
TOOL_VERSION = "harness-1"
_SEEDS = [b"A" * 8, b"", b"%s%s%s%n", b"MAGIC", b"../../etc/passwd", b"\xff" * 16]


def _discovered_argv(ctx, target, key=None):
    """The target's own required flags, read off the binary -- `-g <group> -p <port>` for a
    multicast receiver -- with the CHANNEL's address filled in.

    The placeholders invocation discovery proposes are deliberately generic ("x", "8080"): it
    cannot know a deployment. Here we do know, because the harness chose the address it is
    about to send to. A receiver told to join group "x" on port 8080 while the driver sends to
    239.9.9.9:5004 binds somewhere nothing arrives, and the campaign starves -- correctly
    reported, and still a wasted run.

    `@@` is dropped along with its flag: a channel-driven target takes its input from the
    channel, not from a file named on the command line.
    """
    from ..invocation import discover, propose_argv, raw_strings
    try:
        from ...db.dao import StringDAO
        rows = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id) if x.value]
        if not rows:
            rows = raw_strings(ctx.content.path(target.sha256).read_bytes())
        found = discover(rows)
        argv = propose_argv(found)
    except Exception:
        return []
    host, port = _hostport_of(key)
    kinds = {f["flag"]: f.get("kind") for f in found.get("flags") or []}
    out: list = []
    i = 0
    while i < len(argv):
        a = argv[i]
        val = argv[i + 1] if i + 1 < len(argv) else None
        if val == "@@":
            i += 2                       # drop the flag and its placeholder together
            continue
        kind = kinds.get(a)
        if val is not None and kind in ("host", "id") and host:
            val = host                   # the group/address the harness will send to
        elif val is not None and kind == "port" and port:
            val = str(port)
        out.append(a)
        if val is not None:
            out.append(val)
            i += 2
        else:
            i += 1
    return out


def _hostport_of(key):
    """(host, port) from a channel key like "239.9.9.9:5004", or (None, None)."""
    if not key or ":" not in str(key):
        return None, None
    host, _, port = str(key).rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return None, None


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
        ctx.progress(pct=100,
                     msg=f"channel family {family!r} not drivable "
                         f"({'/'.join(sorted(DRIVABLE))})")
        return {"metrics": {"error": f"cannot drive {family}"}}

    # A datagram receiver is dropped into, not connected to: it needs longer to bind and join
    # a group than a stream server needs to accept, and there is no handshake to wait on.
    readiness = float(p.get("readiness", 2.0 if family in ("udp", "multicast") else 1.0))

    # A listener has to be TOLD what to listen on. Launched bare, a multicast receiver prints
    # its usage and exits, and every payload lands on a process that is already gone -- which
    # reads exactly like a channel the target ignores. The flags come from the same invocation
    # discovery the fuzzer uses, so this needs nothing from the operator.
    base_argv = [str(a) for a in (p.get("argv") or [])]
    if not base_argv:
        base_argv = _discovered_argv(ctx, target, key)
    if base_argv:
        ctx.emit("harness.invocation", payload={"argv": base_argv, "family": family,
                                                "key": key})

    # One listener, many payloads. Restarting the target per input is what makes network
    # fuzzing slow -- a listener does not exit when it is done with an input, so every
    # non-crashing execution pays startup, group join AND the full timeout. Measured on a JVM
    # multicast receiver: 0.12 exec/s one-shot against 12.2 persistent, a 98x difference.
    #
    # The trade is attribution: when the process dies, the payload in flight is a SUSPECT, not
    # a proven cause. The session marks itself dead on a crash, so the campaign's own
    # `_reproduces` check -- which calls this same run_fn -- starts a fresh process and
    # delivers only that payload. A crash that does not survive that is not recorded.
    persistent = p.get("persistent")
    if persistent is None:
        persistent = family in ("udp", "multicast")
    session = {"s": None}

    def run_fn(exe, mode, workfile, timeout, arch, data, *, endianness=None, bits=None):
        if not persistent:
            res = channel_run(exe, family, key, data, timeout=timeout, arch=arch,
                              readiness=readiness, argv=base_argv)
            return [], res
        if session["s"] is None:
            session["s"] = ChannelSession(exe, family, key, argv=base_argv, arch=arch,
                                          readiness=readiness,
                                          settle=float(p.get("settle", 0.08)))
        return [], session["s"].send(data)

    rng = random.Random(int(p.get("seed", 1337)))
    corpus = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_SEEDS)
    dictionary = _mine_dictionary(StringDAO(ctx.conn).list_by_target(target.id))
    # A protocol on the wire is as structured as a file format, and blind mutation fares worse
    # here than anywhere: an MPEG-TS packet whose sync byte is not 0x47 is dropped before any
    # parsing code runs, so nearly every mutant tests nothing. Measured on a multicast
    # receiver with a planted overflow: 60 executions, 3 distinct behaviours, no crash.
    mutator = None
    fmt = p.get("format_name")
    if fmt:
        model = structure.builtin(fmt)
        if model is None:
            ctx.emit("harness.done", payload={
                "error": f"unknown format model {fmt!r}", "execs": 0, "crashes": 0,
                "known": structure.builtin_names()})
            ctx.progress(pct=100, msg=f"unknown format model {fmt!r}")
            return {"metrics": {"error": "unknown format"}}
        mutator = structure.StructMutator(rng, model, dictionary)
        if not p.get("seeds"):
            seed = structure.seed_for_name(fmt)
            if seed:
                corpus = [seed] + list(corpus)
        ctx.emit("harness.format", payload={"model": fmt})
    ctx.emit("harness.start", payload={"family": family, "key": key})
    if persistent:
        ctx.emit("harness.persistent", payload={
            "family": family, "settle": float(p.get("settle", 0.08)),
            "note": ("one listener process serves many payloads; a crash is re-checked "
                     "against a fresh process before it is recorded")})
    stats = fuzz_campaign(
        ctx, target, corpus=corpus, dictionary=dictionary, mode="channel",
        max_execs=int(p.get("max_execs", 800)), max_seconds=float(p.get("max_seconds", 30)),
        exec_timeout=float(p.get("exec_timeout", 2)), rng=rng, detector="boundary",
        event_prefix="harness", note_prefix=f"found by boundary harness ({family} channel {key})",
        # The listener's own flags go on the crash row. "Which invocation produced this" is the
        # first thing anyone replaying a network crash needs -- `-g 239.9.9.9 -p 5004` is not
        # recoverable from the payload -- and the campaign records this, not run_fn's return.
        run_fn=run_fn, mutator=mutator, base_argv=base_argv)
    if session["s"] is not None:
        ctx.emit("harness.restarts", payload={"restarts": session["s"].restarts})
        session["s"].close()
    return {"metrics": {**stats, "family": family, "key": key,
                        "persistent": bool(persistent)}}


def register() -> None:
    register_stage(BOUNDARY_STAGE, boundary_fuzz_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=3600)


def enqueue_boundary(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, BOUNDARY_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
