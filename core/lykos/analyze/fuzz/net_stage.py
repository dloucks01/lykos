"""The `net_fuzz` stage: fuzz a socket server's network input.

Detects a TCP/UDP server from its imports, spawns it, and drives netfuzz.fuzz_server over a real
socket, recording a confirmed crash as a DynResult (input_mode 'socket') + a crash finding so the
PoC/root-cause pipeline picks it up exactly like a stdin/file crash. Host-native targets only --
a cross-arch server would need a networked emulator (out of scope).
"""
from __future__ import annotations

import logging
import os

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import netfuzz

_log = logging.getLogger(__name__)

NET_FUZZ_STAGE = "net_fuzz"
TOOL = "netfuzz"
TOOL_VERSION = "netfuzz-1"


def net_fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("net_fuzz requires a target_id")
    p = ctx.params or {}

    # Host-native only: we spawn and connect over localhost; an emulated guest's sockets are not
    # reachable from the host without a networked emulator.
    host = sandbox.host_arch()
    if target.arch and host and target.arch != host:
        ctx.emit("net_fuzz.done", payload={"applicable": False,
                 "note": f"cross-arch target ({target.arch}); network fuzzing needs a native host"})
        return {}

    proto, is_server = netfuzz.detect_server(CallEdgeDAO(ctx.conn).list_by_target(target.id))
    proto = p.get("proto", proto)
    if not is_server and "proto" not in p:
        ctx.emit("net_fuzz.done", payload={"applicable": False,
                 "note": "no socket-server imports (bind/listen/accept/recvfrom) found"})
        return {}

    exe = ctx.scratch() / "net_target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    argv = [str(a) for a in (p.get("argv") or [])]
    ctx.progress(msg=f"fuzzing {proto.upper()} server over a socket")
    res = netfuzz.fuzz_server(str(exe), proto, argv=argv, port=p.get("port"),
                              max_execs=int(p.get("max_execs", 1500)),
                              seed=int(p.get("seed", 1337)))

    if not res.crashed:
        ctx.emit("net_fuzz.done", payload={"applicable": True, "crashed": False,
                 "execs": res.execs, "port": res.port, "note": res.note})
        ctx.progress(pct=100, msg=f"{res.execs} socket exec(s), no crash ({res.note})")
        return {}

    input_sha = ctx.put_artifact("fuzz-crash-input", data=res.payload)
    iso = f"net-{proto}"
    dd = DynResultDAO(ctx.conn)
    dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
              input_mode="socket", argv=argv, signal=res.signal, signal_name=res.signal_name,
              crashed=True, isolation=iso, note=f"{proto} port {res.port}")
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, crash_finding_candidate(
        res.signal_name, input_sha, iso, "net_fuzz",
        extra=f"(reproduced over a {proto.upper()} socket on port {res.port})"))
    ctx.emit("net_fuzz.done", payload={"applicable": True, "crashed": True,
             "signal": res.signal_name, "port": res.port, "proto": proto,
             "input_sha": input_sha, "execs": res.execs})
    ctx.progress(pct=100, msg=f"{proto.upper()} crash: {res.signal_name} on port {res.port}")
    return {}


def register() -> None:
    register_stage(NET_FUZZ_STAGE, net_fuzz_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_net_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, NET_FUZZ_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
