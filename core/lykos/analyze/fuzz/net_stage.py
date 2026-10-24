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
from .. import substrate
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
    why = substrate.native_only_reason(target.file_type, "the localhost network campaign")
    if why:
        ctx.emit("net_fuzz.done", payload={"applicable": False, "note": why})
        return {}
    host = sandbox.host_arch()
    if substrate.foreign_cpu(target.arch, target.file_type, host):
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
    # stage_target, not a bare write: a bundled target needs its relocated loader/libc staged
    # BESIDE it, or every spawn dies in the loader and the campaign reads "no-listen".
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)
    # Containment is reported, never silent: without bubblewrap the server runs rlimits-only
    # (no read-only root, no secret mask), and the operator has to be able to see that.
    tier = netfuzz.isolation_tier()
    if tier == "rlimits-only":
        ctx.emit("net_fuzz.isolation", level="warn", payload={
            "isolation": tier,
            "note": "bubblewrap is unusable on this host, so the server runs with resource "
                    "limits only -- no read-only root, no secret masking, no pid namespace. "
                    "Fuzzing continues; install/enable bubblewrap for full containment."})

    argv = [str(a) for a in (p.get("argv") or [])]
    ctx.progress(msg=f"fuzzing {proto.upper()} server over a socket")
    # Every delivery, with what happened to the server (fuzz/attempts.py).
    from . import attempts as _attempts
    alog = _attempts.AttemptLog(ctx, "net_fuzz", "net_fuzz", unit="none", target_id=target.id)

    def _on_attempt(data, d, phase):
        o = d.get("outcome") or "error_exit"
        # The engine's own explanation is the "error text" for a delivery that went wrong, so
        # the verdict can quote it ("no tcp listening port within 5s").
        alog.record(data, outcome=o, phase=phase, rc=d.get("rc"), sig=d.get("sig"),
                    stderr=(d.get("note") or "").encode() if o != "clean_exit" else b"",
                    note=d.get("note"), extra={"proto": proto})

    res = netfuzz.fuzz_server(str(exe), proto, argv=argv, port=p.get("port"),
                              max_execs=int(p.get("max_execs", 1500)),
                              seed=int(p.get("seed", 1337)), on_attempt=_on_attempt,
                              should_stop=lambda: ctx.should_cancel() or ctx.timed_out())
    _att = alog.finish()
    _att_brief = {k: _att.get(k) for k in ("counts", "verdict", "verdict_note", "log")}

    if not res.crashed:
        _erroring = _att.get("verdict") == _attempts.ERRORING or res.note in ("spawn-failed",
                                                                                "no-listen")
        ctx.emit("net_fuzz.done", payload={"applicable": True, "crashed": False,
                 "execs": res.execs, "port": res.port,
                 "note": (_att.get("verdict_note") if _att.get("verdict") == _attempts.ERRORING
                          else ((_att.get("top_errors") or {}).get("no_start") or [{}])[0].get("msg")
                          or res.note if _erroring else res.note),
                 "did_not_run": _erroring, "attempts": _att_brief,
                 "isolation": res.isolation or tier})
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
             "input_sha": input_sha, "execs": res.execs, "attempts": _att_brief,
             "isolation": res.isolation or tier})
    ctx.progress(pct=100, msg=f"{proto.upper()} crash: {res.signal_name} on port {res.port}")
    return {}


def register() -> None:
    register_stage(NET_FUZZ_STAGE, net_fuzz_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_net_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, NET_FUZZ_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
