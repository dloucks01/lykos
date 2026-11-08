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
    from . import attempts as _attempts
    alog = _attempts.AttemptLog(ctx, "net_fuzz", "net_fuzz", unit="none", target_id=target.id)

    # STATEFUL SESSIONS first (session.py): multi-message conversations with coverage + protocol-
    # state feedback. The one-shot engine below remains the fallback for a server the session
    # engine could not start at all.
    if p.get("engine", "session") == "session":
        out = _session_campaign(ctx, target, exe, proto, argv, p, alog, tier)
        if out is not None:
            return out

    ctx.progress(msg=f"fuzzing {proto.upper()} server over a socket")

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


def _stage_variant(ctx, target, kind: str, name: str):
    """Write a stored build variant of the target beside it; its path, or None."""
    from ..poc.capture import variant_build_bytes
    blob = variant_build_bytes(ctx, target, kind)
    if not blob:
        return None
    path = ctx.scratch() / name
    path.write_bytes(blob)
    os.chmod(path, 0o755)
    return path


def _operator_sessions(p) -> list:
    """Operator-supplied sessions: `sessions` = [[b64 msg, ...], ...]; legacy `seeds` = [b64]."""
    import base64
    out = []
    for sess in p.get("sessions") or []:
        try:
            out.append([base64.b64decode(m) for m in sess])
        except (TypeError, ValueError):
            continue
    for one in p.get("seeds") or []:
        try:
            out.append([base64.b64decode(one)])
        except (TypeError, ValueError):
            continue
    return out


def _session_campaign(ctx, target, exe, proto, argv, p, alog, tier):
    """Run the stateful session engine; record every DISTINCT confirmed crash. None when the
    engine could not even start the server (the caller falls back to one-shot payloads)."""
    from ...db.dao import StringDAO
    from . import session as S

    # Which binary to fuzz and which to confirm on. Best: an AFL-instrumented ASan build (one
    # process gives coverage AND the memory-error oracle). Next: the uninstrumented build under
    # afl-qemu-trace for coverage, with the sanitizer build as the confirming oracle. Else the
    # target itself, with whatever coverage its form allows (qemu for a plain binary).
    fuzz_exe, oracle, how = exe, None, "target"
    aflsan = _stage_variant(ctx, target, "aflsan-blob", "net_target.aflsan")
    if aflsan is not None:
        fuzz_exe, how = aflsan, "afl+asan build"
    elif sandbox._is_sanitizer_exe(str(exe)):
        plain = _stage_variant(ctx, target, "plain-blob", "net_target.plain")
        if plain is not None and S.coverage_launch(str(plain), target.arch)[1]:
            fuzz_exe, oracle, how = plain, exe, "uninstrumented build under qemu, ASan confirms"
    strings = StringDAO(ctx.conn).list_by_target(target.id, limit=20000)
    creds = [[str(c).encode() for c in pair] for pair in (p.get("creds") or []) if len(pair) == 2]
    max_s = float(p.get("max_seconds", 120))
    ctx.progress(msg=f"stateful {proto.upper()} session fuzzing ({how})")

    def _on_session(sess, r, phase):
        o = "crash" if r.crashed else ("no_start" if r.connect_failed else "clean_exit")
        alog.record(S.encode_session(sess), outcome=o, phase=phase, sig=r.signal_name,
                    stderr=(r.stderr or b"")[-2048:] if r.crashed else b"",
                    note=("states " + ">".join(r.states))[:200],
                    extra={"proto": proto, "messages": len(sess), "new_cov": r.new_cov})

    res = S.fuzz_sessions(str(fuzz_exe), proto, argv=argv, port=p.get("port"), arch=target.arch,
                          strings=strings, seeds=_operator_sessions(p), creds=creds,
                          max_seconds=max_s, seed=int(p.get("seed", 1337)),
                          oracle_exe=(str(oracle) if oracle else None),
                          max_crashes=int(p.get("max_crashes", 6)), on_session=_on_session,
                          should_stop=lambda: ctx.should_cancel() or ctx.timed_out(),
                          scratch=ctx.scratch())
    _att = alog.finish()
    _att_brief = {k: _att.get(k) for k in ("counts", "verdict", "verdict_note", "log")}
    if res.did_not_run and not res.sessions:
        _log.info("session engine could not start %s: %s", target.id, res.note)
        return None
    iso = f"net-{proto}"
    recorded = []
    dd, fd = DynResultDAO(ctx.conn), FindingDAO(ctx.conn)
    for c in res.crashes:
        blob = S.encode_session(c.session)
        input_sha = ctx.put_artifact("fuzz-crash-input", data=blob)
        what = (f"a {len(c.session)}-message {res.protocol.upper()} session"
                if len(c.session) > 1 else f"one {proto.upper()} message")
        # The server's report (the sanitizer's, or the fault line) is what root-causes it later.
        stderr_sha = ctx.put_artifact("fuzz-crash-stderr", data=c.stderr) if c.stderr else None
        dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                  input_mode="socket", argv=argv, signal=c.signal, signal_name=c.signal_name,
                  crashed=True, isolation=iso, stderr_sha=stderr_sha,
                  note=f"{what}; {c.signature}; confirmed on a fresh server")
        fd.upsert(target.id, target.case_id, crash_finding_candidate(
            c.signal_name, input_sha, iso, "net_fuzz",
            extra=f"(reproduced by replaying {what} against a fresh server)"))
        recorded.append({"input_sha": input_sha, "signal": c.signal_name,
                         "signature": c.signature, "messages": len(c.session),
                         "minimized_from": c.minimized_from})
    # The sessions that reached new code or protocol state: the corpus a later run starts from.
    if res.corpus_sessions:
        import json as _json
        import base64 as _b64
        ctx.put_artifact("net-session-corpus", data=_json.dumps(
            [[_b64.b64encode(m).decode() for m in s] for s in res.corpus_sessions]).encode())
    payload = {"applicable": True, "engine": "session", "crashed": bool(recorded),
               "crashes": recorded, "protocol": res.protocol, "coverage": res.coverage or "none",
               "fuzzed": how, "sessions": res.sessions, "execs": res.sessions,
               "edges": res.edges, "states": res.states, "transitions": res.transitions,
               "corpus": res.corpus, "verified_commands": res.verified_commands[:40],
               "note": res.note, "attempts": _att_brief, "isolation": res.isolation or tier,
               "did_not_run": bool(res.did_not_run), "elapsed": round(res.elapsed, 1)}
    if recorded:
        payload.update({"signal": recorded[0]["signal"], "input_sha": recorded[0]["input_sha"],
                        "proto": proto})
    ctx.emit("net_fuzz.done", payload=payload)
    ctx.progress(pct=100, msg=(f"{len(recorded)} distinct {proto.upper()} crash(es) from "
                               f"{res.sessions} sessions ({res.protocol})" if recorded else
                               f"{res.sessions} {res.protocol} sessions, {res.transitions} state "
                               f"transitions, no crash"))
    return {"metrics": {"sessions": res.sessions, "crashes": len(recorded),
                        "protocol": res.protocol, "coverage": res.coverage or "none"}}


def register() -> None:
    register_stage(NET_FUZZ_STAGE, net_fuzz_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_net_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, NET_FUZZ_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
