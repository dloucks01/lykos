"""Phase 6 — the `debug_monitor` stage: instrumented dangerous-call monitor.

Runs the target under GDB with breakpoints on the dangerous sinks it imports, and records the
concrete arguments at each call (copy lengths, command strings, size args). Turns static
candidates into dynamic evidence -- a `system("...")` we watched execute, a `strcpy` copying
more bytes than the destination function's stack buffer holds -- without needing a crash.

Sound signals become findings: an executed command (CWE-78), a `gets` call (CWE-242), and an
unbounded copy whose observed length exceeds the caller's recovered stack buffer (CWE-121,
matched by function name so it survives PIE). Every observed call is emitted as a runtime log.
Native-arch only (host GDB); cross-arch via the qemu-gdbstub is future work (doc 20 §C).
"""
from __future__ import annotations

import os

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from . import monitor

MONITOR_STAGE = "debug_monitor"
TOOL = "monitor"
TOOL_VERSION = "monitor-1"


def _smallest_buffer_by_func(ctx, target_id):
    """function name -> smallest recovered stack-buffer size (for the overflow predicate)."""
    fdao = FunctionDAO(ctx.conn)
    out = {}
    for f in fdao.list_by_target(target_id):
        if not f.blocks or not f.name:
            continue
        full = fdao.get(f.id)
        bufs = [v.get("size") for v in ((full.frame or {}).get("vars") or [])
                if full and v.get("is_buffer") and v.get("size")]
        if bufs:
            out[f.name] = min(bufs)
    return out


def _finding(cwe, title, sev, detail, *, func_addr=None, dedup, conf=0.75, state="corroborated"):
    return {"cwe": cwe, "title": title, "severity": sev, "detector": "monitor",
            "evidence": [{"channel": "runtime-monitor", "detail": detail}],
            "function_addr": func_addr, "site_addr": None, "dedup_key": dedup,
            "state": state, "confidence": conf}


def monitor_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("debug_monitor requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    if target.arch and target.arch != host:
        ctx.emit("monitor.done", payload={"ok": False, "supported": False,
                 "note": f"runtime monitor is native-arch only (target {target.arch}, host "
                         f"{host}); cross-arch via qemu-gdbstub is future work"})
        ctx.progress(pct=100, msg="monitor not supported for this cross-arch target")
        return {}
    if not monitor.supported(target.arch or host):
        ctx.emit("monitor.done", payload={"ok": False, "supported": False,
                 "note": f"no GDB argument map for {target.arch or host}"})
        return {}

    # which dangerous sinks does the binary actually import? (only breakpoint those)
    names = {normalize(e.dst_name) for e in CallEdgeDAO(ctx.conn).list_by_target(target.id)
             if e.dst_name}
    funcs = sorted(names & set(monitor.CATALOG))
    if not funcs:
        ctx.emit("monitor.done", payload={"ok": True, "hits": [], "findings": 0,
                 "note": "no monitored dangerous sinks imported by this binary"})
        ctx.progress(pct=100, msg="no dangerous sinks to monitor")
        return {}

    mode = p.get("input_mode", "stdin")
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 20))
    if p.get("input_sha"):
        data = ctx.content.get_bytes(p["input_sha"])
    else:
        data = b"A" * 256                              # a probing input to drive the copies
    stdin = data if mode == "stdin" else b""
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    ctx.progress(msg=f"monitoring {len(funcs)} sink(s) under GDB: {', '.join(funcs)}")
    res = monitor.run_monitor(exe, funcs, target.arch or host, argv=run_argv, stdin=stdin,
                              timeout=timeout)
    if not res.get("ok"):
        ctx.emit("monitor.done", payload={"ok": False, "note": res.get("note")})
        ctx.progress(pct=100, msg="monitor could not run: " + str(res.get("note")))
        return {}

    hits = res.get("hits", [])
    bufsz = _smallest_buffer_by_func(ctx, target.id)
    fd = FindingDAO(ctx.conn)
    findings = 0
    for h in hits:
        k, fn = h.get("kind"), h.get("func")
        if k == "exec" and h.get("cmd"):
            fd.upsert(target.id, target.case_id, _finding(
                "CWE-78", f"Command executed at runtime via {fn}()", "high",
                f'{fn}("{h["cmd"][:160]}") observed executing under the monitor',
                dedup=f"CWE-78:runtime:{fn}:{h['cmd'][:60]}", conf=0.8))
            findings += 1
        elif fn == "gets":
            fd.upsert(target.id, target.case_id, _finding(
                "CWE-242", "Use of gets() observed at runtime", "high",
                "gets() reached at runtime -- inherently unbounded", dedup="CWE-242:runtime:gets"))
            findings += 1
        elif k == "copy" and isinstance(h.get("length"), int) and h["length"] >= 0:
            cap = bufsz.get(h.get("caller_name"))
            if cap is not None and h["length"] > cap:
                fd.upsert(target.id, target.case_id, _finding(
                    "CWE-121", f"Stack overflow observed: {fn}() copied {h['length']} bytes "
                    f"into {h['caller_name']}()'s {cap}-byte buffer", "critical",
                    f"{fn}() copied {h['length']} bytes at runtime; {h['caller_name']}()'s "
                    f"smallest recovered stack buffer is {cap} bytes (overflow)",
                    dedup=f"CWE-121:runtime:{h.get('caller_name')}:{fn}", conf=0.9,
                    state="corroborated"))
                findings += 1

    # a compact runtime call log (first 40) for the UI/report
    log = [{k: v for k, v in h.items() if k in
            ("func", "kind", "cmd", "length", "caller_name")} for h in hits[:40]]
    ctx.emit("monitor.done", payload={"ok": True, "sinks": funcs, "calls": len(hits),
             "findings": findings, "log": log})
    ctx.progress(pct=100, msg=f"{len(hits)} dangerous call(s) observed, {findings} finding(s)")
    return {}


def register() -> None:
    register_stage(MONITOR_STAGE, monitor_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_monitor(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, MONITOR_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
