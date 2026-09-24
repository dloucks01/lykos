"""Phase 6 — the `debug_monitor` stage: instrumented dangerous-call monitor.

Runs the target under GDB with breakpoints on the dangerous sinks it imports, and records the
concrete arguments at each call (copy lengths, command strings, size args). Turns static
candidates into dynamic evidence -- a `system("...")` we watched execute, a `strcpy` copying
more bytes than the destination function's stack buffer holds -- without needing a crash.

Sound signals become findings: an executed command (CWE-78), a `gets` call (CWE-242), and an
unbounded copy whose observed length exceeds the caller's recovered stack buffer (CWE-121,
matched by function name so it survives PIE). Every observed call is emitted as a runtime log.

Native targets run under host GDB (full backtrace, so CWE-121 is available). Cross-arch targets
run under the qemu-user gdbstub via `qemu_gdb.monitor_calls`, breakpointing sinks resolved from
the ELF's own symbols (`elfsyms`); the stub gives no backtrace, so CWE-121 is skipped there.
Windows PE targets run under Wine and capture the dangerous-sink arguments from the `+relay` log
(`winmonitor`, the Windows analog): executed command (CWE-78), format string (CWE-134), remote
download (CWE-494), plus a copy/arg call log.
"""
from __future__ import annotations

import os

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from ..poc.capture import how_to_feed
from . import elfsyms, monitor, qemu_gdb, winmonitor

MONITOR_STAGE = "debug_monitor"
TOOL = "monitor"
TOOL_VERSION = "monitor-1"


def program_calls(hits):
    """(the program's own calls, the ones that were not).

    The loader resolves symbols through the same libc entry points long before `main` runs, so
    an unfiltered log is mostly ld.so startup: on ncompress 11 of 13 recorded calls came from
    `_dl_new_object` and friends, burying the two the program actually made. `winmonitor`
    already attributes this way; the Linux path did not.

    A hit whose origin could not be determined is KEPT -- absence of attribution is not
    evidence the program did not make the call.
    """
    return ([h for h in hits if h.get("in_target") is not False],
            [h for h in hits if h.get("in_target") is False])


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


def _win_monitor(ctx, target, p) -> dict:
    """Windows PE branch: run under Wine and capture the concrete arguments at dangerous Win32
    sinks (the Windows analog of the GDB monitor). Sound signals -> findings; the rest is a log."""
    if not winmonitor.supported():
        ctx.emit("monitor.done", payload={"ok": False, "supported": False,
                 "note": "wine not installed; cannot monitor a Windows PE's calls here"})
        ctx.progress(pct=100, msg="runtime monitor needs wine for PE targets")
        return {}
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)
    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 45))
    data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b""
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv
    stdin = data if mode == "stdin" else b""

    ctx.progress(msg="monitoring Win32 dangerous calls under Wine (+relay)")
    res = winmonitor.monitor(exe, argv=run_argv, stdin=stdin, timeout=timeout)
    if not res.get("ok"):
        ctx.emit("monitor.done", payload={"ok": False, "note": res.get("note")})
        ctx.progress(pct=100, msg="win32 monitor could not run: " + str(res.get("note")))
        return {}

    hits = res.get("hits", [])
    fd = FindingDAO(ctx.conn)
    findings = 0
    for h in hits:
        kind, api, val = h.get("kind"), h.get("api"), h.get("value")
        if kind == "exec" and val:
            fd.upsert(target.id, target.case_id, _finding(
                "CWE-78", f"Command executed at runtime via {api}()", "high",
                f'{api}("{val[:160]}") observed executing under the Wine monitor',
                dedup=f"CWE-78:win:{api}:{val[:60]}", conf=0.8))
            findings += 1
        elif kind == "format" and val and ("%n" in val or "%s" in val):
            fd.upsert(target.id, target.case_id, _finding(
                "CWE-134", f"Format string reaches {api}() at runtime", "high",
                f'{api}(fmt="{val[:120]}") -- attacker-influenced format specifiers',
                dedup=f"CWE-134:win:{api}:{val[:40]}", conf=0.7))
            findings += 1
        elif kind == "download" and val:
            fd.upsert(target.id, target.case_id, _finding(
                "CWE-494", f"Remote file download via {api}()", "medium",
                f'{api}("{val[:200]}") -- fetches a remote resource at runtime',
                dedup=f"CWE-494:win:{val[:80]}", conf=0.7))
            findings += 1

    log = [{k: v for k, v in h.items() if k in ("api", "kind", "value", "length")}
           for h in hits[:60]]
    # A monitor run we cut short is a partial call list; an empty one is not the same claim
    # as "this PE calls no dangerous sink". The flags existed and were dropped here.
    from .trace_stage import _partial_note
    partial = _partial_note(res)
    ctx.emit("monitor.done", payload={"ok": True, "platform": "windows", "calls": len(hits),
             "findings": findings, "log": log,
             "partial": bool(partial), "truncated": bool(res.get("truncated")),
             "timed_out": bool(res.get("timed_out")),
             "note": partial or (None if hits else
                     "no monitored Win32 sink calls observed on this input")})
    ctx.progress(pct=100, msg=f"{len(hits)} Win32 sink call(s), {findings} finding(s)"
                 + (f" -- {partial}" if partial else ""))
    return {}


def _decode_xarch(raw):
    """Convert cross-arch monitor_calls arg data into the native hit shape (kind/func/cmd/length)
    using the sink catalog. Caller name isn't available over the gdbstub -> None."""
    out = []
    for h in raw:
        spec = monitor.CATALOG.get(h["func"])
        if not spec:
            continue
        ai, as_ = h.get("argints", []), h.get("argstrs", [])
        rec = {"func": h["func"], "kind": spec["kind"], "cwe": spec["cwe"], "caller_name": None}
        k = spec["kind"]
        if k == "exec":
            i = spec["cmd"]; rec["cmd"] = as_[i] if i < len(as_) else None
        elif k == "format":
            i = spec["fmt"]; rec["fmt"] = as_[i] if i < len(as_) else None
        else:
            if spec.get("strlen") is not None and spec["strlen"] < len(as_):
                rec["length"] = len(as_[spec["strlen"]])
            elif spec.get("len_arg") is not None and spec["len_arg"] < len(ai):
                rec["length"] = ai[spec["len_arg"]]
            else:
                rec["length"] = None
        out.append(rec)
    return out


def _parse_sink_addrs(raw) -> dict:
    """Analyst escape hatch: {catalog-name: vaddr} to breakpoint sinks a stripped/static binary
    lost (no symbols/PLT names). vaddr may be an int or a hex/dec string. Only catalog names are
    kept -- others can't be decoded. Bad entries are skipped rather than failing the run."""
    out = {}
    for name, addr in (raw or {}).items():
        if name not in monitor.CATALOG:
            continue
        try:
            out[name] = int(addr, 0) if isinstance(addr, str) else int(addr)
        except (ValueError, TypeError):
            continue
    return out


def monitor_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("debug_monitor requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    # ELF runs under host GDB (native) / qemu-user (cross-arch); a Windows PE runs under Wine.
    fmt = (target.file_type or "").lower()
    if fmt == "pe":
        return _win_monitor(ctx, target, p)
    if fmt and fmt != "elf":                              # Mach-O etc.: no substrate here
        ctx.emit("monitor.done", payload={"ok": False, "supported": False,
                 "note": f"the runtime monitor runs Linux ELF (GDB/qemu-user) or Windows PE "
                         f"(Wine); this target is {fmt.upper()} (macOS needs a full-system VM)."})
        ctx.progress(pct=100, msg=f"monitor does not support {fmt.upper()} targets")
        return {}
    emulated = bool(target.arch and target.arch != host)
    if emulated and not qemu_gdb.breakpoints_supported(target.arch):
        ctx.emit("monitor.done", payload={"ok": False, "supported": False,
                 "note": f"no cross-arch breakpoint support for {target.arch} (host {host})"})
        ctx.progress(pct=100, msg="monitor not supported for this cross-arch target")
        return {}
    if not emulated and not monitor.supported(host):
        ctx.emit("monitor.done", payload={"ok": False, "supported": False,
                 "note": f"no GDB argument map for {host}"})
        return {}

    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
    argv = list(p.get("argv") or [])
    sink_addrs = _parse_sink_addrs(p.get("sink_addrs"))
    timeout = float(p.get("timeout", 20))
    data = ctx.content.get_bytes(p["input_sha"]) if p.get("input_sha") else b"A" * 256
    stdin = data if mode == "stdin" else b""
    run_argv = argv + [data.decode("latin-1")] if (mode == "arg" and data) else argv

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    if emulated:
        # cross-arch: breakpoint the sinks defined in the ELF's own symbols, under qemu-gdbstub.
        # analyst-supplied sink_addrs are merged in (a stripped/static binary has no .symtab).
        info = elfsyms.read(exe)
        symbols = {**info["symbols"], **sink_addrs}
        funcs = sorted(set(symbols) & set(monitor.CATALOG))
        if not funcs:
            ctx.emit("monitor.done", payload={"ok": True, "hits": [], "findings": 0,
                     "note": "no monitored sinks found in the binary's symbols (stripped or "
                             "dynamically linked). Supply params.sink_addrs {name: vaddr} to "
                             "breakpoint sinks by address (cross-arch needs static syms)."})
            ctx.progress(pct=100, msg="no dangerous sinks to monitor")
            return {}
        via = " (+%d analyst addr)" % len(sink_addrs) if sink_addrs else ""
        ctx.progress(msg=f"monitoring {len(funcs)} sink(s) under qemu-{target.arch} gdbstub{via}")
        res = qemu_gdb.monitor_calls(exe, target.arch, symbols=symbols,
                                     entry=info["entry"], pie=info["pie"], sink_names=set(funcs),
                                     endianness=target.endianness, bits=target.bits,
                                     argv=run_argv, stdin=stdin, timeout=timeout)
        hits = _decode_xarch(res.get("hits", [])) if res.get("ok") else []
    else:
        names = {normalize(e.dst_name) for e in CallEdgeDAO(ctx.conn).list_by_target(target.id)
                 if e.dst_name}
        funcs = sorted(names & set(monitor.CATALOG))
        if not funcs and not sink_addrs:
            ctx.emit("monitor.done", payload={"ok": True, "hits": [], "findings": 0,
                     "note": "no monitored dangerous sinks imported by this binary. Supply "
                             "params.sink_addrs {name: vaddr} to breakpoint sinks by address "
                             "(e.g. a stripped statically-linked binary)."})
            ctx.progress(pct=100, msg="no dangerous sinks to monitor")
            return {}
        via = " (+%d analyst addr)" % len(sink_addrs) if sink_addrs else ""
        shown = ", ".join(funcs) or "sink_addrs only"
        ctx.progress(msg=f"monitoring {len(funcs)} sink(s) under GDB: {shown}{via}")
        res = monitor.run_monitor(exe, funcs, host, argv=run_argv, stdin=stdin, timeout=timeout,
                                  addr_sinks=sink_addrs)
        hits, loader = program_calls(res.get("hits", []))
    if not res.get("ok"):
        ctx.emit("monitor.done", payload={"ok": False, "note": res.get("note")})
        ctx.progress(pct=100, msg="monitor could not run: " + str(res.get("note")))
        return {}

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
             "loader_calls_excluded": len(loader),
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
