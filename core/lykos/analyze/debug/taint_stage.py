"""Phase 6 -- the `dynamic_taint` stage: confirm at runtime that program INPUT reaches a sink.

Static taint (detect_cwe) flags candidate source->sink flows; this proves them by observation. It
feeds a unique marker as the program's input, runs the target under the dangerous-call monitor
(native GDB or the cross-arch qemu-gdbstub, same routing as debug_monitor), and reports a
CONFIRMED flow wherever that exact marker turns up in a sink's captured argument:

  - input reaches an exec sink (system/popen/exec*)     -> CWE-78  (command injection flow)
  - input reaches a format string (printf/sprintf/...)  -> CWE-134 (format-string flow)
  - input reaches a string copy's source (strcpy/...)   -> CWE-120 (unbounded-copy flow)

If the marker reaches the sink argument, input demonstrably flows there -- not full byte-level
DTA, but a sound runtime confirmation of the flow the static pass could only approximate. The
finding is Confirmed (dynamic evidence), keyed by sink so it promotes the matching static finding.
ELF only (native + cross-arch); Windows PE taint is future work.
"""
from __future__ import annotations

import os
import secrets

from ...db.dao import CallEdgeDAO, FindingDAO, TargetDAO
from ...jobs.registry import register_stage
from ..detect.catalog import normalize
from ..dynamic import sandbox
from ..poc.capture import how_to_feed
from . import elfsyms, monitor, qemu_gdb

TAINT_STAGE = "dynamic_taint"
TOOL = "taint"
TOOL_VERSION = "taint-1"

# sink kind -> (cwe, severity) for the confirmed data-flow finding
_CWE = {"exec": ("CWE-78", "high"), "format": ("CWE-134", "high"), "copy": ("CWE-120", "high")}


def _marker() -> str:
    # pure-ASCII nonce so it survives string copies / printf unchanged and won't collide with
    # anything the program already contains.
    return "LYKOSTAINT" + secrets.token_hex(6)


def _kind(fn):
    spec = monitor.CATALOG.get(fn)
    return spec["kind"] if spec else None


def _flows_from_native(exe, funcs, host, run_argv, stdin, marker, timeout):
    res = monitor.run_monitor(exe, funcs, host, argv=run_argv, stdin=stdin, timeout=timeout)
    if not res.get("ok"):
        return None, res.get("note")
    flows = []
    for h in res.get("hits", []):
        for key in ("cmd", "fmt", "src"):                # the string args the monitor captures
            v = h.get(key)
            if v and marker in v:
                flows.append({"sink": h["func"], "kind": h.get("kind"), "arg": v})
                break
    return flows, None


def _flows_from_qemu(exe, arch, info, funcs, target, run_argv, stdin, marker, timeout):
    res = qemu_gdb.monitor_calls(exe, arch, symbols=info["symbols"], entry=info["entry"],
                                 pie=info["pie"], sink_names=set(funcs),
                                 endianness=target.endianness, bits=target.bits,
                                 argv=run_argv, stdin=stdin, timeout=timeout)
    if not res.get("ok"):
        return None, res.get("note")
    flows = []
    for h in res.get("hits", []):
        for v in h.get("argstrs", []):                   # every arg register deref'd as a C-string
            if v and marker in v:
                flows.append({"sink": h["func"], "kind": _kind(h["func"]), "arg": v})
                break
    return flows, None


def taint_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("dynamic_taint requires a target_id")
    p = ctx.params or {}
    host = sandbox.host_arch()
    fmt = (target.file_type or "").lower()
    if fmt and fmt != "elf":
        ctx.emit("taint.done", payload={"ok": False, "supported": False,
                 "note": f"dynamic taint runs Linux ELF only (this target is {fmt.upper()})"})
        ctx.progress(pct=100, msg="taint not supported for this format")
        return {}
    emulated = bool(target.arch and target.arch != host)
    if emulated and not qemu_gdb.breakpoints_supported(target.arch):
        ctx.emit("taint.done", payload={"ok": False, "supported": False,
                 "note": f"no cross-arch monitor for {target.arch}"})
        ctx.progress(pct=100, msg="taint not supported for this cross-arch target")
        return {}
    if not emulated and not monitor.supported(host):
        ctx.emit("taint.done", payload={"ok": False, "supported": False,
                 "note": f"no GDB argument map for {host}"})
        return {}

    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(ctx.content.path(target.sha256).read_bytes())
    os.chmod(exe, 0o755)

    marker = _marker()
    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
    argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 20))
    stdin = marker.encode() if mode == "stdin" else b""
    run_argv = argv
    if mode == "arg":
        run_argv = argv + [marker]
    elif mode == "file":
        infile = ctx.scratch() / "taint-input.bin"
        infile.write_text(marker)
        run_argv = argv + [str(infile)]

    if emulated:
        info = elfsyms.read(exe)
        funcs = sorted(set(info["symbols"]) & set(monitor.CATALOG))
        if not funcs:
            ctx.emit("taint.done", payload={"ok": True, "flows": [], "findings": 0,
                     "note": "no monitored sinks in the binary's symbols (stripped/PLT-only)"})
            ctx.progress(pct=100, msg="no sinks to watch for taint")
            return {}
        ctx.progress(msg=f"tainting {len(funcs)} sink(s) under qemu-{target.arch} with a marker")
        flows, note = _flows_from_qemu(exe, target.arch, info, funcs, target, run_argv, stdin,
                                       marker, timeout)
    else:
        names = {normalize(e.dst_name) for e in CallEdgeDAO(ctx.conn).list_by_target(target.id)
                 if e.dst_name}
        funcs = sorted(names & set(monitor.CATALOG))
        if not funcs:
            ctx.emit("taint.done", payload={"ok": True, "flows": [], "findings": 0,
                     "note": "no monitored dangerous sinks imported (run disassemble first)"})
            ctx.progress(pct=100, msg="no sinks to watch for taint")
            return {}
        ctx.progress(msg=f"tainting {len(funcs)} sink(s) under GDB with a marker input")
        flows, note = _flows_from_native(exe, funcs, host, run_argv, stdin, marker, timeout)

    if flows is None:
        ctx.emit("taint.done", payload={"ok": False, "note": note})
        ctx.progress(pct=100, msg="taint run could not complete: " + str(note))
        return {}

    fd = FindingDAO(ctx.conn)
    seen = set()
    findings = 0
    for f in flows:
        if f["sink"] in seen:
            continue
        seen.add(f["sink"])
        cwe, sev = _CWE.get(f["kind"], ("CWE-20", "medium"))
        fd.upsert(target.id, target.case_id, {
            "cwe": cwe, "severity": sev, "detector": "taint", "state": "confirmed",
            "confidence": 0.85,
            "title": f"Input reaches {f['sink']}() at runtime (dynamic taint confirmed)",
            "evidence": [{"channel": "dynamic-taint",
                          "detail": f"a unique marker fed as input was observed in {f['sink']}()'s "
                                    f"argument at runtime: {f['arg'][:120]!r}"}],
            "function_addr": None, "site_addr": None, "dedup_key": f"taint:{f['sink']}"})
        findings += 1

    ctx.emit("taint.done", payload={"ok": True, "flows": [
        {"sink": f["sink"], "cwe": _CWE.get(f["kind"], ("CWE-20",))[0]} for f in flows],
        "findings": findings, "sinks_watched": funcs,
        "note": None if flows else "the marker input did not reach any monitored sink"})
    ctx.progress(pct=100, msg=f"{findings} confirmed input->sink flow(s)")
    return {}


def register() -> None:
    register_stage(TAINT_STAGE, taint_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=120)


def enqueue_taint(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, TAINT_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
