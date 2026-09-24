"""Multi-process debugging (doc 17.3) — the `multi_debug` stage.

Runs the entry component under GDB with follow-fork/exec, so when a spawned child (a
fork()ed worker or an execve()d helper) crashes, we capture *its* fault -- signal, fault
address, faulting instruction, symbolized backtrace -- classify it with the Phase-6 root-
cause engine, and attribute it back to the input that entered the parent (cross-boundary
blame across the process boundary). GDB-only (follow-fork needs a real debugger); reports
unsupported when GDB is absent or the target is cross-arch.
"""
from __future__ import annotations

import json
import os

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from .. import elf
from ..dynamic import sandbox
from ..dynamic.stage import crash_dedup_key
from ..fuzz.runner import place
from ..poc.capture import MODES, how_to_feed
from . import gdb, rootcause

MULTI_DEBUG_STAGE = "multi_debug"
TOOL = "lykos-multidebug"
TOOL_VERSION = "multidebug-1"


def _hex(v):
    return None if v is None else (v if isinstance(v, str) else hex(v))


def _crash_binary(cap):
    """Best-effort path of the executable the fault PC lives in (the crashing image)."""
    if cap.get("execed"):
        return cap["execed"]
    pc = cap.get("pc")
    exe_maps = [m for m in cap.get("maps", []) if "x" in (m.get("perms") or "")
                and m.get("path") and not m["path"].startswith("[")]
    if pc is not None:
        for m in exe_maps:
            if m["start"] <= pc < m["end"]:
                return m["path"]
    return exe_maps[0]["path"] if exe_maps else None


def multi_debug_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("multi_debug requires a target_id (the entry component)")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha and not p.get("input"):
        raise ValueError("multi_debug requires params.input_sha or params.input")
    mode = how_to_feed(ctx.conn, target, p.get("input_sha"), p)[0]
    base_argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 12))

    host = sandbox.host_arch()
    if target.arch and target.arch != host:
        ctx.emit("multidebug.done", payload={"supported": False,
                 "note": f"needs native execution; target {target.arch} != {host}"})
        ctx.progress(pct=100, msg="multi-process debug not supported for cross-arch target")
        return {}
    gpath = gdb.locate_gdb(p.get("gdb_path"))
    if gpath is None:
        ctx.emit("multidebug.done", payload={"supported": False,
                 "note": "follow-fork multi-process debugging requires gdb (not installed)"})
        ctx.progress(pct=100, msg="gdb not installed; multi-process debug unavailable")
        return {}

    import base64
    input_bytes = ctx.content.get_bytes(input_sha) if input_sha \
        else base64.b64decode(p["input"])
    exe = ctx.scratch() / "entry.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    exe.chmod(0o755)

    def _deliver(m):
        stdin_file, argv = None, list(base_argv)
        if m == "stdin":
            stdin_file = str(ctx.scratch() / "stdin.bin")
            (ctx.scratch() / "stdin.bin").write_bytes(input_bytes)
        elif m == "arg":
            # execve truncates at the first NUL; a raw decode raises instead, so every payload
            # carrying an address was undeliverable here.
            argv = place(argv, sandbox.argv_arg(input_bytes, truncate=True))
        else:
            (ctx.scratch() / "input.bin").write_bytes(input_bytes)
            argv = place(argv, str(ctx.scratch() / "input.bin"))
        return argv, stdin_file

    # Try the believed channel, then the rest. A crashing input fed the wrong way does not
    # fault, and "no fault reproduced" then means "we fed it wrong" while reading as a real
    # negative -- the same defect root_cause and build_poc had.
    tried = []
    for m in [mode] + [x for x in MODES if x != mode]:
        argv, stdin_file = _deliver(m)
        ctx.progress(msg=f"detonating entry under gdb (follow-fork/exec, {m})")
        cap = gdb.run_gdb_follow(gpath, exe, argv, stdin_file, ctx=ctx, timeout=int(timeout))
        tried.append(m)
        if cap.get("ok") and cap.get("signal_name"):
            mode = m
            break
    argv, stdin_file = _deliver(mode)

    if not cap.get("ok") or not cap.get("signal_name"):
        ctx.emit("multidebug.done", payload={
            "supported": True, "multiproc": cap.get("multiproc", False),
            "input_modes_tried": tried,
            "note": ("no fault reproduced under the debugger via any of "
                     + ", ".join(tried) + ": " + str(cap.get("reason", "")))})
        ctx.progress(pct=100, msg="no fault reproduced (tried %s)" % ", ".join(tried))
        return {}

    # which component crashed -- match the crashing image to a case target
    crash_path = _crash_binary(cap)
    crash_base = os.path.basename(crash_path) if crash_path else None
    victim = target
    if cap.get("execed") and crash_base:
        for t in TargetDAO(ctx.conn).list_by_case(target.case_id):
            if t.filename == crash_base:
                victim = t
                break

    functions = FunctionDAO(ctx.conn).list_by_target(victim.id)
    call_edges = CallEdgeDAO(ctx.conn).list_by_target(victim.id)
    fdao = FindingDAO(ctx.conn)
    # Exclude the crash rows themselves, or an earlier run's finding at the faulting address
    # attributes the crash to itself.
    findings = [f for f in fdao.list_by_target(victim.id)
                if not (f.dedup_key or "").startswith("dynamic-crash:")]
    elf_entry = None
    try:
        elf_entry = elf.parse(exe.read_bytes()).entry
    except Exception:
        pass                                  # not an ELF, or unreadable: match absolutely
    rc = rootcause.analyze(cap, functions, call_edges, findings, str(exe),
                           victim.arch or host, fdao.sites_by_target(victim.id), elf_entry)
    v = rc["classification"]

    relation = ("execve" if cap.get("execed") else "fork") if cap.get("multiproc") \
        else "same-process"
    blame = (f"input into {target.filename} -> {relation} -> "
             f"{victim.filename} crashed ({cap['signal_name']})")
    report = {
        "entry": target.filename, "entry_target": target.id,
        "crashing": victim.filename, "crashing_target": victim.id,
        "relation": relation, "child_pid": cap.get("child_pid"),
        "execed": cap.get("execed"), "multiproc": cap.get("multiproc", False),
        "signal": cap["signal_name"], "classification": v,
        "backtrace": [hex(a) for a in cap.get("backtrace", [])],
        "blame": blame, "root_cause": rc["summary"], "backend": "gdb",
    }
    report_sha = ctx.put_artifact("multi-debug", data=json.dumps(
        report, indent=2, sort_keys=True, default=str).encode(),
        meta={"cwe": v["cwe"], "multiproc": report["multiproc"]})

    detail = (f"multi-process debug: {blame}; {v['class']} — {rc['summary']}"
              if report["multiproc"]
              else f"debug: {v['class']} — {rc['summary']}")
    crash_fn = (rc["slice"].get("crash_function") or {})
    _fault_pc = (DynResultDAO(ctx.conn).fault_pc_for(victim.id, input_sha)
                 if input_sha else None)
    fdao.upsert(victim.id, victim.case_id, {
        "cwe": v["cwe"], "title": f"Root cause ({relation}): {v['class']}",
        "severity": v["severity"], "state": "confirmed", "confidence": 0.9,
        "detector": "multi_debug",
        "site_addr": _hex(crash_fn.get("static_addr")),
        "function_addr": crash_fn.get("func_addr"),
        "dedup_key": crash_dedup_key(cap["signal_name"], _fault_pc),
        "evidence": [{"channel": "multi-process-debug", "detail": detail}]})

    # A crash found through a forked child demonstrates the child's findings just as much.
    by_id = {f.id: f for f in findings}
    promoted = 0
    for a in rc["slice"].get("attributed") or []:
        f = by_id.get(a["finding_id"])
        if f is None:
            continue
        fdao.upsert(victim.id, victim.case_id,
                    rootcause.attribution_upsert(f, a, cap["signal_name"]))
        promoted += a["tier"] == "fault-site"
    report["attributed"] = rc["slice"].get("attributed") or []

    ctx.emit("multidebug.done", payload={
        "supported": True, "multiproc": report["multiproc"], "relation": relation,
        "entry": target.filename, "crashing": victim.filename, "cwe": v["cwe"],
        "classification": v["class"], "blame": blame, "report": report_sha,
        "attributed": len(report["attributed"]), "poc_backed": promoted})
    ctx.progress(pct=100, msg=blame[:90])
    return {"output_shas": [report_sha], "output_kind": "multi-debug"}


def register() -> None:
    register_stage(MULTI_DEBUG_STAGE, multi_debug_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_multi_debug(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, MULTI_DEBUG_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
