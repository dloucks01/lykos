"""Phase 6 — the `root_cause` stage: explain a confirmed crash. Uses GDB when installed,
otherwise the pure-stdlib ptrace helper; produces a structured root-cause report (fault
classification + backtrace + a static call-graph/taint slice), stores it as an artifact, and
attaches a root-cause evidence line to the crash finding. Native-arch only."""
from __future__ import annotations

import json
import shutil
import sys

from ...db.dao import CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..poc.capture import make_capture, materialize_helper
from . import gdb, rootcause

ROOT_CAUSE_STAGE = "root_cause"
TOOL = "rootcause"
TOOL_VERSION = "rootcause-1"


def root_cause_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("root_cause requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("root_cause requires params.input_sha (a crashing input)")
    mode = p.get("input_mode", "stdin")
    base_argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 10))

    host = sandbox.host_arch()
    if target.arch and target.arch != host:
        ctx.emit("rootcause.done", payload={"supported": False,
                 "note": f"root-cause needs native execution; target {target.arch} != {host}"})
        ctx.progress(pct=100, msg="root-cause not supported for cross-arch target")
        return {}

    input_bytes = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(target_bytes)
    exe.chmod(0o755)

    # capture the fault: GDB backend if available, else the ptrace helper
    gpath = gdb.locate_gdb(p.get("gdb_path"))
    helper_dir = None
    if gpath is not None:
        ctx.progress(msg="capturing fault under gdb")
        stdin_file = None
        argv = list(base_argv)
        if mode == "stdin":
            stdin_file = str(ctx.scratch() / "stdin.bin")
            (ctx.scratch() / "stdin.bin").write_bytes(input_bytes)
        elif mode == "arg":
            argv = argv + [input_bytes.decode("latin-1")]
        elif mode == "file":
            (ctx.scratch() / "input.bin").write_bytes(input_bytes)
            argv = argv + [str(ctx.scratch() / "input.bin")]
        cap = gdb.run_gdb(gpath, exe, argv, stdin_file, ctx=ctx, timeout=int(timeout))
        backend = "gdb"
    else:
        ctx.progress(msg="capturing fault under ptrace (gdb not installed)")
        helper = materialize_helper()
        helper_dir = helper.parent
        capture = make_capture(ctx, helper, exe, mode, base_argv, timeout, sys.executable)
        cap = capture(input_bytes)
        backend = "ptrace"

    try:
        if not cap.get("ok") or not cap.get("signal_name"):
            ctx.emit("rootcause.done", payload={"supported": True, "backend": backend,
                     "note": "input did not fault under the debugger: "
                             + str(cap.get("reason", ""))})
            ctx.progress(pct=100, msg="no fault reproduced")
            return {}

        functions = FunctionDAO(ctx.conn).list_by_target(target.id)
        call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        findings = FindingDAO(ctx.conn).list_by_target(target.id)
        report = rootcause.analyze(cap, functions, call_edges, findings,
                                   str(exe), target.arch or host)
        report["backend"] = backend

        report_sha = ctx.put_artifact("root-cause", data=json.dumps(report, indent=2,
                                      sort_keys=True, default=str).encode(),
                                      meta={"cwe": report["classification"]["cwe"]})
        # attach a root-cause evidence line to the crash finding (keyed by signal)
        v = report["classification"]
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": v["cwe"], "title": f"Root cause: {v['class']}", "severity": v["severity"],
            "state": "confirmed", "confidence": 0.9, "detector": "root_cause",
            "site_addr": None, "function_addr": None,
            "dedup_key": f"dynamic-crash:{cap['signal_name']}",
            "evidence": [{"channel": "root-cause", "detail": report["summary"]}]})

        ctx.emit("rootcause.done", payload={
            "supported": True, "backend": backend, "cwe": v["cwe"],
            "classification": v["class"], "summary": report["summary"],
            "reachable_from_source": report["slice"]["reachable_from_source"],
            "report": report_sha})
        ctx.progress(pct=100, msg=report["summary"][:80])
        return {"output_shas": [report_sha], "output_kind": "root-cause"}
    finally:
        if helper_dir is not None:
            shutil.rmtree(helper_dir, ignore_errors=True)


def register() -> None:
    register_stage(ROOT_CAUSE_STAGE, root_cause_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_root_cause(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, ROOT_CAUSE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
