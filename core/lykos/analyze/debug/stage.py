"""Phase 6 — the `root_cause` stage: explain a confirmed crash. Uses GDB when installed,
otherwise the pure-stdlib ptrace helper; produces a structured root-cause report (fault
classification + backtrace + a static call-graph/taint slice), stores it as an artifact, and
attaches a root-cause evidence line to the crash finding. Cross-arch targets are captured
via qemu-user's gdbstub."""
from __future__ import annotations

import json
import shutil
import sys

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, TargetDAO
from ...jobs.registry import register_stage
from .. import elf
from ..dynamic import sandbox
from ..dynamic.stage import crash_dedup_key
from ..poc.capture import MODES, how_to_feed, make_capture, make_qemu_capture, materialize_helper
from . import gdb, qemu_gdb, rootcause

ROOT_CAUSE_STAGE = "root_cause"
TOOL = "rootcause"
TOOL_VERSION = "rootcause-1"


def _hex(v):
    """Addresses reach the finding table as hex strings; the slice carries them as ints."""
    return None if v is None else (v if isinstance(v, str) else hex(v))


def root_cause_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("root_cause requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("root_cause requires params.input_sha (a crashing input)")
    timeout = float(p.get("timeout", 10))
    mode, base_argv, mode_why = how_to_feed(ctx.conn, target, input_sha, p)

    host = sandbox.host_arch()
    emulated = bool(target.arch and target.arch != host)
    if emulated and not qemu_gdb.supported(target.arch):
        ctx.emit("rootcause.done", payload={"supported": False,
                 "note": f"root-cause for cross-arch {target.arch}: no qemu gdbstub layout "
                         f"(host {host})"})
        ctx.progress(pct=100, msg="root-cause not supported for this cross-arch target")
        return {}

    input_bytes = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(target_bytes)
    exe.chmod(0o755)

    # capture the fault: qemu-user gdbstub (cross-arch), else GDB, else the ptrace helper
    gpath = None if emulated else gdb.locate_gdb(p.get("gdb_path"))
    helper_dir = None
    helper = None
    if not emulated and gpath is None:
        helper = materialize_helper()
        helper_dir = helper.parent
    backend = ("qemu-gdbstub" if emulated else "gdb" if gpath is not None else "ptrace")

    def _capture_with(m):
        if emulated:
            return make_qemu_capture(exe, target.arch, m, base_argv, timeout,
                                     endianness=target.endianness,
                                     bits=target.bits)(input_bytes)
        if gpath is not None:
            stdin_file = None
            argv = list(base_argv)
            if m == "stdin":
                stdin_file = str(ctx.scratch() / "stdin.bin")
                (ctx.scratch() / "stdin.bin").write_bytes(input_bytes)
            elif m == "arg":
                argv = argv + [input_bytes.decode("latin-1")]
            elif m == "file":
                (ctx.scratch() / "input.bin").write_bytes(input_bytes)
                argv = argv + [str(ctx.scratch() / "input.bin")]
            return gdb.run_gdb(gpath, exe, argv, stdin_file, ctx=ctx, timeout=int(timeout))
        return make_capture(ctx, helper, exe, m, base_argv, timeout, sys.executable)(
            input_bytes)

    # Try the mode we believe in, then the others. A crashing input fed the wrong way looks
    # exactly like an input that does not crash, and reporting that as "no fault reproduced"
    # turns a wrong setup into what reads as a clean negative result.
    order = [mode] + [m for m in MODES if m != mode]
    tried = []
    for m in order:
        ctx.progress(msg=f"capturing fault under {backend} ({m})")
        cap = _capture_with(m)
        tried.append(m)
        if cap.get("ok") and cap.get("signal_name"):
            if m != mode:
                mode_why = f"{mode_why}, but it only faulted via {m}"
            mode = m
            break

    try:
        if not cap.get("ok") or not cap.get("signal_name"):
            ctx.emit("rootcause.done", payload={"supported": True, "backend": backend,
                     "input_modes_tried": tried,
                     "note": ("input did not fault under the debugger via any of "
                              + ", ".join(tried) + ": " + str(cap.get("reason", "")))})
            ctx.progress(pct=100, msg="no fault reproduced (tried %s)" % ", ".join(tried))
            return {}

        functions = FunctionDAO(ctx.conn).list_by_target(target.id)
        call_edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
        # Exclude the crash rows themselves: a previous root_cause run leaves a finding at
        # the faulting address, which would otherwise attribute the crash to itself.
        findings = [f for f in FindingDAO(ctx.conn).list_by_target(target.id)
                    if not (f.dedup_key or "").startswith("dynamic-crash:")]
        sites_by_finding = FindingDAO(ctx.conn).sites_by_target(target.id)
        elf_entry = None
        try:
            elf_entry = elf.parse(target_bytes).entry
        except Exception:
            pass                                  # not an ELF, or unreadable: match absolutely
        report = rootcause.analyze(cap, functions, call_edges, findings,
                                   str(exe), target.arch or host, sites_by_finding, elf_entry)
        report["backend"] = backend

        report_sha = ctx.put_artifact("root-cause", data=json.dumps(report, indent=2,
                                      sort_keys=True, default=str).encode(),
                                      meta={"cwe": report["classification"]["cwe"]})
        # attach root-cause + exploitability evidence to the crash finding
        v = report["classification"]
        ex = report["exploitability"]
        ex_line = (f"exploitability: {ex['rating']} ({ex['score']}/100) -- "
                   + "; ".join(ex["reasons"]))
        crash_fn = (report["slice"].get("crash_function") or {})
        fdao = FindingDAO(ctx.conn)
        # from the run that FOUND the input, not from this capture, so every stage that files
        # a crash finding derives the same key and they merge instead of multiplying
        _fault_pc = DynResultDAO(ctx.conn).fault_pc_for(target.id, input_sha)
        fdao.upsert(target.id, target.case_id, {
            "cwe": v["cwe"], "title": f"Root cause: {v['class']} [{ex['rating']}]",
            "severity": v["severity"],
            "state": "confirmed", "confidence": 0.9, "detector": "root_cause",
            # The crash is now locatable, and the key carries WHERE it faulted so two
            # defects that both segfault stay two findings. The address comes from the run
            # that found the input, not from this capture, so every stage derives the same key.
            "site_addr": _hex(crash_fn.get("static_addr")),
            "function_addr": crash_fn.get("func_addr"),
            "dedup_key": crash_dedup_key(cap["signal_name"], _fault_pc),
            "evidence": [{"channel": "root-cause", "detail": report["summary"]},
                         {"channel": "exploitability", "detail": ex_line}]})

        # Attribute the crash to the static findings it actually demonstrates. Without this a
        # verified PoC sits beside the static inventory instead of ranking it: on jhead, one
        # crash next to 38 unknown copy sites, several in the faulting function.
        by_id = {f.id: f for f in findings}
        promoted = 0
        for a in report["slice"].get("attributed") or []:
            f = by_id.get(a["finding_id"])
            if f is None:
                continue
            fdao.upsert(target.id, target.case_id,
                        rootcause.attribution_upsert(f, a, cap["signal_name"]))
            promoted += a["tier"] == "fault-site"

        ctx.emit("rootcause.done", payload={
            "supported": True, "backend": backend, "cwe": v["cwe"],
            "classification": v["class"], "summary": report["summary"],
            "input_mode": mode, "input_mode_why": mode_why,
            "attributed": len(report["slice"].get("attributed") or []),
            "poc_backed": promoted,
            "exploitability": ex["rating"], "exploit_score": ex["score"],
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
