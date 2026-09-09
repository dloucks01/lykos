"""Phase 6 — the `poc_primitive` stage (L2): prove a confirmed crash yields instruction-
pointer control, via the cyclic-pattern technique and ptrace register capture. On success it
builds an L2 PoC bundle and promotes the finding. Native-architecture targets only; cross-arch
(qemu) targets are reported as unsupported rather than failing."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from ...db.dao import FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import bundle, primitive

PRIMITIVE_STAGE = "poc_primitive"
TOOL = "primitive"
TOOL_VERSION = "primitive-1"
_HELPER = "ptrace_capture.py"


def _materialize_helper() -> Path:
    d = Path(tempfile.mkdtemp(prefix="lykos-ptrace-"))
    try:
        from importlib import resources
        data = (resources.files("lykos.analyze.poc") / _HELPER).read_bytes()
    except Exception:
        data = (Path(__file__).parent / _HELPER).read_bytes()
    p = d / _HELPER
    p.write_bytes(data)
    return p


def _make_capture(ctx, helper, exe, mode, base_argv, timeout, python):
    work = helper.parent

    def capture(data: bytes) -> dict:
        stdin_file = None
        argv = list(base_argv)
        if mode == "stdin":
            stdin_file = str(work / "stdin.bin")
            (work / "stdin.bin").write_bytes(data)
        elif mode == "arg":
            argv = argv + [data.decode("latin-1")]
        elif mode == "file":
            (work / "input.bin").write_bytes(data)
            argv = argv + [str(work / "input.bin")]
        spec = {"exe": str(exe), "argv": argv, "stdin_file": stdin_file,
                "timeout": timeout}
        spec_path = work / "spec.json"
        spec_path.write_text(json.dumps(spec))
        proc = ctx.run_subprocess([python, str(helper), str(spec_path)],
                                  timeout=timeout + 30)
        out = (proc.stdout or b"").decode("latin-1", "ignore").strip()
        try:
            return json.loads(out) if out else {"ok": False, "reason": "no output"}
        except json.JSONDecodeError:
            return {"ok": False, "reason": "bad helper output: " + out[:200]}

    return capture


def primitive_stage(ctx) -> dict:
    import sys
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("poc_primitive requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("poc_primitive requires params.input_sha (a crashing input)")
    mode = p.get("input_mode", "stdin")
    base_argv = list(p.get("argv") or [])
    timeout = float(p.get("timeout", 8))

    host = sandbox.host_arch()
    if target.arch and target.arch != host:
        ctx.emit("primitive.done", payload={"primitive": None, "supported": False,
                 "note": f"L2 primitive analysis needs native execution; target {target.arch}"
                         f" != host {host} (cross-arch/qemu not supported yet)"})
        ctx.progress(pct=100, msg="L2 not supported for cross-arch target")
        return {}

    orig = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    exe.write_bytes(target_bytes)
    exe.chmod(0o755)

    length = min(max(len(orig) * 2, 256), 4096)
    helper = _materialize_helper()
    try:
        capture = _make_capture(ctx, helper, exe, mode, base_argv, timeout, sys.executable)

        ctx.progress(msg=f"detonating {length}-byte cyclic pattern under ptrace")
        cap0 = capture(primitive.cyclic(length))
        if not cap0.get("ok") or not cap0.get("signal_name"):
            ctx.emit("primitive.done", payload={"primitive": None, "supported": True,
                     "note": "cyclic pattern did not fault: " + str(cap0.get("reason", ""))})
            ctx.progress(pct=100, msg="no fault under cyclic pattern (no L2 primitive)")
            return {}

        rec = primitive.recover_ip_offset(cap0, length)
        regs = primitive.controlled_registers(cap0, length)
        if rec is None:
            ctx.emit("primitive.done", payload={
                "primitive": ("register-control" if regs else None), "supported": True,
                "registers": regs, "signal": cap0.get("signal_name"),
                "note": "crash reproduced but no instruction-pointer control found"})
            ctx.progress(pct=100, msg="crash without IP control"
                         + (" (registers controlled)" if regs else ""))
            return {}

        offset, source = rec
        ctx.progress(msg=f"IP-control offset {offset} ({source}); confirming with sentinel")
        control = primitive.control_input(offset, length)
        cap1 = capture(control)
        confirmed = primitive.marker_confirmed(cap1)

        prim = {"type": "instruction-pointer-control", "offset": offset, "source": source,
                "marker": primitive.MARKER, "observed_pc": cap1.get("pc", 0),
                "confirmed": confirmed, "registers": regs,
                "signal": cap0.get("signal_name")}

        control_sha = ctx.put_artifact("poc-l2-input", data=control)
        meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
                "level": "L2" if confirmed else "L1", "primitive": prim,
                "tool_version": TOOL_VERSION}
        data = bundle.build(target_bytes, control, meta, b"", mode, base_argv,
                            cap0.get("signal_name") or "SIGSEGV", primitive=prim)
        level = "L2" if confirmed else "L1"
        bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                      meta={"level": level, "verified": confirmed})
        PocDAO(ctx.conn).insert(target.id, target.case_id, level=level, verified=confirmed,
                                signal_name=cap0.get("signal_name"), input_sha=control_sha,
                                bundle_sha=bundle_sha)

        if confirmed:
            FindingDAO(ctx.conn).upsert(target.id, target.case_id, crash_finding_candidate(
                cap0.get("signal_name"), control_sha, "ptrace", "primitive",
                f"(L2 primitive: instruction-pointer control at offset {offset})",
                state="poc-backed", confidence=0.98, bundle_sha=bundle_sha))

        ctx.emit("primitive.done", payload={"primitive": prim["type"] if confirmed else
                 "ip-control-unconfirmed", "supported": True, "offset": offset,
                 "confirmed": confirmed, "level": level, "bundle": bundle_sha,
                 "registers": regs})
        ctx.progress(pct=100, msg=(f"L2 confirmed: IP control at offset {offset}")
                     if confirmed else f"IP control indicated at {offset} (unconfirmed)")
        return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}
    finally:
        shutil.rmtree(helper.parent, ignore_errors=True)


def register() -> None:
    register_stage(PRIMITIVE_STAGE, primitive_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_primitive(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, PRIMITIVE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
