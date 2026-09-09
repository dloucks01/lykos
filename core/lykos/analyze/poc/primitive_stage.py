"""Phase 6 — the `poc_primitive` stage (L2): prove a confirmed crash yields instruction-
pointer control, via the cyclic-pattern technique and ptrace register capture. On success it
builds an L2 PoC bundle and promotes the finding. Native-architecture targets only; cross-arch
(qemu) targets are reported as unsupported rather than failing."""
from __future__ import annotations

import shutil

from ...db.dao import FindingDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..debug import rootcause
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import bundle, primitive
from .capture import make_capture, materialize_helper

PRIMITIVE_STAGE = "poc_primitive"
TOOL = "primitive"
TOOL_VERSION = "primitive-1"


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
    helper = materialize_helper()
    try:
        capture = make_capture(ctx, helper, exe, mode, base_argv, timeout,
                               sys.executable)

        ctx.progress(msg=f"detonating {length}-byte cyclic pattern under ptrace")
        cap0 = capture(primitive.cyclic(length))
        if not cap0.get("ok") or not cap0.get("signal_name"):
            ctx.emit("primitive.done", payload={"primitive": None, "supported": True,
                     "note": "cyclic pattern did not fault: " + str(cap0.get("reason", ""))})
            ctx.progress(pct=100, msg="no fault under cyclic pattern (no L2 primitive)")
            return {}

        rec = primitive.recover_ip_offset(cap0, length)
        regs = primitive.controlled_registers(cap0, length)
        disasm = rootcause.disasm_one(bytes.fromhex(cap0.get("pc_bytes", "")),
                                      target.arch or host)
        mnem = (disasm or "").split()[0] if disasm else ""

        # 1) instruction-pointer control -- trust the stack-slot heuristic only when the fault
        # is actually at a return (else a fuzzed buffer of stack locals looks like a retaddr);
        # a cyclic PC (source "pc") is a hijack and is always trusted.
        if rec is not None and (rec[1] == "pc" or mnem in ("ret", "retq", "retn")):
            offset, source = rec
            ctx.progress(msg=f"IP-control offset {offset} ({source}); confirming")
            control = primitive.control_input(offset, length)
            confirmed = primitive.marker_confirmed(capture(control))
            prim = {"type": "instruction-pointer-control", "offset": offset, "source": source,
                    "marker": primitive.MARKER, "observed_pc": cap0.get("pc", 0),
                    "confirmed": confirmed, "registers": regs}
            extra = f"instruction-pointer control at offset {offset}"
            return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                             prim, confirmed, extra)

        # 2) memory primitive (write-what-where / controlled read at a faulting mem access)
        memp = primitive.analyze_memory_primitive(cap0, length, disasm)
        if memp is not None:
            ctx.progress(msg=f"{memp['type']} at addr offset {memp['addr_offset']}; confirming")
            control = primitive.two_marker_input(memp["addr_offset"], memp.get("value_offset"),
                                                 length)
            addr_ok, value_ok = primitive.memory_primitive_confirmed(capture(control), memp)
            confirmed = addr_ok and (value_ok or memp["type"] != "write-what-where")
            reg_map = {memp["addr_reg"]: memp["addr_offset"]}
            if memp.get("value_reg") and memp.get("value_offset") is not None:
                reg_map[memp["value_reg"]] = memp["value_offset"]
            prim = {"type": memp["type"], "offset": memp["addr_offset"],
                    "marker": primitive.MARKER, "observed_pc": cap0.get("pc", 0),
                    "confirmed": confirmed, "registers": reg_map, "access": memp["access"],
                    "value_offset": memp.get("value_offset"), "disasm": disasm}
            extra = (f"{memp['type']}: {memp['access']} through attacker-controlled address "
                     f"(offset {memp['addr_offset']}"
                     + (f", value offset {memp['value_offset']}"
                        if memp.get("value_offset") is not None else "") + f") via `{disasm}`")
            return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                             prim, confirmed, extra)

        # 3) crash reproduced but no controllable primitive found
        ctx.emit("primitive.done", payload={
            "primitive": ("register-control" if regs else None), "supported": True,
            "registers": regs, "signal": cap0.get("signal_name"),
            "note": "crash reproduced but no instruction-pointer / memory primitive found"})
        ctx.progress(pct=100, msg="crash without a controllable primitive")
        return {}
    finally:
        shutil.rmtree(helper.parent, ignore_errors=True)


def _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control, prim, confirmed,
              extra):
    """Bundle the demonstrating input, record an L2 (or L1) PoC, promote the crash finding on
    confirmation, and emit the result -- shared by every primitive kind."""
    level = "L2" if confirmed else "L1"
    control_sha = ctx.put_artifact("poc-l2-input", data=control)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "input_mode": mode,
            "level": level, "primitive": prim, "tool_version": TOOL_VERSION}
    data = bundle.build(target_bytes, control, meta, b"", mode, base_argv,
                        cap0.get("signal_name") or "SIGSEGV", primitive=prim)
    bundle_sha = ctx.put_artifact("poc-bundle", data=data,
                                  meta={"level": level, "verified": confirmed})
    PocDAO(ctx.conn).insert(target.id, target.case_id, level=level, verified=confirmed,
                            signal_name=cap0.get("signal_name"), input_sha=control_sha,
                            bundle_sha=bundle_sha)
    if confirmed:
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, crash_finding_candidate(
            cap0.get("signal_name"), control_sha, "ptrace", "primitive",
            f"(L2 primitive: {extra})", state="poc-backed", confidence=0.98,
            bundle_sha=bundle_sha))
    ctx.emit("primitive.done", payload={
        "primitive": prim["type"], "supported": True, "offset": prim.get("offset"),
        "confirmed": confirmed, "level": level, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=(f"L2 confirmed: {prim['type']}") if confirmed
                 else f"{prim['type']} indicated (unconfirmed)")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle"}


def register() -> None:
    register_stage(PRIMITIVE_STAGE, primitive_stage, resource_class="cpu",
                   tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_primitive(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, PRIMITIVE_STAGE, target_id=target.id,
                         params=params or {}, input_hashes=[target.sha256], tool=TOOL,
                         tool_version=TOOL_VERSION, resource_class="cpu", force=force)
