"""Phase 6 — the `poc_primitive` stage (L2): prove a confirmed crash yields instruction-
pointer control, via the cyclic-pattern technique and ptrace register capture. On success it
builds an L2 PoC bundle and promotes the finding. Native targets use the ptrace helper;
cross-arch (emulated) targets are captured via qemu-user's gdbstub (pc-based IP control)."""
from __future__ import annotations

import json
import shutil

from ...db.dao import DynResultDAO, FindingDAO, FunctionDAO, PocDAO, TargetDAO
from ...jobs.registry import register_stage
from ..debug import qemu_gdb, rootcause
from ..dynamic import sandbox
from ..dynamic.stage import crash_finding_candidate
from . import bundle, primitive
from .capture import MODES, how_to_feed, make_capture, make_qemu_capture, materialize_helper

# ISAs whose indirect branch MASKS bit 0 of the loaded PC (ARM/AArch64 for Thumb interworking,
# RISC-V because JALR is specified to clear it), so a captured fault PC is `value & ~1` and its
# cyclic window can alias one word early. Defined once, next to the gdbstub that also has to
# account for it when placing breakpoints.
_LSB_MASKED_PC = qemu_gdb.LSB_MASKED_PC

PRIMITIVE_STAGE = "poc_primitive"
TOOL = "primitive"
TOOL_VERSION = "primitive-1"


def _slack_txt(slack):
    """Describe how the confirmed offset sits relative to the recovered buffer's frame base."""
    if slack > 0:
        return " + saved frame pointer"
    if slack < 0:
        return " - saved register slot"
    return " + saved frame"


def _hydrate_frames(ctx, target_id, target=None):
    """Recovered stack frames per function addr (empty if the target wasn't disassembled).

    Restricted to the PROGRAM's own functions where the symbol table can say which those are.
    A statically linked binary carries its libc, and the candidate ranking prefers the
    tightest buffer -- so on jhead every attempt went into 8-byte scratch buffers inside
    glibc, and the stage spent its whole budget without touching jhead's own frames.
    """
    fdao = FunctionDAO(ctx.conn)
    functions = fdao.list_by_target(target_id)
    ranges, base = (), 0
    if target is not None:
        try:
            from ..debug import rootcause
            from ..elf import parse as parse_elf
            from ..elf import program_ranges
            blob = ctx.content.path(target.sha256).read_bytes()
            ranges = program_ranges(blob)
            base = rootcause.image_base(functions, parse_elf(blob).entry) or 0
        except Exception:
            ranges = ()
    frames = {}
    for f in functions:
        if not f.blocks:
            continue
        if ranges and not _own_code(f.addr, base, ranges):
            continue
        full = fdao.get(f.id)
        if full and full.frame and full.frame.get("vars"):
            frames[f.addr] = full.frame
    return frames


def _own_code(addr, base, ranges) -> bool:
    import bisect
    try:
        a = (int(addr, 16) if isinstance(addr, str) else int(addr or 0)) - base
    except (TypeError, ValueError):
        return True
    los = [lo for lo, _ in ranges]
    i = bisect.bisect_right(los, a) - 1
    return i >= 0 and a < ranges[i][1]


def primitive_stage(ctx) -> dict:
    import sys
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("poc_primitive requires a target_id")
    p = ctx.params or {}
    input_sha = p.get("input_sha")
    if not input_sha:
        raise ValueError("poc_primitive requires params.input_sha (a crashing input)")
    timeout = float(p.get("timeout", 8))
    mode, base_argv, mode_why = how_to_feed(ctx.conn, target, input_sha, p)

    host = sandbox.host_arch()
    emulated = bool(target.arch and target.arch != host)
    if emulated and not qemu_gdb.supported(target.arch):
        ctx.emit("primitive.done", payload={"primitive": None, "supported": False,
                 "note": f"L2 for cross-arch {target.arch}: no qemu gdbstub register layout "
                         f"(host {host})"})
        ctx.progress(pct=100, msg="L2 not supported for this cross-arch target")
        return {}

    orig = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    exe.chmod(0o755)

    # Static RE corroboration: recovered stack-buffer sizes predict IP-control offsets.
    word = 8 if (target.bits or 64) >= 64 else 4
    endian = "big" if target.endianness == "big" else "little"
    frames = _hydrate_frames(ctx, target.id, target)
    offset_candidates = primitive.frame_offset_candidates(frames, word)
    if offset_candidates:
        ctx.emit("primitive.static", payload={"candidates": offset_candidates[:8]})

    need = (max((c["offset"] for c in offset_candidates), default=0) + word + 64)
    length = min(max(len(orig) * 2, need, 256), 4096)
    helper = materialize_helper()
    try:
        def _capture_for(m):
            if emulated:
                return make_qemu_capture(exe, target.arch, m, base_argv, timeout,
                                         endianness=target.endianness, bits=target.bits)
            return make_capture(ctx, helper, exe, m, base_argv, timeout, sys.executable)

        ctx.progress(msg=f"detonating {length}-byte cyclic pattern under "
                         + (f"qemu-{target.arch} gdbstub" if emulated else "ptrace"))
        # Try the mode we believe in, then the others. A crashing input fed the wrong way
        # does not fault, and reporting that as "no L2 primitive" turns a wrong setup into
        # what reads as a real negative result.
        pattern = primitive.cyclic(length)
        tried = []
        for m in [mode] + [x for x in MODES if x != mode]:
            capture = _capture_for(m)
            cap0 = capture(pattern)
            tried.append(m)
            if cap0.get("ok") and cap0.get("signal_name"):
                if m != mode:
                    mode_why = f"{mode_why}, but it only faulted via {m}"
                mode = m
                break
        capture = _capture_for(mode)
        if not cap0.get("ok") or not cap0.get("signal_name"):
            ctx.emit("primitive.done", payload={
                "primitive": None, "supported": True, "input_modes_tried": tried,
                "note": ("cyclic pattern did not fault via any of " + ", ".join(tried)
                         + ": " + str(cap0.get("reason", "")))})
            ctx.progress(pct=100, msg="no fault under cyclic pattern (tried %s)"
                         % ", ".join(tried))
            return {}

        rec = primitive.recover_ip_offset(cap0, length, endian=endian, word=word)
        regs = primitive.controlled_registers(cap0, length, endian=endian, word=word)
        disasm = rootcause.disasm_one(bytes.fromhex(cap0.get("pc_bytes", "")),
                                      target.arch or host)
        mnem = (disasm or "").split()[0] if disasm else ""

        # 1) instruction-pointer control. Trust the dynamic slot heuristic only when the fault
        # is actually at a return (else a fuzzed buffer of stack locals looks like a retaddr); a
        # cyclic pc, or a controlled return-address register (lr/x30/$ra on link-register ABIs),
        # is a hijack and always trusted. We then CONFIRM by placing the marker at the control
        # slot -- and confirmation, not the raw heuristic, decides the reported offset, so an
        # off-by-a-word recovery self-corrects.
        #
        # Build the confirm candidates in priority order:
        #   - the dynamic offset (when trusted);
        #   - on an LSB-masking ISA, its alias sibling (see _LSB_MASKED_PC): the captured PC
        #     is `value & ~1`, whose cyclic window can alias one word early -- searching
        #     `(pc | 1)` restores the exact slot;
        #   - the static-frame predictions (also the sole source when the fault isn't a ret).
        trusted = rec is not None and (rec[1] in ("pc",) + primitive.ra_regs(cap0)
                                       or mnem in ("ret", "retq", "retn"))
        confirm_cands = []                         # (offset, source, static_match, fp_slack)
        if trusted:
            off0, src0 = rec
            sm0, sl0 = primitive.match_frame_candidate(off0, offset_candidates, word)
            confirm_cands.append((off0, src0, sm0, sl0))
            if (target.arch or "") in _LSB_MASKED_PC and src0 == "pc":
                alt = primitive.cyclic_find(
                    primitive._reg_window((cap0.get("pc") or 0) | 1, word, endian, 4), length, 4)
                if alt != -1 and alt != off0:
                    sm1, sl1 = primitive.match_frame_candidate(alt, offset_candidates, word)
                    confirm_cands.append((alt, "pc(lsb-masked)", sm1, sl1))
        for off, c, fp_slack in primitive.seed_offsets(offset_candidates, word, length):
            confirm_cands.append((off, "static-frame", c, fp_slack))

        seen_off = set()
        for off, source, static_match, fp_slack in confirm_cands:
            if off in seen_off:
                continue
            seen_off.add(off)
            ctx.progress(msg=f"confirming IP-control at offset {off} ({source})")
            control = primitive.control_input(off, length, word, endian)
            if not primitive.marker_confirmed(capture(control), word, endian):
                continue
            prim = {"type": "instruction-pointer-control", "offset": off, "source": source,
                    "marker": primitive._ip_marker(word), "observed_pc": cap0.get("pc", 0),
                    "confirmed": True, "registers": regs,
                    "static_offset": static_match, "static_candidates": offset_candidates}
            extra = f"instruction-pointer control at offset {off} ({source})"
            if static_match:
                extra += (f"; corroborated by static stack frame -- {static_match['size']}-byte"
                          f" buffer {static_match['buffer']}{_slack_txt(fp_slack)}"
                          f" = offset {off}")
            return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                             prim, True, extra)

        # 1c) nothing confirmed -- if we had a trusted dynamic offset, still report it as an
        # unconfirmed IP-control primitive (the crash reproduces; the marker just didn't pin).
        if trusted:
            offset, source = rec
            static_match, fp_slack = primitive.match_frame_candidate(offset, offset_candidates,
                                                                     word)
            control = primitive.control_input(offset, length, word, endian)
            prim = {"type": "instruction-pointer-control", "offset": offset, "source": source,
                    "marker": primitive._ip_marker(word), "observed_pc": cap0.get("pc", 0),
                    "confirmed": False, "registers": regs,
                    "static_offset": static_match, "static_candidates": offset_candidates}
            extra = f"instruction-pointer control at offset {offset} ({source})"
            if static_match:
                extra += (f"; corroborated by static stack frame -- {static_match['size']}-byte"
                          f" buffer {static_match['buffer']}{_slack_txt(fp_slack)}"
                          f" = offset {offset}")
            return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                             prim, False, extra)

        # 2) memory primitive (write-what-where / controlled read at a faulting mem access)
        memp = primitive.analyze_memory_primitive(cap0, length, disasm, endian=endian,
                                                  word=word)
        if memp is not None:
            ctx.progress(msg=f"{memp['type']} at addr offset {memp['addr_offset']}; confirming")
            control = primitive.two_marker_input(memp["addr_offset"], memp.get("value_offset"),
                                                 length, word=word, endian=endian)
            addr_ok, value_ok = primitive.memory_primitive_confirmed(capture(control), memp,
                                                                     word=word, endian=endian)
            confirmed = addr_ok and (value_ok or memp["type"] != "write-what-where")
            reg_map = {memp["addr_reg"]: memp["addr_offset"]}
            if memp.get("value_reg") and memp.get("value_offset") is not None:
                reg_map[memp["value_reg"]] = memp["value_offset"]
            prim = {"type": memp["type"], "offset": memp["addr_offset"],
                    "marker": primitive._ip_marker(word), "observed_pc": cap0.get("pc", 0),
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
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level=level,
                                     verified=confirmed, signal_name=cap0.get("signal_name"),
                                     input_sha=control_sha, bundle_sha=bundle_sha)
    if confirmed:
        fd = FindingDAO(ctx.conn)
        # A confirmed primitive DEMONSTRATES an end effect -- headline it and relabel the crash
        # finding authoritatively (RIP control -> RCE, write-what-where -> arbitrary write,
        # controlled read -> info disclosure), instead of leaving it as "Reproduced crash".
        # An L2 instruction-pointer-control primitive DEMONSTRATES a control-flow hijack -- not
        # code execution. Under NX/ASLR no attacker code has run at this level; that is precisely
        # what the L3 exploit stage proves (and then upgrades RCE to demonstrated). Reporting L2 as
        # "RCE demonstrated" is an over-claim, so IP-control headlines a demonstrated hijack and
        # carries RCE only as POTENTIAL. Write/read primitives ARE their effect, so stay demonstrated.
        _EFF = {"instruction-pointer-control": ("control-flow-hijack", "Control-flow hijack"),
                "write-what-where": ("memory-corruption", "Memory corruption (arbitrary write)"),
                "arbitrary-write": ("memory-corruption", "Memory corruption (arbitrary write)"),
                "arbitrary-read": ("info-disclosure", "Information disclosure (memory leak)"),
                "controlled-read": ("info-disclosure", "Information disclosure (memory leak)")}
        _kind_title = _EFF.get(prim.get("type"))
        # Key on the ORIGINAL crash's faulting address (as root_cause does), NOT this capture's,
        # so the primitive finding merges into the crash finding instead of forking a duplicate:
        # on a native target the fault PC is in the dedup key, and omitting it here split one
        # defect into two poc-backed findings.
        _orig = (ctx.params or {}).get("input_sha")
        _fpc = DynResultDAO(ctx.conn).fault_pc_for(target.id, _orig) if _orig else None
        cand = crash_finding_candidate(
            cap0.get("signal_name"), control_sha, "ptrace", "primitive",
            f"(L2 primitive: {extra})", state="poc-backed", confidence=0.98,
            bundle_sha=bundle_sha, fault_pc=_fpc)
        if _kind_title:
            _kind, _title = _kind_title
            cand["title"] = f"{_title} (demonstrated): L2 primitive"
            cand["authoritative"] = True
            cand["title_only"] = True                  # keep root_cause's specific CWE
            # Promote the matching end effect to DEMONSTRATED and attach the L2 bundle that
            # proves it -- the confirmed primitive (RIP control / write-what-where / controlled
            # read), the exact input that achieves it, and how (offset, captured marker).
            _effects = [{
                "kind": _kind, "title": _title, "status": "demonstrated", "detail": extra,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": control_sha,
                          "note": extra}}]
            if prim.get("type") == "instruction-pointer-control":
                # RCE is POTENTIAL at L2 (hijack achieved, code execution not shown); L3 upgrades it.
                _effects.append({"kind": "rce", "title": "Remote code execution",
                                 "status": "potential",
                                 "detail": "control-flow hijack achieved at L2; code execution not "
                                           "demonstrated at this level (see L3 exploit)"})
            cand.setdefault("evidence", []).append(
                {"channel": "effects", "detail": json.dumps(_effects)})
        fd.upsert(target.id, target.case_id, cand)
        fid = fd.id_for_dedup(target.id, cand["dedup_key"])   # the pc-keyed crash finding
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)
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
