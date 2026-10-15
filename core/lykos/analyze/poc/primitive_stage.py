"""Phase 6 — the `poc_primitive` stage (L2): prove a confirmed crash yields instruction-
pointer control, via the cyclic-pattern technique and ptrace register capture. On success it
builds an L2 PoC bundle and promotes the finding. Native targets use the ptrace helper;
cross-arch (emulated) targets are captured via qemu-user's gdbstub (pc-based IP control)."""
from __future__ import annotations

import json
import shutil

from ...db.dao import DynResultDAO, FindingDAO, FunctionDAO, PocDAO, TargetDAO

# What a CONFIRMED primitive proves about the defect, used only where root_cause's class does
# not already name a memory-corruption weakness (see the comment at the override below).
# Reaching a saved return address or an arbitrary address IS an out-of-bounds write, and a
# controlled read of memory the program did not intend to expose IS an out-of-bounds read.
_PRIM_CWE = {"instruction-pointer-control": "CWE-787",
             "write-what-where": "CWE-787",
             "arbitrary-write": "CWE-787",
             "arbitrary-read": "CWE-125",
             "controlled-read": "CWE-125",
             # A sanitizer-reported access, classified by the direction ASan states. An
             # out-of-bounds READ is CWE-125 whether or not its distance is attacker-chosen; the
             # distance decides the PoC LEVEL (L2 vs L1), not the weakness.
             "controlled-oob-read": "CWE-125",
             "oob-read": "CWE-125",
             "controlled-oob-write": "CWE-787",
             "oob-write": "CWE-787",
             # A LIFETIME defect's weakness is the lifetime error itself, in both directions: a
             # use-after-free READ is still CWE-416, because the defect is the use of released
             # memory and not the disclosure it happens to produce. As above, control decides the
             # LEVEL and not the weakness.
             "controlled-uaf-read": "CWE-416",
             "uaf-read": "CWE-416",
             "controlled-uaf-write": "CWE-416",
             "uaf-write": "CWE-416",
             "controlled-double-free": "CWE-415",
             "double-free": "CWE-415",
             "controlled-bad-free": "CWE-590",
             "bad-free": "CWE-590"}
# `alloc-dealloc-mismatch` is deliberately absent: its CWE (762) is not in the memory-corruption
# family this map is allowed to install, and it does not need to be. root_cause already labels
# that class CWE-762 from the sanitizer's own report, so the verdict relabels the TITLE and keeps
# the class it was given -- which is what `title_only` is for. Adding 762 here would have broken
# the invariant that every replacement is itself a class the override outranks, so a second pass
# over the same finding would flip the label back.

#: How a quantity-shaped defect headlines. Separate from `_EFF` because these are not keyed on
#: the verdict TYPE (which carries a `controlled-` prefix) but on the sanitizer class.
_QUANTITY_TITLE = {
    "allocation-size-too-big": "Resource exhaustion (attacker-sized allocation)",
    "out-of-memory": "Resource exhaustion (memory)",
    "memory-leak": "Resource exhaustion (memory leak)",
    "negative-size-param": "Memory corruption (negative length to a memory routine)",
    "array-index-out-of-bounds": "Memory corruption (out-of-bounds index)",
    "bad-shift": "Undefined behaviour (shift exponent)",
}
# root_cause classes that are already a memory-corruption defect and so are kept as-is.
# The one definition lives beside the finding vocabulary; a second copy here would drift.
from ...db.models import OUTRANKS_PRIMITIVE_CWES as _MEM_CORRUPTION
from ...jobs.registry import register_stage
from .. import substrate
from ..debug import qemu_gdb, rootcause
from ..dynamic import sandbox
from ..dynamic.minimize import minimize
from ..dynamic.stage import crash_finding_candidate, crash_hijack
from ..fuzz.runner import place
from . import bundle, primitive
from .capture import (
    MODES,
    env_var_from_argv,
    how_to_feed,
    make_capture,
    make_qemu_capture,
    materialize_helper,
    replay_exe_for,
)

# ISAs whose indirect branch MASKS bit 0 of the loaded PC (ARM/AArch64 for Thumb interworking,
# RISC-V because JALR is specified to clear it), so a captured fault PC is `value & ~1` and its
# cyclic window can alias one word early. Defined once, next to the gdbstub that also has to
# account for it when placing breakpoints.
_LSB_MASKED_PC = qemu_gdb.LSB_MASKED_PC

PRIMITIVE_STAGE = "poc_primitive"
TOOL = "primitive"
TOOL_VERSION = "primitive-1"


_MIN_FILLER_RUN = 16


def _overflow_frame(orig: bytes):
    """(prefix, suffix) around the longest single-byte run in the crashing input -- the filler that
    smashes the frame.

    A structured input only faults when the structure around the overflow is intact: a config
    `name=<AAAA...>` crashes, but a whole-buffer cyclic (`aaaabaaac...`) is not a `name=` line, so
    the target never reaches the sink and L2 reports a false "no fault". Putting the cyclic exactly
    where the filler was keeps the `name=` prefix (and any trailing bytes) and reproduces the crash.
    Returns (b"", b"") when there is no significant run -- an unstructured input the pattern can
    replace whole, exactly as before."""
    if not orig:
        return b"", b""
    best_s = best_len = run_s = 0
    for i in range(1, len(orig) + 1):
        if i < len(orig) and orig[i] == orig[run_s]:
            continue
        if i - run_s > best_len:
            best_s, best_len = run_s, i - run_s
        run_s = i
    if best_len < _MIN_FILLER_RUN:
        return b"", b""
    return orig[:best_s], orig[best_s + best_len:]


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


#: How many input variants steps 2b/2c detonate. Each one is a full sandbox run, so this is a
#: budget, not a sample size: it buys the ONE bit the verdict turns on (does the distance move?).
_OOB_VARIANTS = 10
#: Byte deltas tried at a sampled offset. A length field that sets a read size usually responds
#: to being made larger, so a large additive delta and a saturated byte are the two probes most
#: likely to move the distance without destroying the structure around them.
_OOB_DELTAS = (0x40, 0xff)


def _detonate_for_report(ctx, target, exe, mode, base_argv, data, timeout):
    """Run `exe` on `data` and return the parsed sanitizer report, or None.

    Separate from `make_capture` on purpose: the ptrace helper returns registers and throws the
    child's stderr away, and for this class of defect the stderr IS the evidence. Nothing about
    the registers of an ASan abort is informative.
    """
    from ..debug.rootcause import parse_asan_report
    work = ctx.scratch()
    argv, stdin_bytes, env = list(base_argv), None, None
    if mode == "stdin":
        stdin_bytes = data
    elif mode == "file":
        (work / "oob_input.bin").write_bytes(data)
        argv = place(argv, str(work / "oob_input.bin"))
    elif mode == "arg":
        try:
            argv = place(argv, sandbox.argv_arg(data, truncate=True))
        except sandbox.ArgvNulError:
            return None
    elif mode == "env":
        var, argv = env_var_from_argv(argv)
        if not var:
            return None
        env = {var: data.decode("latin-1")}
    else:
        return None
    try:
        res = sandbox.run(exe, argv=argv, stdin=stdin_bytes, timeout=timeout,
                          arch=target.arch, endianness=target.endianness, bits=target.bits,
                          env_overrides=env)
    except Exception:                                    # noqa: BLE001 -- advisory step
        return None
    return parse_asan_report((res.stderr or b"").decode("utf-8", "replace"))


def _probe_variants(orig: bytes, pre: bytes, post: bytes):
    """`(label, bytes)` inputs that probe whether the reach of the defect is ours to choose.

    Shared by the out-of-bounds verdict (does the DISTANCE past the end move?) and the lifetime
    verdict (does the OFFSET inside the freed chunk, or its SIZE, move?). The families below are
    about how an input sets a number, which is the same question in both cases.

    Two families, because two shapes of input set the reach two different ways:
      * the filler run -- an unstructured overflow reads/writes as far as the run is long, so
        extending and truncating it moves the distance directly;
      * a field value -- a structured input (a TIFF tag, a packet length) sets the reach with a
        NUMBER, and its file size is irrelevant. Those are probed by raising sampled bytes.
    """
    out = [("orig", orig)]
    body = orig[len(pre):len(orig) - len(post)] if (pre or post) else orig
    if len(body) >= _MIN_FILLER_RUN:
        filler = body[:1] or b"A"
        for d in (64, 256):
            out.append((f"filler+{d}", pre + body + filler * d + post))
        half = len(body) // 2
        if half >= _MIN_FILLER_RUN:
            out.append((f"filler-{len(body) - half}", pre + body[:half] + post))
    # Sampled byte probes, spread across the input so a length field anywhere in a header gets
    # hit. Offsets are evenly spaced rather than random: a verdict that changes between two runs
    # of the same stage on the same input is not a verdict.
    room = max(0, _OOB_VARIANTS - len(out))
    if room and orig:
        step = max(1, len(orig) // max(1, room // len(_OOB_DELTAS) or 1))
        for i in range(0, len(orig), step):
            for d in _OOB_DELTAS:
                if len(out) >= _OOB_VARIANTS:
                    return out
                b = bytearray(orig)
                b[i] = (b[i] + d) & 0xFF if d != 0xFF else 0xFF
                out.append((f"byte@{i:#x}={b[i]:#02x}", bytes(b)))
    return out


def _oob_primitive(ctx, target, exe, mode, base_argv, orig, pre, post, timeout, first=None):
    """Step 2b: the out-of-bounds-access verdict, or None when this is not that kind of fault."""
    first = first or _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)
    if not first or first.get("class") not in primitive.OOB_CLASSES:
        return None                                      # not a sanitizer-reported OOB access
    ctx.progress(msg=f"{first['class']} ({first.get('access')}): varying the input to see "
                     f"whether the out-of-bounds distance is attacker-controlled")
    obs = [("orig", first)]
    for label, data in _probe_variants(orig, pre, post)[1:]:
        rep = _detonate_for_report(ctx, target, exe, mode, base_argv, data, timeout)
        if rep:
            obs.append((label, rep))
    prim = primitive.oob_access_primitive(obs)
    if prim is not None:
        ctx.emit("primitive.oob", payload={
            "class": prim["sanitizer_class"], "access": prim["access"],
            "distance_min": prim["distance_min"], "distance_max": prim["distance_max"],
            "region_size": prim["region_size"], "controlled": prim["confirmed"],
            "variants_detonated": len(obs), "observations": prim["observations"][:10]})
    return prim


def _lifetime_primitive(ctx, target, exe, mode, base_argv, orig, pre, post, timeout, first=None):
    """Step 2c: the lifetime-defect verdict (use-after-free, double free), or None.

    Same experiment as step 2b, different question. The out-of-bounds verdict asks how far past
    the end of an object the access reached; for a dead object that has no meaning. What decides
    whether a lifetime defect is a primitive is whether the attacker chooses WHICH PART of the
    stale chunk is touched and HOW BIG the chunk is -- see `primitive.lifetime_primitive`.
    """
    first = first or _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)
    if not first or first.get("class") not in primitive.LIFETIME_CLASSES:
        return None
    ctx.progress(msg=f"{first['class']}: varying the input to see whether the offset inside the "
                     f"freed chunk, or its size, is attacker-controlled")
    obs = [("orig", first)]
    for label, data in _probe_variants(orig, pre, post)[1:]:
        rep = _detonate_for_report(ctx, target, exe, mode, base_argv, data, timeout)
        if rep:
            obs.append((label, rep))
    prim = primitive.lifetime_primitive(obs)
    if prim is not None:
        ctx.emit("primitive.lifetime", payload={
            "class": prim["sanitizer_class"], "access": prim.get("access"),
            "region_offset_min": prim.get("region_offset_min"),
            "region_offset_max": prim.get("region_offset_max"),
            "region_size_min": prim.get("region_size_min"),
            "region_size_max": prim.get("region_size_max"),
            "offset_controlled": prim["offset_controlled"],
            "size_controlled": prim["size_controlled"],
            "controlled": prim["confirmed"], "used_at": prim.get("used_at"),
            "freed_at": prim.get("freed_at"), "allocated_at": prim.get("allocated_at"),
            "variants_detonated": len(obs), "observations": prim["observations"][:10]})
    return prim


def _quantity_primitive(ctx, target, exe, mode, base_argv, orig, pre, post, timeout, first=None):
    """Step 2d: the verdict for a class whose report states a MAGNITUDE and no access.

    Same experiment again, third question. A 35 TB allocation request, a leak, a negative length,
    an out-of-bounds index: none of these describes an access past an object or a use of a dead
    one, so steps 2b and 2c both decline and the ladder used to end on "no instruction-pointer /
    memory primitive found" -- an answer to a question nobody asked about this defect. What the
    report states is a number, and the question is whether the attacker picks it.
    """
    first = first or _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)
    if not first or first.get("class") not in primitive.QUANTITY_CLASSES:
        return None
    if first.get("quantity") is None:
        return None                                      # the class fits; the report has no number
    ctx.progress(msg=f"{first['class']}: varying the input to see whether the "
                     f"{first.get('quantity_name') or 'magnitude'} is attacker-controlled")
    obs = [("orig", first)]
    for label, data in _probe_variants(orig, pre, post)[1:]:
        rep = _detonate_for_report(ctx, target, exe, mode, base_argv, data, timeout)
        if rep:
            obs.append((label, rep))
    prim = primitive.quantity_primitive(obs)
    if prim is not None:
        ctx.emit("primitive.quantity", payload={
            "class": prim["sanitizer_class"], "quantity_name": prim["quantity_name"],
            "quantity_min": prim["quantity_min"], "quantity_max": prim["quantity_max"],
            "quantity_limit": prim.get("quantity_limit"),
            "effect_kind": prim["effect_kind"], "effect_status": prim["effect_status"],
            "controlled": prim["confirmed"], "variants_detonated": len(obs),
            "observations": prim["observations"][:10]})
    return prim


def _race_primitive(ctx, target, exe, mode, base_argv, orig, timeout, first=None):
    """Step 2e: the concurrency verdict, measured by REPEATING the same input.

    The other three verdicts vary the input and watch a number move. A race's outcome does not
    depend on the bytes, so that experiment says nothing about it -- which is why this stage used
    to decline the whole family by name. The property that IS measurable, and the one whoever acts
    on the finding needs, is how often the same input shows the defect: a 1-in-8 race is real and
    needs a looping reproducer, and a fault that reproduces on none of the repeats is a fact about
    OUR evidence that has to be said out loud rather than shipped as a one-shot PoC.
    """
    first = first or _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)
    if not first or first.get("sanitizer") != primitive.TSAN:
        return None
    if first.get("class") not in primitive.RACE_CLASSES:
        return None
    ctx.progress(msg=f"{first['class']}: repeating the SAME input {primitive.RACE_RUNS} times to "
                     f"measure how often it reports")
    obs = [("run1", first)]
    for i in range(2, primitive.RACE_RUNS + 1):
        if ctx.should_cancel():
            break
        obs.append((f"run{i}",
                    _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)))
    prim = primitive.race_primitive(obs)
    if prim is not None:
        ctx.emit("primitive.race", payload={
            "class": prim["sanitizer_class"], "runs": prim["runs"], "hits": prim["hits"],
            "rate": prim["rate"], "intermittent": prim["intermittent"],
            "retries": prim["retries"], "accesses": prim["accesses"],
            "race_sites": prim["race_sites"], "location": prim.get("location"),
            "observations": prim["observations"][:10]})
    return prim


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

    # A substrate that owns the instruction pointer cannot be asked for L2, and the reason
    # matters: `target.arch` holds the RUNTIME's name for a managed target ("cil", "jvm",
    # "cpython", "wasm"), so the cross-arch test below fired for every one of them and the
    # decline read "no qemu gdbstub register layout (host x86-64)" -- naming a missing TOOL for
    # something no tool can do. `known()` first, because an empty file_type means triage has not
    # run yet, not that nothing can run this.
    if substrate.known(target.file_type) and not substrate.supports_ip_control(target.file_type):
        note = substrate.no_ip_control_reason(target.file_type)
        ctx.emit("primitive.done", payload={"primitive": None, "supported": False, "note": note})
        ctx.progress(pct=100, msg="L2 is not a claim this substrate can support")
        return {}

    host = sandbox.host_arch()
    emulated = substrate.foreign_cpu(target.arch, target.file_type, host)
    if emulated and not qemu_gdb.supported(target.arch):
        ctx.emit("primitive.done", payload={"primitive": None, "supported": False,
                 "note": f"L2 for cross-arch {target.arch}: no qemu gdbstub register layout "
                         f"(host {host})"})
        ctx.progress(pct=100, msg="L2 not supported for this cross-arch target")
        return {}

    # AFTER the guards above, not before: discovery reads the content store and the
    # target's import table, which is wasted work on a target this stage is about to
    # refuse outright -- and it made the stage touch `ctx.content` before it had decided
    # anything, so a managed target could not even be declined without one.
    mode, base_argv, mode_why = how_to_feed(ctx.conn, target, input_sha, p,
                                            content=ctx.content)

    orig = ctx.content.get_bytes(input_sha)
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    exe.chmod(0o755)

    # Detonate the binary that ACTUALLY crashed. `build_poc` already replays a libFuzzer crash
    # against the harness it was found in; this stage did not, so it detonated a tool that never
    # calls the vulnerable path, the cyclic pattern did not fault, and the stage reported "no L2
    # primitive" for a defect it had simply never reached. One finding cannot be at L1 because
    # two stages disagree about what the target is.
    _harness = replay_exe_for(ctx, target, input_sha)
    if _harness:
        exe = ctx.scratch() / "harness.bin"
        exe.write_bytes(_harness)
        exe.chmod(0o755)
        target_bytes = _harness                          # the bundle must ship the HARNESS
        mode, base_argv = "file", ["@@"]
        mode_why = ("detonated against the libFuzzer harness the crash was found in "
                    "(the ingested binary need not call the vulnerable path)")
        ctx.emit("primitive.harness", payload={"bytes": len(_harness), "mode": mode,
                                               "why": mode_why})

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

        # Structure-preserving framing: a structured input (a config `name=<AAAA...>`, a packet)
        # only faults when the bytes AROUND the overflow stay intact -- the smash is the long filler
        # run, not the whole input. The FUZZER's crashing input is often messy (dictionary tokens +
        # a trailing run), so first MINIMIZE it to its essential crashing shape; then the longest
        # run is the real filler and the prefix/suffix are the true structure. The cyclic (and the
        # control marker) then go exactly where the filler was. Unstructured inputs minimize to a
        # single run and frame as a whole (b"", b""), i.e. exactly the old behaviour.
        min_cap = _capture_for(mode)

        def _still_faults(b):
            c = min_cap(b)
            return bool(c.get("ok") and c.get("signal_name"))
        # Native only: minimization is up to `cap` detonations, cheap under ptrace but far too slow
        # over a qemu gdbstub (each exec is a full emulated run), where it would blow the stage's
        # budget. Cross-arch keeps the raw crash input, exactly as before.
        if len(orig) > 64 and not emulated:
            ctx.progress(msg=f"minimizing the {len(orig)}-byte crash to its essential shape")
            mini, _mx = minimize(_still_faults, orig, cap=120)
            if len(mini) < len(orig) and _still_faults(mini):
                ctx.emit("primitive.minimized", payload={"from": len(orig), "to": len(mini)})
                orig = mini
        _pre, _post = _overflow_frame(orig)

        def frame(payload):
            return _pre + payload + _post

        ctx.progress(msg=f"detonating {length}-byte cyclic pattern under "
                         + (f"qemu-{target.arch} gdbstub" if emulated else "ptrace"))
        # Try the mode we believe in, then the others. A crashing input fed the wrong way
        # does not fault, and reporting that as "no L2 primitive" turns a wrong setup into
        # what reads as a real negative result.
        pattern = primitive.cyclic(length)
        tried = []
        # Prefer the structure-preserving framing (keeps a `name=` prefix etc.); fall back to the
        # raw pattern so an input whose longest run is NOT the overflow still works exactly as
        # before. `active_frame` is whichever reproduced the fault, reused for the confirm step.
        identity = (lambda b: b)
        framings = ([frame, identity] if (_pre or _post) else [identity])
        active_frame = identity
        cap0 = {}
        for fr in framings:
            for m in [mode] + [x for x in MODES if x != mode]:
                capture = _capture_for(m)
                cap0 = capture(fr(pattern))
                if m not in tried:
                    tried.append(m)
                if cap0.get("ok") and cap0.get("signal_name"):
                    active_frame, mode = fr, m
                    break
            if cap0.get("ok") and cap0.get("signal_name"):
                break
        frame = active_frame                       # confirm uses the framing that actually faulted
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
            control = frame(primitive.control_input(off, length, word, endian))
            if not primitive.marker_confirmed(capture(control), word, endian):
                continue
            prim = {"type": "instruction-pointer-control", "offset": off, "source": source,
                    "marker": primitive._ip_marker(word), "observed_pc": cap0.get("pc", 0),
                    "confirmed": True, "registers": regs,
                    "static_offset": static_match, "static_candidates": offset_candidates}
            if _pre or _post:                          # structured input: record the framing
                prim["prefix"] = _pre.hex()
                prim["suffix"] = _post.hex()
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
            control = frame(primitive.control_input(offset, length, word, endian))
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
            control = frame(primitive.two_marker_input(memp["addr_offset"], memp.get("value_offset"),
                                                       length, word=word, endian=endian))
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

        # 2b) NOTHING in the registers -- because on a sanitizer build there is nothing in the
        # registers to find. ASan aborts inside its own runtime, so the fault-time pc belongs to
        # the reporting machinery, `recover_ip_offset` sees no cyclic word and
        # `analyze_memory_primitive` has no faulting access to read. The stage fell through to
        # step 3 and said "crash reproduced but no controllable primitive found", which is
        # technically true and completely empty: libtiff's `putRGBcontig8bittile` heap
        # out-of-bounds READ -- a real, reachable, demonstrable information disclosure -- got no
        # verdict at all, because the only verdicts on offer were about controlling the
        # instruction pointer.
        #
        # The primitive for this class is in the REPORT, and the experiment is to vary the input
        # and watch the distance past the end of the object move.
        _first = None
        if not emulated:
            # ONE detonation for all three sanitizer verdicts and for the decline below. Each
            # used to run its own copy to decide whether it applied, so the same input was
            # detonated four times before any variant was tried -- four sandbox runs out of a
            # budget that buys ten.
            _first = _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)
            prim = _oob_primitive(ctx, target, exe, mode, base_argv, orig, _pre, _post,
                                  timeout, first=_first)
            if prim is not None:
                control = frame(orig[len(_pre):len(orig) - len(_post)] if (_pre or _post)
                                else orig)
                extra = primitive.oob_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra)

            # 2c) the same reasoning, one bug class further on. A use-after-free and a double
            # free are the two defects this link had NO verdict for -- the distance experiment
            # does not apply to a dead object -- so both got "crash reproduced but no
            # instruction-pointer / memory primitive found" on every sanitizer build.
            prim = _lifetime_primitive(ctx, target, exe, mode, base_argv, orig, _pre, _post,
                                       timeout, first=_first)
            if prim is not None:
                control = frame(orig[len(_pre):len(orig) - len(_post)] if (_pre or _post)
                                else orig)
                extra = primitive.lifetime_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra)

            # 2e) a concurrency defect, whose experiment is a REPEAT rather than a variation.
            prim = _race_primitive(ctx, target, exe, mode, base_argv, orig, timeout,
                                   first=_first)
            if prim is not None:
                control = frame(orig[len(_pre):len(orig) - len(_post)] if (_pre or _post)
                                else orig)
                extra = primitive.race_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra)

            # 2d) and the classes that describe a MAGNITUDE rather than an access.
            prim = _quantity_primitive(ctx, target, exe, mode, base_argv, orig, _pre, _post,
                                       timeout, first=_first)
            if prim is not None:
                control = frame(orig[len(_pre):len(orig) - len(_post)] if (_pre or _post)
                                else orig)
                extra = primitive.quantity_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra)

        # 3) nothing to claim. Where the defect's CLASS is one this stage cannot reason about --
        # a data race, an uninitialised read -- say which and why, because the generic note reads
        # as if the right question had been asked and answered. Measured: a ThreadSanitizer data
        # race and an MSan uninitialised read both ended on "no instruction-pointer / memory
        # primitive found", which sends the reader looking for a missing capability instead of at
        # `mem_oracle` (the uninit verdict) or at a timing experiment this stage does not run.
        _cls = (_first or {}).get("class")
        _why = primitive.no_verdict_reason(_cls)
        ctx.emit("primitive.done", payload={
            "primitive": ("register-control" if regs else None), "supported": True,
            "registers": regs, "signal": cap0.get("signal_name"), "sanitizer_class": _cls,
            "note": (f"no primitive verdict for {_cls}: {_why}" if _why else
                     "crash reproduced but no instruction-pointer / memory primitive found")})
        ctx.progress(pct=100, msg=(f"{_cls}: no verdict ({_why[:60]})" if _why
                                   else "crash without a controllable primitive"))
        return {}
    finally:
        shutil.rmtree(helper.parent, ignore_errors=True)


def _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control, prim, confirmed,
              extra):
    """Bundle the demonstrating input, record an L2 (or L1) PoC, promote the crash finding on
    confirmation, and emit the result -- shared by every primitive kind."""
    # A verdict may CAP its own level. L2 means a confirmed exploitation primitive, and not every
    # confirmed claim is one: an attacker-chosen allocation size or leak volume is an availability
    # defect -- demonstrated, worth reporting, and not a primitive. Calling it one would inflate
    # the single number in a report that exists to resist inflation. The verdict states the cap
    # itself (`max_level`) rather than this function guessing from the type name.
    level = "L2" if (confirmed and int(prim.get("max_level") or 2) >= 2) else "L1"
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
                "controlled-read": ("info-disclosure", "Information disclosure (memory leak)"),
                "controlled-oob-read": ("info-disclosure",
                                        "Information disclosure (out-of-bounds read)"),
                "oob-read": ("info-disclosure", "Information disclosure (out-of-bounds read)"),
                "controlled-oob-write": ("memory-corruption",
                                         "Memory corruption (out-of-bounds write)"),
                "oob-write": ("memory-corruption", "Memory corruption (out-of-bounds write)"),
                "controlled-uaf-read": ("info-disclosure",
                                        "Information disclosure (use-after-free read)"),
                "uaf-read": ("info-disclosure",
                             "Information disclosure (use-after-free read)"),
                "controlled-uaf-write": ("memory-corruption",
                                         "Memory corruption (use-after-free write)"),
                "uaf-write": ("memory-corruption", "Memory corruption (use-after-free write)"),
                "controlled-double-free": ("memory-corruption",
                                           "Memory corruption (allocator state, double free)"),
                "double-free": ("memory-corruption",
                                "Memory corruption (allocator state, double free)"),
                "controlled-bad-free": ("memory-corruption",
                                        "Memory corruption (free of a foreign address)"),
                "bad-free": ("memory-corruption",
                             "Memory corruption (free of a foreign address)"),
                "controlled-alloc-dealloc-mismatch": (
                    "memory-corruption", "Memory corruption (allocator mismatch)"),
                "alloc-dealloc-mismatch": ("memory-corruption",
                                           "Memory corruption (allocator mismatch)")}
        _kind_title = _EFF.get(prim.get("type"))
        # A QUANTITY verdict carries its own effect kind and status -- availability for a refused
        # allocation or a leak, memory corruption marked POTENTIAL for a negative length the
        # sanitizer intercepted before the copy. Read off the verdict so there is one definition
        # rather than a second table that has to agree with the first.
        if prim.get("race"):
            # A race's consequence depends on what the unsynchronised value is used for, which
            # this stage does not determine -- so it headlines the DEFECT and files no effect
            # claim. The reproduction rate is the contribution, and it is in the detail.
            _kind_title = None
        elif prim.get("quantity"):
            _title = _QUANTITY_TITLE.get(prim["sanitizer_class"], "Resource exhaustion")
            _kind_title = (prim["effect_kind"],
                           _title + ("" if prim["effect_status"] == "demonstrated"
                                     else " (potential)"))
        # Key on the ORIGINAL crash's faulting address (as root_cause does), NOT this capture's,
        # so the primitive finding merges into the crash finding instead of forking a duplicate:
        # on a native target the fault PC is in the dedup key, and omitting it here split one
        # defect into two poc-backed findings.
        _orig = (ctx.params or {}).get("input_sha")
        _fpc = DynResultDAO(ctx.conn).fault_pc_for(target.id, _orig) if _orig else None
        _hj = crash_hijack(ctx.conn, target.id, _fpc)
        cand = crash_finding_candidate(
            cap0.get("signal_name"), control_sha, "ptrace", "primitive",
            f"({level} primitive: {extra})", state="poc-backed", confidence=0.98,
            bundle_sha=bundle_sha, fault_pc=_fpc, hijack=_hj)
        if _kind_title:
            _kind, _title = _kind_title
            cand["title"] = (f"{_title} (demonstrated): L2 primitive" if level == "L2"
                             else f"{_title}: attacker-controlled magnitude")
            cand["authoritative"] = True
            # Keep root_cause's CWE only where it already names a MEMORY-CORRUPTION defect --
            # there it genuinely is more specific than a signal-derived class. Where it does not,
            # keeping it makes the finding contradict its own headline. Measured on a service
            # carved out of a SquashFS firmware image: the stack smash left a near-null return
            # address, root_cause classified the fault as CWE-476 (null-pointer dereference), and
            # the finding went out as "Control-flow hijack (demonstrated): L2 primitive" carrying
            # a DoS-grade weakness id -- so anyone filtering for memory corruption would never
            # see a CONFIRMED instruction-pointer hijack at a known stack offset. A confirmed
            # primitive is direct evidence of what the write did, which outranks a guess made
            # from where the process happened to land.
            _prim_cwe = _PRIM_CWE.get(prim.get("type"))
            _prior = next((f for f in fd.list_by_target(target.id)
                           if f.dedup_key == cand["dedup_key"]), None)
            # A QUANTITY verdict is not an override of root_cause's class -- it IS the
            # sanitizer's class, and the crash finding it merges into was labelled from the
            # SIGNAL. Measured: a refused 2 TB allocation went out as CWE-787 (out-of-bounds
            # write) because SIGABRT resolves to that and `_PRIM_CWE` deliberately has no entry
            # for this family. The same no-downgrade guard applies: a finding that already names
            # memory corruption keeps it.
            if prim.get("quantity") and prim.get("cwe"):
                _prim_cwe = prim["cwe"]
            if _prim_cwe and (_prior.cwe if _prior else None) not in _MEM_CORRUPTION:
                cand["cwe"] = _prim_cwe
                cand["title_only"] = False
                if prim.get("type") == "instruction-pointer-control":
                    cand["severity"] = "critical"       # RIP control, confirmed under ptrace
            else:
                cand["title_only"] = True              # keep root_cause's specific CWE
            # Promote the matching end effect to DEMONSTRATED and attach the L2 bundle that
            # proves it -- the confirmed primitive (RIP control / write-what-where / controlled
            # read), the exact input that achieves it, and how (offset, captured marker).
            _effects = [{
                "kind": _kind, "title": _title,
                # The verdict decides its own status: a consequence the sanitizer PREVENTED (a
                # negative length intercepted before the copy, an index whose access is undefined
                # rather than performed) is potential, not demonstrated.
                "status": prim.get("effect_status") or "demonstrated", "detail": extra,
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
