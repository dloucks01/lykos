"""Phase 5 — the `fuzz` stage: black-box mutational fuzzing over the sandbox executor.

Drives inputs through the Phase-4 sandbox, detects crashes, dedups them, saves the crashing
input as an artifact, records a dyn_result, and turns each unique crash into a Confirmed
finding (L1: crash + reproducible input). Budget-bounded (execs + wall-clock); cancellable.

The core loop is exposed as `fuzz_campaign()` so the directed-fuzzing stage can reuse it with
a targeted corpus/dictionary aimed at statically-flagged sinks.
"""
from __future__ import annotations

import base64
import bisect
import hashlib
import inspect
import os
import random
import re
import time

from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, StringDAO, TargetDAO
from ...hashing import canonical_json
from ...jobs.registry import register_stage
from ..dynamic import sandbox
from ..dynamic.minimize import minimize
from ..dynamic.stage import (
    asan_defect_key,
    crash_finding_candidate,
    is_hijack_pc,
    recovered_code_span,
)
from ..poc.capture import modes_for
from . import structure, textconf, xmlgrammar
from .mutator import Mutator
from .runner import invocation, run_input

FUZZ_STAGE = "fuzz"
TOOL = "fuzz"
TOOL_VERSION = "fuzz-1"
# Long seeds are not a luxury: a blind mutator keeps nothing, so without one the campaign can
# only reach a length-triggered bug by growing into it, and it never does. These put the
# overflow class in range from the first exec.
_DEFAULT_SEEDS = [b"", b"A" * 8, b"%s%s%s%n", b"0", b"-1", b"../../etc/passwd",
                  b"A" * 256, b"A" * 1024, b"A" * 4096]


def _mine_dictionary(strings):
    toks = []
    for s in strings:
        v = (s.value or "").strip()
        if v and len(v) <= 64:
            toks.append(v.encode("latin-1", "ignore"))
    return toks[:500]


# How many inputs the corpus may retain, and how big one may be. A blind campaign that keeps
# everything spends its budget re-running near-duplicates of one enormous input.
_MAX_CORPUS = 256
# Below this share of the binary, a call-graph closure is not telling us about dead code --
# it is telling us the call graph could not be read (stripped, or indirect-heavy).
_LIVE_FLOOR = 0.25
_MAX_CRASH_ROWS = 8      # examples kept per signal; a reproducible crash recurs thousands of times
_MAX_KEEP = 16384


def behaviour_of(res, data: bytes = b""):
    """A coarse signature of what the program DID -- a coverage proxy with no instrumentation.

    The campaign was purely blind: the corpus only ever grew on a CRASH, so an input that
    reached new parser code without crashing was discarded and the search random-walked around
    its seeds forever. `unique: 0` on every jhead run was that, not bad luck.

    Real coverage needs instrumentation we do not have for an arbitrary binary, but a parser
    announces which path it took: jhead prints "Illegal subdirectory link", "Illegal value
    pointer", "Invalid Exif alignment marker" and so on. Exit status plus the SHAPE of the
    output is therefore a usable proxy -- digits are collapsed so that "Extraneous 16 padding
    bytes" and "Extraneous 56" count as the same path rather than two.
    """
    blob = (res.stderr or b"") + b"\x00" + (res.stdout or b"")
    shape = re.sub(rb"\d+", b"#", blob[:512])
    # Paths too: a program that echoes the file it was given would otherwise report a new
    # behaviour for every input, and a proxy that fires on everything is noise.
    shape = re.sub(rb"[/\\][^\s'\"]*", b"#PATH", shape)
    # Drop anything the program merely ECHOED back. A parser handed its input as a filename
    # prints that filename in the diagnostic, so every distinct payload looked like a distinct
    # path: 40% of inputs counted as new behaviour in argv mode, which is noise, not coverage.
    if data:
        shape = b" ".join(t for t in re.split(rb"[^A-Za-z#]+", shape)
                          if len(t) > 2 and t not in data)
    return (res.exit_code, res.signal_name,
            hashlib.blake2b(shape, digest_size=8).digest())


def _strings_for(ctx, target):
    """The target's strings -- from the DB when `disassemble` has run, else scanned.

    The string table is written by `disassemble`, which means Ghidra. Fuzzing before that is a
    perfectly reasonable thing to do -- the whole point of leading with execution is that it
    needs no decompilation -- but it silently cost the campaign both of the things it mines
    from strings: the dictionary and the format model. Against a config parser that reads
    `name=`, `listen=`, `workers=`, a dictionary-less mutator has to invent those tokens byte
    by byte and never does.
    """
    rows = [x for x in StringDAO(ctx.conn).list_by_target(target.id) if x.value]
    if rows:
        return rows
    from .. import invocation as invmod
    data = ctx.content.path(target.sha256).read_bytes()
    return invmod.string_rows(invmod.raw_strings(data), where="scan")


def format_aware_seeds(ctx, target) -> list:
    """Seeds that pass the target's INPUT GATE, derived from the binary's own strings: a binary
    format-model seed (jpeg/gif/elf/... -- carries the magic + a minimal valid structure), a text
    `key=value` config seed when the binary looks config-driven, and a handful of the most selective
    mined strings. AFL's entire advantage is coverage feedback from a valid starting point; the
    generic `_DEFAULT_SEEDS` (``""``, ``"AAAA"``, a path) bounce off a real parser at the front door
    (measured: jhead ran 98k executions for zero finds blind, vs seconds WITH a valid sample). The
    `fuzz`/`directed_fuzz` stages already build these, but `coverage_fuzz` used only the generic set
    -- which is exactly why its edge coverage stayed tiny. Every step is best-effort: seeding is an
    optimisation, never a blocker, so any failure just yields fewer seeds."""
    seeds: list = []
    try:
        svals = [x.value for x in _strings_for(ctx, target) if getattr(x, "value", None)]
    except Exception:
        return seeds
    try:
        fmt = structure.detect_format(svals)
        if fmt:
            s = structure.seed_for_name(fmt)
            if s:
                seeds.append(s)
    except Exception:
        pass
    try:
        keys = textconf.keys_from(svals)
        if keys:
            seeds.append(textconf.seed_for(keys))
    except Exception:
        pass
    # the binary's own selective strings (magic tokens, config keywords, path prefixes)
    seeds += [s.encode("latin-1", "ignore") for s in svals[:8] if 2 <= len(s) <= 256]
    # Menu / interactive-protocol navigation seeds: a numbered-menu service hides its bug behind a
    # state machine, so a blind campaign never leaves the front-door menu. Read the menu out of the
    # binary's own option strings and start the fuzzer INSIDE it.
    try:
        from . import menu
        seeds += menu.menu_seeds(svals)
    except Exception:
        pass
    return [s for s in seeds if s]


def menu_model_for(ctx, target, exe, workdir):
    """Learn the target's menu by DRIVING the staged binary: `(model, options, width)` or None.

    The static `menu_seeds` guesses a generic numbered-menu navigation from the option strings; it
    never learns that "Author Note size:" wants a number and "Note:" wants the bytes, so a
    size-then-buffer flow (the overflow) is fed garbage and the campaign stays parked at the
    front-door menu. Crawling the live target learns each option's typed field template
    (`crawl_menu`), which drives BOTH the alloc-primed op-sequence seeds and the menu-aware mutator.

    Only pays the crawl when the strings advertise a menu, and is fully best-effort: any failure
    (no menu, crawl error) yields None and the campaign keeps its static seeds + blind mutator."""
    try:
        from . import menu
        svals = [x.value for x in _strings_for(ctx, target) if getattr(x, "value", None)]
        opts = menu.detect_menu(svals)
        if not opts:
            return None
        from ..dynamic.heap_discover import _crawl_menu_model, _read_width
        width = _read_width(exe)
        model = _crawl_menu_model(workdir, exe, opts, width=width)
        if not model:
            return None
        return model, opts, width
    except Exception:
        return None


def msan_detonate(ctx, target, inputs, mode, exec_timeout, base_argv=()) -> int:
    """Detonate a set of inputs against the target's MemorySanitizer build (built at ingest for
    source targets) to surface uninitialized-value reads (CWE-457) -- the class ASan cannot see. Such
    reads do NOT crash the primary ASan build, so they must be driven with the fuzz CORPUS, not just
    the crashes. Findings land 'corroborated' (the sanitizer directly observed the read) with the
    source line. Fully guarded: it must never break a campaign.

    The MSan binary is native code compiled from attacker-controlled source, so it runs under the
    SAME bubblewrap containment as every other target (ro-root, netns, pid namespace, secret masks)
    via `isolate_prefix` + `run_reaped` -- never a bare host subprocess. It cannot take an RLIMIT_AS
    cap (MSan reserves a ~20TB shadow like ASan), so bwrap provides the isolation and a wall-clock
    budget bounds the cost; the pass fires at the end of every campaign, so it must stay cheap."""
    import os as _os

    from ...db.dao import ArtifactDAO
    try:
        arts = ArtifactDAO(ctx.conn).list_by_case(target.case_id)
        msa = next((a for a in arts if a.kind == "msan-blob"
                    and (a.meta or {}).get("binary_sha") == target.sha256), None)
        if not msa:
            return 0
        msbin = ctx.scratch() / "target.msan"
        msbin.write_bytes(ctx.content.path(msa.sha256).read_bytes())
        _os.chmod(msbin, 0o755)
    except Exception:
        return 0
    # MSan's default abort path spawns llvm-symbolizer, which DEADLOCKS when stderr is a captured
    # pipe (not a TTY) -- every detonation then times out and the pass silently finds nothing. Run
    # with symbolize=0 (report addresses, no symbolizer, exits cleanly) and recover the source line
    # ourselves with addr2line on the offset. exitcode keeps a report distinguishable from a crash.
    env = dict(_os.environ)
    env["MSAN_OPTIONS"] = "symbolize=0:abort_on_error=0:halt_on_error=1:exitcode=86"
    exedir = str(msbin.parent)
    prefix = sandbox.isolate_prefix(exedir, net=False)   # [] if bwrap unavailable -> unwrapped run
    per_timeout = max(2, int(exec_timeout))
    # Bound the whole pass: cap total wall-clock and honour a cancel, so a large corpus can't add
    # minutes to a short campaign (msan_detonate fires once at the tail of each campaign).
    deadline = time.monotonic() + max(15.0, min(90.0, per_timeout * 30))
    _cancel = getattr(ctx, "should_cancel", None)        # defensive: never break a campaign
    fd = FindingDAO(ctx.conn)
    wf = ctx.scratch() / "msan-in.bin"
    found, seen = 0, set()
    for data in list(inputs)[:400]:
        if time.monotonic() > deadline or (_cancel is not None and _cancel()):
            break
        data = data or b""
        tail, stdin = invocation(mode, wf, data, base_argv)   # honour the target's flags / `@@`
        argv = [str(msbin)] + tail
        try:
            r = sandbox.run_reaped(prefix + argv, input=stdin, timeout=per_timeout,
                                   capture_output=True, env=env)
        except Exception:
            continue
        txt = (r.stderr or b"").decode("latin-1", "ignore")
        if "MemorySanitizer: use-of-uninitialized-value" not in txt:
            continue
        src = _msan_source_line(msbin, txt)
        # dedup by source line; when addr2line yields nothing, key on the raw (binary+0xOFFSET)
        # frame so DISTINCT unlocated reads don't all collapse into one "uninit" finding.
        _raw = re.search(r"\(\S+\+0x[0-9a-fA-F]+\)", txt)
        key = src or (_raw.group(0) if _raw else
                      hashlib.sha1(txt[:256].encode("latin-1", "ignore")).hexdigest()[:12])
        if key in seen:
            continue
        seen.add(key)
        try:
            sha = ctx.put_artifact("msan-input", data=data)
            fd.upsert(target.id, target.case_id, {
                "cwe": "CWE-457", "title": "Use of uninitialized value", "severity": "medium",
                "detector": "msan", "state": "corroborated", "confidence": 0.8,
                "dedup_key": f"CWE-457:msan:{key}", "function_addr": None, "site_addr": None,
                "site_detail": src,
                "evidence": [{"channel": "sanitizer",
                              "detail": "MemorySanitizer: use of uninitialized value"
                              + (f" at {src}" if src else "") + f" (input {sha[:12]})"}]})
            found += 1
        except Exception:
            continue
    if found:
        ctx.emit("msan.done", payload={"uninitialized_reads": found})
    return found

def _msan_source_line(binpath, text):
    """file:line for an MSan report produced with symbolize=0: the report carries a raw
    `(<binary>+0xOFFSET)`, and addr2line turns that offset into a source location."""
    import re
    import subprocess as _sp
    m = re.search(r"\(\S+\+0x([0-9a-fA-F]+)\)", text)
    if not m:
        return None
    try:
        r = _sp.run(["addr2line", "-e", str(binpath), "0x" + m.group(1)],
                    capture_output=True, timeout=5)
        loc = (r.stdout or b"").decode("latin-1", "ignore").strip().splitlines()
        if loc and ":" in loc[0] and not loc[0].startswith("?"):
            f, _, line = loc[0].rpartition(":")
            return f"{f.split('/')[-1]}:{line}" if f else None
    except Exception:
        return None
    return None


def _discover_argv(ctx, target, exec_timeout):
    """Work out the target's required arguments -- and CHECK them before using them.

    A service behind `-c <config>` that is fuzzed bare prints its usage and exits on every
    execution: 8,000 runs, one distinct behaviour, no crashes, reported as a clean campaign
    against a program the fuzzer never entered. The flags are written in the binary's own
    usage line, so nobody has to know them in advance.

    But a proposal read off the strings is a hypothesis, and applying one unchecked produces
    the same failure pointing the other way -- unzip needs no flags at all, and `-d <dir> -x x`
    is a command line it refuses. So the proposal costs two executions to verify against the
    target's own no-argument behaviour, and is used only if the target accepts it. Returns
    (argv, note-or-None, takes-a-config) -- an unverified proposal yields ([], note, False) so
    the run still says what was considered and why it was dropped. The third value says the
    binary documents a REQUIRED config path, which is also what says its input is text.
    """
    from .. import invocation as invmod
    try:
        data = ctx.content.path(target.sha256).read_bytes()
        found = invmod.discover([x.value for x in _strings_for(ctx, target)])
        d = ctx.scratch() / "argvprobe"
        # Real files behind every value that names one, or the proposal cannot be tested: a
        # service required to be given `-j <app.jar>` refuses the literal string "app.jar",
        # and the run then throws away an invocation that was right apart from a missing file.
        argv = invmod.materialize(found, d)
        if not argv:
            return [], None, False
        exe = d / "target.bin"
        exe.write_bytes(data)
        exe.chmod(0o755)
        sample = d / "sample"
        sample.write_bytes(b"# lykos\n")

        def _run(a):
            return sandbox.run(exe, argv=a, stdin=b"", timeout=max(4.0, exec_timeout * 2),
                               arch=target.arch, endianness=target.endianness,
                               bits=target.bits)
        v = invmod.verify(_run, exe, argv, str(sample))
    except Exception as e:                     # discovery is an optimisation, never a blocker
        return [], f"invocation discovery failed: {e}", False
    if v["accepted"] and v["bare_rejected"]:
        conf = any(f.get("kind") == "config" and not f.get("optional")
                   for f in found["flags"])
        return argv, (f"discovered from the binary's usage line and verified by running it: "
                      f"{' '.join(argv)}"), conf
    if not v["bare_rejected"]:
        return [], ("the target runs with no arguments, so no flags were added "
                    f"(it does document {' '.join(argv)})"), False
    return [], f"proposed {' '.join(argv)} but the target refused it -- {v['why']}", False


def _takes_blocks(run_fn) -> bool:
    """Does this runner accept coverage blocks? Asked of the signature rather than of the
    function's identity, so a runner other than `run_input` -- the channel harness, above all
    -- can be given them without this having to learn its name."""
    try:
        return "blocks" in inspect.signature(run_fn).parameters
    except (TypeError, ValueError):
        return False


def fuzz_campaign(ctx, target, *, corpus, dictionary, mode, max_execs, max_seconds,
                  exec_timeout, rng, detector, event_prefix, note_prefix, run_fn=run_input,
                  mutator=None, cover_blocks=(), cover_flags=(), base_argv=(), block_dist=None):
    """Shared mutational campaign: mutate -> sandbox -> dedup-by-signal -> minimize ->
    dyn_result + Confirmed finding. Used by both the black-box `fuzz` stage and the directed
    stage (which supplies a corpus/dictionary aimed at specific sinks). Returns stats.

    `run_fn(exe, mode, workfile, timeout, arch, data) -> (argv, RunResult)` is the input
    delivery; boundary-driven harnessing (doc 17.4) swaps in a channel runner."""
    exe = ctx.scratch() / "target.bin"
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)
    workfile = ctx.scratch() / "input.bin"

    corpus = list(corpus) or list(_DEFAULT_SEEDS)
    # A numbered-menu service hides its bug behind a state machine: junk input never selects a valid
    # option, so a blind campaign runs its whole budget parked at the front-door menu. Learn the menu
    # by driving the live target ONCE, then use that model two ways -- seed the corpus with typed
    # operation sequences, AND drive a menu-aware mutator that keeps every navigation valid while
    # mutating the field payloads (so the fuzzer explores the handlers, not the menu parser). Both
    # are best-effort and menu-gated; a non-menu target keeps its static seeds + blind mutator.
    try:
        from . import menu as _menu
        mm = menu_model_for(ctx, target, exe, exe.parent)
        if mm:
            model, opts, mwidth = mm
            op_seeds = [s for s in _menu.menu_op_sequences(model, opts, width=mwidth) if s]
            if op_seeds:
                corpus = list(corpus) + op_seeds
                ctx.progress(msg=f"{event_prefix} learned {len(op_seeds)} menu-op seeds")
            if mutator is None:                        # don't override an explicit format mutator
                mutator = _menu.MenuMutator(rng, model, opts, width=mwidth, dictionary=dictionary)
                ctx.emit("fuzz.format", payload={"model": "menu", "auto": True,
                         "options": opts, "why": "the target drives a numbered menu; navigating it"})
    except Exception:
        pass
    mut = mutator or Mutator(rng, dictionary)          # menu / structure-aware mutator when supplied
    fd = FindingDAO(ctx.conn)
    dd = DynResultDAO(ctx.conn)
    deadline = time.time() + max_seconds
    execs = crashes = crashes_reproducible = 0
    seen_sigs: dict = {}
    code_span = recovered_code_span(ctx.conn, target.id)   # classify an out-of-code (hijack) PC
    seen_behaviour, kept = set(), 0
    # Has the coverage channel EVER answered? A runner that returns block data -- even an empty
    # set -- proves coverage is live and block-novelty is trustworthy. If blocks were armed but
    # nothing ever came back (ptrace refused in this namespace, a runner that cannot report),
    # block-only novelty would freeze the corpus forever, so we fall back to behaviour novelty.
    cover_reported = False

    # Batching pays the sandbox namespace once per BATCH instead of once per input, which is
    # 3.18 ms of every 3.55 ms execution. Only for the plain runner: a stage that supplies its
    # own delivery (boundary harnessing) is not a series of independent executions.
    batchable = run_fn is run_input
    runner_takes_blocks = _takes_blocks(run_fn)   # constant for the campaign; not per-exec
    batch_n = 64
    # Real path coverage when the target has been disassembled. An output-shape proxy notices
    # that a parser printed something new; block coverage notices that it took a branch it has
    # never taken -- which is the difference between a few thousand distinct behaviours and
    # tens of thousands of distinct paths.
    all_blocks = set(cover_blocks or ())
    seen_blocks: set = set()
    # Sink-directed steering (AFLGo-style): `block_dist` maps a block address to its distance to a
    # target sink. We keep the lowest distance any input has reached, and RETAIN an input that gets
    # strictly closer even when it adds no new coverage -- the "exploitation" half of directed
    # greybox fuzzing, driving the search down toward the flagged sink. None => undirected.
    best_dist = None
    directed_kept = 0
    # Flag fuzzing runs ONLY under the batched sandbox. An option like jhead's `-cmd` executes
    # a command built from our input; that is the point (it is where CVE-2020-6624 lives) and
    # it is only acceptable inside the unshared-net, read-only-root namespace. On the
    # rlimits-only fallback the target keeps the plain argv it was given.
    flags = list(cover_flags or ())
    # How the TARGET has to be invoked, as the operator gave it. This was ignored entirely:
    # a service that requires `-c <config>` was run as `daemon <workfile>`, printed its usage
    # and exited -- 8,000 times, reported as a clean campaign with `behaviours: 1`. Mined
    # flags are exploratory and go in front; the operator's argv is the contract and keeps its
    # order, including where `@@` puts the input.
    base_argv = list(base_argv or ())
    flaky = 0
    # Some options make the target launch something INTERACTIVE -- jhead's `-ce` opens an
    # editor, `-cmd` spawns a shell -- and those run at about a second each against 0.5 ms for
    # a plain parse. A single 64-input batch under `-ce` measured 60 seconds: one unlucky
    # option can eat an entire campaign's budget. So probe an option the campaign has not
    # priced on a SMALL batch, and retire any that proves to cost orders more than the norm.
    flag_cost: dict = {}
    retired: set = set()
    suspect: list = []
    cheap_ms = [1.0]
    ctx.progress(msg=f"{event_prefix} campaign")
    while execs < max_execs and time.time() < deadline and not ctx.should_cancel():
        prefix: list = []
        base_ms = sorted(cheap_ms)[len(cheap_ms) // 2]
        if batchable and flags:
            live = [f for f in flags if f not in retired
                    and not _dear(flag_cost.get(f), base_ms)]
            if suspect:
                # An expensive batch names several options but only one is usually to blame,
                # so settle it alone rather than retiring the bystanders it travelled with.
                prefix = [suspect.pop(0)]
            else:
                # One flag combination per batch: run_batch takes a single argv prefix, and
                # many batches cover many combinations.
                prefix = ([] if not live or rng.random() < 0.25
                          else rng.sample(live, min(len(live), rng.randint(1, 3))))
        # A small batch while an option's cost is unknown OR known to be bad: an option under
        # suspicion is still worth running (it reaches code nothing else does) but not at 64
        # executions a batch, which is how one interactive option ate a whole campaign.
        risky = any(f not in flag_cost or _dear(flag_cost.get(f), base_ms) for f in prefix)
        run_argv = prefix + base_argv          # exploration first, the contract last
        want = min((_PROBE_N if risky else batch_n) if batchable else 1, max_execs - execs)
        inputs = [mut.mutate(rng.choice(corpus), corpus) for _ in range(max(1, want))]
        results = None
        if batchable:
            # Only ever arm blocks we have not reached: the breakpoints are one-shot, so
            # the cost decays as coverage saturates instead of being paid in full forever.
            arm = sorted(all_blocks - seen_blocks) if all_blocks else ()
            t_batch = time.time()
            results = sandbox.run_batch(exe, inputs, mode=mode, timeout=exec_timeout,
                                        arch=target.arch, endianness=target.endianness,
                                        bits=target.bits, blocks=arm, base_argv=run_argv)
            if results is None:
                batchable = False                     # not available here; stay per-exec
            else:
                _price(prefix, (time.time() - t_batch) * 1000 / max(1, len(inputs)),
                       flag_cost, retired, suspect, cheap_ms, ctx, event_prefix)
        if results is None:
            # Per-execution fallback -- an emulated target, or no bubblewrap. Coverage still
            # travels: the ptrace tracer cannot reach inside qemu, but qemu logs the guest PC
            # of every block it translates, so a cross-architecture campaign is no longer
            # blind. Eleven of the twelve architectures the platform builds real targets for
            # were running on output shape alone.
            inputs = inputs[:1]
            kw = {"endianness": target.endianness, "bits": target.bits}
            if run_fn is run_input:
                kw["base_argv"] = run_argv
            # Only ever arm blocks we have not reached: the breakpoints are one-shot. Asked by
            # SIGNATURE rather than by identity, because the channel runner takes them too --
            # gated on `run_fn is run_input`, a network campaign could not be given coverage at
            # all, and every payload was judged on output shape alone.
            if all_blocks and runner_takes_blocks:
                kw["blocks"] = tuple(all_blocks - seen_blocks)
            results = [run_fn(exe, mode, workfile, exec_timeout, target.arch, inputs[0],
                              **kw)[1]]
        for data, res in zip(inputs, results):
            # What gets RECORDED is the flag prefix, not the invocation: the workfile path
            # is scratch and means nothing to a later replay. A crash found under an option
            # only reproduces WITH that option -- jhead's `-cmd` runs a command built from the
            # input -- so the prefix travels with the input it crashed.
            argv = list(run_argv)
            execs += 1
            # Keep anything that made the program behave in a way we have not seen. This is the
            # ratchet: without it the corpus never grows and a deeper path is reachable only by a
            # single lucky mutation from a seed.
            new_blocks = set()
            cover_answered = False
            if all_blocks:
                # `blocks_hit` is the explicit answer; `note` is the old channel, kept for a
                # runner that has not been taught the field. A runner with something else to
                # say in `note` -- the channel harness names its endpoint there -- silently
                # reported no coverage for as long as the two shared one string.
                if res.blocks_hit is not None:
                    cover_answered = True
                    new_blocks = set(res.blocks_hit) - seen_blocks
                elif res.note:
                    try:
                        reported = {int(x) for x in res.note.split(",") if x}
                        cover_answered = True
                        new_blocks = reported - seen_blocks
                    except ValueError:
                        pass
                seen_blocks |= new_blocks
                cover_reported = cover_reported or cover_answered
            # Directedness: did this input reach a block closer to a sink than anything before?
            closer = False
            if block_dist and res.blocks_hit is not None:
                from . import blockdist as _bd
                d = _bd.min_distance(res.blocks_hit, block_dist)
                if d is not None and (best_dist is None or d < best_dist):
                    best_dist = d
                    closer = True
            b = behaviour_of(res, data)
            # Trust block novelty only once coverage has actually answered; if it never does,
            # blocks were armed but are not being reported, and behaviour novelty keeps the
            # corpus learning instead of freezing it (block-only novelty would be dead here).
            if all_blocks and cover_reported:
                novel = bool(new_blocks)
            else:
                novel = b not in seen_behaviour
            if b not in seen_behaviour:
                seen_behaviour.add(b)
            if novel or closer:
                if not res.crashed and len(data) <= _MAX_KEEP:  # noqa: SIM102
                    if len(corpus) < _MAX_CORPUS:
                        corpus.append(data)
                    else:
                        # Full: ROTATE rather than stop learning. Capping without replacement
                        # freezes the corpus around whatever shallow behaviours were found first,
                        # which is most of them -- the interesting paths are discovered late.
                        corpus[rng.randrange(len(corpus))] = data
                    kept += 1
                    if closer and not novel:
                        directed_kept += 1
            if res.crashed:
                crashes += 1
                # A crash that does not happen again is not a finding. Some targets REWRITE
                # their input: jhead's `-dc` and `-zt` edit the file in place, so it faulted on
                # bytes it had produced itself and the input we hold is the original, which
                # runs clean. Filing those left every downstream stage chasing a crash that
                # cannot be reproduced, and the release gate failing with "PoC not reproduced".
                if not _reproduces(run_fn, exe, mode, workfile, exec_timeout,
                                   target, data, run_argv):
                    flaky += 1
                    continue
                crashes_reproducible += 1
                # A bucket is (signal, faulting address, sanitizer defect): the same signal from a
                # different instruction is a different defect, and -- because every ASan abort
                # faults at the SAME PC (the abort machinery) -- distinct sanitizer defects must be
                # separated by their defect_key too, or every bug after the first is hidden behind
                # whichever crashed soonest. defect_key MUST be part of the bucket (not computed
                # later), since the bucket is what gates whether a finding is filed at all.
                sig = res.signal_name
                defect_key = asan_defect_key(res.stderr) if sig == "SIGABRT" else None
                # A hijack PC is attacker-controlled (out of the program's code) and differs per
                # input, so it is bucketed as one "cfh" defect rather than one-per-garbage-PC.
                hj = is_hijack_pc(res.fault_pc, code_span)
                bucket = (sig, "cfh" if hj else res.fault_pc, defect_key)
                # Explore near crashers -- while they are still telling us something. Kept
                # unconditionally, one reproducible crash takes the corpus over: jhead crashed
                # on 8,516 of 20,000 executions, all the same defect, and block coverage fell
                # from 978 to 796 because almost every parent was a crasher. So keep the first
                # few of each BUCKET and let the rest through the normal rotation.
                if seen_sigs.get(bucket, 0) < _MAX_CRASH_ROWS:
                    if len(corpus) < _MAX_CORPUS:
                        corpus.append(data)
                    else:
                        corpus[rng.randrange(len(corpus))] = data
                if bucket not in seen_sigs:
                    seen_sigs[bucket] = 1

                    def _same(d, _sig=sig, _prefix=run_argv):
                        # Minimize under the SAME invocation the crash was found and confirmed
                        # with: a crash behind an option (jhead's `-cmd`) does not reproduce
                        # without it, so a flag-less predicate would be false from the first
                        # call and either minimize nothing or reduce to a non-crashing input.
                        kw = {"endianness": target.endianness, "bits": target.bits}
                        if run_fn is run_input:
                            kw["base_argv"] = _prefix
                        r = run_fn(exe, mode, workfile, exec_timeout, target.arch, d, **kw)[1]
                        return r.crashed and r.signal_name == _sig

                    budget = min(200, max(20, max_execs - execs))
                    mdata, mexecs = minimize(_same, data, cap=budget)
                    execs += mexecs
                    note = (f"minimized {len(data)}->{len(mdata)}B"
                            if len(mdata) < len(data) else None)
                    margv = list(run_argv)
                    input_sha = ctx.put_artifact("fuzz-crash-input", data=mdata)
                    dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                              input_mode=mode, argv=margv, signal=res.signal, signal_name=sig,
                              crashed=True, isolation=res.isolation,
                              duration_ms=res.duration_ms, note=note,
                              fault_pc=res.fault_pc, defect_key=defect_key)
                    extra = "(" + note_prefix + ("; " + note if note else "") + ")"
                    fd.upsert(target.id, target.case_id, crash_finding_candidate(
                        sig, input_sha, res.isolation, detector, extra,
                        fault_pc=res.fault_pc, discriminator=defect_key, hijack=hj))
                elif seen_sigs[bucket] < _MAX_CRASH_ROWS:
                    # A campaign that finds a REPRODUCIBLE crash finds it thousands of times:
                    # 8,128 of 20,000 executions on jhead. Storing every one buries the case in
                    # rows that all describe the same defect and say nothing new, so keep a
                    # handful of examples per signal and count the rest.
                    seen_sigs[bucket] += 1
                    input_sha = ctx.put_artifact("fuzz-crash-input", data=data)
                    dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_sha=input_sha,
                              input_mode=mode, argv=argv, signal=res.signal,
                              signal_name=res.signal_name, crashed=True,
                              isolation=res.isolation, duration_ms=res.duration_ms,
                              fault_pc=res.fault_pc,
                              defect_key=(asan_defect_key(res.stderr)
                                          if res.signal_name == "SIGABRT" else None))
        if execs % 250 == 0:
            ctx.emit(f"{event_prefix}.progress", payload={"execs": execs, "crashes": crashes,
                                                          "unique": len(seen_sigs),
                                                          "behaviours": len(seen_behaviour),
                                                          "corpus": len(corpus)})

    elapsed = max(1e-3, max_seconds - max(0.0, deadline - time.time()))
    # An execution rate this low means the campaign barely ran, and "0 crashes" from 16
    # executions must not read like "0 crashes" from 20,000.
    #
    # But slow is not the same as starved, and the flag means the second. An emulated target
    # runs at ~40 executions/second and a network listener at ~3, legitimately -- so a
    # campaign that found a crash, or saw the program behave in more than one way, did real
    # work however slowly it went. Measured: a persistent multicast campaign did 120
    # executions, found and confirmed a CWE-129, and still reported `starved: true` on rate
    # alone, which tells the reader to distrust a result that is sound.
    rate = execs / max(1e-3, max_seconds - max(0.0, deadline - time.time()))
    did_work = crashes > 0 or len(seen_behaviour) > 1
    # Reaching an instrumented block is also proof the program ran: a target whose output shape
    # never varies (behaviours == 1) but whose branches are being covered has plainly entered.
    entered = did_work or len(seen_blocks) > 0
    # Coverage was armed but nothing ever came back OR nothing was reached: either way the
    # campaign learned nothing from coverage, which for a program that also never varied its
    # output means it never got past the gate.
    coverage_armed = bool(all_blocks)
    coverage_dead = coverage_armed and len(seen_blocks) == 0
    # `starved` now means "could not run / never entered the program", not merely "slow":
    #  * it barely ran, slowly (the original signal);
    #  * it ran plenty of executions but never got past the gate (one behaviour, no coverage);
    #  * coverage was armed and nothing was ever reached.
    # A crash, more than one behaviour, or any block reached all clear it -- so a genuinely
    # slow-but-productive campaign (an emulated target, a network listener) is never flagged.
    starved = bool(
        (execs < 200 and rate < 20 and not did_work)
        or (execs >= 200 and not entered)
        or (coverage_dead and not did_work))
    stats = {"execs": execs, "crashes": crashes, "flaky": flaky,
             "crashes_reproducible": crashes_reproducible, "unique": len(seen_sigs),
             "starved": starved, "directed_kept": directed_kept,
             "nearest_sink_dist": (round(best_dist, 2) if best_dist is not None else None),
             "behaviours": len(seen_behaviour), "corpus": len(corpus), "kept": kept,
             "execs_per_sec": round(execs / elapsed),
             "blocks_hit": len(seen_blocks), "blocks_known": len(all_blocks),
             # distinguish "coverage armed and live", "armed but never reported" (a fixable
             # environment defect, not a clean campaign) and "no coverage available at all".
             "coverage": ("unavailable" if (coverage_armed and not cover_reported)
                          else "live" if coverage_armed else "none")}
    if coverage_armed and not cover_reported:
        ctx.emit(f"{event_prefix}.coverage_unavailable", payload={
            "blocks_known": len(all_blocks),
            "note": ("blocks were recovered and armed but the runner reported no coverage for "
                     "any input (ptrace may be unavailable in this sandbox); the campaign fell "
                     "back to output-shape novelty. This is not a clean 'no crashes' result -- "
                     "coverage-guided search did not run.")})
    # Uninitialized-read pass (CWE-457): detonate the corpus we just built against the MSan binary.
    # This is the RIGHT place for source targets -- they compile to an ASan build that coverage_fuzz
    # skips, so they are fuzzed here, and the corpus is the only place uninitialized reads surface.
    try:
        msan_detonate(ctx, target, corpus, mode, exec_timeout, base_argv=base_argv)
    except Exception:
        pass
    ctx.emit(f"{event_prefix}.done", payload=stats)
    ctx.progress(pct=100, msg=f"{execs} execs, {crashes} crashes, {len(seen_sigs)} unique, "
                             f"{len(seen_behaviour)} behaviours")
    return stats


def _reproduces(run_fn, exe, mode, workfile, exec_timeout, target, data, prefix) -> bool:
    """Does this input crash again, on its own, the way it was found?

    Through the campaign's OWN runner: a boundary-harness campaign delivers its input through a
    generated harness, and the default runner cannot deliver it at all -- checking with the
    wrong one discards every crash it finds.
    """
    kw = {"endianness": target.endianness, "bits": target.bits}
    if run_fn is run_input:
        kw["base_argv"] = prefix
    try:
        _argv, res = run_fn(exe, mode, workfile, exec_timeout, target.arch, data, **kw)
    except Exception:
        return False
    return bool(res.crashed)


_PROBE_N = 8                    # batch size while an option's cost is still unknown
_COST_FACTOR = 40               # "orders more than the norm", measured against plain batches
_COST_FLOOR_MS = 100.0          # never retire an option that is fast in absolute terms


def _dear(per_ms, base_ms) -> bool:
    return per_ms is not None and per_ms > max(_COST_FLOOR_MS, base_ms * _COST_FACTOR)


def _price(prefix, per_ms, flag_cost, retired, suspect, cheap_ms, ctx, event_prefix):
    """Record what a batch cost, and retire options that are pathologically slow.

    A batch's cost is only attributable to the whole prefix, so an expensive one with several
    options merely makes each a SUSPECT: they get re-run alone, and only an option that is
    still expensive by itself is retired. Retiring the whole prefix instead loses the innocent
    options that happened to travel with it -- measured on jhead, `-ce` (which opens an editor)
    took `-orp` and `-rgt` down with it.
    """
    if not prefix:
        cheap_ms.append(per_ms)
        del cheap_ms[:-16]
        return
    base = sorted(cheap_ms)[len(cheap_ms) // 2]
    expensive = _dear(per_ms, base)
    for f in prefix:
        prev = flag_cost.get(f)
        flag_cost[f] = per_ms if prev is None else min(prev, per_ms)
    if not expensive:
        return
    if len(prefix) > 1:
        suspect.extend(f for f in prefix if f not in retired and f not in suspect)
        return
    f = prefix[0]
    retired.add(f)
    ctx.emit(f"{event_prefix}.flag_retired",
             payload={"flag": f, "ms_per_exec": round(per_ms), "baseline_ms": round(base, 2),
                      "why": "this option makes the target run something interactive (an "
                             "editor, a shell); at this cost it would consume the campaign "
                             "budget for a handful of executions"})


_FLAG_RE = re.compile(rb"(?<![\w%/.-])(-{1,2}[A-Za-z][A-Za-z0-9_]{0,20})(?![\w/.-])")
_FLAG_CAP = 64


def mine_flags(data: bytes) -> list:
    """Command-line options the binary understands, read out of its own bytes.

    A campaign only ever passed the input, so every path behind a flag was unreachable by
    construction. On jhead that is ~200 blocks across six functions -- `DoFileRenaming`,
    `DoCommand`, `ReplaceThumbnail`, `ClearOrientation`, `DiscardAllButExif`, `WriteJpegFile` --
    and `DoCommand` is where CVE-2020-6624 lives. Real CLI tools put most of their behaviour
    behind options; a fuzzer that only hands over a filename explores the parser and nothing
    else.
    Mined from the RAW bytes rather than the extracted string table, which truncates the usage
    blob where the short flags live: measured on jhead, the string table yields 40% of the real
    flags and the raw bytes yield all 42. False positives (a build string's `-O0`, a helper
    command's `-outfile`) cost nothing -- an unknown flag makes the target print usage, and
    coverage simply does not reward it.
    """
    found: dict = {}
    for run in re.findall(rb"[ -~\t\n]{4,}", data):
        for m in _FLAG_RE.findall(run):
            tok = m.decode("latin-1")
            found[tok] = found.get(tok, 0) + 1
    return sorted(found, key=lambda k: (-found[k], k))[:_FLAG_CAP]


def _recovered_blocks(ctx, target):
    """Basic-block addresses as FILE vaddrs, or () when the target has not been disassembled.

    The decompiler already walked this binary; its block list is coverage instrumentation we
    have already paid for. Addresses are shifted out of the decompiler's image base so the
    runner can place them whether the target is position-independent or not.
    """
    from ..debug import rootcause
    from ..elf import parse as parse_elf
    from ..elf import program_ranges
    fd = FunctionDAO(ctx.conn)
    fns = fd.list_by_target(target.id)
    if not fns:
        return ()
    blob = ctx.content.path(target.sha256).read_bytes()
    try:
        entry = parse_elf(blob).entry
    except Exception:
        entry = None
    base = rootcause.image_base(fns, entry) or 0
    ranges = program_ranges(blob)
    live = _reachable_functions(ctx, target, fns)
    out = set()
    for f in fns:
        if not f.blocks:
            continue
        # The reachable-from-main closure, when we have it, is AUTHORITATIVE: it already names the
        # program's own functions, so trust it and skip the symbol-range filter. That filter is a
        # FALLBACK for when the call graph cannot say -- and it mis-attributes global functions on
        # a statically linked build (globals sit outside the STT_FILE local-symbol grouping, so a
        # program's own main/a/b get charged to an adjacent libc object and dropped).
        if live is not None:
            if f.addr not in live:
                continue
        # ranges come from the ELF's own symbols, so compare in ELF vaddr space: on a PIE the
        # decompiler's addresses sit at a different image base, and comparing raw dropped every
        # function in the binary
        elif ranges and not _in_program(_addr_of(f) - base, ranges):
            continue
        full = fd.get(f.id)
        for b in ((full.ir or {}).get("blocks") or []):
            try:
                out.add(int(b["addr"], 16) - base)
            except (KeyError, TypeError, ValueError):
                continue
    return sorted(out)


# C-runtime / sanitizer / libc symbols the coverage reachability closure must not descend into on
# a statically linked build -- they are linked-in, not the program. Prefix match first (covers the
# whole ASan/UBSan/libstdc++/dynamic-loader families), then a set of the common libc entry points a
# program calls directly (read, malloc, printf, ...) whose names carry no distinguishing prefix.
_RUNTIME_PREFIXES = (
    "__asan", "__ubsan", "__sanitizer", "__lsan", "__tsan", "__interceptor", "___interceptor",
    "__cxa", "__gnu_cxx", "_ZN", "_ZL", "_ZSt", "__libc", "__GI_", "_IO_", "_dl_", "__pthread",
    "pthread_", "__gthread", "_int_", "sysmalloc", "__default_", "__run_exit", "register_tm",
    "deregister_tm", "frame_dummy", "__do_global", "_start", "__libc_csu", "__stack_chk",
)
_RUNTIME_NAMES = frozenset({
    "read", "write", "open", "open64", "close", "lseek", "readv", "writev", "pread", "pwrite",
    "malloc", "free", "calloc", "realloc", "reallocarray", "aligned_alloc", "posix_memalign",
    "memcpy", "memmove", "memset", "memcmp", "memchr", "mempcpy", "bcopy", "bzero",
    "strcpy", "strncpy", "strcat", "strncat", "strlen", "strnlen", "strcmp", "strncmp", "strchr",
    "strrchr", "strstr", "strdup", "strndup", "strtok", "strtol", "strtoul", "atoi", "atol",
    "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vsnprintf", "puts", "fputs", "putchar",
    "fputc", "fwrite", "fread", "fopen", "fclose", "fgets", "getline", "scanf", "sscanf", "fscanf",
    "gets", "system", "popen", "pclose", "execve", "execl", "execlp", "execvp", "fork", "exit",
    "_exit", "abort", "raise", "signal", "sigaction", "mmap", "mmap64", "munmap", "mprotect",
    "brk", "sbrk", "getenv", "setenv", "putenv", "qsort", "bsearch", "rand", "srand", "time",
    "sleep", "usleep", "nanosleep", "isatty", "getpid", "__errno_location", "__assert_fail",
})


def _is_runtime_fn(name: str) -> bool:
    """True for a linked-in C-runtime / sanitizer / libc function (not the program's own code)."""
    if not name:
        return False
    n = name.lstrip(".")                       # ppc64le ELFv2 local-entry dot
    return n.startswith(_RUNTIME_PREFIXES) or n in _RUNTIME_NAMES


def _reachable_functions(ctx, target, functions):
    """Functions the entry point can actually call, or None when the call graph cannot say.

    A program linked against a library carries all of it: gif2rgb only DECODES GIFs, but
    giflib's whole encoder is in the binary, and 36 of the 62 functions the campaign never
    reached were EGifPutLine, EGifCompressLine, EGifSpew and friends -- code no input can
    reach because nothing calls it. Counting it made a campaign covering half of what it can
    reach look like one covering a quarter of the program.

    Closure from the entry point, so it UNDER-approximates wherever calls are indirect -- and
    hiding live code is much worse than counting dead code, because it makes a campaign that
    reaches almost nothing look complete. On stripped unzip the closure reached 100 of 3,705
    blocks: a 46/100 result that measures nothing. So the answer is only used when the call
    graph explains most of the binary; below that it is not evidence of dead code, it is
    evidence that the call graph is too sparse to read.
    """
    edges = CallEdgeDAO(ctx.conn).list_by_target(target.id)
    if not edges:
        return None
    known = {f.addr for f in functions}
    name_by = {f.addr: (f.name or "") for f in functions}
    entries = [f.addr for f in functions if (f.name or "") in ("main", "_start", "entry")]
    if not entries:
        return None
    has_main = any((f.name or "") == "main" for f in functions)
    out_edges: dict = {}
    called = set()
    for e in edges:
        if e.dst_addr:
            out_edges.setdefault(e.src_addr, set()).add(e.dst_addr)
            called.add(e.dst_addr)
    live, stack = set(entries), list(entries)
    while stack:
        cur = stack.pop()
        for dst in out_edges.get(cur, ()):
            if dst in known and dst not in live:
                # On a statically linked build (a sanitizer source build carries all of libc + the
                # ASan/UBSan runtime), do NOT descend into the C runtime: it is thousands of
                # functions `main` reaches transitively but that are not the program, and arming
                # their blocks both dilutes the coverage number and -- since they are re-armed
                # every exec until reached -- collapses fuzz throughput. Keeping the closure to
                # the user's own functions leaves coverage measuring the code that matters.
                if has_main and _is_runtime_fn(name_by.get(dst, "")):
                    continue
                live.add(dst)
                stack.append(dst)
    # The floor guards STRIPPED binaries: their sparse call graph under-approximates, so a tiny
    # reachable set is evidence the graph is unreadable, not evidence of dead code. But a binary
    # with a named `main` is NOT stripped -- its reachable-from-main closure IS the program.
    # A statically linked ASan/sanitizer build carries thousands of runtime functions main never
    # calls (the shadow allocator, interceptors, UBSan handlers): reaching only a handful of the
    # 3,680 is CORRECT, not a broken graph, and the floor must not throw that away or coverage is
    # measured against the entire ASan runtime and reads a meaningless ~2%.
    if len(live) >= 2 and (has_main or len(live) >= _LIVE_FLOOR * len(known)):
        return live if len(live) < len(known) else None
    return None


def _addr_of(f):
    a = getattr(f, "addr", None)
    try:
        return int(a, 16) if isinstance(a, str) else int(a or 0)
    except (TypeError, ValueError):
        return 0


def _in_program(addr, ranges) -> bool:
    i = bisect.bisect_right([lo for lo, _ in ranges], addr) - 1
    return i >= 0 and addr < ranges[i][1]


def fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("fuzz requires a target_id")

    p = ctx.params or {}
    # Which channels to fuzz. Committing to one is wrong even when the inference is right
    # about what the program READS: ncompress genuinely parses files, and its overflow is in
    # the filename it was handed on the command line. A campaign aimed at the wrong channel
    # does no work and reports a clean zero.
    channels = ([p["input_mode"]] if p.get("input_mode")
                else modes_for(CallEdgeDAO(ctx.conn).list_by_target(target.id)))
    max_execs = int(p.get("max_execs", 3000))
    max_seconds = float(p.get("max_seconds", 30))
    exec_timeout = float(p.get("exec_timeout", 2))
    rng = random.Random(int(p.get("seed", 1337)))
    # How to invoke the target. `@@` marks where the input goes -- `["-c", "@@"]` for a
    # service that takes a config path behind a flag; without it the input is appended.
    base_argv = [str(a) for a in (p.get("argv") or [])]
    auto_argv, wants_config = None, False
    if not base_argv and p.get("discover_argv", True):
        base_argv, auto_argv, wants_config = _discover_argv(ctx, target, exec_timeout)
    elif any(a for a in base_argv):
        wants_config = "@@" in base_argv

    if "@@" in base_argv and not p.get("input_mode"):
        # `@@` means "the PATH of the input file goes here". Delivering the input as a raw
        # argv string or over stdin then leaves the placeholder holding payload bytes where a
        # filename belongs, and the target fails to open it -- on every single input. That is
        # not a clean negative and it is worse than one: the JVM target reported 526 crashes,
        # all of them IOException/FileSystemException from a config path that never existed,
        # all at the same site. A harness that cannot deliver the input is not a finding.
        channels = ["file"]
        ctx.emit("fuzz.channel", payload={"mode": "file", "why": (
            "argv carries @@, which is the path of the input file, so the input has to be "
            "delivered as a file")})
    # A PE runs under Wine at about one execution a second (measured: 1,249 ms against ~580/s
    # native) with no coverage feedback, so a campaign manages a few dozen executions and then
    # reports "0 crashes" exactly like a thorough one that found nothing. Say what it is.
    if (target.file_type or "").lower() == "pe":
        ctx.emit("fuzz.slow", payload={
            "format": "pe", "note": (
                "this is a Windows PE: every execution goes through Wine at roughly one per "
                "second and there is no coverage feedback, so this campaign will manage a few "
                "dozen executions rather than thousands. Prefer synthesize_poc, which derives "
                "the overflow from the recovered stack frame without executing at all.")})
    if (target.file_type or "").lower() in ("jar", "class"):
        # Measured on a trivial jar: 27 ms per execution with startup flags tuned, against
        # ~1.7 ms native. That is ~36 executions/second, so a campaign here is thousands of
        # inputs rather than millions -- slow, but three dozen times more workable than the
        # PE/Wine path, and worth saying rather than letting the number surprise someone.
        ctx.emit("fuzz.slow", payload={
            "format": "jvm", "note": (
                "this is a Java target: every execution pays JVM startup (~27 ms measured, "
                "so roughly 36 executions/second against ~580/s native) and there is no "
                "coverage feedback. A defect surfaces as an uncaught exception rather than a "
                "signal. Budget thousands of executions, not millions, and lean on the "
                "constant pool -- it names every string and call in the clear.")})
    strings = _strings_for(ctx, target)
    blocks = _recovered_blocks(ctx, target)
    flags = mine_flags(ctx.content.path(target.sha256).read_bytes())
    corpus = [base64.b64decode(x) for x in p.get("seeds", [])] or list(_DEFAULT_SEEDS)
    dictionary = _mine_dictionary(strings)
    mutator, note = _structure_mutator(p, rng, dictionary), "found by fuzzing"
    fmt = p.get("format_name") or ("custom" if p.get("format") else None)
    if mutator is None and not p.get("format") and any(
            xmlgrammar.looks_like_xml(c) for c in corpus[:8]):
        # XML is a grammar, not a byte layout, and byte mutation does not work on it: measured
        # against xmllint, 2 of 200 mutants parsed cleanly and the other 198 died in the
        # tokeniser. The campaign does not look starved while that happens -- 3,000 executions
        # produced 759 distinct "behaviours", because a parser has a great many ways to say no
        # and the behaviour proxy is output shape. Distinct output is not distinct code.
        mutator, fmt = xmlgrammar.XmlMutator(rng, dictionary), "xml"
        ctx.emit("fuzz.format", payload={"model": "xml", "auto": True,
                                         "why": "the seed is an XML document"})
    if mutator is None and not p.get("format") and wants_config:
        # The binary documents a required `-c <config>`, so its input is a config file, and a
        # config file is text: `key=value` lines. No binary format model describes that, and a
        # byte mutator cannot reach the `strcpy` behind a key it has to invent first -- 2,000
        # executions against one produced 826 distinct behaviours and no crashes.
        keys = textconf.keys_from([x.value for x in strings])
        mutator, fmt = textconf.KeyValueMutator(rng, keys, dictionary), "keyvalue"
        corpus = [textconf.seed_for(keys)] + list(corpus)
        ctx.emit("fuzz.format", payload={"model": "keyvalue", "auto": True,
                                         "keys": keys[:16],
                                         "why": "the binary requires a config path"})
    if mutator is None and not p.get("format"):
        # Nobody supplied a model, so ask the binary. A parser rejects random bytes before it
        # reaches any of its own logic -- jhead ran 98,500 executions for zero finds while
        # AFL++ reached the same bug in 60 seconds WITH a valid sample -- and the target's own
        # strings say which format it reads. The model then yields a seed that passes the gate,
        # so the campaign starts inside the parser instead of at its front door.
        fmt = structure.detect_format([x.value for x in strings])
        if fmt:
            model = structure.builtin(fmt)
            mutator = structure.StructMutator(rng, model, dictionary)
            seed = structure.seed_for_name(fmt)
            if seed:
                corpus = [seed] + list(corpus)
    # Always, not only when a format model was chosen: a wrong invocation is the failure that
    # looks most like a clean campaign, so it has to be visible in the run's own events.
    ctx.emit("fuzz.invocation", payload={
        "argv": base_argv, "placeholder": "@@" in base_argv,
        "discovered": auto_argv,
        "note": ("the input is appended to argv; use \"@@\" to place it elsewhere"
                 if base_argv and "@@" not in base_argv else None)})
    if mutator:
        note = "found by structure-aware fuzzing"
        ctx.emit("fuzz.format", payload={"model": fmt or "custom", "auto": not (
            p.get("format") or p.get("format_name"))})
    # Split the budget across them, stopping early on a REPRODUCIBLE crash. A bug is usually
    # reachable through one channel only, and which one is not knowable in advance. Stopping on
    # the raw crash count would let a channel that only produced non-reproducible (flaky)
    # crashes -- a target that rewrites its own input -- halt the sweep with nothing to show.
    share_execs = max(1, max_execs // len(channels))
    share_secs = max(1.0, max_seconds / len(channels))
    totals = {"execs": 0, "crashes": 0, "crashes_reproducible": 0, "unique": 0,
              "behaviours": 0}
    blocks_hit = 0            # the most blocks any one channel reached (coverage is per-run)
    blocks_known = 0
    for ch in channels:
        st = fuzz_campaign(ctx, target, corpus=list(corpus), dictionary=dictionary, mode=ch,
                           max_execs=share_execs, max_seconds=share_secs,
                           exec_timeout=exec_timeout, rng=rng, detector="fuzz",
                           event_prefix="fuzz", note_prefix=note, mutator=mutator,
                           cover_blocks=blocks, cover_flags=flags, base_argv=base_argv)
        for k in totals:
            totals[k] += st.get(k, 0)
        blocks_hit = max(blocks_hit, st.get("blocks_hit", 0))
        blocks_known = max(blocks_known, st.get("blocks_known", 0))
        if st.get("crashes_reproducible"):
            break
    ctx.emit("fuzz.channels", payload={"channels": channels, "flags": len(flags), **totals})
    # Block coverage: how much of the recovered code the campaign actually reached. A parser
    # that fuzzed for a full budget but hit 3% of blocks never got past its length check.
    pct = round(100.0 * blocks_hit / blocks_known, 1) if blocks_known else None
    summary = {"backend": "blind", "execs": totals["execs"], "crashes": totals["crashes"],
               "coverage": {"kind": "block", "blocks_hit": blocks_hit,
                            "blocks_known": blocks_known, "pct": pct}}
    sha = ctx.put_artifact("fuzz-summary", data=canonical_json(summary))
    return {"output_shas": [sha], "output_kind": "fuzz-summary"}


def _structure_mutator(p, rng, dictionary):
    """Build a structure-aware mutator from params.format (a field spec) or params.format_name
    (a built-in model). params.magic overrides a built-in's placeholder magic. None otherwise."""
    from . import structure
    model = None
    if p.get("format"):
        model = structure.from_spec(p["format"])
    elif p.get("format_name"):
        model = structure.builtin(p["format_name"])
    if model is None:
        return None
    magic = p.get("magic")                             # override the model's magic (e.g. a gate)
    if magic and model.spec and model.spec[0].get("type") == "magic":
        model.spec[0]["value"] = base64.b64decode(magic) if p.get("magic_b64") else magic
    return structure.StructMutator(rng, model, dictionary)


def register() -> None:
    register_stage(FUZZ_STAGE, fuzz_stage, resource_class="cpu", tool=TOOL,
                   tool_version=TOOL_VERSION, timeout=3600)


def enqueue_fuzz(queue, target, *, params=None, force: bool = True):
    return queue.enqueue(target.case_id, FUZZ_STAGE, target_id=target.id, params=params or {},
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="cpu", force=force)
