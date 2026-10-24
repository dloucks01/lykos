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
import logging
import os
import random
import re
import time
from pathlib import Path
from typing import Optional

from ... import observe
from ...db.dao import CallEdgeDAO, DynResultDAO, FindingDAO, FunctionDAO, StringDAO, TargetDAO
from ...hashing import canonical_json
from ...jobs.registry import register_stage
from .. import substrate
from ..dynamic import sandbox
from ..dynamic.minimize import minimize
from ..dynamic.stage import (
    asan_defect_key,
    crash_finding_candidate,
    is_hijack_pc,
    recovered_code_span,
)
from ..poc.capture import modes_for, no_import_evidence
from . import structure, textconf, xmlgrammar
from .mutator import Mutator
from .runner import invocation, run_input

_log = logging.getLogger(__name__)

FUZZ_STAGE = "fuzz"
TOOL = "fuzz"
TOOL_VERSION = "fuzz-1"
# Long seeds are not a luxury: a blind mutator keeps nothing, so without one the campaign can
# only reach a length-triggered bug by growing into it, and it never does. These put the
# overflow class in range from the first exec.
_DEFAULT_SEEDS = [b"", b"A" * 8, b"%s%s%s%n", b"0", b"-1", b"../../etc/passwd",
                  b"A" * 256, b"A" * 1024, b"A" * 4096]


#: A dispatch token is matched at the START of the line (`strncmp(line, "dump=", 5)`), so a
#: mutator that inserts it anywhere reaches that branch only by luck -- and once the campaign has
#: found ONE bug, its corpus fills with inputs that carry the OTHER prefix and keep it through
#: mutation. Measured on the `addr_leak_pie_ret2win` fixture, which has two dispatch branches and
#: a defect behind each: 21 of 21 crashes were the `name=` overflow, the campaign's own inputs
#: show `dump=` being inserted mid-line ("name=.dump=.name=..."), and the read behind `dump=` --
#: the one that defeats ASLR -- was never reached, so the chain stopped at L2 for want of a base.
_PREFIX_TOKEN = __import__("re").compile(rb"^[A-Za-z_][A-Za-z0-9_.-]{1,20}[=:]$")
#: Bodies to try after a dispatch token: a number (an index, a length, a count), a long filler
#: (a copy into a fixed buffer) and a huge number (the wrap/out-of-range case).
_PREFIX_BODIES = (b"0", b"1", b"A" * 96, b"99999999")


def _dispatch_prefix_seeds(dictionary, cap: int = 8) -> list:
    """Seeds that put each mined dispatch token where the program actually tests for it.

    Cheap -- a handful of inputs, no execution -- and it is the difference between fuzzing one
    branch of a command dispatcher and fuzzing several. The token has to look like a dispatch
    key (`name=`, `show:`), not like any string in the image, or this floods the corpus.
    """
    out: list = []
    for tok in dictionary:
        if not _PREFIX_TOKEN.match(tok or b""):
            continue
        out += [tok + body for body in _PREFIX_BODIES]
        if len(out) >= cap * len(_PREFIX_BODIES):
            break
    return out


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
#: The share of a campaign's own slice that may be spent preparing its seed corpus, and a floor
#: so a very tight slice can still minset a handful of seeds. See the call site for the
#: measurement: unbounded, distillation consumed five to twelve times the whole slice.
_DISTILL_SHARE = 0.2
_DISTILL_FLOOR_S = 5.0
# Corpus distillation (afl-cmin-style): only bother minsetting a seed set bigger than this, and
# trace at most this many seeds for the up-front coverage measurement.
_DISTILL_MIN = 12
_DISTILL_CAP = 256
# Seed calibration: run at most this many starting seeds verbatim before mutation begins. Every
# seed a curated corpus supplies (format models, boundary-value configs, menu op-sequences) is
# worth one clean execution up front; the cap stops a large accumulated corpus from spending a
# whole starved budget on replay alone.
_CALIBRATE_CAP = 64
# Largest external seed file to load (configs, sample documents). Big enough for a real config or a
# media sample, small enough that a stray huge file can't blow up the corpus.
_MAX_SEED_BYTES = 1 << 20


def _load_external_seeds(p) -> list[bytes]:
    """Caller-supplied seed bytes: base64 inline (`seeds`), explicit files (`seed_files`), or every
    file in a directory (`seed_dir`).

    Pointing the campaign at REAL example inputs -- a config file, a sample document, a known-
    crashing reproducer -- is how a structured-input parser gets fuzzed at all. A blind mutator
    never invents a valid-enough structure (a parseable JPEG/EXIF, a `key=value` config) to reach a
    bug behind the parser inside a short budget; `jhead`'s EXIF OOB read sat unreproduced for exactly
    this reason. Before this, the only external-seed channel was base64 inline, so an application
    that takes a config file or a sample input could not be seeded from the files you already have.
    Bounded by count (`_MAX_CORPUS`) and per-seed size; an unreadable or oversized entry is skipped,
    never fatal."""
    out: list[bytes] = []
    for b64 in p.get("seeds", []) or []:
        try:
            out.append(base64.b64decode(b64))
        except Exception:                                # noqa: BLE001 -- a bad seed is not fatal
            continue
    paths: list[Path] = [Path(fp) for fp in (p.get("seed_files", []) or [])]
    sd = p.get("seed_dir")
    if sd and Path(sd).is_dir():
        paths += sorted(q for q in Path(sd).iterdir() if q.is_file())
    for q in paths:
        if len(out) >= _MAX_CORPUS:
            break
        try:
            if q.is_file() and 0 <= q.stat().st_size <= _MAX_SEED_BYTES:
                out.append(q.read_bytes())
        except OSError:                                  # unreadable path -> skip
            continue
    return out
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


# Functions that turn INPUT TEXT into a number. Their presence is what justifies spending
# calibration execs on decimal boundary seeds: the program's input is (or contains) a count, an
# index or a size, and those have values that matter rather than lengths that matter.
_NUMERIC_READERS = frozenset({
    "scanf", "__isoc99_scanf", "sscanf", "__isoc99_sscanf", "fscanf", "__isoc99_fscanf",
    "vscanf", "vsscanf", "strtol", "strtoul", "strtoll", "strtoull", "strtoimax",
    "strtoumax", "atoi", "atol", "atoll", "strtod", "strtof",
})


def _reads_a_number(ctx, target) -> bool:
    """Does this target parse a number out of its input?

    Asked of the imports rather than guessed, for the same reason the channel ranking is: a
    `%u` in .rodata proves nothing on its own, since `printf("ok %u", n)` has one too.
    """
    try:
        from ...db.dao import CallEdgeDAO
        from ..detect.catalog import normalize
        names = {normalize(e.dst_name) for e in CallEdgeDAO(ctx.conn).list_by_target(target.id)
                 if e.dst_name}
        return bool(names & _NUMERIC_READERS)
    except Exception:                                    # noqa: BLE001 -- seeding is advisory
        return False


#: How many detected formats get a seed. A real reader reads several (mutool: PDF, XPS/EPUB,
#: PNG, GIF, JPEG); past the third the evidence is no longer evidence, and every extra seed
#: costs calibration time against a target that may not read that format at all.
_MAX_FORMATS = 3


def _triage_symbols_for(ctx, target) -> list:
    """The names triage recorded (imports + exports) -- the channel-ranking evidence that does
    not need `disassemble` to have run. Best-effort: fewer signals, never a failure."""
    try:
        from ..ingest import triage_symbols
        return triage_symbols(ctx.conn, ctx.content, target)
    except Exception:
        observe.absorbed(_log, "answering empty")
        return []


def _imports_for(ctx, target) -> list:
    """The target's imported function names -- the evidence string mining cannot reach.

    A thin CLI over a shared library carries none of that library's strings: `xmlwf` has not
    one XML string in it, because they all live in the libexpat it links against. A
    strings-only format detector is blind to such a target by construction, not by accident,
    and its import table says `XML_ParserCreate` in plain text.

    Call edges carry the names once `disassemble` has run; before that -- and leading with
    execution means fuzzing usually runs first -- the ELF import table does, for the cost of
    parsing bytes already on disk. Best-effort: no imports just means less evidence.
    """
    names: list = []
    try:
        names = [e.dst_name for e in CallEdgeDAO(ctx.conn).list_by_target(target.id)
                 if e.dst_name]
    except Exception:
        observe.absorbed(_log, "keeping the default")
        names = []
    if not names:
        try:
            from .. import elf as elfmod
            data = ctx.content.path(target.sha256).read_bytes()
            names = list((elfmod.parse(data).imports or {}).get("symbols") or [])
        except Exception:
            observe.absorbed(_log, "keeping the default")
            names = []
    return [str(n).split("@")[0] for n in names if n]


def value_seeds_for(ctx, target) -> set:
    """The seeds that exist because of a VALUE, not because of a path.

    Distillation drops an input whose basic blocks another input already covers, which is right
    for a near-duplicate accumulated input and wrong for these. `show=2147483647` takes exactly
    the branches `show=0` takes -- same compare, same call -- so block coverage cannot tell them
    apart, and the one that matters is dropped. Measured on a heap over-read driven by a length
    field: 121 seeds distilled to 1, the boundary seed among the 120 discarded, and the defect
    was never reached in a 900 s autonomous pass though a single execution of that seed reports
    it. `numeric_boundary_seeds` says the same thing in its own docstring -- blind mutation
    "effectively never emits the DECIMAL TEXT of a 9-10 digit number ... it is not a matter of
    budget" -- and then distillation threw the number away.

    So these are forced-keep, exactly as a crash reproducer is: an input nothing in the campaign
    can regenerate is not redundant, whatever its coverage.

    Recomputed rather than threaded through `format_aware_seeds`, whose signature several stages
    share; the string lookups behind it are the same ones that already ran.
    """
    out: set = set()
    try:
        svals = [x.value for x in _strings_for(ctx, target) if getattr(x, "value", None)]
    except Exception:
        observe.absorbed(_log, "answering an empty set")
        return out
    try:
        keys = textconf.keys_from(svals)
        if keys:
            out |= {bytes(b) for b in textconf.boundary_seeds(keys) if b}
    except Exception:
        observe.absorbed(_log, "continuing")
    try:
        out |= {bytes(b) for b in textconf.numeric_boundary_seeds() if b}
    except Exception:
        observe.absorbed(_log, "continuing")
    try:
        # Mirrors the seeder: only the STRONGEST format candidate gets crash-shaped variants, so
        # only its are forced-keep. Same reason -- they wrap a 32-bit bounds check while still
        # pointing out of bounds, which is a value, not a path.
        detected = structure.detect_formats(svals, _imports_for(ctx, target))
        if detected:
            out |= {bytes(b) for b in (structure.boundary_seeds(detected[0]) or ()) if b}
    except Exception:
        observe.absorbed(_log, "continuing")
    return out


def format_aware_seeds(ctx, target) -> list:
    """Seeds that pass the target's INPUT GATE, derived from the binary's own strings AND its
    import table: a format-model seed for each format it looks like a reader for (tiff/pdf/
    elf/... -- carrying the magic and a minimal valid structure), a text
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
        observe.absorbed(_log, "falling back")
        return seeds
    try:
        imps = _imports_for(ctx, target)
    except Exception:
        observe.absorbed(_log, "keeping the default")
        imps = []
    try:
        # EVERY format this binary looks like a reader for, strongest first -- not just the
        # winner. Measured on this corpus: mutool was ranked "zip" (it reads EPUB/XPS, so the
        # ranking is not even wrong) and therefore never got a PDF seed, and libtiff's tools
        # were ranked "jpeg" because they link libjpeg and carry its strings. One guess means
        # the other parsers stay behind their magic check for the whole campaign.
        detected = structure.detect_formats(svals, imps)
        for i, fmt in enumerate(detected[:_MAX_FORMATS]):
            if i == 0:
                # the strongest candidate also gets the crash-shaped variants: one per
                # offset/size pair, wrapping a 32-bit bounds check while still pointing out
                # of bounds, so calibration detonates the structural bug on the first execs
                seeds += structure.boundary_seeds(fmt) or []
            else:
                s = structure.seed_for_name(fmt)
                if s:
                    seeds.append(s)
    except Exception:
        observe.absorbed(_log, "continuing")
    try:
        # A specimen the binary DOCUMENTS for itself -- "in SED format (e.g. s/old/new/)" -- is a
        # valid input written by the author of the parser that reads it, plus a long-field
        # variant of the same shape. What was mined before was the program's ERROR strings,
        # which name the gate without passing it.
        seeds += textconf.example_seeds(svals)
    except Exception:
        observe.absorbed(_log, "continuing")
    try:
        keys = textconf.keys_from(svals)
        if keys:
            seeds.append(textconf.seed_for(keys))
            # ...plus a boundary-value config per numeric edge (0, -1, INT_MAX, overflow): a
            # config field parsed as a number hides an unchecked-index / off-by-one bug behind a
            # specific value that mutating a text placeholder rarely lands inside a short budget.
            seeds += textconf.boundary_seeds(keys)
    except Exception:
        observe.absorbed(_log, "continuing")
    # A target that parses a NUMBER out of its input has values that matter, not lengths: a
    # count multiplied into an allocation wraps at 2**32/elem_size, and no amount of byte
    # mutation emits the decimal text of such a number.
    try:
        if _reads_a_number(ctx, target):
            seeds += textconf.numeric_boundary_seeds(8)
    except Exception:
        observe.absorbed(_log, "continuing")
    # the binary's own selective strings (magic tokens, config keywords, path prefixes)
    seeds += [s.encode("latin-1", "ignore") for s in svals[:8] if 2 <= len(s) <= 256]
    # Menu / interactive-protocol navigation seeds: a numbered-menu service hides its bug behind a
    # state machine, so a blind campaign never leaves the front-door menu. Read the menu out of the
    # binary's own option strings and start the fuzzer INSIDE it.
    try:
        from . import menu
        seeds += menu.menu_seeds(svals)
    except Exception:
        observe.absorbed(_log, "continuing")
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
        from ..dynamic.heap_discover import shared_op_model
        width, model = shared_op_model(ctx, target, workdir, exe, opts)
        if not model:
            return None
        return model, opts, width
    except Exception:
        observe.absorbed(_log, "answering None")
        return None


def linear_protocol_for(ctx, target, exe, workdir):
    """The field template of a LINEAR prompt protocol -- `['str','str']` -- or None.

    A linear protocol is a numbered menu minus the dispatch: prompt, read a field, prompt, read
    the next, then act. `detect_menu` does not fire on it and `crawl_menu` has no options to
    select, so such a target fell to the blind path -- which delivers ONE blob to stdin, where a
    program reading its fields with separate `read(0, buf, N)` calls takes the whole blob as
    field one and hits EOF on field two. Measured on `replaceme`: 63,234 executions, every one
    rejected at the first gate because the sed expression meant for field two arrived inside
    field one.

    Only crawled when there is no menu (the menu path is strictly better when it applies) and
    only accepted at TWO or more fields, because a single-prompt target is what bulk delivery
    already handles and the prompted path costs a drain per field.
    """
    try:
        from ..dynamic.heap_discover import _spawn_menu
        from . import menu
        svals = [x.value for x in _strings_for(ctx, target) if getattr(x, "value", None)]
        if menu.detect_menu(svals):
            return None
        fields = menu.crawl_linear(lambda: _spawn_menu(workdir, exe))
        return fields if len(fields) >= 2 else None
    except Exception:
        observe.absorbed(_log, "answering None")
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
    from ..debug.rootcause import parse_asan_report
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
        observe.absorbed(_log, "answering a default")
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
            observe.absorbed(_log, "skipping this item")
            continue
        txt = (r.stderr or b"").decode("latin-1", "ignore")
        if "MemorySanitizer: use-of-uninitialized-value" not in txt:
            continue
        # Parse it, for the one distinction this class turns on: whether the undefined bytes
        # merely got USED or actually LEFT THE PROCESS through an output call. MSan states it and
        # nothing was reading it, so every uninitialised read in a campaign -- a branch on a
        # stale flag and 128 bytes of a dead frame going out on a socket -- was filed under one
        # title, one CWE and one severity.
        rep = parse_asan_report(txt) or {}
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
            _cwe = rep.get("cwe") or "CWE-457"
            _escaped = rep.get("escape_bytes") is not None
            # The location, from whichever source has one. This pass runs with `symbolize=0`
            # (llvm-symbolizer deadlocks on a captured-pipe stderr), so the report carries no
            # file:line at all and the parser's detail names no site -- `_msan_source_line`
            # recovers it with addr2line instead. Appended unless the detail already says it, so
            # a symbolized report does not get its own site twice.
            _detail = rep.get("detail") or "MemorySanitizer: use of uninitialized value"
            if src and src not in _detail:
                _detail += f" at {src}"
            fd.upsert(target.id, target.case_id, {
                "cwe": _cwe,
                "title": ("Uninitialized memory disclosed to output" if _escaped
                          else "Use of uninitialized value"),
                "severity": rep.get("severity") or "medium",
                "detector": "msan", "state": "corroborated", "confidence": 0.8,
                "dedup_key": f"{_cwe}:msan:{key}", "function_addr": None, "site_addr": None,
                "site_detail": src,
                "evidence": [{"channel": "sanitizer",
                              "detail": _detail + f" (input {sha[:12]})"}]})
            found += 1
        except Exception:
            observe.absorbed(_log, "skipping this item")
            continue
        # RECORD IT AS A RUN, for the reason spelled out in `tsan_detonate`: the PoC ladder
        # iterates dyn_result, and this pass filed only a Finding -- so a real uninitialised-
        # memory disclosure reached the report as `corroborated` and nothing downstream ever
        # touched it. No bundle, no volume, no verdict on whose bytes escaped. The isolation tag
        # names the MSAN build so `replay_exe_for` detonates IT: no other build reports this
        # class, and the ASan one destroys the evidence (it zeroes a fresh frame and fills a
        # fresh heap allocation with 0xbe) **[measured]**.
        #
        # `crashed=True` is how the ladder recognises a run worth proving. It is the right word
        # here in the only sense that matters downstream -- the detector halted the process on a
        # defect it observed -- and the report never calls it a crash: the verdict carries the
        # class, and an uninitialised read that discloses is titled a disclosure.
        try:
            DynResultDAO(ctx.conn).insert(
                target.id, target.case_id, run_id=getattr(ctx, "run_id", None), input_sha=sha,
                input_mode=mode, argv=list(tail), crashed=True,
                signal_name=rep.get("class") or "use-of-uninitialized-value",
                isolation="msan", defect_key=f"msan:{key}",
                note=_detail)
        except Exception:
            try:
                ctx.emit("msan.norun", payload={
                    "note": "the uninitialised read was filed as a finding but NOT recorded as "
                            "a run, so the PoC ladder cannot reach it", "key": str(key)[:80]})
            except Exception:
                observe.absorbed(_log, "continuing")
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
        observe.absorbed(_log, "answering None")
        return None
    return None


def lsan_detonate(ctx, target, inputs, mode, exec_timeout, base_argv=()) -> int:
    """Detonate a set of inputs against the target's LeakSanitizer build (built at ingest for source
    targets) to surface MEMORY LEAKS (CWE-401) -- an allocation never freed. A leak does NOT crash and
    the rest of the pipeline runs ASan with detect_leaks=0, so it must be driven here against a
    dedicated `-fsanitize=leak` build whose LSAN_OPTIONS (not the disabled ASAN_OPTIONS) governs the
    scan. LSan reports AT EXIT, so a benign input that reaches an allocation triggers it; a
    guaranteed-allocating probe is prepended so the pass fires even on an empty corpus. Findings land
    'corroborated' (the sanitizer directly observed the leak) with the allocation site. Fully guarded.

    Runs under the SAME bubblewrap containment as every other target (attacker-controlled native code)
    via isolate_prefix + run_reaped; a wall-clock budget bounds the cost (it fires once per campaign)."""
    import os as _os

    from ...db.dao import ArtifactDAO
    from ..debug.rootcause import parse_asan_report
    try:
        arts = ArtifactDAO(ctx.conn).list_by_case(target.case_id)
        la = next((a for a in arts if a.kind == "lsan-blob"
                   and (a.meta or {}).get("binary_sha") == target.sha256), None)
        if not la:
            return 0
        lsbin = ctx.scratch() / "target.lsan"
        lsbin.write_bytes(ctx.content.path(la.sha256).read_bytes())
        _os.chmod(lsbin, 0o755)
    except Exception:
        observe.absorbed(_log, "answering a default")
        return 0
    # symbolize=0 for the same reason as msan_detonate: llvm-symbolizer deadlocks on a captured-pipe
    # stderr. Recover the allocation site ourselves with addr2line on the raw frame offset. LSan's
    # own default exit code (23) already distinguishes a leak report from a clean exit.
    env = dict(_os.environ)
    env["LSAN_OPTIONS"] = "symbolize=0:exitcode=23"
    exedir = str(lsbin.parent)
    prefix = sandbox.isolate_prefix(exedir, net=False)
    per_timeout = max(2, int(exec_timeout))
    deadline = time.monotonic() + max(15.0, min(90.0, per_timeout * 30))
    _cancel = getattr(ctx, "should_cancel", None)
    fd = FindingDAO(ctx.conn)
    wf = ctx.scratch() / "lsan-in.bin"
    # A leak only surfaces once the program reaches an allocation and EXITS, so a benign allocating
    # probe is tried first -- otherwise an empty/early-returning corpus never frees nothing to see.
    probe = b"lykos-leak-probe\nlykos-leak-probe\nq\n"
    found, seen = 0, set()
    for data in ([probe] + list(inputs))[:400]:
        if time.monotonic() > deadline or (_cancel is not None and _cancel()):
            break
        data = data or b""
        tail, stdin = invocation(mode, wf, data, base_argv)
        argv = [str(lsbin)] + tail
        try:
            r = sandbox.run_reaped(prefix + argv, input=stdin, timeout=per_timeout,
                                   capture_output=True, env=env)
        except Exception:
            observe.absorbed(_log, "skipping this item")
            continue
        txt = (r.stderr or b"").decode("latin-1", "ignore")
        if "LeakSanitizer: detected memory leaks" not in txt and "Direct leak of" not in txt:
            continue
        rep = parse_asan_report(txt) or {}
        src = _msan_source_line(lsbin, txt)          # the allocation site (addr2line, symbolize=0)
        _raw = re.search(r"\(\S+\+0x[0-9a-fA-F]+\)", txt)
        key = src or (_raw.group(0) if _raw else
                      hashlib.sha1(txt[:256].encode("latin-1", "ignore")).hexdigest()[:12])
        if key in seen:
            continue
        seen.add(key)
        _cwe = rep.get("cwe") or "CWE-401"
        _detail = rep.get("detail") or "LeakSanitizer: detected memory leak"
        if src and src not in _detail:
            _detail += f" at {src}"
        try:
            sha = ctx.put_artifact("lsan-input", data=data)
            fd.upsert(target.id, target.case_id, {
                "cwe": _cwe, "title": "Memory leak",
                "severity": rep.get("severity") or "low",
                "detector": "lsan", "state": "corroborated", "confidence": 0.8,
                "dedup_key": f"{_cwe}:lsan:{key}", "function_addr": None, "site_addr": None,
                "site_detail": src,
                "evidence": [{"channel": "sanitizer",
                              "detail": _detail + f" (input {sha[:12]})"}]})
            found += 1
        except Exception:
            observe.absorbed(_log, "skipping this item")
            continue
        # RECORD IT AS A RUN so the ladder can see it (as msan/tsan do): the isolation tag names the
        # LSAN build so replay detonates IT (no other build reports a leak -- the ASan build runs with
        # detect_leaks=0). crashed=True in the only sense downstream cares about: the detector halted
        # the process (exit 23) on a defect it observed; the verdict carries CWE-401, not "crash".
        try:
            DynResultDAO(ctx.conn).insert(
                target.id, target.case_id, run_id=getattr(ctx, "run_id", None), input_sha=sha,
                input_mode=mode, argv=list(tail), crashed=True,
                signal_name=rep.get("class") or "memory-leak",
                isolation="lsan", defect_key=f"lsan:{key}", note=_detail)
        except Exception:
            observe.absorbed(_log, "continuing")
    if found:
        ctx.emit("lsan.done", payload={"memory_leaks": found})
    return found


def tsan_detonate(ctx, target, inputs, mode, exec_timeout, base_argv=()) -> int:
    """Detonate a set of inputs against the target's ThreadSanitizer build (built at ingest for
    source targets) to surface data races (CWE-362) -- the concurrency class no other sanitizer
    sees. A race only manifests when the input drives the threaded path, and it does not crash the
    ASan build, so it must be driven with the fuzz CORPUS. Findings land 'corroborated' (TSan
    directly observed the race) with the source line. Fully guarded -- it must never break a
    campaign. Shares the containment and cost bounds of msan_detonate."""
    import os as _os

    from ...db.dao import ArtifactDAO
    from ..debug.rootcause import parse_asan_report
    try:
        arts = ArtifactDAO(ctx.conn).list_by_case(target.case_id)
        tsa = next((a for a in arts if a.kind == "tsan-blob"
                    and (a.meta or {}).get("binary_sha") == target.sha256), None)
        if not tsa:
            return 0
        tsbin = ctx.scratch() / "target.tsan"
        tsbin.write_bytes(ctx.content.path(tsa.sha256).read_bytes())
        _os.chmod(tsbin, 0o755)
    except Exception:
        observe.absorbed(_log, "answering a default")
        return 0
    env = dict(_os.environ)
    # halt on the first race; no symbolizer (it deadlocks on a captured-pipe stderr, as with MSan)
    env["TSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=0:exitcode=86:symbolize=0:history_size=4"
    exedir = str(tsbin.parent)
    prefix = sandbox.isolate_prefix(exedir, net=False)
    per_timeout = max(2, int(exec_timeout))
    deadline = time.monotonic() + max(15.0, min(90.0, per_timeout * 30))
    _cancel = getattr(ctx, "should_cancel", None)
    fd = FindingDAO(ctx.conn)
    wf = ctx.scratch() / "tsan-in.bin"
    found, seen = 0, set()
    for data in list(inputs)[:400]:
        if time.monotonic() > deadline or (_cancel is not None and _cancel()):
            break
        data = data or b""
        tail, stdin = invocation(mode, wf, data, base_argv)
        try:
            r = sandbox.run_reaped(prefix + [str(tsbin)] + tail, input=stdin, timeout=per_timeout,
                                   capture_output=True, env=env)
        except Exception:
            observe.absorbed(_log, "skipping this item")
            continue
        txt = (r.stderr or b"").decode("latin-1", "ignore")
        if "ThreadSanitizer: data race" not in txt and "ThreadSanitizer: lock-order" not in txt:
            continue
        rep = parse_asan_report(txt) or {}
        src = _msan_source_line(tsbin, txt) or rep.get("source")
        _raw = re.search(r"\(\S+\+0x[0-9a-fA-F]+\)", txt)
        key = src or (_raw.group(0) if _raw else
                      hashlib.sha1(txt[:256].encode("latin-1", "ignore")).hexdigest()[:12])
        if key in seen:
            continue
        seen.add(key)
        try:
            sha = ctx.put_artifact("tsan-input", data=data)
            cwe = rep.get("cwe", "CWE-362")
            fd.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": "Data race" if cwe == "CWE-362" else "Concurrency defect",
                "severity": "high", "detector": "tsan", "state": "corroborated", "confidence": 0.8,
                "dedup_key": f"{cwe}:tsan:{key}", "function_addr": None, "site_addr": None,
                "site_detail": src,
                "evidence": [{"channel": "sanitizer",
                              "detail": (rep.get("detail") or "ThreadSanitizer: data race")
                              + (f" at {src}" if src else "") + f" (input {sha[:12]})"}]})
            found += 1
        except Exception:
            observe.absorbed(_log, "skipping this item")
            continue
        # RECORD IT AS A RUN, or the ladder cannot see it. The prove loop iterates the
        # dyn_result table; this stage filed only a Finding, so a real data race reached the
        # report as `corroborated` and NOTHING downstream ever touched it -- no PoC, no
        # reproduction rate, no looping reproducer, and the conformance gate's data-race case
        # failed with the class found and nothing demonstrated **[measured]**. The libFuzzer
        # stage had exactly this defect and the comment there says the same thing. The isolation
        # tag names the TSAN build so `build_poc` replays against IT and not against the
        # ASan/plain binary, which cannot report a race at all.
        #
        # Separately from the finding, and after the count, for two reasons learned by breaking
        # it: this helper is called with a test double that has no `run_id`, and the enclosing
        # `except: continue` swallowed the AttributeError and discarded a race it had already
        # filed. A defect in the bookkeeping must not be able to retract a finding.
        try:
            DynResultDAO(ctx.conn).insert(
                target.id, target.case_id, run_id=getattr(ctx, "run_id", None), input_sha=sha,
                input_mode=mode, argv=list(tail), crashed=True,
                signal_name=rep.get("class") or "data-race",
                isolation="tsan", defect_key=f"tsan:{key}",
                note=(rep.get("detail") or "ThreadSanitizer: data race")
                     + (f" at {src}" if src else ""))
        except Exception:
            try:
                ctx.emit("tsan.norun", payload={
                    "note": "the race was filed as a finding but NOT recorded as a run, so the "
                            "PoC ladder cannot reach it", "key": str(key)[:80]})
            except Exception:
                observe.absorbed(_log, "continuing")
    if found:
        ctx.emit("tsan.done", payload={"data_races": found})
    return found


def _help_text(exe, target, exec_timeout):
    """Run the target's own help to mine its option table. Modern GNU tools print a terse
    `Usage: ... [options]` in .rodata and keep the real flags in --help, so string-scraping finds
    nothing; `objdump`, `xmllint`, `exiv2`, `tiffcp` all return zero flags without this. Tries the
    usual help triggers, under the sandbox + a tight timeout, and returns the richest output that
    actually looks like an option table (>=2 dash-option lines) OR a subcommand table (>=2 command
    rows), else None.

    The BARE run (no args) is tried too: a dispatch-style tool (mutool, git, busybox) prints its
    command list with no arguments and exits, and that list is what names the subcommand the fuzzer
    must prepend -- without it the campaign runs `tool <input>`, gets usage, and never parses."""
    from ..dynamic import sandbox
    # a command-table row: indented word + a '--'/2-space-gap description (mirrors invocation._SUBCMD_ROW)
    _row = re.compile(r"^[ \t]+[a-z][a-z0-9][a-z0-9_-]{0,18}(?:[ \t]*--|[ \t]{2,}|\t)\s*\S")
    best, best_rows = None, 1
    for argv in ([], ["--help"], ["-h"], ["help"], ["-help"], ["--usage"]):
        try:
            r = sandbox.run(exe, argv=argv, stdin=b"", timeout=max(3.0, exec_timeout * 2),
                            arch=target.arch, endianness=target.endianness, bits=target.bits)
        except Exception:                          # noqa: BLE001 -- help mining is best-effort
            continue
        blob = (getattr(r, "stdout", b"") or b"") + b"\n" + (getattr(r, "stderr", b"") or b"")
        txt = blob.decode("utf-8", "replace")
        lines = txt.splitlines()
        rows = max(sum(1 for ln in lines if ln.lstrip()[:1] == "-"),
                   sum(1 for ln in lines if _row.match(ln.rstrip())))
        if rows > best_rows:
            best, best_rows = txt, rows
    return best


def _multicall_argv(ctx, invmod, help_text, probe, workdir):
    """(argv, note, door) for ONE program inside a multi-call binary, or (None, None, {}).

    `door` carries what the campaign needs downstream: the program's name, the channel the door
    was VERIFIED on (so the input is delivered the way it was shown to be read, rather than the
    way the whole image's imports suggest), and a valid seed if the image can make one.

    The program is chosen from the verified doors, by `params.multicall_door` when the
    orchestrator is taking them one at a time and otherwise the deepest parser available. Both
    the count that was skipped and the doors that verified are emitted, because "we fuzzed
    busybox" and "we fuzzed busybox's unlzma" are different claims and only one of them is
    worth anything.
    """
    if not invmod.is_multicall(help_text):
        # `_help_text` scores candidate outputs by how many option rows they carry and returns
        # None for a program with none -- which is busybox exactly: no `-x` rows, and its 345
        # programs printed as a wrapped comma-separated block. Ask the bare invocation itself,
        # which is what a multi-call binary answers with its own banner. One execution, and only
        # when the scored help text said nothing.
        try:
            r = probe([])
            help_text = ((getattr(r, "stdout", b"") or b"") + b"\n"
                         + (getattr(r, "stderr", b"") or b"")).decode("utf-8", "replace")
        except Exception:                              # noqa: BLE001 -- best-effort probe
            observe.absorbed(_log, "reading the bare invocation's banner")
            return None, None, {}
        if not invmod.is_multicall(help_text):
            return None, None, {}
    listing = None
    flag = invmod.multicall_list_flag(help_text)
    if flag:
        try:
            r = probe([flag])
            listing = (getattr(r, "stdout", b"") or b"").decode("utf-8", "replace")
        except Exception:                              # noqa: BLE001 -- best-effort probe
            observe.absorbed(_log, "reading the multi-call listing")
    names = invmod.multicall_names(help_text, list_output=listing)
    if not names:
        return None, None, {}
    allowed = invmod.rank_multicall(names)
    if not allowed:
        ctx.emit("fuzz.multicall", payload={
            "programs": len(names), "allowed": 0, "doors": [], "note": (
                "this is a multi-call binary, and none of the programs it contains has the "
                "shape of a single-input parser, so none was invoked")})
        return None, None, {}
    sample = workdir / "mc-sample"
    sample.write_bytes(b"# lykos\n")

    def _run(argv, stdin):
        return probe([str(a).replace(invmod.INPUT_PLACEHOLDER, str(sample)) for a in argv], stdin)

    doors = invmod.multicall_doors(_run, allowed, sample=b"")
    if not doors:
        ctx.emit("fuzz.multicall", payload={
            "programs": len(names), "allowed": len(allowed), "doors": [], "note": (
                "this is a multi-call binary, but no contained program accepted an invocation "
                "we could verify, so the campaign was not pointed at one")})
        return None, None, {}
    want = ((ctx.params or {}).get("multicall_door") or "").strip()
    pick = next((d for d in doors if d[0] == want), doors[0])
    # The target makes its own seed. A decompressor rejects random bytes at the header, so a
    # campaign without a valid archive never reaches the decoder -- and the image that holds
    # `unlzma` also holds `lzma`, so the one thing this campaign needs is one execution away.
    seed = invmod.multicall_seed(_run, pick[0])
    ctx.emit("fuzz.multicall", payload={
        "programs": len(names), "allowed": len(allowed),
        "doors": [n for n, _ in doors], "chosen": pick[0],
        "seed_bytes": len(seed), "seed_from": invmod.multicall_inverse(pick[0]),
        "note": (f"multi-call binary: {len(names)} programs, {len(allowed)} with the shape of a "
                 f"single-input parser, {len(doors)} verified by running them. Fuzzing "
                 f"`{' '.join(pick[1])}` -- the image itself only dispatches."
                 + (f" Seeded with {len(seed)} bytes the target's own "
                    f"`{invmod.multicall_inverse(pick[0])}` produced." if seed else ""))})
    return list(pick[1]), (f"multi-call binary: the campaign drives the contained program "
                           f"`{' '.join(pick[1])}`, verified by running it "
                           f"({len(doors)} of {len(names)} programs opened)"), {
        "door": pick[0], "seeds": [seed] if seed else [],
        "verified_on": "file" if invmod.INPUT_PLACEHOLDER in pick[1] else "stdin"}


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
        d = ctx.scratch() / "argvprobe"
        d.mkdir(parents=True, exist_ok=True)
        # A multi-call binary dispatches on argv[0] FIRST: busybox staged as `target.bin`
        # answers `target.bin: applet not found` and exits 1, to every probe and every input.
        # The image states the name it needs in its own usage string, so stage it under that.
        exe = d / (invmod.exec_name_for(data) or "target.bin")
        exe.write_bytes(data)
        exe.chmod(0o755)
        # Mine the option table from the target's OWN --help, so a tool that hides its flags there
        # (objdump/xmllint/exiv2/...) still gets a discovered, verifiable invocation.
        help_text = _help_text(exe, target, exec_timeout)

        def _probe(a, stdin=b""):
            return sandbox.run(exe, argv=[str(x) for x in a], stdin=stdin,
                               timeout=max(4.0, exec_timeout * 2), arch=target.arch,
                               endianness=target.endianness, bits=target.bits)

        # A MULTI-CALL binary is many programs behind one image, and fuzzing the image fuzzes a
        # dispatcher: `busybox` with no function prints its usage and exits, so a campaign
        # against a 1 MB static busybox -- the single most common binary in the firmware this
        # tool carves -- executed the program thousands of times and entered no parser at all.
        # The programs behind the dispatch are where the bugs are: busybox 1.21.1's own CVE
        # list leads with an out-of-bounds read in the unlzma decompressor.
        door_argv, door_note, door = _multicall_argv(ctx, invmod, help_text, _probe, d)
        if door_argv:
            return door_argv, door_note, False, door

        # `prog` anchors usage-line discovery on the program's OWN name: a large daemon embeds
        # hundreds of internal-command usages ("Usage: core show version") that are not how you
        # invoke it, and mixing their flags produced a garbage option set + empty argv -> the
        # daemon was fuzzed with no args and came back static-only.
        found = invmod.discover([x.value for x in _strings_for(ctx, target)], help_text=help_text,
                                prog=getattr(target, "filename", None))
        # Real files behind every value that names one, or the proposal cannot be tested: a
        # service required to be given `-j <app.jar>` refuses the literal string "app.jar",
        # and the run then throws away an invocation that was right apart from a missing file.
        argv = invmod.materialize(found, d)
        if not argv:
            return [], None, False, {}
        sample = d / "sample"
        sample.write_bytes(b"# lykos\n")

        def _run(a):
            return sandbox.run(exe, argv=a, stdin=b"", timeout=max(4.0, exec_timeout * 2),
                               arch=target.arch, endianness=target.endianness,
                               bits=target.bits)
        v = invmod.verify(_run, exe, argv, str(sample))
    except Exception as e:                     # discovery is an optimisation, never a blocker
        return [], f"invocation discovery failed: {e}", False, {}
    if v["accepted"] and v["bare_rejected"]:
        conf = any(f.get("kind") == "config" and not f.get("optional")
                   for f in found["flags"])
        return argv, (f"discovered from the binary's usage line and verified by running it: "
                      f"{' '.join(argv)}"), conf, {}
    if not v["bare_rejected"]:
        return [], ("the target runs with no arguments, so no flags were added "
                    f"(it does document {' '.join(argv)})"), False, {}
    return [], f"proposed {' '.join(argv)} but the target refused it -- {v['why']}", False, {}


def _takes_blocks(run_fn) -> bool:
    """Does this runner accept coverage blocks? Asked of the signature rather than of the
    function's identity, so a runner other than `run_input` -- the channel harness, above all
    -- can be given them without this having to learn its name."""
    try:
        return "blocks" in inspect.signature(run_fn).parameters
    except (TypeError, ValueError):
        return False


def _not_run_reason(isolation, note: str = "") -> str:
    """A human reason a campaign's target never executed, from its not-runnable isolation tag. The
    runner's own `note` (e.g. 'no qemu-user for aarch64 on x86_64') is preferred; otherwise map the
    sentinel isolation to an operator-actionable hint."""
    iso = (isolation or "not-runnable").strip()
    if note and note.strip():
        return f"{iso}: {note.strip()}"
    if iso.startswith("unsupported-arch"):
        return f"{iso}: no qemu-user for the target architecture (bundle/build it for this guest)"
    if iso.endswith("-missing"):
        return f"{iso}: the required runtime is not installed or bundled"
    if iso == "not-runnable" or iso.endswith("/not-runnable"):
        return (f"{iso}: the staged target could not be executed -- a noexec /tmp (set TMPDIR to an "
                "exec-capable path), a missing/incompatible loader, or a guest that could not load")
    return iso


#: Attempts after which a campaign where NONE reached the program stops (an error loop).
_ERROR_LOOP_SAMPLE = 64

#: CONVERGENCE STOP (doc 47 U1). Under run-to-convergence (`params.converge`) the budget is a
#: safety CEILING -- six hours by default -- and the operator's intent is "keep going until it
#: stops finding things". AFL has its own plateau signal (AFL_EXIT_WHEN_DONE); the blind and
#: directed campaigns had none, so they burned the whole ceiling long after coverage stopped
#: moving. A campaign has CONVERGED when nothing new -- no coverage unit (blocks when the coverage
#: channel answers, behaviours otherwise: the same novelty that drives the corpus), no closer
#: approach to a directed sink, no new crash bucket, no hang -- has been found for a window that
#: scales with the run: at least `_PLATEAU_MIN_EXECS` executions AND `_PLATEAU_MIN_S` seconds,
#: and at least `_PLATEAU_FRAC` of everything the campaign has done so far in BOTH. So the idle
#: tail must be as long as the productive head: a campaign whose last find was at 40 minutes
#: runs to at least 80. Only after seed calibration (verbatim seeds are not search), and only
#: under `converge`: a time-boxed run keeps its slice, because there the operator asked for it.
_PLATEAU_MIN_EXECS = 1000
_PLATEAU_MIN_S = 60.0
_PLATEAU_FRAC = 0.5

#: STALL AUTO-SKIP. A campaign whose executions have stopped COMPLETING -- every one runs into the
#: per-execution limit, reaches nothing new and crashes nothing -- is a wedged target (it waits on
#: a peer or a prompt it never gets, or every input now hangs), and the rest of its slice would buy
#: more of the same. It ends itself with `stalled` after a grace window of at least
#: `_STALL_MIN_ATTEMPTS` consecutive such executions AND `_stall_grace_s` seconds of them. ANY
#: execution that completes (exits, faults), any new coverage or behaviour, and any crash resets the
#: window, so a slow-but-progressing target -- one that takes 1.9 s of a 2 s limit, or one whose
#: timeouts still reach new blocks -- never trips it. Off for a target whose BASELINE never
#: terminates (a server/menu loop the orchestrator already runs under a short per-exec timeout): a
#: timeout is how every execution of it ends, not a sign it is wedged.
_STALL_MIN_ATTEMPTS = 32
_STALL_MIN_S = 30.0
_STALL_TIMEOUT_MULT = 15         # ... and at least this many per-execution timeouts' worth
_STALL_SHARE = 0.05              # ... and this share of the campaign's slice,
_STALL_SHARE_CAP_S = 300.0       # ... capped, so a 6-hour ceiling waits 5 minutes, not 18
#: Batch size after a batch that mostly timed out (see the loop): small enough that neither the
#: deadline nor the stall check waits on 64 back-to-back timeouts.
_TIMEOUT_BATCH = 8


def _plateau_window(execs: int, elapsed: float) -> tuple:
    """(idle executions, idle seconds) the campaign must go without a find to have converged."""
    return (max(_PLATEAU_MIN_EXECS, int(_PLATEAU_FRAC * max(0, execs))),
            max(_PLATEAU_MIN_S, _PLATEAU_FRAC * max(0.0, elapsed)))


def _plateaued(execs: int, elapsed: float, gain_exec: int, gain_s: float) -> bool:
    """Has the campaign found nothing new since (`gain_exec`, `gain_s`) for long enough?"""
    need_e, need_s = _plateau_window(execs, elapsed)
    return (execs - gain_exec) >= need_e and (elapsed - gain_s) >= need_s


def _stall_grace_s(exec_timeout: float, max_seconds: float) -> float:
    return max(_STALL_MIN_S, _STALL_TIMEOUT_MULT * float(exec_timeout or 0),
               min(_STALL_SHARE_CAP_S, _STALL_SHARE * float(max_seconds or 0)))


def _stalled(streak: int, streak_s: float, exec_timeout: float, max_seconds: float) -> bool:
    """`streak` consecutive executions, spanning `streak_s` seconds, that all timed out with
    nothing new reached and nothing crashed: past the grace window?"""
    return (streak >= _STALL_MIN_ATTEMPTS
            and streak_s >= _stall_grace_s(exec_timeout, max_seconds))


def _baseline_nonterm(conn, target_id) -> bool:
    """Did the target's own baseline execution (no fuzz input) fail to terminate? The same test
    the orchestrator uses to shorten the per-exec timeout for such a target."""
    try:
        rows = DynResultDAO(conn).list_by_target(target_id)
    except Exception:                                    # noqa: BLE001 -- advisory
        return False
    base = [r for r in rows if (r.input_mode or "none") == "none"]
    return bool(base) and all(getattr(r, "timed_out", False) for r in base)


def hang_input_shas(conn, target_id) -> set:
    """Every recorded input of this target that is KNOWN to hang it: a dyn_result row that timed
    out (any stage, and libFuzzer's `timeout` artifacts, recorded before `timed_out` was set on
    them, by their signal name), plus the input of every non-termination finding (CWE-835 /
    CWE-400 hang evidence), which `_file_hang` deliberately records WITHOUT a dyn_result row.

    Stages that seed or probe themselves from recorded inputs (concolic's `_gather_seeds`,
    mem_oracle's `_probe_inputs`) skip these: a hang input costs each of them a full timeout per
    replay, and buys nothing a terminating input would not."""
    out: set = set()
    try:
        for d in DynResultDAO(conn).list_by_target(target_id):
            if d.input_sha and not d.crashed and (
                    getattr(d, "timed_out", False)
                    or (d.signal_name or "").lower() in ("timeout", "hang")):
                out.add(d.input_sha)
    except Exception:                                    # noqa: BLE001 -- advisory filter
        observe.absorbed(_log, "no dyn_result hang filter")
    try:
        for f in FindingDAO(conn).list_by_target(target_id):
            dk = f.dedup_key or ""
            if f.cwe != "CWE-835" and ":hang:" not in dk and ":timeout" not in dk:
                continue
            for ev in (f.evidence or []):
                sha = ev.get("input_sha") if isinstance(ev, dict) else None
                if sha:
                    out.add(sha)
    except Exception:                                    # noqa: BLE001 -- advisory filter
        observe.absorbed(_log, "no finding hang filter")
    return out


def replayable_input_shas(conn, target_id, limit: int) -> list:
    """Distinct recorded inputs of this target, newest first, with every known HANG input left
    out (see `hang_input_shas`), up to `limit`. Returns (shas, skipped_hangs)."""
    hangs = hang_input_shas(conn, target_id)
    seen, out, skipped = set(), [], 0
    try:
        rows = DynResultDAO(conn).list_by_target(target_id)
    except Exception:                                    # noqa: BLE001
        rows = []
    for d in rows:
        s = d.input_sha
        if not s or s in seen:
            continue
        seen.add(s)
        if s in hangs:
            skipped += 1
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out, skipped

#: HANG / DoS CAPTURE (doc 47 P7). An input on which the target never terminates is a finding in
#: its own right -- an availability defect (CWE-835 infinite loop / CWE-400 unbounded consumption)
#: -- and it used to be discarded as just another timed-out execution. Filing one is held to the
#: same precision bar as a crash, by DIFFERENTIAL evidence rather than a single timeout:
#:   * the target must be one that normally terminates: some input in this campaign ran to a clean
#:     exit, and hangs are a small minority of executions (a server or menu loop that blocks on
#:     EVERY input is not hanging on any one of them -- `_HANG_RATE_MAX`);
#:   * the hanging input is re-run ALONE under a timeout at least twice the campaign's and must
#:     time out again, while the benign control re-run under the same long timeout must exit;
#:   * only the plain runner (stdin/file/arg/env); a harness runner's hang may be the harness.
#: Filed `corroborated` (as libFuzzer's own timeout artifacts are): a reproduced non-termination
#: is not a crash, and there is no fault for the PoC ladder to chase (no crash row is written).
_HANG_MIN_EXECS = 20             # enough executions to know the target normally terminates
_HANG_RATE_MAX = 0.05            # hangs above this share are the target's normal behaviour
_HANG_TIMEOUT_MIN = 4.0          # the re-verification timeout floor (seconds)
_HANG_TIMEOUT_MAX = 30.0         # ... and ceiling, so one check cannot eat a campaign
_HANG_MAX_CHECKS = 2             # re-verifications per campaign (each costs one long timeout)
_HANG_CANDIDATES = 4             # timed-out inputs remembered as candidates


def _hang_timeout(exec_timeout: float) -> float:
    """The re-verification timeout: at least 2x the campaign's own, within the floor/ceiling."""
    return min(_HANG_TIMEOUT_MAX, max(2.0 * float(exec_timeout or 0), _HANG_TIMEOUT_MIN))


def _hang_eligible(execs: int, timeouts: int, have_control: bool) -> bool:
    """Is this campaign one whose timeouts can mean anything? See the block above."""
    return (have_control and execs >= _HANG_MIN_EXECS and timeouts > 0
            and timeouts <= _HANG_RATE_MAX * execs)


def _verify_hang(exe, mode, workfile, exec_timeout, target, cand, control, alog=None):
    """Re-run `cand` and the benign `control` under the long timeout. Returns
    (hang_result, control_result) when the differential holds, else None."""
    t = _hang_timeout(exec_timeout)
    kw = {"endianness": target.endianness, "bits": target.bits}
    c_data, c_prefix, c_guard = control
    h_data, h_prefix, h_guard = cand
    try:
        _a, c = run_input(exe, mode, workfile, t, target.arch, c_data, base_argv=c_prefix,
                          guard_page=c_guard, **kw)
        if alog is not None:
            alog.record_result(c_data, c, phase="confirm", argv=c_prefix)
        if c.timed_out or c.crashed or sandbox.did_not_run(c.isolation):
            return None                              # the control did not exit: no differential
        _a, h = run_input(exe, mode, workfile, t, target.arch, h_data, base_argv=h_prefix,
                          guard_page=h_guard, **kw)
        if alog is not None:
            alog.record_result(h_data, h, phase="confirm", argv=h_prefix)
    except Exception:                                # noqa: BLE001 -- a check, never a finding
        observe.absorbed(_log, "hang not re-verified")
        return None
    if not h.timed_out or h.crashed or sandbox.did_not_run(h.isolation):
        return None
    return h, c


def _file_hang(ctx, target, fd, *, mode, data, prefix, hang, control, exec_timeout,
               detector, event_prefix, control_data: Optional[bytes] = None) -> str:
    """Record a re-verified hang as a CWE-835 finding carrying its input artifact.

    Deliberately NO dyn_result row: several stages seed themselves from every recorded input
    (concolic's `_gather_seeds`, mem_oracle's probes), and a hang input there costs each of them
    a full timeout per replay. The finding's evidence names the input, channel and argv prefix,
    which is everything a replay needs."""
    t = _hang_timeout(exec_timeout)
    input_sha = ctx.put_artifact("fuzz-hang-input", data=data)
    # The benign CONTROL that exited under the same long limit: the other half of the
    # differential, stored so poc/dos.hang_poc re-verifies against the SAME control rather than a
    # guessed b"" / b"\n" the target might itself hang on.
    control_sha = None
    if control_data is not None:
        try:
            control_sha = ctx.put_artifact("fuzz-hang-control", data=bytes(control_data))
        except Exception:                                # noqa: BLE001 -- evidence still filed
            observe.absorbed(_log, "hang control not stored")
    detail = (f"input {input_sha[:12]} ({len(data)}B via {mode}) did not terminate within "
              f"{exec_timeout:g}s in the campaign and again within {t:g}s when re-run alone, "
              f"while a benign input exited in {control.duration_ms} ms under the same "
              f"{t:g}s limit -- an input-dependent non-termination (infinite loop or unbounded "
              f"resource consumption)")
    fd.upsert(target.id, target.case_id, {
        "cwe": "CWE-835", "title": "Input that does not terminate (denial of service)",
        "severity": "medium", "detector": detector, "state": "corroborated",
        "confidence": 0.75, "dedup_key": f"CWE-835:hang:{mode}",
        "function_addr": None, "site_addr": None,
        "evidence": [{"channel": "dynamic", "detail": detail,
                      "input_sha": input_sha, "input_mode": mode, "argv": list(prefix),
                      "control_sha": control_sha, "isolation": hang.isolation}]})
    ctx.emit(f"{event_prefix}.hang", payload={"input_sha": input_sha, "mode": mode,
                                              "argv": list(prefix), "timeout": t,
                                              "control_ms": control.duration_ms})
    return input_sha


#: The campaign's event prefix -> the autopilot stage (engine) it runs as.
_ENGINE_OF_PREFIX = {"fuzz": "fuzz", "directed": "directed_fuzz", "harness": "boundary_fuzz"}


def fuzz_campaign(ctx, target, *, corpus, dictionary, mode, max_execs, max_seconds,
                  exec_timeout, rng, detector, event_prefix, note_prefix, run_fn=run_input,
                  mutator=None, cover_blocks=(), cover_flags=(), base_argv=(), block_dist=None,
                  exe_name: str = ""):
    """Shared mutational campaign: mutate -> sandbox -> dedup-by-signal -> minimize ->
    dyn_result + Confirmed finding. Used by both the black-box `fuzz` stage and the directed
    stage (which supplies a corpus/dictionary aimed at specific sinks). Returns stats.

    `run_fn(exe, mode, workfile, timeout, arch, data) -> (argv, RunResult)` is the input
    delivery; boundary-driven harnessing (doc 17.4) swaps in a channel runner."""
    # `exe_name` is for an image that dispatches on its OWN filename (busybox and every other
    # multi-call binary): staged as `target.bin` it refuses every input with "applet not found",
    # so the campaign would execute thousands of times and enter nothing.
    exe = ctx.scratch() / (exe_name or "target.bin")
    ctx.content.stage_target(target, exe.parent, exe.name)
    os.chmod(exe, 0o755)

    # A shared object has no entry point: run()/run_batch both refuse it (every execution comes
    # back "not-runnable"), so the loop below would spin its whole budget on no-op executions and
    # enter nothing. Worse, on rare harness hiccups one of those no-ops has surfaced as a fault
    # that `root_cause` promoted to a CONFIRMED critical control-flow hijack -- a fabricated RCE on
    # an image that never ran as a program (observed on libfreerdp3.so: baseline DID NOT RUN, the
    # "crash" did not re-verify, yet it was filed critical). A library is fuzzed through a harness
    # (the libFuzzer path), not by executing it, so refuse the campaign here rather than record
    # anything from it. Mirrors `sandbox._is_elf_shared_object`; see its callers in sandbox.run.
    from ..dynamic import sandbox as _sandbox
    if _sandbox._is_elf_shared_object(exe):
        ctx.progress(pct=100, msg=(f"{event_prefix}: an ELF shared object has no entry point -- "
                                   "not executed as a program (fuzz it through a harness)"))
        ctx.emit(f"{event_prefix}.done", payload={"execs": 0, "crashes": 0,
                 "note": "shared object: no entry point, not executed as a program"})
        return {"execs": 0, "crashes": 0, "flaky": 0, "crashes_reproducible": 0, "unique": 0,
                "starved": False, "directed_kept": 0, "nearest_sink_dist": None,
                "behaviours": 0, "corpus": 0, "kept": 0, "execs_per_sec": 0,
                "blocks_hit": 0, "blocks_known": 0, "coverage": "none"}

    # THE GUARD-PAGE HEAP ORACLE, on wherever it can apply. libdislocator puts every allocation
    # at the end of its own page with an unmapped page behind it, so a heap out-of-bounds READ --
    # the class that otherwise runs on silently, and the class most of a stripped binary's CVEs
    # are -- faults where the fuzzer can see it. The sandbox decides applicability (host-arch
    # ELF, never a sanitizer build, library present) and records in the isolation tag whether it
    # applied, which is what lets the crash be replayed the same way later. It is threaded to
    # EVERY execution point below, including minimization and the crash re-runs: a crash found
    # guarded and re-run unguarded does not reproduce, and would be dropped as a false positive.
    guard = bool((ctx.params or {}).get("guard_page", True))
    corpus = list(corpus) or list(_DEFAULT_SEEDS)
    # Give the delivered input file the EXTENSION its format implies (voted from the corpus): a
    # parser that selects its handler by extension (mutool, ImageMagick, ...) rejects an
    # extensionless file outright, so every mutation would bounce off the front door and the
    # campaign would never enter the parser.
    from . import aflpp
    _suffix = aflpp.input_suffix(corpus) if mode == "file" else ""
    workfile = ctx.scratch() / f"input{_suffix or '.bin'}"
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
            # Does this target ALLOCATE? It decides whether an index-only option may be tried as
            # the creator (`new(slot)` for a fixed-size record asks for no size, so the model
            # cannot name it), and the import table is the evidence -- the same test the heap
            # chain's own gate uses. Without it, a notebook whose menu is
            # `1.add(idx) 2.edit(idx,len,data) 3.show(idx) 4.free(idx)` had every seed begin by
            # editing an object that had never been created: 6,736 executions, zero crashes, on
            # a target whose overflow is three operations deep **[measured]**.
            _alloc_seen = False
            try:
                from ..poc import rop as _rop
                _got = _rop.got_entries(exe.read_bytes())
                _alloc_seen = any(n in _got for n in ("malloc", "calloc", "realloc",
                                                      "_Znwm", "_Znam"))
            except Exception:                            # noqa: BLE001 -- evidence, not a gate
                observe.absorbed(_log, "assuming no allocator")
            op_seeds = [s for s in _menu.menu_op_sequences(model, opts, width=mwidth,
                                                           allocates=_alloc_seen) if s]
            if op_seeds:
                corpus = list(corpus) + op_seeds
                ctx.progress(msg=f"{event_prefix} learned {len(op_seeds)} menu-op seeds")
            if mutator is None:                        # don't override an explicit format mutator
                mutator = _menu.MenuMutator(rng, model, opts, width=mwidth, dictionary=dictionary)
                ctx.emit("fuzz.format", payload={"model": "menu", "auto": True,
                         "options": opts, "why": "the target drives a numbered menu; navigating it"})
    except Exception:
        observe.absorbed(_log, "continuing")
    # A WORD-command service -- `strncmp(cmd, "free", 4)` -- is a state machine like a numbered menu
    # but keyed on verbs the menu path cannot see. When no menu (and no explicit format model) fired,
    # mine the verbs (comparison literals, often too short for the string table) and seed ordered
    # command sequences: a use-after-free is `free` then `use`, a double-free is `free` twice --
    # neither reachable by a mutator that has to invent BOTH words and order them across lines.
    if mutator is None:
        try:
            from . import command as _cmd
            verbs = _cmd.mine_verbs(ctx.content.path(target.sha256).read_bytes())
            cseeds = [s for s in _cmd.command_seeds(verbs) if s]
            if cseeds:
                corpus = list(corpus) + cseeds
                mutator = _cmd.CommandMutator(rng, verbs, dictionary)
                ctx.progress(msg=f"{event_prefix} learned {len(cseeds)} command seeds")
                ctx.emit("fuzz.format", payload={"model": "command", "auto": True,
                         "verbs": verbs[:16], "why": "the target dispatches on text commands"})
        except Exception:
            observe.absorbed(_log, "continuing")
    mut = mutator or Mutator(rng, dictionary)          # menu / structure-aware mutator when supplied
    fd = FindingDAO(ctx.conn)
    dd = DynResultDAO(ctx.conn)
    deadline = time.time() + max_seconds
    execs = crashes = crashes_reproducible = 0
    seen_sigs: dict = {}
    code_span = recovered_code_span(ctx.conn, target.id)   # classify an out-of-code (hijack) PC
    seen_behaviour, kept = set(), 0
    # Did the target EVER actually execute? A definitive not-runnable isolation (noexec staging /
    # EACCES, unsupported arch, a qemu guest that could not load, a missing runtime) means every
    # "execution" was a no-op. After the first batch we check this and, if nothing ran, record ONE
    # did-not-run row so the report says WHY instead of reading as a clean empty campaign -- then
    # stop rather than spin the whole budget on executions that cannot run.
    ran_any = False
    first_notrun_iso = None
    first_notrun_note = ""
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
    # One line per attempt (see fuzz/attempts.py): the only way to tell a campaign that tested
    # 20,000 inputs from one that tried 20,000 times and never started the program.
    from . import attempts as _attempts
    alog = _attempts.AttemptLog(
        ctx, _ENGINE_OF_PREFIX.get(event_prefix, event_prefix), event_prefix,
        unit=("blocks" if all_blocks else "behaviours"), target_id=target.id)
    # Corpus distillation: before spending the budget, drop seeds whose block coverage another seed
    # already covers, so the campaign starts from a small high-coverage minset instead of re-running
    # near-duplicate accumulated inputs (ISSTA'21: minset quality dominates fuzzer choice). Crashers
    # are always kept. Gated on a corpus worth minimising, block coverage to measure with, and the
    # batched runner (the only one that reports per-input blocks). Never fatal -- it is an optimiser.
    if all_blocks and len(corpus) > _DISTILL_MIN and runner_takes_blocks:
        try:
            from . import distill as _distill
            # Bounded by TIME as well as by count. Distillation is an optimiser for the
            # campaign, so spending more than a fraction of the campaign's own slice on it is
            # self-defeating: on zlib's ASan `example` it took 150s of a 12-34s slice and the
            # campaign it was preparing then executed the target ZERO times. `cap` could not
            # prevent that -- a count bound is not a time bound when one item costs a second.
            _dl = time.time() + max(_DISTILL_FLOOR_S, max_seconds * _DISTILL_SHARE)
            # Forced-keep the VALUE seeds -- see `value_seeds_for`. Without this the distiller
            # drops a boundary seed because another input covers the same blocks, and a
            # value-driven defect (a length field, a wrap threshold, an index) is invisible to
            # block coverage by construction.
            _vs = value_seeds_for(ctx, target)
            _keep = {i for i, d in enumerate(corpus) if bytes(d) in _vs} if _vs else set()
            _d = _distill.distill_corpus(exe, corpus, all_blocks, mode=mode, base_argv=base_argv,
                                         timeout=exec_timeout, arch=target.arch,
                                         endianness=getattr(target, "endianness", None),
                                         bits=getattr(target, "bits", None), cap=_DISTILL_CAP,
                                         deadline=_dl, keep_idx=_keep)
            if _d["dropped"] > 0:
                corpus = _d["kept"]
                _d["stats"]["value_seeds_kept"] = len(_keep)
                ctx.emit(f"{event_prefix}.distill", payload=_d["stats"])
                ctx.progress(msg=f"{event_prefix} distilled corpus "
                                 f"{_d['stats']['in']} -> {_d['stats']['out']} seeds")
        except Exception:
            observe.absorbed(_log, "continuing")
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
    # Seed calibration: run every starting seed ONCE, verbatim, before any mutation. A seed that
    # already crashes then surfaces in the first handful of executions instead of waiting on a
    # mutation to rediscover it -- and a mutation usually destroys the very value that crashes.
    # This is what makes a seeded bug deterministic under a starved budget: a JVM/PE campaign
    # under CPU contention completes a few dozen executions, not thousands, and an unchecked
    # array index behind `slot=0` (CWE-129) has to be HIT, not stumbled upon. AFL calibrates
    # every seed for the same reason. Verbatim, so the seed's own bytes reach the parser; the
    # boundary-value configs the JVM path puts first in the corpus are exactly the payloads this
    # detonates first. Bounded so a large distilled corpus cannot eat the whole budget on replay.
    # EVERY SEED UNDER BOTH ORACLES, because they catch different overflows and each HIDES the
    # other's. The guard page makes a heap over-READ fault where the fuzzer can see it; it also
    # suppresses an overflow the KERNEL performs -- `read(fd, buf, n)` into a buffer at the end
    # of its page returns EFAULT instead of faulting, the copy never lands, and the program runs
    # on. Measured on the heap-notebook fixture: the sequence that overwrites an object's
    # callback and calls it is SIGSEGV plain and exit 0 under libdislocator, so a campaign that
    # ran every execution guarded reported 5,810 executions and zero crashes on a target that
    # crashes on its own seed. Only the seeds are doubled (a few dozen executions): the
    # mutation phase keeps the stage's chosen oracle.
    # Hang capture (see `_HANG_MIN_EXECS`): a benign control, the first few timed-out inputs.
    hang_control = None
    hang_cands: list = []
    hang_timeouts = 0
    hang_checks = 0
    hang_sha = None
    _seeds = list(corpus)[:_CALIBRATE_CAP]
    replay: list = [(s, guard) for s in _seeds] + [(s, not guard) for s in _seeds]
    # Convergence + stall monitors (see `_PLATEAU_*` / `_STALL_*`). `stopped` is why the loop
    # ended early, when it did: "converged" or "stalled" -- either way the unused slice goes back
    # to the case budget (it is wall-clock), and the stage's other channels.
    _p = ctx.params or {}
    converge = bool(_p.get("converge"))
    stall_check = bool(_p.get("stall_check", True))
    if stall_check and _baseline_nonterm(ctx.conn, target.id):
        stall_check = False
        ctx.emit(f"{event_prefix}.stall_check", payload={"enabled": False, "why": (
            "the target's baseline never terminates, so a timeout is how its executions normally "
            "end -- a run of them is not a wedged target")})
    t_start = time.time()
    stopped, stop_note, stop_payload = None, None, None
    gain_exec, gain_t = 0, 0.0                   # last find: executions / seconds into the campaign
    plateau_armed = False                        # set once seed calibration has finished
    stall_streak, stall_s = 0, 0.0               # consecutive timed-out, gainless executions
    last_batch_n, last_batch_timeouts = 0, 0     # the previous batch's size and its timeouts
    ctx.progress(msg=f"{event_prefix} campaign")
    last_emit = time.time()                      # live-console heartbeat, independent of exec count
    while execs < max_execs and time.time() < deadline and not ctx.should_cancel():
        calibrating = bool(replay)
        if not calibrating and not plateau_armed:
            # The idle clock starts when the SEARCH starts: calibration replays the seeds
            # verbatim, and a seed that adds nothing is not a mutation that failed to.
            plateau_armed = True
            gain_exec, gain_t = max(gain_exec, execs), max(gain_t, time.time() - t_start)
        guard_eff = guard
        prefix: list = []
        base_ms = sorted(cheap_ms)[len(cheap_ms) // 2]
        if batchable and flags and not calibrating:
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
        if batchable and last_batch_timeouts * 2 >= max(1, last_batch_n):
            # The last batch was mostly TIMEOUTS: each input now costs the full per-exec limit,
            # so a 64-input batch is 64 x exec_timeout (128 s at 2 s) that neither the deadline
            # nor the stall check can interrupt. Batching only amortises the namespace setup,
            # which is noise next to a timeout -- so shrink the batch to what the slice has left.
            _fit = int(max(0.0, deadline - time.time()) / max(1e-3, float(exec_timeout or 0)))
            want = max(1, min(want, _TIMEOUT_BATCH, _fit))
        if calibrating:
            # Verbatim seeds first, in corpus order (boundary-value configs lead), up to the
            # batch size -- never mutated, so a seed that crashes is caught as itself.
            # One oracle per batch: `run_batch` preloads (or does not) for the whole batch, so
            # the queue is consumed in runs of the same flag.
            guard_eff = replay[0][1]
            take = 0
            cap = min(len(replay), max(1, want))
            while take < cap and replay[take][1] == guard_eff:
                take += 1
            inputs = [d for d, _g in replay[:take]]
            del replay[:take]
        else:
            inputs = [mut.mutate(rng.choice(corpus), corpus) for _ in range(max(1, want))]
        results = None
        if batchable:
            # Only ever arm blocks we have not reached: the breakpoints are one-shot, so
            # the cost decays as coverage saturates instead of being paid in full forever.
            arm = sorted(all_blocks - seen_blocks) if all_blocks else ()
            t_batch = time.time()
            results = sandbox.run_batch(exe, inputs, mode=mode, timeout=exec_timeout,
                                        arch=target.arch, endianness=target.endianness,
                                        bits=target.bits, blocks=arm, base_argv=run_argv,
                                        guard_page=guard_eff)
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
                kw["guard_page"] = guard_eff
            # Only ever arm blocks we have not reached: the breakpoints are one-shot. Asked by
            # SIGNATURE rather than by identity, because the channel runner takes them too --
            # gated on `run_fn is run_input`, a network campaign could not be given coverage at
            # all, and every payload was judged on output shape alone.
            if all_blocks and runner_takes_blocks:
                kw["blocks"] = tuple(all_blocks - seen_blocks)
            results = [run_fn(exe, mode, workfile, exec_timeout, target.arch, inputs[0],
                              **kw)[1]]
        last_batch_n = len(results)
        last_batch_timeouts = sum(1 for r in results if r.timed_out and not r.crashed)
        for data, res in zip(inputs, results):
            # What gets RECORDED is the flag prefix, not the invocation: the workfile path
            # is scratch and means nothing to a later replay. A crash found under an option
            # only reproduces WITH that option -- jhead's `-cmd` runs a command built from the
            # input -- so the prefix travels with the input it crashed.
            argv = list(run_argv)
            execs += 1
            # Did this execution actually run the program? A definitive not-runnable isolation means
            # it did not (see the did-not-run bail after this batch).
            if not ran_any:
                if sandbox.did_not_run(res.isolation):
                    first_notrun_iso = first_notrun_iso or res.isolation
                    first_notrun_note = first_notrun_note or (res.note or "")
                else:
                    ran_any = True
            if run_fn is run_input and not sandbox.did_not_run(res.isolation):
                if res.timed_out and not res.crashed:
                    hang_timeouts += 1
                    if hang_sha is None and len(hang_cands) < _HANG_CANDIDATES:
                        hang_cands.append((data, list(run_argv), guard_eff))
                elif hang_control is None and not res.crashed and not res.timed_out:
                    hang_control = (data, list(run_argv), guard_eff)
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
            new_behaviour = b not in seen_behaviour
            if new_behaviour:
                seen_behaviour.add(b)
            kept_this = False
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
                    kept_this = True
                    if closer and not novel:
                        directed_kept += 1
            if all_blocks and cover_reported:
                alog.set_unit("blocks")
                _new_units = len(new_blocks)
            else:
                alog.set_unit("behaviours")
                _new_units = 1 if new_behaviour else 0
            alog.record_result(data, res, phase=("seed" if calibrating else "mutate"),
                               argv=prefix, new=_new_units, kept=kept_this)
            if novel or closer:
                gain_exec, gain_t = execs, time.time() - t_start
            # Stall window: only a timed-out execution that reached nothing new extends it;
            # anything that completed, crashed, or found something resets it.
            if (res.timed_out and not res.crashed and not (novel or closer)
                    and not sandbox.did_not_run(res.isolation)):
                stall_streak += 1
                stall_s += (res.duration_ms / 1000.0 if res.duration_ms
                            else float(exec_timeout or 0))
            else:
                stall_streak, stall_s = 0, 0.0
            if res.crashed:
                crashes += 1
                # A crash that does not happen again is not a finding. Some targets REWRITE
                # their input: jhead's `-dc` and `-zt` edit the file in place, so it faulted on
                # bytes it had produced itself and the input we hold is the original, which
                # runs clean. Filing those left every downstream stage chasing a crash that
                # cannot be reproduced, and the release gate failing with "PoC not reproduced".
                if not _reproduces(run_fn, exe, mode, workfile, exec_timeout,
                                   target, data, run_argv, guard_page=guard_eff, alog=alog):
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
                    gain_exec, gain_t = execs, time.time() - t_start   # a new defect is a find

                    def _same(d, _sig=sig, _prefix=run_argv, _guard=guard_eff):
                        # Minimize under the SAME invocation the crash was found and confirmed
                        # with: a crash behind an option (jhead's `-cmd`) does not reproduce
                        # without it, so a flag-less predicate would be false from the first
                        # call and either minimize nothing or reduce to a non-crashing input.
                        kw = {"endianness": target.endianness, "bits": target.bits}
                        if run_fn is run_input:
                            kw["base_argv"] = _prefix
                            kw["guard_page"] = _guard
                        r = run_fn(exe, mode, workfile, exec_timeout, target.arch, d, **kw)[1]
                        alog.record_result(d, r, phase="minimize", argv=_prefix)
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
                        fault_pc=res.fault_pc, discriminator=defect_key, hijack=hj,
                        file_type=target.file_type))
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
        # Re-verify a hang candidate while the slice can still afford the long re-run (two of
        # them: the control and the candidate), never past the campaign's own deadline.
        if (hang_cands and hang_sha is None and hang_checks < _HANG_MAX_CHECKS
                and _hang_eligible(execs, hang_timeouts, hang_control is not None)
                and deadline - time.time() > 2 * _hang_timeout(exec_timeout) + 1.0):
            hang_checks += 1
            _hd, _hp, _hg = hang_cands.pop(0)
            _v = _verify_hang(exe, mode, workfile, exec_timeout, target, (_hd, _hp, _hg),
                              hang_control, alog=alog)
            execs += 2
            if _v is not None:
                try:
                    hang_sha = _file_hang(ctx, target, fd, mode=mode, data=_hd, prefix=_hp,
                                          hang=_v[0], control=_v[1], exec_timeout=exec_timeout,
                                          detector=detector, event_prefix=event_prefix,
                                          control_data=hang_control[0])
                    gain_exec, gain_t = execs, time.time() - t_start
                except Exception:                    # noqa: BLE001 -- never break the campaign
                    observe.absorbed(_log, "hang not filed")
        # An ERROR LOOP: the program "ran" as far as the sandbox is concerned, but the loader refused
        # it every time (missing .so, wrong interpreter -> exit 127). Without this the campaign spent
        # its whole budget re-proving it -- measured: 3,100 attempts across fuzz + directed on one
        # target, every one "error while loading shared libraries". Stop after a fair sample and say
        # why, so the budget goes to the stages that do not need execution.
        _c = alog.tally.counts
        if (alog.tally.total >= _ERROR_LOOP_SAMPLE and not _c["crash"] and not alog.progressed()
                and _c["no_start"] >= 0.95 * alog.tally.total):
            ran_any = False
            first_notrun_iso = "loader-failed"
            first_notrun_note = alog.tally.verdict()[1]
        # The whole first batch executed but NOTHING ran as a program -- record why and stop,
        # instead of spending the budget on no-op executions and reporting a clean empty campaign.
        if not ran_any and execs > 0:
            reason = _not_run_reason(first_notrun_iso, first_notrun_note)
            alog.finish(did_not_run=True)
            dd.insert(target.id, target.case_id, run_id=ctx.run_id, input_mode=mode,
                      crashed=False, isolation=first_notrun_iso or "not-runnable", note=reason)
            ctx.emit(f"{event_prefix}.done", payload={"execs": execs, "crashes": 0,
                     "did_not_run": True, "isolation": first_notrun_iso or "not-runnable",
                     "note": reason})
            ctx.progress(pct=100, msg=f"{event_prefix}: target did not run -- {reason}")
            return {"execs": execs, "crashes": 0, "flaky": 0, "crashes_reproducible": 0,
                    "unique": 0, "starved": True, "directed_kept": 0, "nearest_sink_dist": None,
                    "behaviours": 0, "corpus": len(corpus), "kept": 0, "execs_per_sec": 0,
                    "blocks_hit": 0, "blocks_known": len(all_blocks), "coverage": "none",
                    "did_not_run": True}
        # Stall auto-skip, then the convergence stop (see `_STALL_*` / `_PLATEAU_*`).
        _now = time.time()
        if stall_check and _stalled(stall_streak, stall_s, exec_timeout, max_seconds):
            stopped = "stalled"
            stop_note = (f"the last {stall_streak:,} executions ({stall_s:.0f}s of them) all ran "
                         f"into the {exec_timeout:g}s per-execution limit, reached nothing new "
                         f"and crashed nothing -- the target is wedged (waiting on a peer, a "
                         f"prompt or a channel it never gets, or every input now hangs), so the "
                         f"campaign stopped instead of spending the rest of its slice on more of "
                         f"the same")
            stop_payload = {"reason": "stalled", "streak": stall_streak,
                            "streak_s": round(stall_s, 1),
                            "grace_s": round(_stall_grace_s(exec_timeout, max_seconds), 1),
                            "exec_timeout": exec_timeout}
        elif converge and plateau_armed and _plateaued(execs, _now - t_start, gain_exec, gain_t):
            _we, _ws = _plateau_window(execs, _now - t_start)
            _unit = "blocks" if (all_blocks and cover_reported) else "behaviours"
            _cov = len(seen_blocks) if _unit == "blocks" else len(seen_behaviour)
            stopped = "converged"
            stop_note = (f"coverage plateaued at {_cov:,} {_unit}: nothing new (no {_unit[:-1]}, "
                         f"no closer sink approach, no new crash or hang) for "
                         f"{execs - gain_exec:,} executions / {_now - t_start - gain_t:.0f}s "
                         f"since the last find at {gain_t:.0f}s -- converged, so the rest of the "
                         f"ceiling goes back to the run")
            stop_payload = {"reason": "plateau", "unit": _unit, "coverage": _cov,
                            "last_gain_exec": gain_exec, "last_gain_s": round(gain_t, 1),
                            "idle_execs": execs - gain_exec,
                            "idle_s": round(_now - t_start - gain_t, 1),
                            "window_execs": _we, "window_s": round(_ws, 1)}
        if stopped:
            stop_payload.update({"execs": execs, "elapsed": round(_now - t_start, 1),
                                 "budget": round(max_seconds, 1),
                                 "budget_returned_s": round(max(0.0, deadline - _now), 1),
                                 "crashes": crashes, "unique": len(seen_sigs),
                                 "note": stop_note})
            ctx.emit(f"{event_prefix}.{stopped}", payload=stop_payload)
            ctx.progress(msg=f"{event_prefix}: {stopped} -- "
                             f"{stop_payload['budget_returned_s']:.0f}s of budget returned")
            break
        # Progress heartbeat for the live console. Emit every 250 execs OR every 3 s, whichever
        # comes first -- the time floor matters because a SLOW campaign (a target that hits its
        # per-exec timeout on every input) reaches 250 execs only every few minutes, which is why
        # the console looked frozen. The payload carries everything a live view needs: rate, how
        # much of the budget is spent, coverage reached, and the running crash tally.
        _now = time.time()
        if execs % 250 == 0 or (_now - last_emit) >= 3.0:
            last_emit = _now
            _elapsed = max(1e-3, max_seconds - max(0.0, deadline - _now))
            ctx.emit(f"{event_prefix}.progress", payload={
                "execs": execs, "crashes": crashes, "unique": len(seen_sigs),
                "behaviours": len(seen_behaviour), "corpus": len(corpus),
                "elapsed": round(_elapsed, 1), "budget": round(max_seconds, 1),
                "pct": min(100, round(100 * _elapsed / max(1e-3, max_seconds))),
                "execs_per_sec": round(execs / _elapsed),
                "blocks_hit": len(seen_blocks), "blocks_known": len(all_blocks),
                "outcomes": alog.snapshot(),
                # plateau / stall telemetry for the live view: when it last found something,
                # and how many executions in a row have run into the limit with nothing new
                "last_gain_s": round(gain_t, 1), "since_gain_execs": execs - gain_exec,
                "timeout_streak": stall_streak, "converge": converge})

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
             # Timed-out executions, and the re-verified hang filed from them (if any) -- so a
             # campaign whose timeouts were never checked does not read as "no hang".
             "timeouts": hang_timeouts, "hang_input": hang_sha,
             "hang_checked": hang_checks,
             "crashes_reproducible": crashes_reproducible, "unique": len(seen_sigs),
             "starved": starved, "directed_kept": directed_kept,
             "nearest_sink_dist": (round(best_dist, 2) if best_dist is not None else None),
             "behaviours": len(seen_behaviour), "corpus": len(corpus), "kept": kept,
             "execs_per_sec": round(execs / elapsed),
             "blocks_hit": len(seen_blocks), "blocks_known": len(all_blocks),
             # Why the campaign ended before its budget, if it did ("converged" / "stalled"),
             # and how much of its slice it handed back.
             "stopped": stopped, "stop_reason": stop_note,
             "budget_returned_s": (stop_payload or {}).get("budget_returned_s"),
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
    # A campaign that RAN plenty but never got past the program's front gate (many execs, one
    # behaviour, no coverage, no crash) is almost always the target refusing the input before it
    # parses it: it needs a config/data file, specific arguments, or a working directory it cannot
    # find. Say so, with the remedy -- the operator watched it run for half an hour and a bare
    # "starved" tells them nothing actionable.
    starved_reason = None
    _verdict, _vnote = alog.tally.verdict(alog.progressed() or crashes > 0)
    if _verdict in (_attempts.ERRORING, _attempts.TIMING_OUT, _attempts.REJECTING):
        # The attempt log KNOWS why it never got anywhere -- quote that instead of guessing
        # "needs a config file" for what is really a loader error or a hang on every input.
        starved_reason = _vnote
        ctx.emit(f"{event_prefix}.noprogress", payload={"execs": execs, "note": starved_reason,
                                                        "verdict": _verdict})
    elif starved and execs >= 200 and not entered and crashes == 0:
        starved_reason = (
            "the target executed but never varied its behaviour or reached new code -- it is "
            "bailing out before it parses the input. That usually means it needs a config/data "
            "file, command-line arguments, or a specific working directory it cannot find. Provide "
            "its runtime files by ingesting the binary as a DIRECTORY that contains them (they are "
            "staged beside it), and verify `./target < input` runs normally by hand first.")
        ctx.emit(f"{event_prefix}.noprogress", payload={"execs": execs, "note": starved_reason})
    stats["starved_reason"] = starved_reason
    # Uninitialized-read pass (CWE-457): detonate the corpus we just built against the MSan binary.
    # This is the RIGHT place for source targets -- they compile to an ASan build that coverage_fuzz
    # skips, so they are fuzzed here, and the corpus is the only place uninitialized reads surface.
    try:
        msan_detonate(ctx, target, corpus, mode, exec_timeout, base_argv=base_argv)
    except Exception:
        observe.absorbed(_log, "continuing")
    # Data-race pass (CWE-362): detonate the same corpus against the ThreadSanitizer binary.
    try:
        tsan_detonate(ctx, target, corpus, mode, exec_timeout, base_argv=base_argv)
    except Exception:
        observe.absorbed(_log, "continuing")
    # Memory-leak pass (CWE-401): detonate the same corpus against the LeakSanitizer binary. A leak
    # surfaces only at a normal exit (ASan runs detect_leaks=0 everywhere else), so this dedicated
    # -fsanitize=leak build + corpus is the one place it is caught.
    try:
        lsan_detonate(ctx, target, corpus, mode, exec_timeout, base_argv=base_argv)
    except Exception:
        observe.absorbed(_log, "continuing")
    _att = alog.finish()
    stats["attempts"] = {k: _att.get(k) for k in ("counts", "verdict", "verdict_note", "value", "log")}
    ctx.emit(f"{event_prefix}.done", payload=stats)
    ctx.progress(pct=100, msg=f"{execs} execs, {crashes} crashes, {len(seen_sigs)} unique, "
                             f"{len(seen_behaviour)} behaviours")
    return stats


def _reproduces(run_fn, exe, mode, workfile, exec_timeout, target, data, prefix,
                guard_page: bool = False, alog=None) -> bool:
    """Does this input crash again, on its own, the way it was found?

    Through the campaign's OWN runner: a boundary-harness campaign delivers its input through a
    generated harness, and the default runner cannot deliver it at all -- checking with the
    wrong one discards every crash it finds.

    `guard_page` is part of "the way it was found" for the same reason the argv prefix is: a
    heap out-of-bounds caught by the guard-page allocator is SILENT without it, so re-running
    unguarded would discard every crash the oracle exists to find.
    """
    kw = {"endianness": target.endianness, "bits": target.bits}
    if run_fn is run_input:
        kw["base_argv"] = prefix
        kw["guard_page"] = guard_page
    try:
        _argv, res = run_fn(exe, mode, workfile, exec_timeout, target.arch, data, **kw)
    except Exception:
        observe.absorbed(_log, "answering no")
        return False
    if alog is not None:
        alog.record_result(data, res, phase="reproduce", argv=prefix)
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
        observe.absorbed(_log, "keeping the default")
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


def _recovered_gate_tokens(ctx, target) -> list:
    """The values `extract_secrets` recovered as input-compared GATES, as dictionary tokens.

    extract_secrets breaks on the target's comparison functions under GDB and records -- in the
    `secrets.done` event -- every constant the program checked OUR input against (a password, magic
    bytes, an expected token), with `gate=True` for the ones that were actually compared against the
    input. The autopilot runs it in the recover phase BEFORE every campaign precisely so the fuzzer
    can get PAST those gates instead of waiting to invent the magic bytes (orchestrate.py's
    "the values every later stage needs in order to get PAST a gate" comment) -- but nothing read
    them back. This is that consumer: the persisted gates go to the FRONT of the dictionary, same as
    the libtokencap runtime tokens. It reuses the single GDB pass extract_secrets already did rather
    than re-running the target, and it surfaces gates on a non-host-arch target too (extract_secrets
    runs under the target's own debugger), where the host-arch-only libtokencap path cannot."""
    try:
        from ...db.dao import EventDAO
        toks: list = []
        for pl in EventDAO(ctx.conn).payloads_of_type("secrets.done", target_id=target.id,
                                                       stage="extract_secrets"):
            for r in (pl.get("recovered") or []):
                v = r.get("value")
                if r.get("gate") and isinstance(v, str) and 1 <= len(v) <= 128:
                    toks.append(v.encode("latin-1", "ignore"))
        return list(dict.fromkeys(toks))                 # de-duped, order preserved
    except Exception:                                    # noqa: BLE001 -- the dictionary is advisory
        return []


def fuzz_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("fuzz requires a target_id")

    p = ctx.params or {}
    # Which channels to fuzz. Committing to one is wrong even when the inference is right
    # about what the program READS: ncompress genuinely parses files, and its overflow is in
    # the filename it was handed on the command line. A campaign aimed at the wrong channel
    # does no work and reports a clean zero.
    # The call-edge inventory is empty on a managed target (no machine code) AND often empty on
    # a native one, because leading with execution means fuzzing runs before `disassemble`. In
    # both cases the names triage recorded at ingest -- a jar's constant pool, a .NET metadata
    # heap, an ELF's IMPORT TABLE -- answer the same question, so they are passed always rather
    # than only for the managed case. Without them this ranked `arg` first for every target
    # whose edges were missing, and a campaign aimed at a channel the program never reads does
    # no work and reports a clean zero.
    channels = ([p["input_mode"]] if p.get("input_mode")
                else modes_for(CallEdgeDAO(ctx.conn).list_by_target(target.id),
                               symbols=_triage_symbols_for(ctx, target),
                               file_type=target.file_type,
                               no_imports=no_import_evidence(target)))
    max_execs = int(p.get("max_execs", 3000))
    max_seconds = float(p.get("max_seconds", 30))
    exec_timeout = float(p.get("exec_timeout", 2))
    rng = random.Random(int(p.get("seed", 1337)))
    # How to invoke the target. `@@` marks where the input goes -- `["-c", "@@"]` for a
    # service that takes a config path behind a flag; without it the input is appended.
    base_argv = [str(a) for a in (p.get("argv") or [])]
    auto_argv, wants_config, door = None, False, {}
    if not base_argv and p.get("discover_argv", True):
        base_argv, auto_argv, wants_config, door = _discover_argv(ctx, target, exec_timeout)
    elif any(a for a in base_argv):
        wants_config = "@@" in base_argv

    if door.get("verified_on") == "stdin" and not p.get("input_mode"):
        # The door was VERIFIED with the input on stdin, so that is the channel this campaign
        # delivers on. Ranking the channels from the image's imports instead would answer for
        # busybox as a whole -- 345 programs' worth of imports -- and a decompressor handed its
        # input as an argv string sees a filename that does not exist, on every execution.
        channels = ["stdin"]
        ctx.emit("fuzz.channel", payload={"mode": "stdin", "why": (
            "the contained program was verified by running it with the input on stdin, which "
            "is the channel it was shown to read")})
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
    if (target.file_type or "").lower() == "pyc":
        # Measured through the sandbox: 53 ms per execution (~19/s) against ~580/s native --
        # interpreter start-up plus the bwrap namespace, and no coverage feedback, because the
        # only machine code in the process is CPython's own.
        ctx.emit("fuzz.slow", payload={
            "format": "pyc", "note": (
                "this is CPython bytecode: every execution pays interpreter start-up (~53 ms "
                "measured, so roughly 19 executions/second against ~580/s native) and there is "
                "no coverage feedback. A defect surfaces as an uncaught exception rather than a "
                "signal. Budget hundreds of executions, not millions, and lean on the "
                "marshalled code object -- it names every identifier and literal in the clear.")})
    if (target.file_type or "").lower() == "wasm":
        # Measured through the sandbox: 90 ms per execution (~11/s) -- node start-up plus
        # module compilation on every input, the dearest substrate here after Wine.
        ctx.emit("fuzz.slow", payload={
            "format": "wasm", "note": (
                "this is a WebAssembly module: every execution pays node start-up and a fresh "
                "module compile (~90 ms measured, roughly 11 executions/second against ~580/s "
                "native), with no coverage feedback. A defect surfaces as a TRAP, and only an "
                "access past the END of linear memory traps -- an overflow that stays inside it "
                "corrupts the module's own data silently, so this substrate cannot see the "
                "ordinary in-bounds buffer overflow at all.")})
    if (target.file_type or "").lower() == "dotnet":
        # Measured through the sandbox: 122 ms per execution (~8/s) -- the CLR bootstraps and
        # JITs on every input. The dearest managed substrate here, though still eight times
        # the PE/Wine path.
        ctx.emit("fuzz.slow", payload={
            "format": "dotnet", "note": (
                "this is a .NET assembly: every execution pays CLR start-up and a fresh JIT "
                "(~122 ms measured, roughly 8 executions/second against ~580/s native), with "
                "no coverage feedback. A defect surfaces as an unhandled managed exception "
                "rather than a signal, and the trace names the exception class and the method "
                "-- with file:line when a PDB shipped. Budget hundreds of executions, not "
                "millions, and lean on the metadata: #Strings names every type and method and "
                "#US holds every string literal in the clear.")})
    strings = _strings_for(ctx, target)
    blocks = _recovered_blocks(ctx, target)
    flags = mine_flags(ctx.content.path(target.sha256).read_bytes())
    corpus = _load_external_seeds(p) or list(_DEFAULT_SEEDS)
    if door.get("seeds"):
        # A valid archive, made by the target's own compressor for the decompressor door this
        # campaign is driving. It goes in FRONT: a decompressor checks its header first, so
        # every generic seed above is rejected before the decoder runs at all.
        corpus = list(door["seeds"]) + list(corpus)
    if p.get("seed_files") or p.get("seed_dir"):
        ctx.emit("fuzz.seeds", payload={"loaded": len(corpus),
                                        "from": [k for k in ("seed_files", "seed_dir") if p.get(k)]})
    dictionary = _mine_dictionary(strings)
    _pfx = _dispatch_prefix_seeds(dictionary)
    if _pfx:
        # In FRONT of the corpus: a dispatch branch nobody has entered yet is worth more than
        # another mutation of the branch that already crashed.
        corpus = _pfx + list(corpus)
        ctx.emit("fuzz.dispatch_seeds", payload={
            "tokens": sorted({t.split(b"=")[0].split(b":")[0].decode("latin-1", "replace")
                              for t in _pfx})[:12], "seeds": len(_pfx),
            "why": ("a dispatch token is matched at the START of the line, so each mined "
                    "`key=`/`key:` token is seeded as a prefix with a number, a filler and an "
                    "out-of-range number behind it")})
    # Gate values extract_secrets already recovered under GDB (run in the recover phase, before this
    # campaign): the exact constants the program compared our input against. To the FRONT -- a
    # comparison the program actually performed beats a .rodata string -- and reused from the one
    # pass extract_secrets did, rather than re-run here.
    _gate_tokens = _recovered_gate_tokens(ctx, target)
    if _gate_tokens:
        dictionary = _gate_tokens + [t for t in dictionary if t not in set(_gate_tokens)]
        ctx.emit("fuzz.dictionary", payload={
            "gate_tokens": len(_gate_tokens), "total": len(dictionary),
            "sample": [t.decode("latin-1", "replace")[:32] for t in _gate_tokens[:8]],
            "why": "values extract_secrets saw the target compare our input against -- seeded so "
                   "the fuzzer gets past the gate instead of having to invent the magic bytes"})
    # The target's own strings give the tokens visible in the IMAGE. The ones that matter most for
    # getting past a gate are often not there: a magic value that is COMPUTED (a decoded header, a
    # checksum, a token read from a config or the environment) exists only at runtime. libtokencap
    # hooks the comparison functions and reports exactly those, and it was already discovered by
    # `memoracle.tokencap_lib` and never called -- the static half of this dictionary
    # (`fuzz.cmpdict`, in directed_fuzz) was wired and the runtime half was not. One extra
    # execution, host-arch ELF only, and the tokens go to the FRONT: a comparison the program
    # actually performed beats a string that merely sits in .rodata.
    _rt_tokens = []
    try:
        if not substrate.is_managed(target.file_type):
            from ..dynamic import memoracle
            # Staged with its deps, as every stage that executes the target does: the
            # content-addressed blob is not an executable file.
            _tc_exe = ctx.scratch() / "target.bin"
            ctx.content.stage_target(target, _tc_exe.parent, _tc_exe.name)
            _rt_tokens = memoracle.runtime_tokens(
                _tc_exe, (corpus[0] if corpus else b""),
                mode=channels[0] if channels else "stdin",
                base_argv=base_argv, host_arch=sandbox.host_arch(), target_arch=target.arch,
                # Bounded by the campaign's own per-exec limit: one execution, and libtokencap
                # reports at EXIT, so a run killed at the limit yields nothing however long the
                # limit was -- the 20 s default spent two-thirds of a 30 s slice on a wedged target.
                timeout=min(20.0, max(5.0, 4.0 * exec_timeout)))
    except Exception:                                    # noqa: BLE001 -- the dictionary is advisory
        _rt_tokens = []
    if _rt_tokens:
        dictionary = _rt_tokens + [t for t in dictionary if t not in set(_rt_tokens)]
        ctx.emit("fuzz.dictionary", payload={
            "runtime_tokens": len(_rt_tokens), "total": len(dictionary),
            "sample": [t.decode("latin-1", "replace")[:32] for t in _rt_tokens[:8]],
            "why": "values the target COMPARED its input against at runtime, which a static "
                   "string scan cannot see when the value is computed"})
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
        # Boundary-value configs FIRST in the corpus, then the valid placeholder seed. A field
        # parsed as a number (atoi / Integer.parseInt / an array index) hides its bug behind a
        # specific value -- 0, -1, INT_MAX, overflow -- that the mutator lands only by luck, and
        # never inside a short, JVM-slow budget under load. Seeding them makes such a bug crash on
        # the first executions instead of stochastically; a robust parser just accepts them.
        corpus = textconf.boundary_seeds(keys) + [textconf.seed_for(keys)] + list(corpus)
        ctx.emit("fuzz.format", payload={"model": "keyvalue", "auto": True,
                                         "keys": keys[:16],
                                         "why": "the binary requires a config path"})
    if mutator is None and not p.get("format"):
        # Nobody supplied a model, so ask the binary. A parser rejects random bytes before it
        # reaches any of its own logic -- jhead ran 98,500 executions for zero finds while
        # AFL++ reached the same bug in 60 seconds WITH a valid sample -- and the target's own
        # strings say which format it reads. The model then yields a seed that passes the gate,
        # so the campaign starts inside the parser instead of at its front door.
        _detected = structure.detect_formats([x.value for x in strings],
                                             _imports_for(ctx, target))
        fmt = _detected[0] if _detected else None
        if fmt == "xml":
            # XML is a grammar, and the grammar mutator already exists -- but it could only be
            # chosen when the CORPUS already looked like XML (`looks_like_xml` above), which on
            # a target nobody seeded it never does. So the one capability that works on XML was
            # unreachable on exactly the targets that need it: measured on xmlwf, whose own
            # strings contain no XML at all because they live in the libexpat it links.
            mutator = xmlgrammar.XmlMutator(rng, dictionary)
            _xs = structure.seed_for_name("xml")
            if _xs:
                corpus = [_xs] + list(corpus)
            ctx.emit("fuzz.format", payload={
                "model": "xml", "auto": True,
                "why": "the binary's strings or imports say it parses XML; seeded with a "
                       "well-formed document so the grammar mutator has something to mutate"})
        elif fmt:
            model = structure.builtin(fmt)
            mutator = structure.StructMutator(rng, model, dictionary)
            # Boundary seeds FIRST: the valid skeleton AND one crash-shaped variant per offset/size
            # record (an offset+length that wraps a 32-bit bounds check while pointing out of
            # bounds -- jhead's GPS read, and the shape of many parser OOB bugs). Calibration
            # detonates these before mutation, so a structural bug that a byte/field mutator lands
            # only by luck (jhead: 259 near-misses in 20k, zero crashes) is found on the first execs.
            bseeds = structure.boundary_seeds(fmt)
            # The runner-up formats cannot drive the mutator -- a StructMutator models one
            # format -- but their seeds still belong in the corpus: a multi-format reader is
            # several parsers behind several magic checks, and the only one this campaign
            # could otherwise reach is the one that won the ranking.
            for _other in _detected[1:_MAX_FORMATS]:
                _s = structure.seed_for_name(_other)
                if _s:
                    bseeds = (bseeds or []) + [_s]
            if bseeds:
                corpus = bseeds + list(corpus)
    # Documented specimens go in the corpus whatever model was chosen: they are evidence from
    # the binary about its own input, not a guess, and a campaign that cannot pass the first
    # gate measures nothing however good its mutator is.
    try:
        _ex = textconf.example_seeds([x.value for x in strings if getattr(x, "value", None)])
        if _ex:
            corpus = _ex + list(corpus)
            ctx.emit("fuzz.seeds", payload={
                "documented_examples": len(_ex),
                "why": "the binary documents its own input format (usage/prompt 'e.g. ...'), "
                       "so the example and a long-field variant of it seed the campaign"})
    except Exception:
        observe.absorbed(_log, "continuing")
    if not fmt and _reads_a_number(ctx, target):
        # No document format to model, and the target converts input text to a number: its bug
        # is behind a VALUE, not a length. `n * 16` wraps at 2**28, and the wrapped product is
        # small enough that the allocation succeeds and the following loop runs off it -- while
        # the type boundary a fuzzer would reach for, 4294967295, wraps to a size malloc simply
        # refuses, so the program exits cleanly. Blind mutation does not emit nine-digit decimal
        # text at all, so this class was unreachable by budget, not merely expensive.
        _nseeds = textconf.numeric_boundary_seeds()
        corpus = _nseeds + list(corpus)
        ctx.emit("fuzz.seeds", payload={
            "numeric_boundaries": len(_nseeds),
            "why": "the target converts input text to a number (scanf/strtol family), so "
                   "allocation- and index-wrap thresholds are seeded verbatim"})
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
    # A PROMPT-DRIVEN target is fed one field per prompt, not one blob. The blob arrives whole,
    # and a program that reads its fields with separate `read(0, buf, N)` calls takes all of it
    # as field one -- so every input is rejected at the first gate whatever it contains. The
    # delivery that fixes it is the one the menu path already uses, applied to a linear protocol.
    _lin_fields, _lin_run = None, None
    # Keyed on the CHANNEL, not on how the channel was chosen. Gating this on
    # `not p.get("input_mode")` meant it never fired under the autopilot, which always passes
    # `input_mode` -- that parameter carries the orchestrator's channel decision, not an
    # operator override -- so the path worked when the stage was driven directly and silently
    # did nothing in the pipeline that needs it.
    if "stdin" in channels:
        _exe_probe = ctx.scratch() / "target.bin"
        try:
            ctx.content.stage_target(target, _exe_probe.parent, _exe_probe.name)
            os.chmod(_exe_probe, 0o755)
            _lin_fields = linear_protocol_for(ctx, target, _exe_probe, _exe_probe.parent)
        except Exception:
            observe.absorbed(_log, "keeping the default")
            _lin_fields = None
    if _lin_fields:
        from . import menu as _menu2
        from .runner import prompted_runner
        _ex = textconf.example_seeds([x.value for x in strings
                                      if getattr(x, "value", None)])
        _lseeds = [x for x in _menu2.linear_seeds(_lin_fields, _ex) if x]
        if _lseeds:
            corpus = _lseeds + list(corpus)
        _lin_run = prompted_runner(_lin_fields)
        channels = ["stdin"]                 # the other channels cannot carry a prompt protocol
        ctx.emit("fuzz.format", payload={
            "model": "linear-prompt", "auto": True, "fields": _lin_fields,
            "seeds": len(_lseeds),
            "why": "the target prompts for each field in turn, so the input is delivered one "
                   "field per prompt instead of as one blob that field one would swallow"})

    share_execs = max(1, max_execs // len(channels))
    share_secs = max(1.0, max_seconds / len(channels))
    # Mined from the TARGET, not from the door that was chosen: a multi-call image refuses
    # every input under the wrong filename whether or not a door opened, so the campaign is
    # staged under the name it demands either way.
    from ..invocation import exec_name_for as _exec_name_for
    _exec_name = _exec_name_for(ctx.content.path(target.sha256).read_bytes())
    if _exec_name:
        ctx.emit("fuzz.exec_name", payload={"name": _exec_name, "why": (
            "this image dispatches on its own filename -- staged as target.bin it answers "
            "'applet not found' to every input, so it is staged under the name its usage "
            "string states")})
    totals = {"execs": 0, "crashes": 0, "crashes_reproducible": 0, "unique": 0,
              "behaviours": 0}
    blocks_hit = 0            # the most blocks any one channel reached (coverage is per-run)
    blocks_known = 0
    stage_deadline = time.time() + max_seconds
    stopped_by: dict = {}
    for i, ch in enumerate(channels):
        _kw = {"run_fn": _lin_run} if _lin_run is not None else {}
        # A channel that converged or stalled early hands its unused slice to the channels after
        # it rather than to nothing: the share is never LESS than the even split, and never more
        # than what is left of the stage's own budget split over the channels still to run.
        left = len(channels) - i
        _secs, _execs = share_secs, share_execs
        if i and stopped_by:
            _secs = max(share_secs, (stage_deadline - time.time()) / left)
            _execs = max(share_execs, (max_execs - totals["execs"]) // left)
        st = fuzz_campaign(ctx, target, corpus=list(corpus), dictionary=dictionary, mode=ch,
                           max_execs=_execs, max_seconds=_secs,
                           exec_timeout=exec_timeout, rng=rng, detector="fuzz",
                           event_prefix="fuzz", note_prefix=note, mutator=mutator,
                           cover_blocks=blocks, cover_flags=flags, base_argv=base_argv,
                           exe_name=_exec_name, **_kw)
        for k in totals:
            totals[k] += st.get(k, 0)
        blocks_hit = max(blocks_hit, st.get("blocks_hit", 0))
        blocks_known = max(blocks_known, st.get("blocks_known", 0))
        if st.get("stopped"):
            stopped_by[ch] = st["stopped"]
        if st.get("crashes_reproducible"):
            break
    ctx.emit("fuzz.channels", payload={"channels": channels, "flags": len(flags), **totals,
                                       "stopped": stopped_by or None})
    # Block coverage: how much of the recovered code the campaign actually reached. A parser
    # that fuzzed for a full budget but hit 3% of blocks never got past its length check.
    pct = round(100.0 * blocks_hit / blocks_known, 1) if blocks_known else None
    summary = {"backend": "blind", "execs": totals["execs"], "crashes": totals["crashes"],
               "stopped": stopped_by or None,
               "coverage": {"kind": "block", "blocks_hit": blocks_hit,
                            "blocks_known": blocks_known, "pct": pct}}
    sha = ctx.put_artifact("fuzz-summary", data=canonical_json(summary))
    return {"output_shas": [sha], "output_kind": "fuzz-summary"}


def _structure_mutator(p, rng, dictionary):
    """Build a format-aware mutator. A GRAMMAR (params.grammar spec, or params.grammar_name for a
    built-in: kv/tlv/json/sexpr) is preferred -- it generates recursive, structurally-valid inputs
    that reach code behind nested parsers a flat field model never builds. Otherwise a flat
    StructMutator from params.format / params.format_name. None when neither is specified."""
    if p.get("grammar") or p.get("grammar_name"):
        try:
            from . import grammar as _grammar
            g = (_grammar.compile_grammar(p["grammar"]) if p.get("grammar")
                 else _grammar.builtin(p["grammar_name"]))
            if g is not None:
                return _grammar.GrammarMutator(rng, g, dictionary)
        except Exception:
            observe.absorbed(_log, "continuing")
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
