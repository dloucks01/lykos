"""Non-fuzzing (concolic / AEG) confirmation of a memory-safety bug reachable through a libFuzzer
harness -- the primary rung of the source confirmation ladder.

angr explores the harness as a bytes->parser DRIVER: it enters directly at `LLVMFuzzerTestOneInput`
with a symbolic input buffer (the 'harness' input_mode of angr_driver) and SOLVES the parser's gates
(magic constants, length/format checks) that blind fuzzing struggles with. Each input it generates is
then REPLAYED through the ASan-instrumented build; a concrete ASan fault at the predicted site is the
sound proof -- a static prediction confirmed by execution, which is what the never-a-false-positive bar
requires (a pure static "proof" of corruption in a real parser is unsound). A negative control (an
input that does not drive the bug) must NOT fault, so the fault is attributed to the solved bytes.

Two builds, because they pull in opposite directions: angr is confused by ASan's shadow-memory
accesses, so it explores a NON-ASan build (`-fsanitize=fuzzer` only), while confirmation needs the
ASan build. The parser logic is identical, so an input the clean build's parser accepts drives the
same path in the ASan build. Both must be STATIC (the parser linked into the harness ELF) -- angr loads
with auto_load_libs=False, so a parser left in a .so would never be explored.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from pathlib import Path

from . import concolic as _concolic

#: A GENUINE sanitizer MEMORY-SAFETY error banner. ASan prints exactly one of these `ERROR:
#: AddressSanitizer: <kind>` lines for a real memory fault; the kind list is ASan's own. This is the
#: sound signal -- NOT the bare substring "AddressSanitizer", which also appears when ASan merely
#: annotates an unrelated SIGABRT (e.g. an abort() from an assertion), and NOT a libFuzzer "deadly
#: signal" line, which a plain abort() also produces.
_ASAN_MEMERR = re.compile(
    r"ERROR: AddressSanitizer: ("
    r"heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
    r"heap-use-after-free|stack-use-after-return|stack-use-after-scope|use-after-poison|"
    r"dynamic-stack-buffer-overflow|container-overflow|"
    r"SEGV|negative-size-param|allocation-size-too-big|calloc-overflow|"
    r"double-free|attempting free|invalid-free|requested allocation size|stack-overflow)")

#: A crash that is a DELIBERATE assertion / abort(), not a memory-safety bug. FreeRDP (and any
#: project built with verbose asserts) aborts on malformed input BY DESIGN -- `WINPR_ASSERT`,
#: libc `__assert_fail`, a `[FATAL] ... assert` log line. That is at most a reachable-assertion DoS
#: (CWE-617), never a memory-corruption PoC, so it must not confirm a memory-safety finding. Only
#: suppresses when there is NO genuine memory-error banner (a real overflow that also trips an assert
#: on the way down is still a real overflow).
_ASSERT_ABORT = re.compile(
    r"winpr_int_assert|__assert_fail|Assertion\s+.*failed|\bSIGABRT\b|"
    r"\babort\b|\[FATAL\][^\n]*assert", re.I)


def _memory_fault(rep: str, cls: dict | None) -> bool:
    """Whether `rep` is a GENUINE memory-safety / UB sanitizer fault -- the only thing that may
    confirm a memory-safety finding. True when a parsed ASan class exists, or a real ASan
    memory-error banner / UBSan runtime error is present; and NOT when the crash is only a
    deliberate assertion/abort with no such banner. This is the 0-FP gate: a `WINPR_ASSERT` abort
    (a DoS-by-design on malformed input) reaches the parser through a synthesized driver and would
    otherwise be mis-counted as a crash -- for nearly every parser in a verbose-assert project."""
    rep = rep or ""
    hard = bool(cls) or bool(_ASAN_MEMERR.search(rep)) \
        or "SUMMARY: UndefinedBehaviorSanitizer" in rep or "runtime error:" in rep
    if not hard:
        return False
    # a genuine memory-error banner wins even if an assert also fired; a bare assert/abort does not.
    if _ASSERT_ABORT.search(rep) and not (bool(cls) or _ASAN_MEMERR.search(rep)):
        return False
    return True


#: A crash that is a DENIAL OF SERVICE, not memory corruption: a reachable assertion/abort, an
#: unhandled fatal signal, or a libFuzzer "deadly signal" with no memory-error banner. A reachable
#: WINPR_ASSERT (or libc assert / __stack_chk_fail / abort) driven by attacker input terminates the
#: process -- a real remote DoS (CWE-617 reachable assertion) whose reproducer is the input. This is
#: the SECOND confirmation lane: the thing `_memory_fault` deliberately rejects is itself a valid
#: (lower-severity) finding, so it must not be thrown away -- it is captured here instead.
_DOS_SIGNAL = re.compile(
    r"\bSIGABRT\b|\bSIGSEGV\b|\bSIGFPE\b|\bSIGILL\b|\bSIGBUS\b|"
    r"libFuzzer: deadly signal|runtime error:|ERROR: libFuzzer: timeout|"
    r"__stack_chk_fail|stack smashing detected")


def _dos_class(rep: str) -> "str | None":
    """Classify a non-memory-safety crash as a DoS, or None. A reachable assertion/abort is the
    common FreeRDP case (always-on WINPR_ASSERT) and maps to CWE-617; a bare fatal signal maps to
    CWE-248 (uncaught exception / crash). Returns the CWE string, or None when the report shows no
    process-terminating fault. Memory-safety faults are NOT reported here -- they belong to
    `_memory_fault` (the stronger finding), so callers check that first."""
    rep = rep or ""
    if _ASSERT_ABORT.search(rep):
        return "CWE-617"                                 # reachable assertion -> abort
    if _DOS_SIGNAL.search(rep):
        return "CWE-248"                                 # uncaught fatal signal / crash
    return None


def _asan_replay(binary, data: bytes, lib_dirs=None, *, timeout: float = 30.0) -> dict:
    """Run the ASan harness on one input (as libFuzzer's single-file replay) and report the fault.
    Returns {faulted, report, source, cls}."""
    from ..debug.rootcause import parse_asan_report
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:" + env.get("ASAN_OPTIONS", "")
    if lib_dirs:
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [str(d) for d in lib_dirs] + ([env["LD_LIBRARY_PATH"]] if env.get("LD_LIBRARY_PATH") else []))
    with tempfile.NamedTemporaryFile(prefix="lykos-dc-", suffix=".bin", delete=False) as f:
        f.write(data)
        inp = f.name
    try:
        r = subprocess.run([str(binary), inp], capture_output=True, text=True, env=env, timeout=timeout)
        rep = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return {"faulted": False, "report": "replay timed out", "source": None, "cls": None}
    except OSError as e:
        return {"faulted": False, "report": f"replay could not run: {e!r}", "source": None, "cls": None}
    finally:
        try:
            os.unlink(inp)
        except OSError:
            pass
    cls = parse_asan_report(rep) or {}
    # An ASan-reported MEMORY-SAFETY fault is the sound signal -- a parsed class or a real
    # `ERROR: AddressSanitizer: <kind>` / UBSan banner, and NOT a deliberate assertion/abort (which
    # a verbose-assert project trips on malformed input by design). The return code alone is NOT
    # trusted -- libFuzzer exits non-zero for benign reasons too. See `_memory_fault`.
    faulted = _memory_fault(rep, cls)
    # DoS lane: a non-memory crash (reachable assertion / fatal signal) is still a real fault --
    # captured so the DoS confirmation rung can turn it into a CWE-617/248 PoC. Memory faults take
    # precedence (the stronger finding), so `dos` is reported only when it is NOT a memory fault.
    dos = None if faulted else _dos_class(rep)
    return {"faulted": faulted, "report": rep, "source": cls.get("source"),
            "cls": cls.get("class") or cls.get("cwe"), "dos": dos}


def concolic_confirm(explore_binary, replay_binary, *, harness_fn: str = "LLVMFuzzerTestOneInput",
                     input_size: int = 256, lib_dirs=None, targets=None, target_syms=None,
                     load_libs=None, seeds=None, timeout: int = 120, ctx=None) -> dict:
    """Confirm a memory-safety bug via concolic input synthesis + ASan replay. See module docstring.

    `explore_binary` is the NON-ASan harness angr explores; `replay_binary` the ASan harness used to
    confirm (may be the same file, but ASan makes angr worse). `targets` optionally lists sink
    addresses to steer angr toward, and `target_syms` function NAMES to steer toward (resolved by
    angr's loader -- finding-directed, so angr heads for the statically-suspected functions). Steering
    only changes exploration efficiency: every generated input is still replayed under ASan with a
    negative control, so it can never cause a false positive. Returns {confirmed, input (bytes),
    report, source, class, rung:"concolic", reason}."""
    out = {"confirmed": False, "input": None, "report": None, "source": None, "class": None,
           "rung": "concolic", "reason": None}
    py = _concolic.locate_angr_python()
    if py is None:
        out["reason"] = "angr unavailable"
        return out
    spec = {"binary": str(explore_binary), "input_mode": "harness", "harness_fn": harness_fn,
            "input_size": int(input_size), "max_seconds": int(timeout), "num_find": 16}
    if seeds:
        # concolic/hybrid seeding: preconstrain states from structure-VALID inputs so angr starts
        # PAST the outer parse gates and only has to solve the vulnerable region -- the fix for a
        # deep parser where a blank-buffer explore hits the cutoff with no inputs generated.
        import base64 as _b64
        spec["seeds"] = [_b64.b64encode(s).decode() for s in seeds if s]
    if targets:
        spec["targets"] = list(targets)
    if target_syms:
        spec["target_syms"] = list(target_syms)
    if load_libs:                                            # explore a SHARED harness with the
        spec["load_libs"] = list(load_libs)                  # project's own .so visible (no static link)
    try:
        res = _concolic.run_explore(py, spec, ctx=ctx, timeout=timeout)
    except Exception as e:                                   # noqa: BLE001 -- a stuck/failed explore
        out["reason"] = f"concolic exploration failed: {e}"
        return out
    out["entry"] = res.get("harness_entry")                  # which entry angr used (parser vs wrapper)
    cands = [base64.b64decode(g["input_b64"]) for g in res.get("generated", []) if g.get("input_b64")]
    if not cands:
        out["reason"] = "concolic generated no inputs" + (" (cutoff)" if res.get("cutoff") else "")
        return out
    for data in cands:
        rep = _asan_replay(replay_binary, data, lib_dirs, timeout=min(30.0, timeout))
        if not rep["faulted"]:
            continue
        # NEGATIVE CONTROL: an empty input reaches the harness but not the bug; if it also faults,
        # the harness faults regardless of our bytes and this proves nothing.
        neg = _asan_replay(replay_binary, b"", lib_dirs, timeout=min(30.0, timeout))
        if neg["faulted"]:
            out["reason"] = "negative control (empty input) also faulted -- not attributable"
            return out
        out.update(confirmed=True, input=data, report=rep["report"], source=rep["source"])
        out["class"] = rep["cls"]
        return out
    out["reason"] = f"no concolic-generated input faulted under ASan ({len(cands)} tried)"
    return out


def _length_field_templates(payload_len: int = 64) -> list:
    """Length-prefix probes (format-aware): a parser that reads a LEADING size field and trusts it --
    `len = read_u32(in); memcpy(dst, in+4, len)` / `malloc(len)` -- is tripped deterministically when
    the field names more bytes than the input holds (over-read) or than the destination holds
    (overflow). A fixed set across the common field widths and byte orders, with the all-ones max, a
    modest oversize, and the signed-32 boundary -- still no fuzzing. Distinct from the generic blobs,
    whose own bytes would decode to an absurd length a bounds check rejects."""
    body = b"A" * payload_len
    tpls: list = []
    for width in (2, 4, 8):
        maxv = (1 << (8 * width)) - 1
        for v in (maxv, 4096):
            for endian in ("little", "big"):
                tpls.append(v.to_bytes(width, endian) + body)
    for endian in ("little", "big"):
        tpls.append((0x80000000).to_bytes(4, endian) + body)      # signed 32-bit boundary
    return tpls


def _default_templates(input_size: int = 4096) -> list:
    """The deterministic known-bad shapes, SMALLEST-first so the minimal triggering input wins.

    Families, each covering a directly-triggerable memory-safety bug without solving or fuzzing:
      * oversized blobs -- a length-driven copy (`memcpy(buf, in, len)`, unbounded strcpy/sprintf)
        overflows once the input passes the fixed buffer; the size ladder finds the threshold;
      * format-string probes -- `printf(in)` with attacker bytes dereferences `%s`/reads `%n`/leaks
        `%p`, which these specifier runs trigger directly;
      * length-prefix probes -- a leading size field the parser trusts over the actual input size.
    These are a fixed handful, not a mutation loop: deterministic, so this is the ladder's FIRST rung."""
    sizes = sorted({32, 64, 256, 1024, 4096, 16384, 65536, int(input_size), int(input_size) * 2})
    tpls = [b"A" * s for s in sizes if 1 <= s <= (1 << 20)]
    tpls += [b"%n" * 32, b"%s" * 64, b"%p" * 128, b"%s%p%n%x" * 32]
    tpls += _length_field_templates()
    return tpls


def template_confirm(asan_binary, *, lib_dirs=None, templates=None, input_size: int = 4096,
                     timeout: int = 60) -> dict:
    """Deterministic TEMPLATE rung (the ladder's smartest/first): replay a small fixed set of
    known-bad-shape inputs under ASan -- no solver, no fuzzing. The first input that faults, with a
    passing empty-input negative control, is the proof. Only an ASan/UBSan memory fault counts (a
    benign reject/abort does not), so this never fabricates a confirmation. Returns the concolic_confirm
    result shape with rung="template"."""
    import time as _t
    out = {"confirmed": False, "input": None, "report": None, "source": None, "class": None,
           "rung": "template", "reason": None}
    tpls = templates if templates is not None else _default_templates(input_size)
    deadline = _t.time() + float(timeout)
    tried = 0
    for data in tpls:
        if _t.time() >= deadline:
            break
        tried += 1
        rep = _asan_replay(asan_binary, data, lib_dirs, timeout=min(15.0, timeout))
        if not rep["faulted"]:
            continue
        neg = _asan_replay(asan_binary, b"", lib_dirs, timeout=min(15.0, timeout))
        if neg["faulted"]:
            out["reason"] = "negative control (empty input) also faulted -- not attributable"
            return out
        out.update(confirmed=True, input=data, report=rep["report"], source=rep["source"])
        out["class"] = rep["cls"]
        return out
    out["reason"] = f"no template input faulted under ASan ({tried} shapes tried)"
    return out


# ---- the confirmation LADDER ---------------------------------------------------------------------
# Rungs tried SMARTEST-FIRST per the operator's order: a deterministic template (no solver, no
# fuzzing), then concolic (solver, no fuzzing), then directed SMART fuzzing (stochastic but steered --
# the floor). Discovery stays static; this only CONFIRMS a discovered bug by producing a concrete
# ASan fault. Each rung takes a harness descriptor and returns a confirm dict (see concolic_confirm)
# or None when it does not apply / cannot synthesize. The first rung that confirms wins, and the
# result records WHICH rung proved it.


def _rung_template(h, *, timeout, ctx):
    """B2 (deterministic template synthesis): replay the known-bad shapes against the ASan harness
    (the static replay build, or the shared fuzz build). No solver, no fuzzing -- the fastest rung,
    so it runs FIRST and a directly-triggerable overflow / format-string bug is proven instantly."""
    asan = h.get("replay_binary") or h.get("fuzz_binary")
    if not asan:
        return {"confirmed": False, "rung": "template", "skipped": True,
                "reason": "no ASan harness build to replay templates against"}
    return template_confirm(asan, lib_dirs=h.get("lib_dirs"),
                            input_size=int(h.get("input_size", 4096)), timeout=timeout)


#: cap on the concolic SYMBOLIC-input size. A parser's gates (magic/length/type fields) sit in the
#: first bytes, and every symbolic byte multiplies angr's per-step solver cost, so a 2 KB symbolic
#: buffer makes a large target (FreeRDP) cut off before it reaches the parser. A bounded symbolic
#: PREFIX lets concolic get DEEP and solve the gates; the template/smart-fuzz rungs cover the
#: large-input overflows a short prefix cannot express.
_CONCOLIC_MAX_INPUT = 256


def _rung_concolic(h, *, timeout, ctx):
    # needs a CLEAN build with the parser visible: the STATIC clean harness (parser in the ELF), or a
    # SHARED clean harness with the project's .so force-loaded (load_libs). Absent -> skip; the
    # smart-fuzz floor covers it.
    if not h.get("explore_binary"):
        return {"confirmed": False, "rung": "concolic", "skipped": True,
                "reason": "no clean explore build (neither static nor shared-clean linked)"}
    return concolic_confirm(
        h["explore_binary"], h.get("replay_binary") or h["explore_binary"],
        harness_fn=h.get("harness_fn", "LLVMFuzzerTestOneInput"),
        input_size=min(int(h.get("input_size", 256)), _CONCOLIC_MAX_INPUT), lib_dirs=h.get("lib_dirs"),
        targets=h.get("targets"), target_syms=h.get("target_syms"),
        load_libs=h.get("load_libs"), timeout=timeout, ctx=ctx)


def smartfuzz_confirm(fuzz_binary, *, lib_dirs=None, seeds=None, input_size=4096, timeout=90,
                      workdir=None) -> dict:
    """Directed, structure-seeded SMART fuzzing of an ASan harness -- the ladder's floor rung, for
    deep parser bugs the solver cannot reach, and the rung that works on a SHARED build (so it runs on
    projects whose static link the concolic rung cannot produce). Coverage-guided libFuzzer seeded with
    `seeds` (format specimens / concolic hand-offs); the first ASan-faulting crash is the proof, with an
    empty-input negative control. Returns the concolic_confirm result shape with rung="smart-fuzz"."""
    from ..libfuzzer import run_libfuzzer
    out = {"confirmed": False, "input": None, "report": None, "source": None, "class": None,
           "rung": "smart-fuzz", "reason": None, "execs": 0,
           "confirmed_dos": False, "dos_class": None, "impact": None}
    own_wd = workdir is None
    wd = Path(tempfile.mkdtemp(prefix="lykos-sf-")) if own_wd else Path(workdir)
    try:
        corpus = list(seeds or []) + [b"A" * n for n in (16, 64, 256, 1024)]
        res = run_libfuzzer(fuzz_binary, wd, seconds=int(timeout), max_len=int(input_size),
                            corpus=corpus, lib_dirs=lib_dirs)
        out["execs"] = int(res.get("execs") or 0)            # honest telemetry: did the harness run?
        from ..debug.rootcause import parse_asan_report
        dos_cand = None                                      # first DoS crash, used only if no mem fault
        for cr in res.get("crashes", []):
            rep = cr.get("report") or ""
            cls = parse_asan_report(rep) or {}
            if not _memory_fault(rep, cls):
                if dos_cand is None:                         # DoS lane: keep the first reachable abort/
                    dcw = _dos_class(rep)                    # signal as a fallback (memory wins if found)
                    if dcw:
                        dos_cand = (cr.get("input"), rep, dcw)
                continue                                     # not a mem fault; try next crash
            neg = _asan_replay(fuzz_binary, b"", lib_dirs, timeout=min(30.0, timeout))
            if neg["faulted"]:
                out["reason"] = "negative control (empty input) also faulted -- not attributable"
                return out
            out.update(confirmed=True, input=cr.get("input"), report=rep, source=cls.get("source"))
            out["class"] = cls.get("class") or cls.get("cwe")
            return out
        # No memory fault, but a reachable assertion / fatal signal -> a confirmed DoS (CWE-617/248),
        # gated by the same negative control: the empty input must NOT also DoS, so the crash is
        # attributable to the fuzzed bytes rather than a broken harness.
        if dos_cand is not None:
            neg = _asan_replay(fuzz_binary, b"", lib_dirs, timeout=min(30.0, timeout))
            if not neg["faulted"] and not neg.get("dos"):
                out.update(confirmed_dos=True, input=dos_cand[0], report=dos_cand[1],
                           dos_class=dos_cand[2], impact="dos")
                out["reason"] = f"reachable {dos_cand[2]} (remote DoS); no memory-safety fault"
                return out
            out["reason"] = "DoS crash but the negative control also crashed -- not attributable"
        # Distinguish "ran and found nothing" from "could not launch the harness" -- 0 executions
        # means the binary never fuzzed (a run/link problem), which must NOT read as a clean no-find.
        if out["execs"] <= 1:
            out["reason"] = (f"smart-fuzz produced {out['execs']} executions -- the harness did not run "
                             f"(check the shared-lib link); not a clean no-find")
        else:
            out["reason"] = f"no crash in {int(timeout)}s of smart fuzzing ({out['execs']} executions)"
        return out
    finally:
        if own_wd:
            import shutil
            shutil.rmtree(wd, ignore_errors=True)


def _rung_smartfuzz(h, *, timeout, ctx):
    # needs the SHARED ASan build (coverage-guided libFuzzer); the floor rung below concolic.
    if not h.get("fuzz_binary"):
        return {"confirmed": False, "rung": "smart-fuzz", "skipped": True,
                "reason": "no shared fuzz build"}
    return smartfuzz_confirm(h["fuzz_binary"], lib_dirs=h.get("lib_dirs"), seeds=h.get("seeds"),
                             input_size=int(h.get("input_size", 4096)), timeout=timeout,
                             workdir=(ctx.scratch() / f"sf-{h.get('name', 'h')}") if ctx else None)


_LADDER = (_rung_template, _rung_concolic, _rung_smartfuzz)


def confirm_ladder(harnesses, *, timeout_per: int = 120, ctx=None, attempts_out=None,
                   deadline: float | None = None) -> list:
    """Run the non-fuzzing confirmation ladder over a set of harness descriptors and return the
    CONFIRMED bugs. Each harness is {name, explore_binary, replay_binary?, lib_dirs?, input_size?,
    harness_fn?, targets?}. For each harness the rungs are tried smartest-first; the first that
    confirms wins. Returns [{harness, confirmed:True, input, report, source, class, rung}] -- the
    proven PoCs, each tagged with the rung that proved it. Deduped by (source, class) so the same
    defect reached through two harnesses is reported once (the first harness that proved it).

    If `attempts_out` is a list, every rung attempt is appended to it as
    {harness, rung, outcome: confirmed|no-confirm|skipped|error, reason, execs?} -- the honest account
    of what ran, what was skipped and why, so a '0 confirmed' is never silent about its cause.

    `deadline` (an absolute time.monotonic() value) is the HARD overall budget: the ladder runs
    multiple rungs across every harness, so without it their sum (harnesses x rungs x timeout_per)
    overruns the caller's slice. Once the deadline passes the remaining harnesses/rungs are skipped
    (recorded as such), and each rung's timeout is clamped to the time that is actually left."""
    import time as _t
    out: list = []
    seen: set = set()
    for h in harnesses:
        if deadline is not None and _t.monotonic() >= deadline:
            if attempts_out is not None:
                attempts_out.append({"harness": h.get("name"), "rung": "ladder",
                                     "outcome": "skipped", "reason": "stage time budget reached"})
            continue
        for rung in _LADDER:
            if deadline is not None and _t.monotonic() >= deadline:
                break
            per = timeout_per
            if deadline is not None:
                per = max(5, min(timeout_per, int(deadline - _t.monotonic())))
            try:
                r = rung(h, timeout=per, ctx=ctx)
            except Exception as e:                           # noqa: BLE001 -- a rung must never abort
                r = {"confirmed": False, "rung": getattr(rung, "__name__", "?").replace("_rung_", ""),
                     "reason": f"error: {e}", "error": True}
            r = r or {"confirmed": False, "rung": "?", "skipped": True, "reason": "no result"}
            if attempts_out is not None:
                outcome = ("confirmed" if r.get("confirmed") else
                           "confirmed-dos" if r.get("confirmed_dos") else
                           "error" if r.get("error") else
                           "skipped" if r.get("skipped") else "no-confirm")
                rec = {"harness": h.get("name"), "rung": r.get("rung", "?"), "outcome": outcome,
                       "reason": r.get("reason")}
                if r.get("execs") is not None:
                    rec["execs"] = r.get("execs")
                if r.get("entry"):
                    rec["entry"] = r.get("entry")
                attempts_out.append(rec)
            if r.get("confirmed"):
                key = (r.get("source"), r.get("class"))
                if key in seen:
                    break
                seen.add(key)
                # WHICH BINARY proved it, so the PoC can be replayed against that binary and not
                # against the ingested program (which may never reach this harness's entry).
                out.append({"harness": h.get("name"), **r,
                            "binary": _rung_binary(h, r.get("rung")),
                            "lib_dirs": list(h.get("lib_dirs") or [])})
                break
            if r.get("confirmed_dos"):
                # The DoS lane: a reachable assertion / fatal signal. A weaker finding than a memory
                # fault, so it never short-circuits the ladder (a later rung may still find memory
                # corruption), but it IS collected as a confirmed CWE-617/248 PoC, deduped per
                # (harness, dos_class).
                dkey = ("dos", h.get("name"), r.get("dos_class"))
                if dkey not in seen:
                    seen.add(dkey)
                    out.append({"harness": h.get("name"), **r,
                                "binary": _rung_binary(h, r.get("rung")),
                                "lib_dirs": list(h.get("lib_dirs") or [])})
                # do not break: keep trying rungs for a stronger (memory) confirmation
    return out


def _rung_binary(h: dict, rung) -> str | None:
    """The ASan build a confirmed rung replayed its input against."""
    if rung == "smart-fuzz":
        return h.get("fuzz_binary")
    if rung == "concolic":
        return h.get("replay_binary") or h.get("explore_binary")
    return h.get("replay_binary") or h.get("fuzz_binary")
