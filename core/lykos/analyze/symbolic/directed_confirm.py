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
import subprocess
import tempfile
from pathlib import Path

from . import concolic as _concolic


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
    # An ASan-reported fault is the sound signal (a parsed sanitizer class, or the banner). The
    # return code alone is NOT trusted -- libFuzzer can exit non-zero for benign reasons.
    faulted = bool(cls) or "AddressSanitizer" in rep or "SUMMARY: UndefinedBehaviorSanitizer" in rep
    return {"faulted": faulted, "report": rep, "source": cls.get("source"),
            "cls": cls.get("class") or cls.get("cwe")}


def concolic_confirm(explore_binary, replay_binary, *, harness_fn: str = "LLVMFuzzerTestOneInput",
                     input_size: int = 256, lib_dirs=None, targets=None, target_syms=None,
                     load_libs=None, timeout: int = 120, ctx=None) -> dict:
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
           "rung": "smart-fuzz", "reason": None, "execs": 0}
    own_wd = workdir is None
    wd = Path(tempfile.mkdtemp(prefix="lykos-sf-")) if own_wd else Path(workdir)
    try:
        corpus = list(seeds or []) + [b"A" * n for n in (16, 64, 256, 1024)]
        res = run_libfuzzer(fuzz_binary, wd, seconds=int(timeout), max_len=int(input_size),
                            corpus=corpus, lib_dirs=lib_dirs)
        out["execs"] = int(res.get("execs") or 0)            # honest telemetry: did the harness run?
        from ..debug.rootcause import parse_asan_report
        for cr in res.get("crashes", []):
            rep = cr.get("report") or ""
            cls = parse_asan_report(rep) or {}
            if not (cls or "AddressSanitizer" in rep):
                continue                                     # oom/timeout artifact, not a fault
            neg = _asan_replay(fuzz_binary, b"", lib_dirs, timeout=min(30.0, timeout))
            if neg["faulted"]:
                out["reason"] = "negative control (empty input) also faulted -- not attributable"
                return out
            out.update(confirmed=True, input=cr.get("input"), report=rep, source=cls.get("source"))
            out["class"] = cls.get("class") or cls.get("cwe")
            return out
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


def confirm_ladder(harnesses, *, timeout_per: int = 120, ctx=None, attempts_out=None) -> list:
    """Run the non-fuzzing confirmation ladder over a set of harness descriptors and return the
    CONFIRMED bugs. Each harness is {name, explore_binary, replay_binary?, lib_dirs?, input_size?,
    harness_fn?, targets?}. For each harness the rungs are tried smartest-first; the first that
    confirms wins. Returns [{harness, confirmed:True, input, report, source, class, rung}] -- the
    proven PoCs, each tagged with the rung that proved it. Deduped by (source, class) so the same
    defect reached through two harnesses is reported once (the first harness that proved it).

    If `attempts_out` is a list, every rung attempt is appended to it as
    {harness, rung, outcome: confirmed|no-confirm|skipped|error, reason, execs?} -- the honest account
    of what ran, what was skipped and why, so a '0 confirmed' is never silent about its cause."""
    out: list = []
    seen: set = set()
    for h in harnesses:
        for rung in _LADDER:
            try:
                r = rung(h, timeout=timeout_per, ctx=ctx)
            except Exception as e:                           # noqa: BLE001 -- a rung must never abort
                r = {"confirmed": False, "rung": getattr(rung, "__name__", "?").replace("_rung_", ""),
                     "reason": f"error: {e}", "error": True}
            r = r or {"confirmed": False, "rung": "?", "skipped": True, "reason": "no result"}
            if attempts_out is not None:
                outcome = ("confirmed" if r.get("confirmed") else
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
                out.append({"harness": h.get("name"), **r})
                break
    return out
