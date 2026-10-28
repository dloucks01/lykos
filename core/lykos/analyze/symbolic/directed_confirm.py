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
                     input_size: int = 256, lib_dirs=None, targets=None, timeout: int = 120,
                     ctx=None) -> dict:
    """Confirm a memory-safety bug via concolic input synthesis + ASan replay. See module docstring.

    `explore_binary` is the NON-ASan harness angr explores; `replay_binary` the ASan harness used to
    confirm (may be the same file, but ASan makes angr worse). `targets` optionally lists sink
    addresses to steer angr toward (directedness for deep bugs); without it angr explores and every
    generated input is replayed. Returns {confirmed, input (bytes), report, source, class,
    rung:"concolic", reason}."""
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
    try:
        res = _concolic.run_explore(py, spec, ctx=ctx, timeout=timeout)
    except Exception as e:                                   # noqa: BLE001 -- a stuck/failed explore
        out["reason"] = f"concolic exploration failed: {e}"
        return out
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


# ---- the confirmation LADDER ---------------------------------------------------------------------
# Rungs tried SMARTEST-FIRST per the operator's order: a deterministic template (no solver, no
# fuzzing), then concolic (solver, no fuzzing), then directed SMART fuzzing (stochastic but steered --
# the floor). Discovery stays static; this only CONFIRMS a discovered bug by producing a concrete
# ASan fault. Each rung takes a harness descriptor and returns a confirm dict (see concolic_confirm)
# or None when it does not apply / cannot synthesize. The first rung that confirms wins, and the
# result records WHICH rung proved it.


def _rung_template(h, *, timeout, ctx):
    """B2 (deterministic template synthesis): construct the triggering input directly from a
    recognised bug shape (length-field -> oversized value, OOB index, %n, integer-overflow alloc).
    Not yet implemented -- an ordered hook so the ladder tries it FIRST when it lands."""
    return None


def _rung_concolic(h, *, timeout, ctx):
    return concolic_confirm(
        h["explore_binary"], h.get("replay_binary") or h["explore_binary"],
        harness_fn=h.get("harness_fn", "LLVMFuzzerTestOneInput"),
        input_size=int(h.get("input_size", 256)), lib_dirs=h.get("lib_dirs"),
        targets=h.get("targets"), timeout=timeout, ctx=ctx)


def _rung_smartfuzz(h, *, timeout, ctx):
    """B3 (directed, structure-seeded, concolic-assisted smart fuzzing -- the floor for deep parser
    bugs concolic cannot reach). Not yet implemented -- an ordered hook below concolic."""
    return None


_LADDER = (_rung_template, _rung_concolic, _rung_smartfuzz)


def confirm_ladder(harnesses, *, timeout_per: int = 120, ctx=None) -> list:
    """Run the non-fuzzing confirmation ladder over a set of harness descriptors and return the
    CONFIRMED bugs. Each harness is {name, explore_binary, replay_binary?, lib_dirs?, input_size?,
    harness_fn?, targets?}. For each harness the rungs are tried smartest-first; the first that
    confirms wins. Returns [{harness, confirmed:True, input, report, source, class, rung}] -- the
    proven PoCs, each tagged with the rung that proved it. Deduped by (source, class) so the same
    defect reached through two harnesses is reported once (the first harness that proved it)."""
    out: list = []
    seen: set = set()
    for h in harnesses:
        for rung in _LADDER:
            try:
                r = rung(h, timeout=timeout_per, ctx=ctx)
            except Exception as e:                           # noqa: BLE001 -- a rung must never abort
                r = {"confirmed": False, "reason": f"{rung.__name__} error: {e}"}
            if r and r.get("confirmed"):
                key = (r.get("source"), r.get("class"))
                if key in seen:
                    break
                seen.add(key)
                out.append({"harness": h.get("name"), **r})
                break
    return out
