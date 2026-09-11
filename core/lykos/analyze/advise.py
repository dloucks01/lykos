"""What to do next with a target -- as a real function, not view code.

This logic used to live in the GUI (`recommendFuzz()` in index.html), which meant the API
and CLI could not reach it. Driving the pipeline over the API therefore meant guessing, and
guessing wrong is not hypothetical: a scripted run against jhead chose plain black-box
fuzzing, burned 98,500 executions with `unique: 0`, and found nothing -- while the GUI was
sitting there saying "this is a parser, attach a seed and use a structure model".

It also fixes what that GUI logic got wrong. It recommended `directed` fuzzing whenever
static findings existed and never mentioned coverage-guided fuzzing at all. But `directed`
is still BLIND mutation that merely biases toward sink addresses: measured on jhead it
managed ~195 execs/sec with no coverage feedback and found nothing in 505 seconds, where
AFL++ on the same program sustained ~15,000 execs/sec WITH edge coverage and found five
SIGSEGV crashes in 60. Coverage feedback is the single biggest lever on a real target, so
it is now the first choice whenever the backend is actually usable.
"""
from __future__ import annotations

import re
from typing import Optional

# imports that tell us how the program takes its input
_FILE_RE = re.compile(r"fopen|fread|open64|mmap|freopen|getline|fseek", re.I)
_STDIN_RE = re.compile(r"\bread\b|fgets|scanf|getchar|\bgets\b", re.I)


def _input_mode(imports: list) -> tuple:
    """(mode, human description) from the import table."""
    blob = " ".join(imports or [])
    if _FILE_RE.search(blob):
        return "file", "a file parser"
    if _STDIN_RE.search(blob):
        return "stdin", "stdin-driven"
    return "arg", "argv/none"


def fuzz_backend(afl_usable: bool, static_findings: int) -> tuple:
    """(stage, why) -- which fuzzer to reach for first.

    Coverage feedback beats sink-direction by a wide margin on real code, and unlike
    `directed` it does not need the target decompiled and detected first, so it also
    shortens the path to the first crash.
    """
    if afl_usable:
        return ("coverage_fuzz",
                "AFL++ is available — coverage-guided fuzzing explores new paths instead of "
                "mutating blindly, and needs no prior decompilation")
    if static_findings > 0:
        return ("directed_fuzz",
                f"no coverage backend; {static_findings} static finding"
                f"{'s' if static_findings != 1 else ''} to bias execs toward")
    return ("fuzz",
            "no coverage backend and no static findings yet — black-box mutation is the "
            "only option; expect low yield on structured input")


def advise(*, imports: list, functions: int, findings: int, seeds: int,
           has_format: bool, afl_usable: bool, crashes: int = 0,
           pocs: int = 0) -> dict:
    """A recommendation and an ORDERED PLAN for this target.

    The plan is dynamic-first on purpose. Running decompile -> detect -> maybe-fuzz produces
    a wall of undemonstrated findings: on jhead that was 27 findings, 0 confirmed, 0
    poc-backed. Leading with execution means static analysis arrives to EXPLAIN something
    real rather than to speculate, and anything never reached at runtime ranks below
    anything that was.
    """
    mode, shape = _input_mode(imports)
    backend, backend_why = fuzz_backend(afl_usable, findings)
    file_parser = mode == "file"

    checks = [
        {"ok": seeds > 0 or not file_parser,
         "text": (f"seeds — {seeds} attached" if seeds else
                  "seeds — attach a valid sample; a parser rejects random bytes before it "
                  "reaches any interesting code")},
        {"ok": has_format or not file_parser or backend == "coverage_fuzz",
         "text": ("structure model — set" if has_format else
                  "structure model — lets the mutator keep length and payload coherent "
                  "(less critical with coverage feedback, which learns structure)")},
        {"ok": functions > 0,
         "text": (f"decompiled — {functions} functions" if functions else
                  "decompiled — not yet; needed to explain a crash, not to find one")},
        {"ok": findings > 0,
         "text": (f"static findings — {findings}" if findings else
                  "static findings — none yet")},
    ]

    plan = [{"stage": backend, "why": backend_why, "params": {"input_mode": mode},
             "ready": True}]
    if crashes or pocs:
        plan += [
            {"stage": "root_cause", "why": "name the faulting function and CWE",
             "params": {"input_mode": mode}, "ready": True},
            {"stage": "build_poc", "why": "turn the crashing input into a verified, "
                                          "shareable reproducer", "params": {"input_mode": mode},
             "ready": True},
            {"stage": "poc_primitive", "why": "does the crash give instruction-pointer "
                                              "control?", "params": {"input_mode": mode},
             "ready": True},
        ]
    else:
        plan.append({"stage": "root_cause", "why": "runs once a crashing input exists",
                     "params": {"input_mode": mode}, "ready": False})
    plan += [
        {"stage": "disassemble", "why": "explain what execution found, and enable the "
                                        "static channels", "params": {},
         "ready": True, "done": functions > 0},
        {"stage": "detect_cwe", "why": "static findings — supporting evidence, ranked below "
                                       "anything demonstrated", "params": {},
         "ready": functions > 0, "done": findings > 0},
    ]

    headline = (f"Input looks like {shape}. Start with {backend} — {backend_why}."
                if not crashes else
                f"Input looks like {shape}. {crashes} crash"
                f"{'es' if crashes != 1 else ''} already found — root-cause and package "
                f"{'them' if crashes != 1 else 'it'} before widening the search.")
    return {"input_mode": mode, "shape": shape, "backend": backend,
            "backend_why": backend_why, "headline": headline,
            "checks": checks, "plan": plan,
            "file_parser": file_parser, "afl_usable": afl_usable}


def afl_usable(afl_path: Optional[str] = None) -> bool:
    """Is coverage-guided fuzzing actually runnable here?

    Checks the qemu-mode helper too, not just afl-fuzz: `-Q` needs afl-qemu-trace, which
    ships separately, and without it a campaign aborts at the fork-server handshake while
    still exiting 0.
    """
    from .fuzz import aflpp
    afl = aflpp.locate_afl(afl_path)
    if afl is None:
        return False
    return aflpp.locate_qemu_trace(afl) is not None
