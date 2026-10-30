"""Step 5 (doc 52 §3c): a hybrid fuzzing fallback that runs ALONGSIDE the directed solver.

The directed symbolic engine stalls on deep or heavily-structured input (a protocol parser, a
multi-line format); robustness evidence (AIxCC) is blunt that plain fuzzing triggers most C bugs.
So when budget remains, fuzz the target -- seeded with the inputs the driver already REACHED the
sinks with -- and hand every crashing input back to the SAME validator. The fuzzer only proposes
candidate inputs; it can never produce a confirmation, so the 0-false-confirmation invariant holds.

Source targets are fuzzed on an afl-instrumented build (fast, reliable); a bare binary falls back to
AFL's qemu-mode.
"""
from __future__ import annotations

import glob
import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable, List

from .validate import Target

MAX_CRASHES = 12            # most unique crashing inputs to hand the validator


def available() -> bool:
    from ..analyze.fuzz.aflpp import locate_afl
    return locate_afl() is not None


def fuzz(target: Target, seeds: List[bytes], *, seconds: int,
         log: Callable[[str], None] = lambda _m: None) -> List[bytes]:
    """Run a bounded AFL++ campaign and return up to MAX_CRASHES unique crashing inputs."""
    from ..analyze.fuzz.aflpp import locate_afl, run_campaign
    afl = locate_afl()
    if afl is None or target.mode not in ("file", "stdin"):
        return []
    exe = target.afl_exe or target.exe
    qemu = target.afl_exe is None               # no instrumented build: fuzz the plain ELF via qemu
    tmp = Path(tempfile.mkdtemp(prefix="lykos-fuzz-"))
    sd, od = tmp / "seeds", tmp / "out"
    sd.mkdir()
    n = 0
    seen = set()
    for s in seeds:
        s = s.split(b"\0", 1)[0] if target.mode == "arg" else s
        if not s or s in seen:
            continue
        seen.add(s)
        (sd / f"s{n}").write_bytes(s)
        n += 1
        if n >= 32:
            break
    if n == 0:
        (sd / "s0").write_bytes(b"A" * 16 + b"\n")      # AFL needs a non-empty corpus
    argv_template = list(target.argv) if target.mode == "file" else \
        [a for a in target.argv if a != "@@"] or None
    cmplog = target.afl_cmplog if (target.afl_exe and target.afl_cmplog) else None
    try:
        run_campaign(afl, str(exe), str(sd), str(od), seconds=int(seconds), mode=target.mode,
                     qemu=qemu, argv_template=argv_template, cmplog=cmplog)
    except Exception as e:                       # noqa: BLE001 - a fuzz failure is "no candidates"
        log(f"fuzz campaign error: {e}")
        return []
    crashes, out = [], set()
    for f in sorted(glob.glob(str(od / "**" / "crashes" / "id*"), recursive=True)):
        try:
            data = Path(f).read_bytes()
        except OSError:
            continue
        if data and data not in out:
            out.add(data)
            crashes.append(data)
        if len(crashes) >= MAX_CRASHES:
            break
    shutil.rmtree(tmp, ignore_errors=True)
    return crashes
