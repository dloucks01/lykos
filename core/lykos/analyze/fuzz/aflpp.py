"""AFL++ coverage-guided fuzzing backend (qemu-mode), graceful when not installed.

Located via LYKOS_AFL / AFL_PATH / PATH. We run afl-fuzz for a fixed wall-clock budget
(`-V`), then harvest the crashing inputs it saved and hand them to our own confirm/
minimize/finding pipeline. AFL++ (with afl-qemu) ships in the full offline bundle.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def locate_afl(config: Optional[str] = None) -> Optional[Path]:
    for env in ("LYKOS_AFL", "AFL_PATH"):
        v = os.environ.get(env)
        if v:
            p = Path(v)
            cand = p if p.name == "afl-fuzz" else p / "afl-fuzz"
            if cand.exists():
                return cand
    if config:
        p = Path(config)
        if p.exists():
            return p
    w = shutil.which("afl-fuzz")
    return Path(w) if w else None


# qemu names its guest architecture in its own version banner: "qemu-aarch64 version 5.2.50".
# That is the ONLY reliable way to ask what an afl-qemu-trace can run, because the binary
# itself is always built for the HOST -- it is an emulator. Reading `file` output and seeing
# "ELF 64-bit x86-64" says nothing about the guest, and concluding otherwise is how this
# platform ended up blocking coverage-guided fuzzing on the one architecture its installed
# afl-qemu-trace could actually drive, while recommending it for the one that aborts at the
# fork-server handshake.
_QEMU_GUEST = re.compile(rb"qemu-([a-z0-9_]+)\s+version")
# qemu's spelling -> ours (the inverse of sandbox._QEMU)
_GUEST_ARCH = {
    "x86_64": "x86-64", "i386": "x86", "aarch64": "aarch64", "arm": "arm",
    "mips": "mips", "mipsel": "mips", "mips64": "mips64", "mips64el": "mips64",
    "ppc": "ppc", "ppc64": "ppc64", "ppc64le": "ppc64", "riscv32": "riscv32",
    "riscv64": "riscv64", "s390x": "s390x", "sparc": "sparc", "sparc64": "sparc64",
    "sh4": "sh4", "m68k": "m68k", "loongarch64": "loongarch64", "hppa": "hppa",
    "alpha": "alpha", "xtensa": "xtensa", "microblaze": "microblaze",
}
_guest_cache: dict = {}


def qemu_trace_arch(trace: Optional[Path]) -> Optional[str]:
    """Which guest architecture this afl-qemu-trace emulates, or None if it cannot say.

    Cached: the capabilities endpoint asks once per target, and this is a subprocess.
    """
    if trace is None:
        return None
    key = str(trace)
    if key in _guest_cache:
        return _guest_cache[key]
    arch = None
    try:
        r = subprocess.run([key, "--version"], capture_output=True, timeout=10)
        m = _QEMU_GUEST.search((r.stdout or b"") + (r.stderr or b""))
        if m:
            arch = _GUEST_ARCH.get(m.group(1).decode("ascii", "replace").lower())
    except Exception:
        arch = None
    _guest_cache[key] = arch
    return arch


def locate_qemu_trace(afl: Path) -> Optional[Path]:
    """afl-qemu-trace, which `-Q` (binary-only) mode requires.

    Shipped separately from afl-fuzz -- Ubuntu's afl++ package does NOT include it, it comes
    from AFL++'s qemu_mode/build_qemu_support.sh. Without it `-Q` dies at the fork-server handshake.
    """
    cand = Path(afl).parent / "afl-qemu-trace"
    if cand.exists():
        return cand
    found = shutil.which("afl-qemu-trace")
    return Path(found) if found else None


def run_campaign(afl: Path, exe, seeds_dir, out_dir, *, seconds: int = 30,
                 mode: str = "file", qemu: bool = True):
    target = [str(exe)] + (["@@"] if mode == "file" else [])
    cmd = [str(afl)] + (["-Q"] if qemu else []) + \
        ["-i", str(seeds_dir), "-o", str(out_dir), "-V", str(int(seconds)), "--"] + target
    env = dict(os.environ)
    env.update({
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_UI": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_BENCH_JUST_ONE": "0",
    })
    return subprocess.run(cmd, env=env, capture_output=True, timeout=int(seconds) + 90)


# afl-fuzz exits 0 after printing these, so the return code alone does not tell you it failed
_ABORTED = (b"PROGRAM ABORT", b"Fork server handshake failed",
            b"handshake with the injected code")


def campaign_failed(proc) -> Optional[str]:
    """A one-line reason the campaign did not actually fuzz, or None if it ran.

    afl-fuzz can abort having produced no queue and no crashes, and STILL exit 0. Reading
    only the crash directory then reports a clean "0 crashes" run that never executed the
    target once -- which is indistinguishable from "this binary has no bugs".
    """
    err = (proc.stderr or b"") + (proc.stdout or b"")
    for marker in _ABORTED:
        if marker in err:
            tail = err.split(b"PROGRAM ABORT")[-1][:200].decode("utf-8", "replace").strip()
            return f"afl-fuzz aborted: {tail or marker.decode()}"
    if proc.returncode not in (0, None):
        return f"afl-fuzz exited {proc.returncode}"
    return None


def harvest_crashes(out_dir) -> list:
    """Return de-duplicated crashing inputs from an AFL++ output directory."""
    out = Path(out_dir)
    dirs = list(out.glob("*/crashes")) + [out / "crashes"]
    seen, inputs = set(), []
    for cd in dirs:
        if not cd.is_dir():
            continue
        for f in sorted(cd.iterdir()):
            if not f.is_file() or f.name.startswith("README"):
                continue
            try:
                data = f.read_bytes()
            except OSError:
                continue
            key = (len(data), data[:64])
            if key in seen:
                continue
            seen.add(key)
            inputs.append(data)
    return inputs
