"""AFL++ coverage-guided fuzzing backend (qemu-mode), graceful when not installed.

Located via LYKOS_AFL / AFL_PATH / PATH. We run afl-fuzz for a fixed wall-clock budget
(`-V`), then harvest the crashing inputs it saved and hand them to our own confirm/
minimize/finding pipeline. AFL++ (with afl-qemu) ships in the full offline bundle.
"""
from __future__ import annotations

import hashlib
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
    return locate_qemu_trace_for(afl, None)


def _trace_candidates(afl: Path, arch: Optional[str]):
    """Where an afl-qemu-trace for `arch` might be, strongest first.

    One machine can hold several: afl-qemu-trace is an emulator and each build targets a
    single guest, so covering ARM and AArch64 and x86-64 means three binaries. AFL++ installs
    them all under the same name, which is why they have to be kept apart by directory or by
    suffix -- and why looking only for the bare name finds whichever was installed last.
    """
    here = Path(afl).parent if afl else None
    if arch:
        # an explicit override wins, and names the file directly
        env = os.environ.get("LYKOS_AFL_QEMU_" + arch.upper().replace("-", "_"))
        if env:
            yield Path(env)
        # ...then arch-suffixed neighbours, in both our spelling and qemu's
        spellings = {arch, {"x86-64": "x86_64", "x86": "i386"}.get(arch, arch)}
        for sp in sorted(spellings):
            for d in ([here] if here else []) + [None]:
                name = f"afl-qemu-trace-{sp}"
                cand = (d / name) if d else shutil.which(name)
                if cand:
                    yield Path(cand)
    if here:
        yield here / "afl-qemu-trace"
    found = shutil.which("afl-qemu-trace")
    if found:
        yield Path(found)


def locate_qemu_trace_for(afl: Optional[Path], arch: Optional[str]) -> Optional[Path]:
    """An afl-qemu-trace that can run `arch`, or None.

    When `arch` is given the candidate's GUEST is verified before it is accepted -- a binary
    named afl-qemu-trace-arm that was actually built for something else would otherwise abort
    at the fork-server handshake, which is the failure this whole path exists to avoid.
    """
    seen = set()
    for cand in _trace_candidates(afl, arch):
        key = str(cand)
        if key in seen or not cand.exists():
            continue
        seen.add(key)
        if arch is None or qemu_trace_arch(cand) == arch:
            return cand
    return None


def stage_qemu_trace(trace: Path, workdir) -> str:
    """Put `trace` where afl-fuzz will find it, and return the AFL_PATH to use.

    afl-fuzz looks for its helper under the single name `afl-qemu-trace` (in AFL_PATH, then
    its own directory, then PATH). A machine holding one emulator per guest cannot satisfy
    that with names alone, so the chosen one is linked under the expected name in a private
    directory and AFL_PATH is pointed at it. Nothing is copied: a symlink keeps the 9 MB
    binary in one place and makes the indirection visible if anyone looks.
    """
    d = Path(workdir) / "aflpath"
    d.mkdir(parents=True, exist_ok=True)
    link = d / "afl-qemu-trace"
    if link.exists() or link.is_symlink():
        link.unlink()
    try:
        link.symlink_to(Path(trace).resolve())
    except OSError:
        shutil.copy2(Path(trace).resolve(), link)     # no symlinks here (some sandboxes)
        link.chmod(0o755)
    return str(d)


def is_sanitizer_build(data: bytes) -> bool:
    """Is this ELF built with AddressSanitizer/UBSan? Cheap byte-scan for the runtime's marker
    symbol. Sanitizer builds need special AFL handling (no memory cap, longer fork-server
    startup), which must NOT be applied to ordinary targets -- an uncapped ordinary target can
    allocate without bound and OOM the host."""
    return b"__asan_init" in data or b"__asan_report" in data or b"__ubsan_handle" in data


def run_campaign(afl: Path, exe, seeds_dir, out_dir, *, seconds: int = 30,
                 mode: str = "file", qemu: bool = True, afl_path: Optional[str] = None,
                 cmplog: Optional[Path] = None, argv_template=None):
    # NOTE: AFL keeps its default memory cap here. Sanitizer builds (which need `-m none`) are
    # deliberately NOT run through this path -- an uncapped run OOM'd the host -- they are fuzzed
    # by the sandbox `fuzz`/`directed_fuzz` stages under rlimits instead (see coverage_stage).
    # `argv_template` is the discovered invocation (e.g. ['draw', '@@'] for `mutool draw @@`): a
    # dispatch/parameter-driven tool parses nothing without it, so AFL would fuzz only the usage
    # banner. AFL recognises the literal '@@' as the input-file slot; for stdin mode there is none.
    if argv_template:
        tail = [str(a) for a in argv_template if not (mode != "file" and a == "@@")]
        target = [str(exe)] + tail
    else:
        target = [str(exe)] + (["@@"] if mode == "file" else [])
    cmd = [str(afl)] + (["-Q"] if qemu else []) + \
        ["-i", str(seeds_dir), "-o", str(out_dir), "-V", str(int(seconds)), "--"] + target
    env = dict(os.environ)
    if afl_path:
        env["AFL_PATH"] = afl_path
    env.update({
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_UI": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_BENCH_JUST_ONE": "0",
    })
    if qemu:
        # Input-to-state (COMPCOV): the qemu tracer instruments comparisons and splits multi-byte
        # ones, so AFL learns the magic value / checksum / length a branch demands and reaches code a
        # blind mutator never would -- deterministically, with no symbolic execution. Level 2 also
        # intercepts strcmp/memcmp-family calls. Measured on gif2rgb: 751 -> 1534 edges. The compcov
        # plugin is built into qemuafl, so this is free when present and simply a no-op if not.
        env.setdefault("AFL_COMPCOV_LEVEL", "2")
    elif cmplog is not None:
        # Native (afl-cc-instrumented) build: CmpLog is the same idea via a second, cmplog-
        # instrumented copy of the target that AFL runs alongside the main one (`-c <binary>`).
        cmd = [cmd[0], "-c", str(cmplog)] + cmd[1:]
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


def campaign_stats(out_dir) -> dict:
    """AFL's own fuzzer_stats: how much work actually happened.

    Without this a campaign reports "0 crashes" whether it executed two million inputs or
    none, and those are opposite conclusions -- one says the target looks robust, the other
    says nothing ran. afl-fuzz can also exit 0 having aborted, which `campaign_failed` catches,
    but a campaign that merely ran badly (a seed the target rejects, a timeout per exec that
    swallows the budget) leaves no marker at all.
    """
    out: dict = {}
    for name in ("fuzzer_stats", "default/fuzzer_stats"):
        f = Path(out_dir) / name
        if not f.exists():
            continue
        try:
            for line in f.read_text(errors="replace").splitlines():
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k in ("execs_done", "execs_per_sec", "unique_crashes", "corpus_count",
                         "unique_hangs", "cycles_done", "paths_total",
                         # edge coverage: AFL's own measure of how much of the target the
                         # campaign actually exercised. `bitmap_cvg` is a percentage of the
                         # shared-memory edge map filled; `edges_found` is the absolute count.
                         "bitmap_cvg", "edges_found"):
                    out[k] = v
        except OSError:
            pass
        if out:
            break
    return out


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
            # Full-content digest, not a 64-byte prefix: two distinct crashing inputs of equal
            # length that share their first 64 bytes (common for one file format) hashed to the
            # same key and one was dropped before it could be replayed.
            key = hashlib.sha256(data).digest()
            if key in seen:
                continue
            seen.add(key)
            inputs.append(data)
    return inputs
