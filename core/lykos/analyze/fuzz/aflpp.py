"""AFL++ coverage-guided fuzzing backend (qemu-mode), graceful when not installed.

Located via LYKOS_AFL / AFL_PATH / PATH. We run afl-fuzz for a fixed wall-clock budget
(`-V`), then harvest the crashing inputs it saved and hand them to our own confirm/
minimize/finding pipeline. AFL++ (with afl-qemu) ships in the full offline bundle.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ... import observe

_log = logging.getLogger(__name__)


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
        observe.absorbed(_log, "keeping the default")
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


def _resolve_trace_binary(trace: Path) -> Path:
    """The REAL afl-qemu-trace ELF behind a relocatable shell wrapper.

    afl-fuzz `-Q` execs the trace as its fork-server QEMU and speaks a pipe protocol over fixed
    descriptors (198/199); a shell WRAPPER between afl and qemu breaks that handshake -- the exact
    "Fork server handshake failed" abort that killed EVERY coverage_fuzz run from the air-gap bundle,
    whose tools ship as `.wrappers/<name>` scripts (`exec "$r/usr/local/bin/<name>" "$@"`) to stay
    relocatable. The real binary is already relink-self-contained (the wrapper sets no LD_LIBRARY_PATH),
    so afl can exec it directly. Follow a non-ELF wrapper to the ELF it execs; leave a real ELF alone."""
    t = Path(trace)
    try:
        with open(t, "rb") as f:
            if f.read(4) == b"\x7fELF":
                return t                               # already the real emulator binary
    except OSError:
        return t
    try:
        text = t.read_text(errors="replace")
    except OSError:
        return t
    m = re.search(r'exec\s+"([^"]+)"', text)           # the wrapper's `exec "<path>" "$@"`
    if not m:
        return t
    tgt = m.group(1)
    # the bundle wrapper resolves its root as `$r = <wrapper_dir>/..` then execs "$r/usr/local/bin/..."
    root = t.resolve().parent.parent
    for var in ("$r", "${r}"):
        tgt = tgt.replace(var, str(root))
    cand = Path(tgt)
    if not cand.is_absolute():
        cand = (t.resolve().parent / cand)
    return cand if cand.exists() else t


def stage_qemu_trace(trace: Path, workdir) -> str:
    """Put `trace` where afl-fuzz will find it, and return the AFL_PATH to use.

    afl-fuzz looks for its helper under the single name `afl-qemu-trace` (in AFL_PATH, then
    its own directory, then PATH). A machine holding one emulator per guest cannot satisfy
    that with names alone, so the chosen one is linked under the expected name in a private
    directory and AFL_PATH is pointed at it. Nothing is copied: a symlink keeps the 9 MB
    binary in one place and makes the indirection visible if anyone looks.

    The link points at the REAL ELF, never a shell wrapper: afl's `-Q` fork server cannot hand
    the fork-server descriptors through a shell `exec` and aborts at the handshake (see
    `_resolve_trace_binary`) -- the air-gap bundle's relocatable `.wrappers/afl-qemu-trace-*`
    scripts tripped exactly this on every coverage_fuzz run.
    """
    d = Path(workdir) / "aflpath"
    d.mkdir(parents=True, exist_ok=True)
    link = d / "afl-qemu-trace"
    if link.exists() or link.is_symlink():
        link.unlink()
    real = _resolve_trace_binary(Path(trace).resolve())
    try:
        link.symlink_to(real)
    except OSError:
        shutil.copy2(real, link)                       # no symlinks here (some sandboxes)
        link.chmod(0o755)
    return str(d)


def is_sanitizer_build(data: bytes) -> bool:
    """Is this ELF built with a sanitizer runtime (ASan/UBSan/MSan/TSan/LSan)? Cheap byte-scan for
    the runtime's marker symbol. Sanitizer builds need special handling (no RLIMIT_AS cap, longer
    fork-server startup) which must NOT be applied to ordinary targets -- an uncapped ordinary
    target can allocate without bound and OOM the host.

    EVERY sanitizer runtime reserves a huge fixed virtual region at startup (ASan/MSan ~20TB of
    shadow; LSan's primary allocator a fixed 0x500000000000 base), so an RLIMIT_AS cap makes that
    mmap fail. For the aborting sanitizers (ASan/UBSan/MSan/TSan, built here with abort_on_error=1)
    the failure is a spurious pre-main SIGABRT that merely looks like a crash; for LeakSanitizer,
    which reports at a clean exit rather than aborting, the allocator CHECK-fails and the leak is
    NEVER reported -- so a standalone `-fsanitize=leak` build has to be recognised here or the PoC
    replay (`sandbox.run`) caps its address space and the leak silently vanishes. MSan/TSan/LSan are
    mutually exclusive with ASan, so their own `__{m,t,l}san_init` markers are what identify them
    (an LSan build carries no `__asan_init`)."""
    return (b"__asan_init" in data or b"__asan_report" in data or b"__ubsan_handle" in data
            or b"__msan_init" in data or b"__tsan_init" in data or b"__lsan_init" in data)


# Leading-bytes -> the file EXTENSION a format sniffer expects. Many parsers (mutool/ImageMagick/
# ffmpeg/...) pick their handler from the input's EXTENSION, and AFL's `.cur_input` has none -- so
# every mutation is rejected as an unknown format and the campaign never enters the parser. Giving
# AFL's input file the right suffix fixes it. Low-FP magics only.
_MAGIC_SUFFIX = [
    (b"%PDF", ".pdf"), (b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"), (b"GIF89a", ".gif"), (b"II*\x00", ".tif"), (b"MM\x00*", ".tif"),
    (b"BM", ".bmp"), (b"RIFF", ".webp"), (b"\x00\x00\x01\x00", ".ico"), (b"PK\x03\x04", ".zip"),
    (b"\x1f\x8b", ".gz"), (b"\xfd7zXZ\x00", ".xz"), (b"OggS", ".ogg"), (b"fLaC", ".flac"),
    (b"\x00\x00\x00\x18ftyp", ".mp4"), (b"<?xml", ".xml"), (b"<svg", ".svg"), (b"{", ".json"),
]


def input_suffix(seeds) -> str:
    """The input-file extension a format sniffer expects, voted from the seed corpus (most common
    magic wins). Empty when no seed matches a known magic -- then the current extension-less
    behaviour is kept."""
    from collections import Counter
    votes: Counter = Counter()
    for s in seeds or []:
        for magic, suf in _MAGIC_SUFFIX:
            if s[:len(magic)] == magic or (magic == b"RIFF" and s[:4] == b"RIFF" and s[8:12] == b"WEBP"):
                votes[suf] += 1
                break
    return votes.most_common(1)[0][0] if votes else ""


def run_campaign(afl: Path, exe, seeds_dir, out_dir, *, seconds: int = 30,
                 mode: str = "file", qemu: bool = True, afl_path: Optional[str] = None,
                 cmplog: Optional[Path] = None, argv_template=None, input_file=None,
                 qemu_ld_prefix: Optional[str] = None, converge: bool = False):
    # NOTE: AFL keeps its default memory cap here. Sanitizer builds (which need `-m none`) are
    # deliberately NOT run through this path -- an uncapped run OOM'd the host -- they are fuzzed
    # by the sandbox `fuzz`/`directed_fuzz` stages under rlimits instead (see coverage_stage).
    # `argv_template` is the discovered invocation (e.g. ['draw', '@@'] for `mutool draw @@`): a
    # dispatch/parameter-driven tool parses nothing without it, so AFL would fuzz only the usage
    # banner. AFL recognises the literal '@@' as the input-file slot; for stdin mode there is none.
    # AFL writes each test case to `.cur_input` (no extension) unless `-f FILE` is given. An
    # extension-sniffing parser (mutool, ImageMagick, ...) rejects an extensionless file as an
    # unknown format, so the whole campaign bounces off the front door; `input_file` (e.g.
    # `.../afl_input.pdf`) makes AFL write to a path WITH the right suffix, which @@ then points at.
    slot = str(input_file) if input_file else "@@"
    if argv_template:
        tail = [(slot if a == "@@" else str(a)) for a in argv_template
                if not (mode != "file" and a == "@@")]
        target = [str(exe)] + tail
    else:
        target = [str(exe)] + ([slot] if mode == "file" else [])
    ffile = ["-f", str(input_file)] if input_file else []
    # A generous, auto-extending per-exec timeout for qemu-mode: a real binary under qemu runs
    # several times slower than native, and AFL's default calibration timeout marks it "too slow"
    # and can abort the whole run. `<ms>+` keeps going and skips the slow entries instead of
    # failing. Native (instrumented) runs keep AFL's own auto-calibration.
    tmout = ["-t", "5000+"] if qemu else []
    cmd = [str(afl)] + (["-Q"] if qemu else []) + tmout + ffile + \
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
    if converge:
        # Run-to-convergence (doc 47 U1): stop when AFL has cycled through every path with no new
        # find for a while -- its own coverage-plateau signal -- instead of burning the full `-V`
        # ceiling. `-V` (set from `seconds`, the convergence ceiling) stays the hard upper bound, so
        # a target that never plateaus is still bounded. AFL's forkserver already handles a hung
        # target (per-exec timeout -> the input is marked a hang and skipped), so "stuck" is covered
        # natively. setdefault keeps an operator's explicit env.
        env.setdefault("AFL_EXIT_WHEN_DONE", "1")
    if qemu:
        # Input-to-state (COMPCOV): the qemu tracer instruments comparisons and splits multi-byte
        # ones, so AFL learns the magic value / checksum / length a branch demands and reaches code a
        # blind mutator never would -- deterministically, with no symbolic execution. Level 2 also
        # intercepts strcmp/memcmp-family calls. Measured on gif2rgb: 751 -> 1534 edges. The compcov
        # plugin is built into qemuafl, so this is free when present and simply a no-op if not.
        env.setdefault("AFL_COMPCOV_LEVEL", "2")
        # A LARGE binary takes far longer to reach the fork point under qemu than a small one --
        # qemu translates the path from _start through libc init before handing back, and the gate's
        # tiny ELF does this in well under a second while a 20-100MB real-world binary does not. The
        # DEFAULT fork-server init timeout then aborts the handshake ("Fork server handshake failed")
        # and the whole coverage campaign is lost before a single input runs. Scale the window with
        # the binary's size (base 120s, +3s per MB, capped at 600s) and skip the binary check -Q does
        # not need (the target is uninstrumented by design). setdefault, so an operator's env wins.
        try:
            _mb = Path(exe).stat().st_size / (1024 * 1024)
        except OSError:
            _mb = 0
        env.setdefault("AFL_FORKSRV_INIT_TMOUT", str(int(min(600_000, 120_000 + _mb * 3_000))))
        env.setdefault("AFL_SKIP_BIN_CHECK", "1")
        # The guest sysroot for a CROSS-ARCH target: afl-qemu-trace is qemu under the hood, so a
        # dynamically-linked foreign ELF needs QEMU_LD_PREFIX to find its loader -- without it the
        # fork-server handshake fails the instant the first exec hits the loader (the "Fork server
        # handshake failed" abort seen on a cross-arch campaign), and the whole campaign is lost.
        if qemu_ld_prefix:
            env.setdefault("QEMU_LD_PREFIX", qemu_ld_prefix)
            # QEMU_LD_PREFIX fixes the loader's default search, but a supplied sysroot is often a
            # FLAT directory of .so files (or uses a layout the loader's defaults miss). Put its
            # library dirs on LD_LIBRARY_PATH too -- the guest glibc loader reads it, so a
            # dynamically-linked target finds its deps regardless of how the sysroot is laid out.
            from ..dynamic.sandbox import _sysroot_lib_dirs
            _libdirs = [str(d) for d in _sysroot_lib_dirs(qemu_ld_prefix)]
            if _libdirs:
                env["LD_LIBRARY_PATH"] = ":".join(
                    _libdirs + ([env["LD_LIBRARY_PATH"]] if env.get("LD_LIBRARY_PATH") else []))
    elif cmplog is not None:
        # Native (afl-cc-instrumented) build: CmpLog is the same idea via a second, cmplog-
        # instrumented copy of the target that AFL runs alongside the main one (`-c <binary>`).
        cmd = [cmd[0], "-c", str(cmplog)] + cmd[1:]
    # afl-fuzz enforces `-V` itself; this is the backstop for when it does not. On a real HTB
    # binary under `-Q` it overran, the `TimeoutExpired` propagated out of `coverage_fuzz`, and
    # the stage was recorded as an ERROR -- which the real-corpus gate rejects outright, because
    # an error is never an acceptable outcome while a decline is. A campaign that overruns has
    # usually still written a queue and maybe crashes, so stop it and keep what it produced;
    # `campaign_failed` / `campaign_stats` / `harvest_crashes` then decide whether anything ran.
    #
    # Output goes to FILES, not pipes. Killing a process whose output is piped can block on a
    # surviving grandchild still holding the write end -- and afl under `-Q` has several (the
    # forkserver, the qemu tracer). Files cannot block, and survive the kill so the stderr tail
    # the caller reports is still there.
    import tempfile

    from ..dynamic import sandbox as _sandbox
    with tempfile.TemporaryDirectory(prefix="afl-io-") as _io:
        o_path, e_path = Path(_io) / "stdout", Path(_io) / "stderr"
        with o_path.open("wb") as _o, e_path.open("wb") as _e:
            proc = subprocess.Popen(cmd, env=env, stdout=_o, stderr=_e,
                                    start_new_session=True)
            try:
                rc = proc.wait(timeout=int(seconds) + 90)
                overran = False
            except subprocess.TimeoutExpired:
                _sandbox.kill_quietly(proc)
                rc, overran = -9, True
        out, err = o_path.read_bytes(), e_path.read_bytes()
    if overran:
        # Say so in the stderr the caller reports, so "0 crashes" from an overrun campaign is
        # never read as a clean negative.
        err += (b"\n[lykos] afl-fuzz overran its %ds budget by more than 90s and was stopped; "
                b"whatever queue and crashes it had written are kept\n" % int(seconds))
        # Report success ONLY if it actually produced something. An overrun that wrote a queue
        # really did fuzz, and calling that an error throws the work away; an overrun that wrote
        # nothing did NOT fuzz, and must not be reported as a clean "0 crashes" -- so it keeps
        # the kill status and falls into the caller's existing "no output" path. The two are
        # opposite conclusions and the return value has to tell them apart.
        if (out_dir / "default").exists() or (out_dir / "crashes").exists() \
                or (out_dir / "queue").exists():
            rc = 0
    return subprocess.CompletedProcess(cmd, rc, out, err)


# afl-fuzz exits 0 after printing these, so the return code alone does not tell you it failed
_ABORTED = (b"PROGRAM ABORT", b"Fork server handshake failed",
            b"handshake with the injected code")

_LD_MISSING = re.compile(
    rb"error while loading shared libraries:\s*([^\s:]+):\s*cannot open shared object", re.I)
_LD_SYMBOL = re.compile(rb"symbol lookup error:\s*(\S+):\s*undefined symbol:\s*(\S+)", re.I)
_QEMU_NOLOADER = re.compile(rb"Could not open ['\"](/lib[^'\"]*ld[^'\"]*)['\"]", re.I)


def _loader_failure_hint(err: bytes) -> Optional[str]:
    """If a child's stderr shows a dynamic-loader failure, a one-line cause + remedy; else None.
    This is the authoritative 'why the handshake failed' when the reason is a missing / wrong
    shared library -- the common case for a real dynamically-linked target off its own system."""
    m = _LD_MISSING.search(err)
    if m:
        return (f"missing shared library '{m.group(1).decode('latin-1', 'ignore')}'. "
                "Supply the target's libraries: set LYKOS_QEMU_SYSROOT to a directory holding its "
                "loader + .so files (rootfs layout), or ingest the binary as a DIRECTORY with them.")
    m = _LD_SYMBOL.search(err)
    if m:
        return (f"a shared library is the WRONG version (undefined symbol "
                f"'{m.group(2).decode('latin-1', 'ignore')}' needed by "
                f"'{m.group(1).decode('latin-1', 'ignore')}'). Supply the target's OWN libraries "
                "(the versions it was built against) via LYKOS_QEMU_SYSROOT or a directory ingest.")
    m = _QEMU_NOLOADER.search(err)
    if m:
        return (f"the dynamic loader '{m.group(1).decode('latin-1', 'ignore')}' is not present "
                "where the target runs. Set LYKOS_QEMU_SYSROOT to a sysroot that contains it.")
    return None


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
            # When afl's abort is a handshake failure, the ROOT cause is usually in the target's
            # own last words, which afl echoes ("the target binary terminated ... last output").
            # A loader/linker failure there means the target never reached main -- so report THAT
            # (which library, missing vs wrong-version) rather than the generic handshake line.
            lib_hint = _loader_failure_hint(err)
            if lib_hint:
                return f"the target could not start: {lib_hint}"
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
