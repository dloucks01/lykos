"""Tiered-isolation process sandbox for detonating untrusted binaries (best-effort).

Isolation, strongest available first:
  1. bubblewrap + network namespace (read-only root, tmpfs cwd, no net) -- T1
  2. resource limits only (rlimits, process group, wall-clock kill)     -- fallback
Cross-architecture targets run under qemu-user when the matching qemu-<arch> is installed.
Detects crashes (fatal signals) and timeouts. This is the substrate fuzzing/symbolic feed
inputs into; stronger tiers (microVM) come later.
"""
from __future__ import annotations

import os
import platform
import re
import resource
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CRASH_SIGNALS = {
    int(signal.SIGSEGV): "SIGSEGV", int(signal.SIGABRT): "SIGABRT",
    int(signal.SIGBUS): "SIGBUS", int(signal.SIGILL): "SIGILL",
    int(signal.SIGFPE): "SIGFPE",
}
_QEMU = {"x86-64": "x86_64", "x86": "i386", "aarch64": "aarch64", "arm": "arm",
         "mips": "mips", "mipsel": "mipsel", "mips64": "mips64", "ppc": "ppc",
         "ppc64": "ppc64", "riscv": "riscv64", "riscv64": "riscv64", "s390": "s390x",
         "sparc": "sparc", "sh": "sh4", "m68k": "m68k", "loongarch": "loongarch64"}
_HOST = {"x86_64": "x86-64", "amd64": "x86-64", "aarch64": "aarch64", "arm64": "aarch64",
         "armv7l": "arm", "mips": "mips", "ppc64": "ppc64", "ppc64le": "ppc64",
         "riscv64": "riscv64"}
_bwrap_cache: Optional[bool] = None
# Shared flag set for the probe AND the real run (so the probe predicts reality). No PID
# namespace / procfs: those need privileges some VMs restrict; net isolation + ro-root +
# tmpfs is the portable T1.
_BWRAP_ARGS = ["--ro-bind", "/", "/", "--tmpfs", "/tmp", "--dev", "/dev",
               "--unshare-net", "--die-with-parent", "--chdir", "/tmp", "--"]


@dataclass
class RunResult:
    isolation: str
    crashed: bool = False
    timed_out: bool = False
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    signal_name: Optional[str] = None
    stdout: bytes = b""
    stderr: bytes = b""
    duration_ms: int = 0
    cmd: list = field(default_factory=list)
    note: Optional[str] = None


def host_arch() -> str:
    return _HOST.get(platform.machine().lower(), platform.machine().lower())


def classify_rc(rc: Optional[int]):
    """Map a subprocess returncode to (crashed, signal, signal_name, exit_code).

    Native subprocesses report -signum; wrappers (bwrap/qemu) report 128+signum.
    """
    if rc is None:
        return False, None, None, None
    sig = None
    if rc < 0:
        sig = -rc
    elif rc > 128 and (rc - 128) in CRASH_SIGNALS:
        sig = rc - 128
    if sig in CRASH_SIGNALS:
        return True, sig, CRASH_SIGNALS[sig], None
    return False, None, None, rc


def _qemu_for(arch, endianness=None, bits=None) -> Optional[str]:
    """Pick the qemu-user binary for a target, honouring endianness and word size.

    The ELF arch name is endianness-blind (a little-endian MIPS is still "mips") and
    bit-blind ("riscv" for both RV32/RV64), so route those to the right qemu here -- otherwise
    a LE-MIPS target would be handed the big-endian emulator and fail to run.
    """
    suf = _QEMU.get(arch)
    if arch in ("mips", "mips64") and endianness == "little":
        suf = "mipsel" if arch == "mips" else "mips64el"
    elif arch == "ppc64" and endianness == "little":
        suf = "ppc64le"
    elif arch == "riscv":
        suf = "riscv32" if bits == 32 else "riscv64"
    return shutil.which("qemu-" + suf) if suf else None


def _bwrap_usable() -> bool:
    global _bwrap_cache
    if _bwrap_cache is not None:
        return _bwrap_cache
    ok = False
    if shutil.which("bwrap"):
        try:
            r = subprocess.run(["bwrap"] + _BWRAP_ARGS + ["/bin/true"],
                               capture_output=True, timeout=5)
            ok = r.returncode == 0
        except Exception:
            ok = False
    _bwrap_cache = ok
    return ok


_nproc_base: Optional[int] = None


def _nproc_cap(emu: bool) -> int:
    """A process/thread cap that bounds a fork bomb WITHOUT dropping below the machine's live
    baseline. RLIMIT_NPROC is a per-UID count, so a fixed small value (the old 256) is below
    the threads a loaded desktop already runs and makes every clone -- including qemu's own
    worker threads -- fail with EAGAIN. So cap = live baseline + headroom, measured once."""
    global _nproc_base
    if _nproc_base is None:
        try:
            _nproc_base = sum(len(os.listdir(f"/proc/{p}/task"))
                              for p in os.listdir("/proc") if p.isdigit())
        except Exception:
            _nproc_base = 2048
    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    cap = _nproc_base + (4096 if emu else 1024)          # emulation spawns extra worker threads
    return min(cap, hard) if hard != resource.RLIM_INFINITY else cap


def _rlimits(mem_mb: int, cpu_s: int, set_as: bool, nproc: Optional[int] = None):
    if nproc is None:
        nproc = _nproc_cap(False)              # default: baseline-aware native cap
    def _apply():
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
            if set_as:
                lim = mem_mb << 20
                resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
        except Exception:
            pass
    return _apply


def _killpg(p):
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def _spawn(cmd, stdin, timeout, preexec, env=None):
    start = time.monotonic()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             preexec_fn=preexec, env=env)
    except Exception as e:
        return None, b"", ("spawn failed: %r" % e).encode(), False, 0
    timed = False
    try:
        out, err = p.communicate(input=stdin, timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        _killpg(p)
        try:
            out, err = p.communicate(timeout=5)
        except Exception:
            out, err = b"", b""
        rc, timed = None, True
    dur = int((time.monotonic() - start) * 1000)
    return rc, out or b"", err or b"", timed, dur


# --- Windows PE substrate: Wine (optional, like qemu-user for cross-arch ELF) ----------------
# Wine surfaces a guest crash not as a Unix signal but as a non-zero exit plus an stderr line
# `err:seh:NtRaiseException Unhandled exception code cXXXXXXXX`; we classify from that NT status.
_WINE_EXC = {
    "c0000005": "ACCESS_VIOLATION", "c00000fd": "STACK_OVERFLOW",
    "c000001d": "ILLEGAL_INSTRUCTION", "c0000094": "INT_DIVIDE_BY_ZERO",
    "c0000409": "STACK_BUFFER_OVERRUN", "c0000374": "HEAP_CORRUPTION",
    "c0000025": "NONCONTINUABLE_EXCEPTION", "c0000602": "FAIL_FAST_EXCEPTION",
    "80000003": "BREAKPOINT",
}
_WINE_EXC_RE = re.compile(rb"Unhandled exception code ([0-9a-fA-F]{8})")


def _wine() -> Optional[str]:
    return shutil.which("wine") or shutil.which("wine64")


def _is_pe(exe) -> bool:
    """A PE (Windows) image: 'MZ' DOS stub then a 'PE\\0\\0' signature at the e_lfanew offset."""
    try:
        with open(exe, "rb") as f:
            head = f.read(0x40)
            if head[:2] != b"MZ" or len(head) < 0x40:
                return False
            off = int.from_bytes(head[0x3C:0x40], "little")
            f.seek(off)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False


def _default_wineprefix() -> str:
    # One persistent prefix (bootstrapped once) reused across runs -- re-bootstrapping per exec
    # would make fuzzing unusably slow; wineserver is keyed by prefix so workers can share it.
    # It must live in a directory the invoking user OWNS: wine refuses to create a prefix under a
    # world-writable sticky dir like /tmp ("'/tmp' is not owned by you"), so use ~/.cache. A
    # freshly bootstrapped prefix also gets the WoW64 (32-bit) DLLs, so PE32 targets run too.
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "lykos", "wineprefix")


def _ensure_wineprefix(wine: str, prefix: str) -> None:
    if os.path.exists(os.path.join(prefix, "system.reg")):
        return
    os.makedirs(prefix, exist_ok=True)
    env = {**os.environ, "WINEPREFIX": prefix, "WINEDEBUG": "-all", "DISPLAY": ""}
    try:
        subprocess.run([wine, "wineboot", "--init"], env=env,
                       capture_output=True, timeout=180)
    except Exception:
        pass


def _run_windows(exe, *, argv, stdin, timeout, mem_mb, capture, wineprefix) -> RunResult:
    wine = _wine()
    if not wine:
        return RunResult(isolation="unsupported-windows",
                         note="wine not installed; cannot run a Windows PE here "
                              "(install wine, or analyze statically)")
    prefix = wineprefix or _default_wineprefix()
    _ensure_wineprefix(wine, prefix)
    # WINEDEBUG=fixme-all drops the noisy fixme channel but keeps err:/warn: (the unhandled-
    # exception marker we classify on). DISPLAY="" avoids GUI popups on headless hosts.
    env = {**os.environ, "WINEPREFIX": prefix, "WINEDEBUG": "fixme-all", "DISPLAY": ""}
    cmd = [wine, str(exe)] + [str(a) for a in argv]
    eff_timeout = max(timeout, 10.0)                   # wine bootstraps a wineserver -> headroom
    # wine + wineserver need many fds/threads and a large AS; don't cap AS, widen nproc.
    preexec = _rlimits(mem_mb, int(eff_timeout) + 5, set_as=False, nproc=_nproc_cap(True))
    rc, out, err, timed, dur = _spawn(cmd, stdin, eff_timeout, preexec, env=env)
    m = _WINE_EXC_RE.search(err or b"")
    code = m.group(1).decode().lower() if m else None
    crashed = code is not None
    name = ("EXCEPTION_" + _WINE_EXC.get(code, code.upper())) if code else None
    # a launch failure (esp. a 32-bit PE with no i386 WoW64 runtime) must not read as a clean run.
    # key only on the loader's "failed to load" message (a bare c0000135 is a benign DLL-probe miss)
    low = (err or b"").lower()
    if not crashed and b"wine: failed to load" in low:
        wow = b"syswow64" in low or b"wine32" in low
        note = "wine could not launch this PE" + (
            " -- it is 32-bit; install the i386 WoW64 runtime (wine32:i386)" if wow else "")
        return RunResult(isolation="wine-launch-failed", crashed=False, timed_out=timed,
                         exit_code=rc, stdout=(out or b"")[:capture],
                         stderr=(err or b"")[:capture], duration_ms=dur, cmd=cmd, note=note)
    return RunResult(
        isolation="wine", crashed=crashed, timed_out=timed,
        exit_code=(None if crashed else rc), signal=None, signal_name=name,
        stdout=(out or b"")[:capture], stderr=(err or b"")[:capture],
        duration_ms=dur, cmd=cmd,
        note=None if crashed or not timed else "timed out")


def run(exe, *, argv=(), stdin: bytes = b"", timeout: float = 10.0,
        arch: Optional[str] = None, endianness: Optional[str] = None,
        bits: Optional[int] = None, host: Optional[str] = None, mem_mb: int = 2048,
        capture: int = 65536, wineprefix: Optional[str] = None) -> RunResult:
    host = host or host_arch()
    if _is_pe(exe):                                     # Windows PE -> Wine substrate
        return _run_windows(exe, argv=argv, stdin=stdin, timeout=timeout, mem_mb=mem_mb,
                            capture=capture, wineprefix=wineprefix)
    emu = None
    if arch and host and arch != host:
        emu = _qemu_for(arch, endianness, bits)
        if not emu:
            return RunResult(isolation="unsupported-arch",
                             note=f"no qemu-user for {arch} ({endianness or '?'}-endian) "
                                  f"on {host}")

    base = [str(exe)] + [str(a) for a in argv]
    inner = [emu] + base if emu else base
    # emulation is several times slower than native, so give it a longer wall-clock budget or
    # correct runs would be misreported as timeouts.
    eff_timeout = max(timeout * 3, 5.0) if emu else timeout
    # emulated processes need a larger address space; don't cap AS then
    preexec = _rlimits(mem_mb, int(eff_timeout) + 2, set_as=(emu is None),
                       nproc=_nproc_cap(emu is not None))

    iso = "rlimits-only" + ("+qemu" if emu else "")
    cmd = inner
    if _bwrap_usable():
        # The exe is staged under /tmp, which _BWRAP_ARGS masks with a tmpfs. A native target
        # then triggers a "bwrap:" exec error and we fall back below; but an EMULATED target
        # runs qemu (visible) which just can't open the masked guest -> a silent no-crash. So
        # bind the exe's scratch dir back in read-only when emulating.
        extra = []
        if emu:
            exedir = str(Path(exe).resolve().parent)
            extra = ["--ro-bind", exedir, exedir]
        cmd = ["bwrap"] + _BWRAP_ARGS[:-1] + extra + ["--"] + inner
        iso = ("bwrap+netns" + ("+qemu" if emu else ""))

    rc, out, err, timed, dur = _spawn(cmd, stdin, eff_timeout, preexec)

    # bubblewrap setup failed at runtime (some VMs rate-limit namespace creation) -> fall
    # back to rlimits-only and stop trying bwrap this session.
    if iso.startswith("bwrap") and not timed and err.startswith(b"bwrap:"):
        global _bwrap_cache
        _bwrap_cache = False
        cmd, iso = inner, "rlimits-only" + ("+qemu" if emu else "")
        rc, out, err, timed, dur = _spawn(cmd, stdin, eff_timeout, preexec)

    # crash signal: native subprocess reports -signum; wrappers (bwrap) report 128+signum
    sig = None
    exit_code = None
    if rc is not None:
        if rc < 0:
            sig = -rc
        elif rc > 128 and (rc - 128) in CRASH_SIGNALS:
            sig = rc - 128
        else:
            exit_code = rc
    return RunResult(
        isolation=iso, crashed=(sig in CRASH_SIGNALS if sig else False), timed_out=timed,
        exit_code=exit_code, signal=sig,
        signal_name=CRASH_SIGNALS.get(sig) if sig else None,
        stdout=(out or b"")[:capture], stderr=(err or b"")[:capture],
        duration_ms=dur, cmd=cmd)
