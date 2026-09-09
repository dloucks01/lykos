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
import resource
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

CRASH_SIGNALS = {
    int(signal.SIGSEGV): "SIGSEGV", int(signal.SIGABRT): "SIGABRT",
    int(signal.SIGBUS): "SIGBUS", int(signal.SIGILL): "SIGILL",
    int(signal.SIGFPE): "SIGFPE",
}
_QEMU = {"x86-64": "x86_64", "x86": "i386", "aarch64": "aarch64", "arm": "arm",
         "mips": "mips", "mipsel": "mipsel", "ppc": "ppc", "ppc64": "ppc64",
         "riscv64": "riscv64", "sparc": "sparc"}
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


def _qemu_for(arch: str) -> Optional[str]:
    suf = _QEMU.get(arch)
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


def _rlimits(mem_mb: int, cpu_s: int, set_as: bool):
    def _apply():
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
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


def _spawn(cmd, stdin, timeout, preexec):
    start = time.monotonic()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             preexec_fn=preexec)
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


def run(exe, *, argv=(), stdin: bytes = b"", timeout: float = 10.0,
        arch: Optional[str] = None, host: Optional[str] = None, mem_mb: int = 2048,
        capture: int = 65536) -> RunResult:
    host = host or host_arch()
    emu = None
    if arch and host and arch != host:
        emu = _qemu_for(arch)
        if not emu:
            return RunResult(isolation="unsupported-arch",
                             note=f"no qemu-user for {arch} on {host}")

    base = [str(exe)] + [str(a) for a in argv]
    inner = [emu] + base if emu else base
    # emulated processes need a larger address space; don't cap AS then
    preexec = _rlimits(mem_mb, int(timeout) + 2, set_as=(emu is None))

    iso = "rlimits-only"
    cmd = inner
    if _bwrap_usable():
        cmd = ["bwrap"] + _BWRAP_ARGS + inner
        iso = "bwrap+netns"

    rc, out, err, timed, dur = _spawn(cmd, stdin, timeout, preexec)

    # bubblewrap setup failed at runtime (some VMs rate-limit namespace creation) -> fall
    # back to rlimits-only and stop trying bwrap this session.
    if iso == "bwrap+netns" and not timed and err.startswith(b"bwrap:"):
        global _bwrap_cache
        _bwrap_cache = False
        cmd, iso = inner, "rlimits-only"
        rc, out, err, timed, dur = _spawn(cmd, stdin, timeout, preexec)

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
