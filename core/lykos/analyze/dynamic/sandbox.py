"""Tiered-isolation process sandbox for detonating untrusted binaries (best-effort).

Isolation, strongest available first:
  1. bubblewrap + network namespace (read-only root, tmpfs cwd, no net) -- T1
  2. resource limits only (rlimits, process group, wall-clock kill)     -- fallback
Cross-architecture targets run under qemu-user when the matching qemu-<arch> is installed.
Detects crashes (fatal signals) and timeouts. This is the substrate fuzzing/symbolic feed
inputs into; stronger tiers (microVM) come later.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import resource
import shutil
import signal
import struct
import subprocess
import tempfile
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
         "sparc": "sparc", "sparcv9": "sparc64", "sh": "sh4", "m68k": "m68k",
         "loongarch": "loongarch64"}
_HOST = {"x86_64": "x86-64", "amd64": "x86-64", "aarch64": "aarch64", "arm64": "aarch64",
         "armv7l": "arm", "mips": "mips", "ppc64": "ppc64", "ppc64le": "ppc64",
         "riscv64": "riscv64"}
_bwrap_cache: Optional[bool] = None
# Shared flag set for the probe AND the real run (so the probe predicts reality).
#
# `--proc /proc` overlays a FRESH procfs on the read-only root. Without it /proc arrives
# through the read-only bind and opening /proc/<pid>/mem O_RDWR fails with EROFS -- which is
# how the block-coverage tracer plants breakpoints. It fell back silently to two ptrace
# syscalls per block, 72,000 of them per execution on a statically linked target.
#
# `--unshare-pid` is what makes that procfs mean anything. A fresh procfs without a PID
# namespace still lists every process on the host: a target could read 564 entries of
# /proc/<pid>/cmdline and, for anything running as the same user, /proc/<pid>/environ. With
# the namespace it sees four, and the tracer is unaffected because a pid namespace is exactly
# the scope ptrace and /proc/<pid>/mem already work in.
_BWRAP_ARGS = ["--ro-bind", "/", "/", "--unshare-pid", "--proc", "/proc",
               "--tmpfs", "/tmp", "--dev", "/dev",
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
    # Image-relative address of the faulting instruction, when the target was traced. Two
    # crashes at different addresses are different defects, however alike their signals look.
    fault_pc: Optional[int] = None


class ArgvNulError(ValueError):
    """A payload that cannot be delivered as a command-line argument."""


def argv_arg(data: bytes, *, truncate: bool = False) -> str:
    """Render a payload as ONE argv element, or refuse with a clear reason.

    execve() argument strings are NUL-terminated, so an argument cannot contain a NUL byte --
    the kernel truncates there. This is not a Python limitation to work around: any payload
    that embeds an address (an L2/L3 confirmation payload almost always does) is undeliverable
    via argv on most ABIs and must go over stdin or a file. Raising a NAMED error lets callers
    report that honestly instead of surfacing a bare ValueError("embedded null byte") from
    inside subprocess, which reads like a crash in the tool rather than a property of the
    delivery channel.

    `truncate` delivers what the kernel WOULD deliver -- everything up to the first NUL --
    instead of refusing. Refusing outright was too strong for the case that matters: an
    argv-reachable `strcpy` overflow copies until the NUL anyway, so a payload whose control
    slot sits BEFORE the first NUL is delivered perfectly intact. That is not a hypothetical
    -- it is CVE-2001-1413 in ncompress, where the return address lands at offset 1048 and
    the marker's own high zero bytes are the first NUL at 1054. Nothing is assumed by
    truncating: if the control slot does not survive, the marker check simply fails and no
    primitive is claimed.
    """
    if b"\x00" in data:
        if truncate:
            return data.split(b"\x00", 1)[0].decode("latin-1")
        raise ArgvNulError(
            "payload contains a NUL byte at offset %d and cannot be delivered as a command-"
            "line argument (execve truncates at NUL); use input_mode 'stdin' or 'file'"
            % data.index(b"\x00"))
    return data.decode("latin-1")


def argv_bytes(a):
    """One argv element as BYTES, without re-encoding a binary payload.

    `argv_arg` renders a payload as latin-1 text because that is the lossless round-trip for
    arbitrary bytes through JSON. Handing that str to subprocess/execv undoes it: they encode
    with the filesystem encoding, so every byte >= 0x80 becomes two UTF-8 bytes and any
    payload carrying an address is silently corrupted. That is most L2/L3 payloads, and it is
    why argv-delivered instruction-pointer control never confirmed.

    A latin-1-decoded payload only ever holds code points <= U+00FF, so encoding it back with
    latin-1 is exact. A genuine non-ASCII path (real text, code points above that) cannot be
    a payload and is encoded the way the filesystem expects.
    """
    if isinstance(a, bytes):
        return a
    if not isinstance(a, str):
        a = str(a)
    try:
        return a.encode("latin-1")
    except UnicodeEncodeError:
        return a.encode("utf-8", "surrogateescape")


# One namespace, many executions. Spawning bubblewrap costs 3.18 ms of a 3.55 ms execution --
# a 9.5x tax paid on EVERY input -- which is why a campaign managed 256 exec/s against AFL++'s
# 6,100. The runner lives in a real module rather than an embedded string, because it now also
# carries a ptrace tracer and that does not belong in a quoted blob.
def _batch_runner_path() -> str:
    from ..fuzz import batch_runner
    return str(Path(batch_runner.__file__).resolve())


def run_batch(exe, payloads, *, mode="stdin", base_argv=(), timeout: float = 2.0,
              arch=None, endianness=None, bits=None, host=None, mem_mb: int = 2048,
              blocks=()):
    """Execute many inputs inside ONE sandbox. Returns a list of RunResult, or None.

    `blocks` are image-relative basic-block addresses to watch; each result then carries the
    ones this input REACHED, in `RunResult.note` as a comma-separated list. Breakpoints are
    one-shot per execution and the caller passes only blocks it has not seen, so the cost
    decays as coverage saturates.

    None means "not available here" -- no bubblewrap, no python3, an emulated or PE target, a
    malformed reply -- and the caller falls back to `run()` per input. Speed is never a reason
    to run a hostile binary with less containment than usual, so this buys throughput by
    amortising the namespace, not by giving one up.
    """
    host = host or host_arch()
    if _is_pe(exe) or _is_jvm(exe) or (arch and host and arch != host):
        # Wine, the JVM and qemu stay per-exec. The batch runner execs the target directly and
        # traces it with ptrace; a jar is not executable and the JVM is not the target, so
        # batching it would run the wrong program under breakpoints meant for another.
        return None
    py = shutil.which("python3")
    if not py or not _bwrap_usable() or not payloads:
        return None
    exedir = str(Path(exe).resolve().parent)
    runner = _batch_runner_path()
    inner = [py, runner, mode, str(timeout), str(exe),
             *[argv_bytes(a).decode("latin-1") for a in base_argv]]
    cmd = (["bwrap"] + _BWRAP_ARGS[:-1] + ["--ro-bind", exedir, exedir, "--"] + inner)
    blocks = list(blocks)
    blob = bytearray(struct.pack("<II", len(payloads), len(blocks)))
    if blocks:
        blob += struct.pack("<%dQ" % len(blocks), *blocks)
    for d in payloads:
        blob += struct.pack("<I", len(d)) + d
    budget = timeout * len(payloads) + 15.0
    t0 = time.time()
    rc, out, err, timed, _dur = _spawn(cmd, bytes(blob), budget,
                                       _rlimits(mem_mb, int(budget) + 5, set_as=False,
                                                nproc=_nproc_cap(False)))
    if timed or rc != 0 or err.startswith(b"bwrap:"):
        return None
    per_ms = int((time.time() - t0) * 1000 / max(1, len(payloads)))
    results, off = [], 0
    for _ in payloads:
        if off + 25 > len(out):
            return None                               # truncated reply: fall back rather than
        code, nso, nse, flags, nnew, fault_pc = struct.unpack(   # invent one
            "<iIIBIQ", out[off:off + 25])
        off += 25
        so, se = out[off:off + nso], out[off + nso:off + nso + nse]
        off += nso + nse
        reached = ()
        if nnew:
            if off + 8 * nnew > len(out):
                return None
            reached = struct.unpack("<%dQ" % nnew, out[off:off + 8 * nnew])
            off += 8 * nnew
        crashed, sig, signame, exit_code = classify_rc(code)
        results.append(RunResult(isolation="bwrap+netns+batch", crashed=bool(crashed),
                                 timed_out=bool(flags & 1), exit_code=exit_code, signal=sig,
                                 signal_name=signame, stdout=so, stderr=se,
                                 duration_ms=per_ms, fault_pc=(fault_pc or None),
                                 note=(",".join(str(x) for x in reached) or None)))
    return results


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
    elif arch == "sparc" and bits == 64:      # EM_SPARC with a 64-bit class -> v9
        suf = "sparc64"
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
# Wine has a SECOND format for the commonest crash there is, and matching only the first meant
# every PE access violation read as a clean exit -- so no PE crash was ever recorded and the
# whole PoC ladder was unreachable for Windows targets:
#   wine: Unhandled page fault on read access to 00007FFFFF8A0C77 at address 000000014000547D
# A page fault IS c0000005; the access word (read/write/execute) is kept for the note.
_WINE_FAULT_RE = re.compile(
    rb"Unhandled page fault on (read|write|execute)(?:-inclusive)? access"
    rb"(?: to ([0-9a-fA-F]+))?(?: at address ([0-9a-fA-F]+))?")


def wine_exception(stderr: bytes):
    """(nt status, human name, detail) for a Wine guest crash, or (None, None, None).

    Two formats, one meaning. Anything that says "Unhandled" and names a fault is a crash:
    reporting it as a clean run is the worst possible answer, because the input that caused
    it then looks uninteresting.
    """
    m = _WINE_EXC_RE.search(stderr or b"")
    if m:
        code = m.group(1).decode().lower()
        return code, "EXCEPTION_" + _WINE_EXC.get(code, code.upper()), None
    m = _WINE_FAULT_RE.search(stderr or b"")
    if m:
        how = m.group(1).decode()
        at = (m.group(3) or m.group(2) or b"").decode()
        detail = f"page fault on {how} access" + (f" at 0x{at}" if at else "")
        return "c0000005", "EXCEPTION_ACCESS_VIOLATION", detail
    return None, None, None


# ---- JVM: a defect surfaces as an uncaught exception, not a signal -----------------------
#
# Exception in thread "main" java.lang.ArrayIndexOutOfBoundsException: Index 99 out of ...
# 	at Svc.setOpt(Svc.java:14)
#
# The "Exception in thread" prefix is the load-bearing part. A program that catches its own
# exception and calls printStackTrace() writes a nearly identical block to stderr and then
# carries on and exits 0 -- reporting that as a crash would turn correct error handling into
# a finding, which is the same defect as counting a usage message as a crash.
_JVM_EXC_RE = re.compile(
    r'Exception in thread "([^"]*)"\s+([A-Za-z_$][\w.$]*(?:Exception|Error|Throwable))'
    r'(?::\s*(.*))?')
_JVM_FRAME_RE = re.compile(r"^\s+at\s+([\w.$/<>]+)\(([^)]*)\)", re.M)
# The JVM itself dying -- a JNI bug, or a VM defect. This IS memory corruption, and it is a
# far stronger result than any Java-level exception.
_JVM_FATAL_RE = re.compile(
    r"A fatal error has been detected by the Java Runtime Environment", re.I)
_JVM_FATAL_SIG = re.compile(r"(SIG[A-Z]+)\s*\(", re.I)
# -XX:+ExitOnOutOfMemoryError makes the VM die immediately instead of unwinding, which is what
# we want (an unbounded allocation must fail fast rather than let the host absorb it) -- but it
# prints THIS instead of a stack trace, so matching only "Exception in thread" made
# uncontrolled memory allocation, one of the most common real Java defects, invisible.
_JVM_TERM_RE = re.compile(r"^Terminating due to (java\.lang\.\w*(?:Error|Exception))"
                          r"(?::\s*(.*))?", re.M)
# Frames inside the JDK are where an exception is CONSTRUCTED, not where the defect is. Every
# NumberFormatException in every program is thrown from
# java.base/java.lang.NumberFormatException.forInputString, so blaming the top frame blames
# the JDK and dedups every such bug in the target into one finding.
_JDK_FRAME = re.compile(r"^(?:java\.base/|java\.\w+/|jdk\.|sun\.|com\.sun\.|javax\.)")


def jvm_exception(stderr: bytes, exit_code: Optional[int] = None, stdout: bytes = b""):
    """(kind, detail, frames) for an uncaught JVM fault, else (None, None, []).

    `kind` is the exception class name, which is this runtime's equivalent of a signal name:
    ArrayIndexOutOfBoundsException says far more about the defect than SIGSEGV does.

    Which STREAM each thing is read from is load-bearing, and the two are not interchangeable.
    An uncaught exception always goes to stderr -- that is what the JVM's default handler
    does. But -XX:+ExitOnOutOfMemoryError prints "Terminating due to ..." to STDOUT, so
    reading stderr alone made unbounded allocation invisible.

    The obvious fix -- scan both streams for everything -- opens a hole a fuzzer finds on its
    own: a target that echoes its input would report a crash the moment a mutation contains
    the text `Exception in thread`, and a mutator that is rewarded for crashes will produce
    that string deliberately. So the exception trace is read from stderr only, where a target
    cannot put it by echoing, and the VM's termination line is corroborated by a non-zero exit
    -- a program echoing text exits 0.
    """
    text = (stderr or b"").decode("utf-8", "replace")
    vm_text = text + "\n" + (stdout or b"").decode("utf-8", "replace")
    if _JVM_FATAL_RE.search(vm_text) and exit_code not in (0, None):
        sig = _JVM_FATAL_SIG.search(vm_text)
        return ("JVM-FATAL-" + (sig.group(1).upper() if sig else "ABORT"),
                "the JVM itself crashed -- native memory corruption, not a Java exception",
                _JVM_FRAME_RE.findall(vm_text))
    m = _JVM_EXC_RE.search(text)
    if not m:
        t = _JVM_TERM_RE.search(vm_text)
        if t and exit_code not in (0, None):
            short = t.group(1).rsplit(".", 1)[-1]
            return short, (f"the VM terminated on {short}"
                           + (f": {t.group(2).strip()}" if t.group(2) else "")
                           + " -- an allocation the input controls"), []
        return None, None, []
    thread, cls, msg = m.group(1), m.group(2), (m.group(3) or "").strip()
    frames = _JVM_FRAME_RE.findall(text)
    short = cls.rsplit(".", 1)[-1]
    blame = app_frame(frames)
    where = f" at {blame[0]}({blame[1]})" if blame else ""
    detail = f"uncaught {short} in thread \"{thread}\"" + (f": {msg}" if msg else "") + where
    return short, detail, frames


def app_frame(frames):
    """The first frame that is the TARGET's code rather than the JDK's.

    `Integer.parseInt("abc")` throws from three JDK frames deep. The defect is not in
    java.base -- it is the line that passed unvalidated input to it, which is the first frame
    below them.
    """
    for fr in frames or ():
        if not _JDK_FRAME.match(fr[0]):
            return fr
    return frames[0] if frames else None


def jvm_site(frames) -> Optional[int]:
    """A stable id for WHERE the exception was thrown, used where a native crash uses the
    faulting PC. Two ArrayIndexOutOfBoundsExceptions thrown from different methods are two
    defects, and without this they dedup into one -- so this keys on the application frame,
    not the JDK frame that constructed the exception."""
    fr = app_frame(frames)
    if not fr:
        return None
    return int(hashlib.sha256(f"{fr[0]}({fr[1]})".encode()).hexdigest()[:8], 16)


# Startup dominates a Java execution, so these are not cosmetic: measured on a trivial jar,
# 37 ms plain against 27 ms with them, and a fuzzing campaign pays it on every input.
# -Xmx/-Xss are bounds, not tuning: an unbounded allocation is one of the defects being
# hunted, and without a heap cap the host absorbs it instead of the target failing fast.
_JVM_FLAGS = ("-XX:TieredStopAtLevel=1", "-XX:+UseSerialGC", "-XX:-UsePerfData",
              "-Xshare:auto", "-Xmx256m", "-Xss512k", "-Djava.awt.headless=true",
              "-XX:+ExitOnOutOfMemoryError")


def _java() -> Optional[str]:
    return shutil.which("java")


def _is_jvm(path) -> bool:
    try:
        head = Path(path).open("rb").read(8)
    except Exception:
        return False
    from ..jvm import is_class
    if is_class(head + b"\x00" * 8):
        return True
    return head[:4] == b"PK\x03\x04" and _looks_like_jar(path)


def _looks_like_jar(path) -> bool:
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
        return any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names
    except Exception:
        return False


def _run_java(exe, *, argv, stdin, timeout, mem_mb, capture, main_class=None) -> RunResult:
    java = _java()
    if not java:
        return RunResult(isolation="jvm-missing",
                         note="no JVM found; install a JDK/JRE to run a Java target "
                              "(or analyse it statically -- the constant pool needs no JVM)")
    exe = Path(exe)
    if _looks_like_jar(exe):
        launch = ["-jar", str(exe)]
    else:
        # a bare .class: the class name is its own, and the classpath is its directory
        cls = main_class or exe.stem
        launch = ["-cp", str(exe.parent), cls]
    cmd = [java, *_JVM_FLAGS, *launch] + [argv_bytes(a) for a in argv]
    eff_timeout = max(timeout, 10.0)                 # JVM startup is tens of milliseconds
    preexec = _rlimits(max(mem_mb, 2048), int(eff_timeout) + 2, set_as=False,
                       nproc=_nproc_cap(True))       # the JVM is threaded; don't cap AS
    iso = "rlimits-only+jvm"
    run = cmd
    if _bwrap_usable():
        exedir = str(exe.resolve().parent)
        run = ["bwrap"] + _BWRAP_ARGS[:-1] + ["--ro-bind", exedir, exedir] + ["--"] + cmd
        iso = "bwrap+netns+jvm"
    rc, out, err, timed, dur = _spawn(run, stdin, eff_timeout, preexec)
    if iso.startswith("bwrap") and not timed and err.startswith(b"bwrap:"):
        # namespace creation is rate-limited on some VMs: drop to rlimits-only for the session
        global _bwrap_cache
        _bwrap_cache = False
        rc, out, err, timed, dur = _spawn(cmd, stdin, eff_timeout, preexec)
        iso = "rlimits-only+jvm"
    kind, detail, frames = jvm_exception(err, rc, out)
    crashed = kind is not None
    return RunResult(
        isolation=iso, crashed=crashed, timed_out=timed,
        exit_code=(None if crashed else rc), signal=None, signal_name=kind,
        stdout=out[:capture], stderr=err[:capture], duration_ms=dur, cmd=run,
        fault_pc=jvm_site(frames) if crashed else None,
        note=(detail if crashed else (None if not timed else "timed out")))


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
    code, name, detail = wine_exception(err or b"")
    crashed = code is not None
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
        note=(detail if crashed and detail else
              (None if crashed or not timed else "timed out")))


def run(exe, *, argv=(), stdin: bytes = b"", timeout: float = 10.0,
        arch: Optional[str] = None, endianness: Optional[str] = None,
        bits: Optional[int] = None, host: Optional[str] = None, mem_mb: int = 2048,
        capture: int = 65536, wineprefix: Optional[str] = None, blocks=()) -> RunResult:
    """`blocks` asks for coverage. On an EMULATED target that is the only way to get it: the
    ptrace tracer the batch runner uses cannot reach inside qemu, so every non-native campaign
    was running blind on output shape alone -- eleven of the twelve architectures the platform
    builds real targets for. qemu logs the guest PC of each translated block itself."""
    host = host or host_arch()
    if _is_pe(exe):                                     # Windows PE -> Wine substrate
        return _run_windows(exe, argv=argv, stdin=stdin, timeout=timeout, mem_mb=mem_mb,
                            capture=capture, wineprefix=wineprefix)
    if _is_jvm(exe):                                    # jar / .class -> the JVM
        return _run_java(exe, argv=argv, stdin=stdin, timeout=timeout, mem_mb=mem_mb,
                         capture=capture)
    emu = None
    if arch and host and arch != host:
        emu = _qemu_for(arch, endianness, bits)
        if not emu:
            return RunResult(isolation="unsupported-arch",
                             note=f"no qemu-user for {arch} ({endianness or '?'}-endian) "
                                  f"on {host}")

    base = [str(exe)] + [argv_bytes(a) for a in argv]
    trace_log = None
    if emu and blocks:
        tdir = tempfile.mkdtemp(prefix="lykos-qtrace-")
        trace_log = str(Path(tdir) / "exec.log")
        inner = [emu, "-d", "exec", "-D", trace_log] + base
    else:
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
        # The exe is staged under /tmp (ctx.scratch()), which _BWRAP_ARGS masks with a tmpfs,
        # so the guest binary vanishes inside the sandbox. Bind its directory back in
        # read-only -- for NATIVE targets as well as emulated ones. Doing this only for the
        # emulated case meant a native target hit a "bwrap:" exec error and silently fell back
        # to the rlimits-only tier: no network namespace and no read-only root, precisely
        # where it matters most (running hostile code on the host CPU).
        exedir = str(Path(exe).resolve().parent)
        extra = ["--ro-bind", exedir, exedir]
        if trace_log:
            # qemu writes its block log to a FILE, and /tmp inside the sandbox is a private
            # tmpfs -- the log is created there and gone the moment the sandbox exits, which
            # is why every traced emulated run reported zero blocks. Bind the log's own
            # directory writable; it holds nothing else.
            tdir = str(Path(trace_log).parent)
            extra += ["--bind", tdir, tdir]
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

    # classify_rc() holds the one copy of this: native subprocesses report -signum while
    # wrappers (bwrap/qemu) report 128+signum, and the two had drifted apart here.
    crashed, sig, sig_name, exit_code = classify_rc(rc)
    note, fault_pc = None, None
    if trace_log:
        reached, last = _qemu_reached(trace_log, blocks, want_last=True)
        note = ",".join(str(x) for x in reached) or None
        # Where it died, for an EMULATED target. The ptrace tracer cannot reach inside qemu,
        # so a cross-architecture crash had no faulting address and every SIGSEGV in the
        # program bucketed as one finding. qemu's log stops at the fault, so the last block it
        # translated is the closest thing to a fault locus available here -- a block address,
        # not the exact instruction, which is enough to tell two defects apart.
        if crashed:
            fault_pc = last
        shutil.rmtree(Path(trace_log).parent, ignore_errors=True)
    return RunResult(
        isolation=iso, crashed=crashed, timed_out=timed,
        exit_code=exit_code, signal=sig, signal_name=sig_name,
        stdout=(out or b"")[:capture], stderr=(err or b"")[:capture],
        duration_ms=dur, cmd=cmd, note=note, fault_pc=fault_pc)


_TRACE_PC = re.compile(rb"^Trace \d+: 0x[0-9a-f]+ \[[^/]*/([0-9a-f]+)/", re.M)


def _qemu_reached(path, blocks, want_last: bool = False):
    """Which of `blocks` qemu executed, from its own -d exec log.

    The log line is `Trace 0: <host addr> [<flags>/<GUEST PC>/...] <symbol>`, so the guest PC
    is the second bracketed field -- the host translation address in front of it is not an
    address in the target at all.
    """
    want = set(blocks)
    empty: tuple = ((), None) if want_last else ()
    if not want:
        return empty
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return empty
    seen, last = set(), None
    for m in _TRACE_PC.finditer(data):
        pc = int(m.group(1), 16)
        seen.add(pc)
        last = pc
    hit = sorted(seen & want)
    return (hit, last) if want_last else hit
