"""Executes many fuzz inputs inside ONE sandbox, optionally recording block coverage.

Spawning bubblewrap costs 3.18 ms of a 3.55 ms execution -- a 9.5x tax paid on every input --
so the namespace is paid for once per batch here instead of once per input. Isolation is
unchanged: every target process is still a child inside the same unshared-net, read-only-root
namespace.

With a block list it also traces each child and reports which of those blocks were reached.
A campaign's coverage proxy was the SHAPE of the program's output, which sees a few thousand
distinct behaviours where real path coverage sees tens of thousands -- the difference between
noticing that a parser printed something new and noticing that it took a branch it never took
before.

Breakpoints are ONE-SHOT and the caller only ever arms blocks it has not seen, so the cost
decays: the first inputs pay a trap per new block and later ones pay almost nothing. That is
also exactly the signal a fuzzer wants -- "did this input reach anywhere new?" -- rather than a
hit count it would have to diff.

Run as: python3 batch_runner.py <mode> <per_timeout> <exe> [base argv...]
stdin:  u32 count, u32 n_blocks, then n_blocks * u64 block addresses (image-relative),
        then per input: u32 length + bytes
stdout: per input: i32 rc, u32 stdout_len, u32 stderr_len, u8 flags, u32 n_new,
        u64 fault_pc (image-relative, 0 if unknown), then stdout, stderr, and
        n_new * u64 newly reached block addresses
"""
import ctypes
import os
import signal
import struct
import subprocess
import sys
import threading
import time

PTRACE_TRACEME, PTRACE_PEEKTEXT, PTRACE_POKETEXT = 0, 1, 4
PTRACE_CONT, PTRACE_KILL, PTRACE_GETREGS = 7, 8, 12
_INT3 = 0xCC
# Signals whose default action is a core-dumping fault -- the only ones that mean "crash". A
# non-fault signal the program does not catch (SIGALRM, SIGTERM, SIGPIPE, SIGCHLD, SIGWINCH...)
# is ordinary termination or is ignored, never a bug. Matches sandbox.CRASH_SIGNALS.
_CRASH_SIGS = {int(signal.SIGSEGV), int(signal.SIGABRT), int(signal.SIGBUS),
               int(signal.SIGILL), int(signal.SIGFPE)}
_SPAN_CAP = 32 << 20            # refuse to slurp a span so wide it is cheaper per block
# A handled fault signal (SIGSEGV caught by a JIT/GC, a guard page re-faulted) is forwarded and
# the program runs on. A program that re-faults in a tight loop would forward one forever, and
# the per-input deadline alone does not stop it because each stop is ready immediately and the
# wait loop that checks the clock never runs. Cap how many we forward, then treat it as a hang.
_MAX_DELIVER = 4096
# Resident-memory cap (MB) for a sanitizer target, since it CANNOT take an RLIMIT_AS cap.
_SAN_RSS_MB = 4096
# Virtual-memory cap (MB) for a non-sanitizer batch child, matching _trace_one's cap.
_BATCH_AS_MB = 4096


def _nontraced_preexec(sanitizer):
    """RLIMIT caps for the NON-traced batch run (blocks == 0). That path runs the target directly
    with no ptrace, so this preexec is the only place a memory bomb is bounded there -- previously
    it had none, and it is the steady state of every campaign once coverage saturates. A sanitizer
    build cannot take an AS cap (its ~20TB shadow); it is bounded by ASAN_OPTIONS hard_rss_limit_mb
    in the child env instead (set in main)."""
    def _apply():
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if not sanitizer:
                lim = _BATCH_AS_MB << 20
                resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
        except Exception:
            pass
    return _apply


def _is_sanitizer(exe) -> bool:
    """True if the ELF at `exe` is an ASan/UBSan build. A sanitizer runtime reserves a ~20TB
    *virtual* shadow region at startup; under an RLIMIT_AS cap that mmap fails and the process
    aborts BEFORE main() -- so every input reads as a spurious SIGABRT and no block is ever
    reached. Such a build must run without the AS cap (resident memory is bounded instead). This
    is the stdlib-only twin of sandbox._is_sanitizer_exe: batch_runner is spawned as a bare
    `python3 batch_runner.py` subprocess and cannot import the package. Cheap byte-scan for the
    runtime's marker symbol; matches aflpp.is_sanitizer_build."""
    try:
        with open(exe, "rb") as fh:
            data = fh.read()
    except OSError:
        return False
    return b"__asan_init" in data or b"__asan_report" in data or b"__ubsan_handle" in data


def _readn(n):
    b = b""
    while len(b) < n:
        c = sys.stdin.buffer.read(n - len(b))
        if not c:
            break
        b += c
    return b


class _Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx",
        "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base",
        "gs_base", "ds", "es", "fs", "gs")]


def _elf_min_vaddr(exe):
    """The vaddr the ELF itself asks to be loaded at: 0x400000 for a fixed image, 0 for PIE.

    Callers send FILE vaddrs (a decompiler address with its image base removed) and this is
    what turns one into a runtime address without the caller needing to know whether the
    target is position-independent.
    """
    try:
        with open(exe, "rb") as fh:
            d = fh.read(4096)
        if d[:4] != b"\x7fELF" or d[4] != 2:
            return 0
        phoff = struct.unpack("<Q", d[0x20:0x28])[0]
        phentsize, phnum = struct.unpack("<HH", d[0x36:0x3A])
        lo = None
        for i in range(phnum):
            e = phoff + i * phentsize
            p_type = struct.unpack("<I", d[e:e + 4])[0]
            if p_type != 1:                              # PT_LOAD
                continue
            vaddr = struct.unpack("<Q", d[e + 0x10:e + 0x18])[0]
            lo = vaddr if lo is None else min(lo, vaddr)
        return lo or 0
    except Exception:
        return 0


def _maps_base(pid, exe):
    """Where the loader actually put the target's first mapping."""
    want = os.path.basename(exe)
    try:
        with open("/proc/%d/maps" % pid) as fh:
            for line in fh:
                if line.rstrip().endswith(want) or ("/" + want) in line:
                    return int(line.split("-", 1)[0], 16)
    except OSError:
        pass
    return 0


def _handles(pid, sig) -> bool:
    """Does the tracee catch this signal? SigCgt in /proc/<pid>/status is the mask it has
    handlers installed for, so there is no need to deliver the signal to find out."""
    try:
        with open(f"/proc/{pid}/status", "rb") as fh:
            for line in fh:
                if line.startswith(b"SigCgt:"):
                    return bool(int(line.split()[1], 16) & (1 << (sig - 1)))
    except (OSError, ValueError, IndexError):
        pass
    return False


def _open_mem(pid):
    try:
        return os.open(f"/proc/{pid}/mem", os.O_RDWR)
    except OSError:
        return None


def _poke_byte(libc, pid, mem, addr, value):
    """Write one byte into the tracee, preferring /proc/pid/mem over a read-modify-write word."""
    if mem is not None:
        try:
            os.pwrite(mem, bytes([value]), addr)
            return
        except OSError:
            pass
    word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), 0)
    if word == -1:
        return
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr),
                ctypes.c_void_p(((word & ~0xFF) | value) & 0xFFFFFFFFFFFFFFFF))


def _arm(libc, pid, mem, base, blocks, plan):
    """Plant an INT3 at every block. Returns {relative address: replaced byte}.

    Done one block at a time this is two ptrace syscalls each, and a campaign re-arms every
    block it has not yet reached on every single execution: on jhead that is ~1,900 syscalls
    before the program starts, which cost more than the execution and held a coverage campaign
    to 23 exec/s against 2,000 without tracing. /proc/pid/mem reads the whole span once and
    writes it back once -- the patched bytes are scattered, but rewriting the untouched ones
    with their own values is free next to a syscall apiece.

    With the syscalls gone the cost became PYTHON: a statically linked binary carries its libc,
    so Ghidra recovers 38,418 blocks instead of 1,887, and building a 36,000-entry patch map
    per execution held the same campaign to 15 exec/s. The patched image is identical for every
    input in a batch -- same binary, same blocks -- so it is built once and replayed, which is
    a single write per execution after the first.
    """
    if mem is not None and len(blocks) > 8 and plan is not None:
        if not plan:
            lo, hi = min(blocks), max(blocks) + 1
            if hi - lo <= _SPAN_CAP:
                try:
                    text = bytearray(os.pread(mem, hi - lo, base + lo))
                    if len(text) == hi - lo:
                        orig = {}
                        for rel in blocks:
                            orig[rel] = text[rel - lo]
                            text[rel - lo] = _INT3
                        plan.update(lo=lo, text=bytes(text), orig=orig)
                except OSError:
                    pass
        if plan:
            try:
                os.pwrite(mem, plan["text"], base + plan["lo"])
                return plan["orig"]
            except OSError:
                pass
    original = {}
    for rel in blocks:
        addr = base + rel
        word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), 0)
        if word == -1:
            continue
        original[rel] = word & 0xFF
        libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr),
                    ctypes.c_void_p(((word & ~0xFF) | _INT3) & 0xFFFFFFFFFFFFFFFF))
    return original


def _trace_one(libc, argv, stdin_data, timeout, blocks, exe, plan=None, sanitizer=False):
    """Run one input under ptrace. Returns (rc, out, err, flags, reached, fault_pc)."""
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    r_in, w_in = os.pipe()
    pid = os.fork()
    if pid == 0:                                        # child
        try:
            try:
                import resource
                # Bound each input's memory and disk writes. The batch path runs native targets
                # directly, so per-exec RLIMIT_AS is the only place a memory bomb is capped
                # (the shared runner cannot set it without capping itself). A SANITIZER build is
                # the exception: ASan reserves a ~20TB virtual shadow at startup, so an AS cap
                # makes it abort before main() -- every input a spurious crash, zero coverage.
                # Bound its RESIDENT memory via ASAN_OPTIONS=hard_rss_limit_mb instead (set below,
                # pre-execv), which is what actually consumes host RAM.
                if not sanitizer:
                    lim = 4096 << 20
                    resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
                resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
            if sanitizer:
                # No AS cap for this build, so bound resident memory the ASan way. Merge, don't
                # clobber: the caller sets abort_on_error=1 so the fuzzer catches the crash.
                opts = os.environ.get("ASAN_OPTIONS", "")
                if "hard_rss_limit_mb" not in opts:
                    os.environ["ASAN_OPTIONS"] = (opts + ":" if opts else "") \
                        + "hard_rss_limit_mb=%d" % _SAN_RSS_MB
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.dup2(r_in, 0); os.dup2(w_out, 1); os.dup2(w_err, 2)
            for fd in (r_out, w_out, r_err, w_err, r_in, w_in):
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.execv(argv[0], argv)
        except Exception:
            os._exit(127)
    os.close(w_out); os.close(w_err); os.close(r_in)
    # Feed stdin from a thread. The tracee is stopped at execve and not yet reading fd 0, so a
    # direct blocking write of a payload larger than the pipe buffer (64 KiB) would deadlock here
    # BEFORE the trace loop -- and the per-input deadline (below) is only checked inside that loop,
    # so it would never fire. The thread does the full (possibly partial/interrupted) write and
    # closes the write end for EOF; if the tracee never reads it, the thread simply blocks and is
    # reaped when the tracee is killed at the deadline.
    def _feed_stdin():
        data = memoryview(stdin_data)
        while data:
            try:
                n = os.write(w_in, data)
            except OSError:
                break
            data = data[n:]
        try:
            os.close(w_in)
        except OSError:
            pass
    threading.Thread(target=_feed_stdin, daemon=True).start()
    os.waitpid(pid, 0)                                  # stop at execve

    base = _maps_base(pid, exe) - _elf_min_vaddr(exe)
    mem = _open_mem(pid)
    # `original` is shared across the batch and keyed by RELATIVE address; what this execution
    # has already put back is per-execution, so the shared map is never mutated
    original, restored = _arm(libc, pid, mem, base, blocks, plan), set()

    reached, regs = [], _Regs()
    deadline = _now() + timeout
    rc, flags, deliver, fault_pc, delivered = 0, 0, 0, 0, 0

    def _kill_reap():
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except (ChildProcessError, ProcessLookupError, OSError):
            pass
    # Drain stdout/stderr WHILE the tracee runs. If we only read after it finished, a target
    # that writes more than one pipe buffer (~64 KB) would block in write(), never reach the
    # next trap, and be killed at the deadline -- a normal verbose run misreported as a hang.
    os.set_blocking(r_out, False); os.set_blocking(r_err, False)
    out_buf, err_buf = bytearray(), bytearray()

    def _pump(cap=4096):
        for fd, buf in ((r_out, out_buf), (r_err, err_buf)):
            try:
                c = os.read(fd, 65536)
            except (BlockingIOError, OSError):
                continue
            if c and len(buf) < cap:
                buf += c[:cap - len(buf)]          # keep a bounded prefix; discard the rest

    while True:
        # Enforce the per-input deadline on EVERY iteration, not only while waiting. A tracee
        # that produces back-to-back stops (a handler that re-faults, a flood of coverage traps)
        # keeps `waitpid(WNOHANG)` returning immediately, so the inner wait loop -- the only
        # place the old code checked the clock -- never runs, and one input could spin forever.
        if _now() >= deadline:
            _kill_reap()                          # reliable, unlike deprecated PTRACE_KILL
            flags = 1
            break
        libc.ptrace(PTRACE_CONT, pid, 0, ctypes.c_void_p(deliver))
        deliver = 0
        try:
            _wpid, status = os.waitpid(pid, os.WNOHANG)
            while _wpid == 0 and _now() < deadline:
                _pump()
                time.sleep(0.0005)                # don't spin a core between traps
                _wpid, status = os.waitpid(pid, os.WNOHANG)
            if _wpid == 0:
                _kill_reap()
                flags = 1
                break
        except ChildProcessError:
            break
        if os.WIFEXITED(status):
            rc = os.WEXITSTATUS(status)
            break
        if os.WIFSIGNALED(status):
            rc = -os.WTERMSIG(status)
            break
        sig = os.WSTOPSIG(status)
        if sig != 5:
            # A signal the program HANDLES is not a crash. Under ptrace every signal stops the
            # tracee and is ours to decide on, and killing on sight reported a program that
            # catches SIGSEGV and recovers as crashed -- the same input then had two different
            # verdicts depending on whether block coverage happened to be switched on.
            # Anything using SIGSEGV deliberately (a JIT, a guard page, lazy mapping) would
            # have produced a finding and a PoC for a bug that is not there. A non-fault signal
            # the program does not catch (SIGALRM, SIGTERM, SIGPIPE, SIGCHLD, SIGWINCH...) is
            # ordinary termination or is ignored -- deliver it and let the program's default
            # action stand, rather than killing here and inventing a fault_pc for a non-bug.
            if _handles(pid, sig) or sig not in _CRASH_SIGS:
                delivered += 1
                if delivered > _MAX_DELIVER:
                    # A program re-raising a handled signal without end -- kill it and mark it a
                    # hang rather than forward signal number 4097. This is the one path that
                    # defeats the deadline when each stop is ready the instant we continue.
                    _kill_reap()
                    flags = 1
                    break
                deliver = sig                           # let the program have it, and see
                continue
            # Where it faulted, which is what tells two bugs apart. Bucketing crashes by
            # signal alone collapsed 8,516 of them into one "unique" -- every SIGSEGV in the
            # program is the same finding, however many distinct defects produced them.
            if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs)) == 0:
                fault_pc = regs.rip - base
            rc = -sig                                   # fatal: report it, and do not deliver,
            os.kill(pid, signal.SIGKILL)                # so no core dump handler runs
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            break
        if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs)) != 0:
            break
        hit = regs.rip - 1
        rel = hit - base
        if rel in original and rel not in restored:     # one-shot: restore and never re-arm
            restored.add(rel)
            _poke_byte(libc, pid, mem, hit, original[rel])
            regs.rip = hit
            libc.ptrace(13, pid, 0, ctypes.byref(regs))  # PTRACE_SETREGS
            reached.append(rel)
    if mem is not None:
        try:
            os.close(mem)
        except OSError:
            pass
    _pump()                                             # anything written just before it stopped
    out, err = bytes(out_buf), bytes(err_buf)
    for fd in (r_out, r_err):
        try:
            os.close(fd)
        except OSError:
            pass
    return rc, out, err, flags, reached, fault_pc


def _now():
    return time.time()


def main():
    mode = sys.argv[1]
    per_timeout = float(sys.argv[2])
    exe = sys.argv[3]
    base_argv = sys.argv[4:]
    sanitizer = _is_sanitizer(exe)          # decide once; an AS cap would abort it before main()
    # For the NON-traced path a sanitizer child is bounded by resident memory (it can't take an AS
    # cap); build its env once with hard_rss_limit_mb merged in (abort_on_error is already set by
    # the caller). None => inherit the environment unchanged (the non-sanitizer case).
    child_env = None
    if sanitizer:
        child_env = dict(os.environ)
        _opts = child_env.get("ASAN_OPTIONS", "")
        if "hard_rss_limit_mb" not in _opts:
            child_env["ASAN_OPTIONS"] = (_opts + ":" if _opts else "") \
                + "hard_rss_limit_mb=%d" % _SAN_RSS_MB
    wf = "/tmp/lykos-fuzz-input.bin"        # fixed: a per-batch name leaked into diagnostics
    (count, n_blocks) = struct.unpack("<II", _readn(8))
    blocks = list(struct.unpack("<%dQ" % n_blocks, _readn(8 * n_blocks))) if n_blocks else []
    libc = ctypes.CDLL("libc.so.6", use_errno=True) if blocks else None
    if libc is not None:
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p,
                                ctypes.c_void_p]
    out = sys.stdout.buffer
    plan: dict = {}          # the patched image, built on the first traced run and replayed
    for _ in range(count):
        (ln,) = struct.unpack("<I", _readn(4))
        data = _readn(ln)
        # "@@" marks where the target wants its input; without it the carrier is appended.
        if mode == "arg":
            carrier = data.split(b"\x00", 1)[0].decode("latin-1")
        elif mode == "file":
            with open(wf, "wb") as fh:
                fh.write(data)
            carrier = wf
        else:
            carrier = None
        if carrier is None:
            argv, stdin = [exe] + base_argv, data
        elif "@@" in base_argv:
            argv = [exe] + [carrier if a == "@@" else a for a in base_argv]
            stdin = b""
        else:
            argv = [exe] + base_argv + [carrier]
            stdin = b""
        reached, fault_pc = [], 0
        if blocks:
            rc, so, se, flags, reached, fault_pc = _trace_one(libc, argv, stdin, per_timeout,
                                                              blocks, exe, plan, sanitizer)
        else:
            try:
                pr = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=per_timeout,
                                    preexec_fn=_nontraced_preexec(sanitizer), env=child_env)
                rc, so, se, flags = pr.returncode, pr.stdout[:4096], pr.stderr[:4096], 0
            except subprocess.TimeoutExpired:
                rc, so, se, flags = 0, b"", b"", 1
            except Exception:
                rc, so, se, flags = 0, b"", b"", 2
        out.write(struct.pack("<iIIBIQ", rc, len(so), len(se), flags, len(reached), fault_pc))
        out.write(so); out.write(se)
        if reached:
            out.write(struct.pack("<%dQ" % len(reached), *reached))
    out.flush()


if __name__ == "__main__":
    main()
