#!/usr/bin/env python3
"""Standalone ptrace register-capture helper (Phase 6, L2 primitives).

Runs the target as a traced child and, when it dies on a fatal signal, reads the CPU register
file at the fault. Pure stdlib (ctypes) so it needs no external tool, but it must run as its
OWN process (never fork from the threaded worker), so the stage invokes it as a subprocess:

    <python> ptrace_capture.py <spec.json>          # writes a JSON result to stdout

spec.json: {exe, argv:[...after exe...], stdin_file: path|null, timeout: seconds}
Only the host architecture is supported (native execution); cross-arch/qemu is out of scope
here. Always prints a JSON object; ok=false with a reason when nothing could be captured.
"""
import ctypes
import json
import os
import platform
import select
import signal
import struct
import sys
import time

# ---------------------------------------------------------------------------------- absorbed
# This driver runs as a standalone script under a different interpreter (the parent copies it to
# a scratch dir), so `lykos.observe` is not importable here. The counter still has to reach the
# parent, because a silently-skipped step in a tracer is exactly what turns a real crash into
# "no crash observed" -- so absorbed steps ride home in the JSON result and the parent folds
# them into its own counter. See observe.absorbed_remote.
_ABSORBED: list = []


def _absorbed(what):
    """Record a deliberately-absorbed failure, with the live exception's repr."""
    import sys as _sys
    exc = _sys.exc_info()[1]
    _ABSORBED.append({"what": what, "exc": repr(exc)[:200]})


PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_KILL = 8
PTRACE_GETSIGINFO = 0x4202
PTRACE_GETREGSET = 0x4204
NT_PRSTATUS = 1
_SI_ADDR_OFFSET = 16          # offset of si_addr in siginfo_t (x86-64 / aarch64)
_SI_CODE_OFFSET = 8           # offset of si_code (after si_signo, si_errno) on both hosts

# stack window captured around SP at the fault (bytes): enough to hold the saved return
# address and adjacent controlled slots, so the offset can be recovered even when a
# non-canonical return address makes RIP report the faulting `ret` site instead.
_STACK_BEFORE = 64
_STACK_AFTER = 256

FATAL = {signal.SIGSEGV: "SIGSEGV", signal.SIGABRT: "SIGABRT", signal.SIGBUS: "SIGBUS",
         signal.SIGILL: "SIGILL", signal.SIGFPE: "SIGFPE", signal.SIGSYS: "SIGSYS"}

# per-arch register decoders: name -> (how to read regs, {reg: index}, pc_name, sp_name)
# x86-64 user_regs_struct order (sys/user.h): 27 u64.
_X86_64 = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax",
           "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss",
           "fs_base", "gs_base", "ds", "es", "fs", "gs"]


def _host():
    m = platform.machine().lower()
    return {"x86_64": "x86-64", "amd64": "x86-64", "aarch64": "aarch64",
            "arm64": "aarch64", "armv7l": "arm"}.get(m, m)


def _libc():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    return libc


def _getregs_x86_64(libc, pid):
    buf = (ctypes.c_uint64 * len(_X86_64))()
    if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(buf)) != 0:
        return None
    regs = {name: int(buf[i]) for i, name in enumerate(_X86_64)}
    return regs, "rip", "rsp"


def _getregset_prstatus(libc, pid, count):
    buf = (ctypes.c_uint64 * count)()

    class Iovec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
    iov = Iovec(ctypes.cast(buf, ctypes.c_void_p), ctypes.sizeof(buf))
    if libc.ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, ctypes.byref(iov)) != 0:
        return None
    return buf


def _read_stack(libc, pid, sp):
    """Read a window around SP one word at a time (PEEKDATA). Returns (base, hex-bytes)."""
    base = sp - _STACK_BEFORE
    out = bytearray()
    addr = base
    end = sp + _STACK_AFTER
    while addr < end:
        ctypes.set_errno(0)
        word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), 0)
        if word == -1 and ctypes.get_errno() != 0:
            break                                     # hit an unmapped page; stop
        out += int(word & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        addr += 8
    return base, out.hex()


def _peek(libc, pid, addr):
    ctypes.set_errno(0)
    word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), 0)
    if word == -1 and ctypes.get_errno() != 0:
        return None
    return word & 0xFFFFFFFFFFFFFFFF


def _set_breakpoint(libc, pid, addr):
    """Write a 0xCC (int3) at addr, returning the original byte, or None on failure."""
    ctypes.set_errno(0)
    word = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(addr), 0)
    if word == -1 and ctypes.get_errno() != 0:
        return None
    word &= 0xFFFFFFFFFFFFFFFF
    orig = word & 0xFF
    patched = (word & ~0xFF) | 0xCC
    if libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(addr),
                   ctypes.c_void_p(patched)) != 0:
        return None
    return orig


def _read_bytes(libc, pid, addr, n):
    out = bytearray()
    while len(out) < n:
        w = _peek(libc, pid, addr + len(out))
        if w is None:
            break
        out += w.to_bytes(8, "little")
    return bytes(out[:n])


def _siginfo_addr(libc, pid):
    buf = (ctypes.c_ubyte * 256)()
    if libc.ptrace(PTRACE_GETSIGINFO, pid, 0, ctypes.byref(buf)) != 0:
        return None
    return _si_addr_from(bytes(buf))


def _si_addr_from(raw):
    """si_addr out of a raw siginfo_t, or None when it is not a fault address.

    si_addr is the faulting address only for a KERNEL-generated fault (si_code > 0). A signal sent
    with raise()/kill()/tgkill() has si_code <= 0 (SI_USER 0, SI_TKILL -6, SI_QUEUE -1, ...) and
    the same union bytes hold the sender's pid/uid -- reporting that as `fault_addr` would hand
    the L2 classifier a fabricated address. Mirrors debug/gdb.py and debug/qemu_gdb.py."""
    if len(raw) < _SI_ADDR_OFFSET + 8:
        return None
    si_code = int.from_bytes(raw[_SI_CODE_OFFSET:_SI_CODE_OFFSET + 4], "little", signed=True)
    if si_code <= 0:
        return None
    return int.from_bytes(raw[_SI_ADDR_OFFSET:_SI_ADDR_OFFSET + 8], "little")


def _maps(pid):
    out = []
    try:
        with open(f"/proc/{pid}/maps") as fh:
            for line in fh:
                parts = line.split(None, 5)
                if len(parts) < 5:
                    continue
                lo, hi = parts[0].split("-")
                out.append({"start": int(lo, 16), "end": int(hi, 16),
                            "perms": parts[1], "path": parts[5].strip()
                            if len(parts) > 5 else ""})
    except OSError:
        pass
    return out


def _backtrace(libc, pid, regs, host, maxframes=32):
    """Return-address chain via the frame pointer (rbp / x29). Best-effort; a smashed stack
    yields garbage, which the analyzer reads as the root cause."""
    fp = regs.get("rbp", 0) if host == "x86-64" else regs.get("x29", 0)
    frames = []
    for _ in range(maxframes):
        if not fp:
            break
        ret = _peek(libc, pid, fp + 8)
        nxt = _peek(libc, pid, fp)
        if ret is None:
            break
        frames.append(ret)
        if nxt is None or nxt <= fp:
            break                                     # chain must ascend or it is corrupt
        fp = nxt
    return frames


def _getregs_aarch64(libc, pid):
    buf = _getregset_prstatus(libc, pid, 34)          # x0..x30, sp, pc, pstate
    if buf is None:
        return None
    regs = {f"x{i}": int(buf[i]) for i in range(31)}
    regs["sp"] = int(buf[31]); regs["pc"] = int(buf[32]); regs["pstate"] = int(buf[33])
    return regs, "pc", "sp"


def _argv_bytes(a):
    """An argv element as bytes, without re-encoding a binary payload.

    argv arrives through JSON as latin-1 text -- the lossless round-trip for arbitrary bytes.
    os.execv encodes str with the filesystem encoding, so UTF-8 turns every byte >= 0x80 into
    two and silently corrupts any payload carrying an address. (Mirrors sandbox.argv_bytes;
    this file is materialised as a standalone helper and cannot import it.)
    """
    if isinstance(a, bytes):
        return a
    if not isinstance(a, str):
        a = str(a)
    try:
        return a.encode("latin-1")
    except UnicodeEncodeError:
        return a.encode("utf-8", "surrogateescape")


def capture(exe, argv, stdin_file, timeout, breakpoints=None, env=None,
            stdin_chunks=None, idle=0.08):
    """Run `exe` under ptrace and capture the fault. When `breakpoints` (x86-64 VAs) are given,
    set software breakpoints and, if execution reaches one, report `breakpoint_hit` instead of
    (or before) a fault -- used to confirm a control-flow hijack reached a chosen function.

    `stdin_chunks` delivers input ONE FIELD PER PROMPT instead of redirecting a file onto stdin.
    A prompt-driven target reads with `read(0, ...)`, which returns whatever is available, so a
    bulk feed puts every field into field one and the program rejects it or desyncs -- the whole
    blob lands in the first `read` and the second reaches EOF. The campaign already knew this
    (`fuzz.runner.run_input_prompted`) and so did the shipped bundle (`replay_prompt.py`), but
    this tracer did not, so a crash recorded as `input_mode="prompt"` was captured with NO INPUT
    AT ALL and reported as "no fatal signal" -- which capped every prompt-paced defect at L1.

    Paced mode keeps the child's stdin as a PIPE and its stdout/stderr as a second pipe, and
    writes the next chunk once the child's output has been quiet for `idle` seconds. It cannot
    use a file redirect, because pacing is the point."""
    host = _host()
    if host not in ("x86-64", "aarch64"):
        return {"ok": False, "reason": f"unsupported host arch {host}", "arch": host}
    if breakpoints and host != "x86-64":
        breakpoints = None                             # software int3 breakpoints: x86-64 only
    libc = _libc()

    paced = bool(stdin_chunks)
    in_r = in_w = out_r = out_w = -1
    if paced:
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()

    pid = os.fork()
    if pid == 0:                                       # ---- child ----
        try:
            if paced:
                # stdin is a PIPE the tracer feeds a field at a time, and stdout/stderr come back
                # to the tracer because its output is the clock the pacing runs on. Everything
                # else keeps /dev/null: a target that prints megabytes must not fill a pipe
                # nobody drains.
                os.dup2(in_r, 0)
                os.dup2(out_w, 1)
                os.dup2(out_w, 2)
                for fd in (in_r, in_w, out_r, out_w):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            else:
                if stdin_file:
                    fd = os.open(stdin_file, os.O_RDONLY)
                    os.dup2(fd, 0)
                dn = os.open(os.devnull, os.O_WRONLY)
                os.dup2(dn, 1); os.dup2(dn, 2)
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CPU, (int(timeout) + 1, int(timeout) + 2))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                # Bound a hostile target's memory and disk writes -- not just its CPU. (NPROC is
                # left to the outer runner's baseline-aware cap; a fixed value here would fail
                # execv with EAGAIN on a busy host.)
                lim = 4096 << 20
                resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
                resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            except Exception:
                _absorbed("continuing")
            try:                                           # deterministic addresses: ASLR off
                cur = libc.personality(0xffffffff)         # query, then OR in ADDR_NO_RANDOMIZE
                if cur != -1:
                    libc.personality(cur | 0x0040000)
            except Exception:
                _absorbed("continuing")
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            # argv elements arrive through JSON as latin-1 text (the lossless round-trip
            # for arbitrary bytes). They MUST go back to bytes the same way: os.execv
            # encodes str with the filesystem encoding, so UTF-8 turns every byte >= 0x80
            # into two, silently corrupting any payload carrying an address. That is most of
            # them -- it broke argv-delivered IP control outright.
            if env:
                # An ENV-delivered input (the channel env_fuzz crashes a getenv() reader on) has to
                # be handed over at exec. Same latin-1 -> bytes round-trip as argv: the value is an
                # arbitrary payload, so re-encoding it as UTF-8 would corrupt every byte >= 0x80.
                e = {k.encode("latin-1", "ignore") if isinstance(k, str) else k: _argv_bytes(v)
                     for k, v in env.items()}
                full = {k.encode() if isinstance(k, str) else k: v.encode() if isinstance(v, str)
                        else v for k, v in os.environb.items()} if hasattr(os, "environb") else {}
                full.update(e)
                os.execve(exe, [exe] + [_argv_bytes(a) for a in argv], full)
            os.execv(exe, [exe] + [_argv_bytes(a) for a in argv])
        except Exception:
            _absorbed("continuing")
        os._exit(127)

    # ---- parent (tracer) ----
    if paced:
        for fd in (in_r, out_w):
            try:
                os.close(fd)
            except OSError:
                pass
        os.set_blocking(out_r, False)
        os.set_blocking(in_w, False)

    pump = {"fed": 0, "quiet_since": time.time(), "closed": False, "out": bytearray()}

    def _pump_once():
        """Drain whatever the child has said; feed the next field when it goes quiet.

        The clock is the child's own output, not a fixed delay: that is what makes this track a
        target whose prompts are slow without waiting for a target whose prompts are fast."""
        try:
            data = os.read(out_r, 65536)
        except (BlockingIOError, InterruptedError):
            data = None
        except OSError:
            data = b""
        if data:
            if len(pump["out"]) < 65536:
                pump["out"] += data
            pump["quiet_since"] = time.time()
            return
        if time.time() - pump["quiet_since"] < idle:
            return
        if pump["fed"] < len(stdin_chunks):
            try:
                os.write(in_w, stdin_chunks[pump["fed"]])
            except (BlockingIOError, InterruptedError):
                return                                 # pipe full: try again next tick
            except OSError:
                pump["fed"] = len(stdin_chunks)        # the child is gone; stop feeding
                return
            pump["fed"] += 1
            pump["quiet_since"] = time.time()
        elif not pump["closed"]:
            # EOF, so a `while (fgets(...))` loop ends instead of blocking until the alarm.
            pump["closed"] = True
            try:
                os.close(in_w)
            except OSError:
                pass

    def _wait():
        """`os.waitpid(pid, 0)`, except that in paced mode the tracer has to keep feeding the
        child while it waits -- a blocking waitpid would deadlock against a child blocked on a
        `read` the tracer has not performed yet."""
        if not paced:
            return os.waitpid(pid, 0)
        while True:
            w, status = os.waitpid(pid, os.WNOHANG)
            if w == pid:                               # test the PID: status 0 is a real exit(0)
                return w, status
            select.select([out_r], [], [], 0.02)
            _pump_once()

    fired = {"timeout": False}

    def _alarm(_s, _f):
        fired["timeout"] = True
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(max(1, int(timeout)))

    _wait()                                            # initial stop at execv (SIGTRAP)
    bp_orig = {}
    if breakpoints:                                    # loaded image is now mapped
        for addr in breakpoints:
            o = _set_breakpoint(libc, pid, int(addr))
            if o is not None:
                bp_orig[int(addr)] = o
    libc.ptrace(PTRACE_CONT, pid, 0, 0)
    result = {"ok": False, "reason": "no fatal signal", "arch": host}
    while True:
        try:
            _wpid, status = _wait()
        except ChildProcessError:
            break
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            break
        if os.WIFSTOPPED(status):
            sig = os.WSTOPSIG(status)
            if bp_orig and sig == signal.SIGTRAP:
                got = _getregs_x86_64(libc, pid)
                pc = got[0][got[1]] if got else 0
                hit = (pc - 1) if (pc - 1) in bp_orig else (pc if pc in bp_orig else None)
                if hit is not None:
                    result = {"ok": True, "arch": host, "breakpoint_hit": hit,
                              "pc": pc, "regs": got[0] if got else {}}
                    libc.ptrace(PTRACE_KILL, pid, 0, 0)
                    break
                libc.ptrace(PTRACE_CONT, pid, 0, 0)    # not our breakpoint; keep going
                continue
            if sig in FATAL:
                got = _getregs_x86_64(libc, pid) if host == "x86-64" \
                    else _getregs_aarch64(libc, pid)
                if got:
                    regs, pc_name, sp_name = got
                    sp_val = regs[sp_name]
                    pc_val = regs[pc_name]
                    stack_base, stack_hex = _read_stack(libc, pid, sp_val)
                    result = {"ok": True, "arch": host, "signal": int(sig),
                              "signal_name": FATAL[sig], "pc_name": pc_name,
                              "sp_name": sp_name, "pc": pc_val, "sp": sp_val,
                              "regs": regs, "stack_base": stack_base, "stack": stack_hex,
                              "fault_addr": _siginfo_addr(libc, pid),
                              "pc_bytes": _read_bytes(libc, pid, pc_val, 16).hex(),
                              "backtrace": _backtrace(libc, pid, regs, host),
                              "maps": _maps(pid)}
                else:
                    result = {"ok": False, "reason": "GETREGS failed", "arch": host,
                              "signal_name": FATAL[sig]}
                libc.ptrace(PTRACE_KILL, pid, 0, 0)
                break
            libc.ptrace(PTRACE_CONT, pid, 0, sig)      # deliver non-fatal signals
    signal.alarm(0)
    if fired["timeout"] and not result.get("ok"):
        # The tracer's own SIGKILL ended the run: that is a TIMEOUT, not a run that finished
        # without faulting. Reporting it as "no fatal signal" read as a clean negative.
        result["reason"] = f"timed out after {max(1, int(timeout))}s (killed by the tracer)"
        result["timed_out"] = True
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    if paced:
        for fd in (out_r,) + ((in_w,) if not pump["closed"] else ()):
            try:
                os.close(fd)
            except OSError:
                pass
        # How many fields actually went in, so a capture that delivered only field one is
        # distinguishable from one that delivered all of them and still did not fault.
        result["fields_delivered"] = pump["fed"]
        result["fields_total"] = len(stdin_chunks)
        result["target_output"] = bytes(pump["out"][:4096]).decode("latin-1", "replace")
    return result


def main(spec_path):
    with open(spec_path) as _f:
        spec = json.load(_f)
    try:
        chunks = spec.get("stdin_chunks")
        # latin-1 is the lossless byte round-trip through JSON, the same convention argv and env
        # already use in this helper.
        if chunks is not None:
            chunks = [c.encode("latin-1") if isinstance(c, str) else bytes(c) for c in chunks]
        res = capture(spec["exe"], spec.get("argv", []), spec.get("stdin_file"),
                      float(spec.get("timeout", 10)), breakpoints=spec.get("breakpoints"),
                      env=spec.get("env"), stdin_chunks=chunks,
                      idle=float(spec.get("idle", 0.08)))
    except Exception as e:                             # noqa: BLE001
        res = {"ok": False, "reason": f"{type(e).__name__}: {e}"}
    res["absorbed"] = _ABSORBED
    sys.stdout.write(json.dumps(res))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: ptrace_capture.py <spec.json>", file=sys.stderr)
        sys.exit(64)
    _ = struct  # reserved for future packed decoders
    sys.exit(main(sys.argv[1]))
