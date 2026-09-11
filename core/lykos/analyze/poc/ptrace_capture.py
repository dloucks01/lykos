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
import signal
import struct
import sys

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
    return int.from_bytes(bytes(buf[_SI_ADDR_OFFSET:_SI_ADDR_OFFSET + 8]), "little")


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


def capture(exe, argv, stdin_file, timeout, breakpoints=None):
    """Run `exe` under ptrace and capture the fault. When `breakpoints` (x86-64 VAs) are given,
    set software breakpoints and, if execution reaches one, report `breakpoint_hit` instead of
    (or before) a fault -- used to confirm a control-flow hijack reached a chosen function."""
    host = _host()
    if host not in ("x86-64", "aarch64"):
        return {"ok": False, "reason": f"unsupported host arch {host}", "arch": host}
    if breakpoints and host != "x86-64":
        breakpoints = None                             # software int3 breakpoints: x86-64 only
    libc = _libc()

    pid = os.fork()
    if pid == 0:                                       # ---- child ----
        try:
            if stdin_file:
                fd = os.open(stdin_file, os.O_RDONLY)
                os.dup2(fd, 0)
            dn = os.open(os.devnull, os.O_WRONLY)
            os.dup2(dn, 1); os.dup2(dn, 2)
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CPU, (int(timeout) + 1, int(timeout) + 2))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            # argv elements arrive through JSON as latin-1 text (the lossless round-trip
            # for arbitrary bytes). They MUST go back to bytes the same way: os.execv
            # encodes str with the filesystem encoding, so UTF-8 turns every byte >= 0x80
            # into two, silently corrupting any payload carrying an address. That is most of
            # them -- it broke argv-delivered IP control outright.
            os.execv(exe, [exe] + [_argv_bytes(a) for a in argv])
        except Exception:
            pass
        os._exit(127)

    # ---- parent (tracer) ----
    def _alarm(_s, _f):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(max(1, int(timeout)))

    os.waitpid(pid, 0)                                 # initial stop at execv (SIGTRAP)
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
            _wpid, status = os.waitpid(pid, 0)
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
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    return result


def main(spec_path):
    spec = json.load(open(spec_path))
    try:
        res = capture(spec["exe"], spec.get("argv", []), spec.get("stdin_file"),
                      float(spec.get("timeout", 10)), breakpoints=spec.get("breakpoints"))
    except Exception as e:                             # noqa: BLE001
        res = {"ok": False, "reason": f"{type(e).__name__}: {e}"}
    sys.stdout.write(json.dumps(res))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: ptrace_capture.py <spec.json>", file=sys.stderr)
        sys.exit(64)
    _ = struct  # reserved for future packed decoders
    sys.exit(main(sys.argv[1]))
