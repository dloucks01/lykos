"""doc 58: bonus detonation oracles -- run a constructed PoC and confirm, soundly, that it did what
the construction claims. Used only when the target can execute here (or once the operator supplies
the deps the pre-flight named); a sound construction never depends on it. x86-64 Linux.

`reaches_address` is the control-flow oracle: it proves a payload transfers control to a chosen
address (a win function, a one-gadget) by setting an INT3 breakpoint there and delivering the input.
A SIGTRAP at that address is proof the hijack fired -- stronger and more general than matching a
program-specific output marker. No PIE only (the address is the file vaddr); a PIE target would need
the runtime load base, which this does not yet resolve."""
from __future__ import annotations

import ctypes
import logging
import os
import signal
import time

_log = logging.getLogger(__name__)

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_CONT = 7
PTRACE_GETREGS = 12


def _libc():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    return libc


class _Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
        "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
        "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")]


def reaches_address(exe: str, payload: bytes, vaddr: int, *, input_mode: str = "stdin",
                    argv=None, timeout: float = 8.0) -> bool:
    """True if delivering `payload` makes control reach `vaddr` (INT3 breakpoint hit there).

    Sound: a SIGTRAP whose RIP is vaddr+1 means the CPU executed our planted 0xCC at vaddr, i.e.
    control was transferred there. False on any other outcome (timeout, clean exit, crash
    elsewhere). Best-effort: never raises."""
    try:
        return _reaches(exe, payload, vaddr, input_mode, argv or [], timeout)
    except Exception:                                    # noqa: BLE001
        _log.debug("reaches_address failed", exc_info=True)
        return False


def _reaches(exe, payload, vaddr, input_mode, argv, timeout) -> bool:
    r0, w0 = os.pipe()                                   # payload -> child stdin
    pid = os.fork()
    if pid == 0:                                         # ---- child ----
        try:
            libc = _libc()
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            if input_mode == "stdin":
                os.dup2(r0, 0)
            os.close(r0); os.close(w0)
            dn = os.open(os.devnull, os.O_WRONLY)
            os.dup2(dn, 1); os.dup2(dn, 2)
            os.execv(exe, [exe] + [str(a) for a in argv])
        except Exception:
            pass
        os._exit(127)
    # ---- parent ----
    os.close(r0)
    libc = _libc()
    reached = False
    try:
        _, status = os.waitpid(pid, 0)                   # stop at execv (SIGTRAP)
        if not os.WIFSTOPPED(status):
            return False
        # plant INT3 at vaddr
        orig = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(vaddr), None)
        if orig == -1 and ctypes.get_errno() != 0:
            return False
        orig &= (1 << 64) - 1
        bp = (orig & ~0xff) | 0xCC
        libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(vaddr), ctypes.c_void_p(bp))
        libc.ptrace(PTRACE_CONT, pid, None, None)
        try:
            if input_mode == "stdin":
                os.write(w0, payload)
        except OSError:
            pass
        finally:
            os.close(w0)
        # watch for the breakpoint, honouring a wall-clock deadline. Poll with WNOHANG rather than
        # SIGALRM: analyze stages run in worker THREADS, where signal.signal/setitimer raise
        # ValueError ("signal only works in main thread") -- which silently killed detonation.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == 0:
                time.sleep(0.002)
                continue
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP:
                regs = _Regs()
                if libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs)) == 0:
                    if regs.rip == (vaddr + 1) & ((1 << 64) - 1):
                        reached = True
                        break
                # not our breakpoint: continue
                libc.ptrace(PTRACE_CONT, pid, None, None)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                break
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass
    return reached


def runs_injected_command(exe: str, payload: bytes, marker: bytes, *, input_mode: str = "stdin",
                          argv=None, timeout: float = 6.0) -> bool:
    """CWE-78 oracle: True if delivering `payload` makes the injected marker command RUN -- i.e.
    `marker` appears in the target's output. The payload injects `echo <marker>`; its appearance is
    proof of arbitrary command execution (sound when paired with a benign negative control)."""
    import subprocess
    try:
        if input_mode == "stdin":
            r = subprocess.run([exe] + [str(a) for a in (argv or [])], input=payload,
                               capture_output=True, timeout=timeout)
        elif input_mode == "arg":
            r = subprocess.run([exe] + [str(a) for a in (argv or [])] + [payload.decode("latin1")],
                               capture_output=True, timeout=timeout)
        else:
            return False
        return marker in ((r.stdout or b"") + (r.stderr or b""))
    except Exception:                                    # noqa: BLE001
        return False


def probe_fmt_offset(exe: str, *, input_mode: str = "stdin", argv=None, timeout: float = 6.0):
    """Recover the printf-varargs arg offset of a format-string sink by delivering the %p probe and
    scanning the output -- the dynamic fallback when the static frame recovery can't place the
    buffer (e.g. the decompiler symbolized the stack local). None if the target cannot run or the
    marker is not seen."""
    import subprocess
    from .fmt import probe_payload, find_fmt_offset
    probe = probe_payload(count=40)
    try:
        if input_mode == "stdin":
            p = subprocess.run([exe] + [str(a) for a in (argv or [])], input=probe,
                               capture_output=True, timeout=timeout)
        else:
            return None
        return find_fmt_offset(p.stdout, marker=0x4141414141414141)
    except Exception:                                    # noqa: BLE001
        return None
