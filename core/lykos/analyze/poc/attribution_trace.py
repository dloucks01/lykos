"""Syscall write-ATTRIBUTION tracer (stdlib ptrace, x86-64): run a target and record every
``write(2)``/``writev(2)`` together with the PID that made it and that PID's lineage relative
to the traced target -- so a caller can credit output only when the TARGET'S OWN process
subtree produced it, not the harness, a helper, or a value reflected back.

Why this over parsing ``strace -f`` text (the usual approach): a text trace loses the process
tree to reassembly, splits long records, renames CLONE_THREAD relays, and forces an execve
success/failure denylist -- each a real bug source. Here the tree is authoritative: children
arrive as ptrace fork/clone/exec EVENTS with the new pid read straight from the kernel, an
in-place ``execve`` keeps the same pid (so a shell that replaces the target stays in lineage),
and a write's pid is the stopped tracee itself -- nothing is inferred from text.

It runs as its OWN process (ptrace must, and it must never fork the threaded worker), driven as
a subprocess:  ``<python> attribution_trace.py <spec.json>`` -> a JSON result on stdout.
Spec: {exe, argv[], stdin_file|null, timeout, max_writes, max_bytes}.
Result: {ok, host, exit, signal, lineage_writes[], foreign_writes[], truncated}
  each write: {pid, fd, data(latin-1), lineage(bool)}.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import signal
import sys

PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201

PTRACE_O_TRACESYSGOOD = 0x01
PTRACE_O_TRACEFORK = 0x02
PTRACE_O_TRACEVFORK = 0x04
PTRACE_O_TRACECLONE = 0x08
PTRACE_O_TRACEEXEC = 0x10
PTRACE_O_EXITKILL = 0x00100000

# status >> 8 == (SIGTRAP | (EVENT << 8)) identifies a ptrace event-stop.
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4

__WALL = 0x40000000          # wait for clone-thread children too, not just fork children
NR_WRITE = 1
NR_WRITEV = 20

FATAL = {signal.SIGSEGV: "SIGSEGV", signal.SIGABRT: "SIGABRT", signal.SIGBUS: "SIGBUS",
         signal.SIGILL: "SIGILL", signal.SIGFPE: "SIGFPE", signal.SIGSYS: "SIGSYS"}


class _Regs(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax",
        "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss",
        "fs_base", "gs_base", "ds", "es", "fs", "gs")]


def _libc():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    return libc


def _getregs(libc, pid):
    buf = _Regs()
    if libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(buf)) != 0:
        return None
    return buf


def _read_bytes(libc, pid, addr, n):
    out = bytearray()
    a = addr
    while len(out) < n:
        ctypes.set_errno(0)
        word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(a), 0)
        if word == -1 and ctypes.get_errno() != 0:
            break
        out += int(word & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
        a += 8
    return bytes(out[:n])


def _read_writev(libc, pid, iov_addr, iovcnt, cap):
    """Reassemble a writev() payload: iovcnt * struct iovec { void *base; size_t len; }."""
    out = bytearray()
    for i in range(min(iovcnt, 1024)):
        rec = _read_bytes(libc, pid, iov_addr + i * 16, 16)
        if len(rec) < 16:
            break
        base = int.from_bytes(rec[0:8], "little")
        ln = int.from_bytes(rec[8:16], "little")
        if base and ln:
            out += _read_bytes(libc, pid, base, min(ln, cap - len(out)))
        if len(out) >= cap:
            break
    return bytes(out)


def trace(exe, argv, stdin_file, timeout, *, max_writes=4000, max_bytes=65536):
    host = platform.machine()
    if host not in ("x86_64", "AMD64"):
        return {"ok": False, "reason": f"attribution tracer is x86-64 only (host {host})",
                "host": host}
    libc = _libc()

    pid = os.fork()
    if pid == 0:                                       # ---- child (the target) ----
        try:
            if stdin_file:
                fd = os.open(stdin_file, os.O_RDONLY)
                os.dup2(fd, 0)
            dn = os.open(os.devnull, os.O_WRONLY)       # captured via ptrace, not the fd
            os.dup2(dn, 1)
            os.dup2(dn, 2)
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CPU, (int(timeout) + 1, int(timeout) + 2))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                lim = 4096 << 20
                resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
                resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            except Exception:
                pass
            libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
            os.execv(exe, [exe] + [a.encode("latin-1", "ignore") if isinstance(a, str) else a
                                   for a in argv])
        except Exception:
            pass
        os._exit(127)

    # ---- parent (tracer) ----
    root = pid                       # the target's own pid; an in-place execve preserves it
    lineage = {root}                 # pids whose lineage execve'd from the target subtree
    insys = {}                       # pid -> awaiting-syscall-EXIT toggle
    result = {"ok": True, "host": "x86-64", "root": root, "exit": None, "signal": None,
              "lineage_writes": [], "foreign_writes": [], "truncated": False}
    nbytes = [0]

    def _alarm(_s, _f):
        for p in list(lineage) + [root]:
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(max(1, int(timeout)))

    os.waitpid(pid, 0)               # initial stop at execv
    opts = (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)
    libc.ptrace(PTRACE_SETOPTIONS, pid, 0, opts)
    libc.ptrace(PTRACE_SYSCALL, pid, 0, 0)

    def _record(cpid, regs):
        nr = regs.orig_rax
        if nr == NR_WRITE:
            fd, buf, cnt = regs.rdi, regs.rsi, regs.rdx
            data = _read_bytes(libc, cpid, buf, min(cnt, max_bytes - nbytes[0]))
        elif nr == NR_WRITEV:
            fd = regs.rdi
            data = _read_writev(libc, cpid, regs.rsi, regs.rdx, max_bytes - nbytes[0])
        else:
            return
        if not data:
            return
        nbytes[0] += len(data)
        bucket = "lineage_writes" if cpid in lineage else "foreign_writes"
        if len(result["lineage_writes"]) + len(result["foreign_writes"]) >= max_writes \
                or nbytes[0] >= max_bytes:
            result["truncated"] = True
        result[bucket].append({"pid": cpid, "fd": int(fd),
                               "data": data.decode("latin-1", "replace"),
                               "lineage": cpid in lineage})

    while lineage:
        try:
            wpid, status = os.waitpid(-1, __WALL)
        except ChildProcessError:
            break
        except OSError:
            break

        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            if wpid == root:
                if os.WIFSIGNALED(status):
                    result["signal"] = FATAL.get(os.WTERMSIG(status), int(os.WTERMSIG(status)))
                else:
                    result["exit"] = os.WEXITSTATUS(status)
            lineage.discard(wpid)
            insys.pop(wpid, None)
            continue

        if not os.WIFSTOPPED(status):
            continue
        stopsig = os.WSTOPSIG(status)
        event = status >> 8

        # A new child from fork/vfork/clone: read its pid from the kernel and adopt it.
        if event in (signal.SIGTRAP | (PTRACE_EVENT_FORK << 8),
                     signal.SIGTRAP | (PTRACE_EVENT_VFORK << 8),
                     signal.SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
            newpid = ctypes.c_ulong(0)
            if libc.ptrace(PTRACE_GETEVENTMSG, wpid, 0, ctypes.byref(newpid)) == 0:
                if wpid in lineage:
                    lineage.add(newpid.value)      # spawned by the target subtree -> in lineage
            libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
            continue
        if event == (signal.SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
            # in-place execve: same pid, still the target's lineage (a shell replacing it stays).
            insys[wpid] = False
            libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
            continue

        if stopsig == (signal.SIGTRAP | 0x80):         # syscall-stop (TRACESYSGOOD)
            entering = not insys.get(wpid, False)
            insys[wpid] = entering
            if entering:
                regs = _getregs(libc, wpid)
                if regs is not None and not result["truncated"]:
                    _record(wpid, regs)
            libc.ptrace(PTRACE_SYSCALL, wpid, 0, 0)
            continue

        # A real signal to the tracee (e.g. SIGSEGV from a failed exploit): deliver it, unless
        # it is the initial group-stop SIGTRAP.
        deliver = 0 if stopsig == signal.SIGTRAP else stopsig
        libc.ptrace(PTRACE_SYSCALL, wpid, 0, deliver)

    signal.alarm(0)
    return result


def main(argv):
    spec = json.loads(open(argv[1]).read())
    res = trace(spec["exe"], spec.get("argv", []), spec.get("stdin_file"),
                spec.get("timeout", 10), max_writes=spec.get("max_writes", 4000),
                max_bytes=spec.get("max_bytes", 65536))
    sys.stdout.write(json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
