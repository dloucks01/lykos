"""Syscall / behavior tracer: run a target and record the security-relevant syscalls it makes
-- process execution, network, file writes/deletes, permission changes, anti-debug, and W^X
violations. A behavioral capability inventory (what the binary *does*), useful for backdoors,
beacons, anti-analysis and persistence. Deterministic; two backends behind one event shape:

- native (x86-64): GDB `catch syscall` stops at each syscall's entry/exit; at entry the kernel
  leaves the return register as -ENOSYS, which we use to read the arguments once. Args come from
  the syscall ABI registers (x86-64: rdi, rsi, rdx, r10, r8, r9; number in orig_rax). Decodes the
  connect() sockaddr to ip:port by reading target memory.
- cross-arch (`trace_qemu`): qemu-user's own `-strace`, which decodes syscall names + most args
  per the target ABI (no gdbstub `catch syscall` exists). It does NOT decode the connect()
  sockaddr (shown as a raw pointer), so a connection's family is inferred from the fd's prior
  socket() call and the destination is left undecoded.
"""
from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from .monitor import _locate_gdb

# x86-64 syscall numbers for the curated catch set (stable ABI)
NR = {59: "execve", 322: "execveat", 42: "connect", 41: "socket", 49: "bind", 43: "accept",
      44: "sendto", 2: "open", 257: "openat", 87: "unlink", 263: "unlinkat", 82: "rename",
      90: "chmod", 268: "fchmodat", 101: "ptrace", 56: "clone", 435: "clone3", 57: "fork",
      58: "vfork", 10: "mprotect", 105: "setuid", 106: "setgid", 62: "kill", 165: "mount",
      155: "pivot_root"}
_NAMES = sorted(set(NR.values()))

_SCRIPT = r'''
import gdb, json
NR = %(nr)s
INPUT_FILE = %(infile)r
RUN_ARGS = %(runargs)r
EV, MAX = [], 4000
AF = {1: "unix", 2: "inet", 10: "inet6"}

def u(r):
    try: return int(gdb.parse_and_eval("$" + r)) & ((1 << 64) - 1)
    except Exception: return None

def sreg(r):  # signed
    try: return int(gdb.parse_and_eval("(long)$" + r))
    except Exception: return None

def cstr(addr, cap=256):
    if not addr: return None
    try:
        return gdb.parse_and_eval("(char*)" + str(addr)).string("latin-1")[:cap]
    except Exception:
        return None

def mem(addr, n):
    try: return bytes(gdb.selected_inferior().read_memory(addr, n))
    except Exception: return b""

def sockaddr(addr):
    b = mem(addr, 16)
    if len(b) < 8: return None
    fam = b[0] | (b[1] << 8)
    if fam == 2:  # AF_INET
        port = (b[2] << 8) | b[3]
        ip = ".".join(str(x) for x in b[4:8])
        return {"family": "inet", "addr": ip, "port": port}
    return {"family": AF.get(fam, str(fam))}

def record():
    nr = u("orig_rax")
    name = NR.get(nr)
    if not name: return
    a0, a1, a2 = u("rdi"), u("rsi"), u("rdx")
    e = {"syscall": name}
    if name in ("execve", "execveat"):
        e["path"] = cstr(a1 if name == "execveat" else a0)
    elif name == "open":
        e["path"] = cstr(a0); e["flags"] = a1
        e["write"] = bool(a1 & 0x043)          # O_WRONLY|O_RDWR|O_CREAT
    elif name == "openat":
        e["path"] = cstr(a1); e["flags"] = a2
        e["write"] = bool((a2 or 0) & 0x043)
    elif name in ("connect", "sendto"):
        e["dest"] = sockaddr(a1)
    elif name == "socket":
        e["family"] = AF.get(a0, str(a0)); e["type"] = a1
    elif name == "mprotect":
        e["prot"] = a2; e["exec"] = bool((a2 or 0) & 0x4)   # PROT_EXEC
    elif name in ("unlink", "chmod", "rename"):
        e["path"] = cstr(a0)
    elif name == "unlinkat":
        e["path"] = cstr(a1)
    elif name == "ptrace":
        e["request"] = a0                      # 0 = PTRACE_TRACEME (anti-debug)
    elif name in ("setuid", "setgid"):
        e["id"] = a0
    elif name == "kill":
        e["pid"] = a0; e["sig"] = a1
    EV.append(e)

gdb.execute("set pagination off")
gdb.execute("set height 0")
gdb.execute("catch syscall " + " ".join(sorted(set(NR.values()))))
RAN, ERR = False, ""
try:
    # args inline: `set args X` then `run < file` resets args to empty (gdb quirk) -> argv lost
    gdb.execute("run " + RUN_ARGS + ((" < " + INPUT_FILE) if INPUT_FILE else ""))
    RAN = True            # the inferior executed (run reached the first catchpoint or exit)
except gdb.error as _e:
    ERR = str(_e)         # never ran (exec-format / cannot-execute / ptrace-denied)
inf = gdb.selected_inferior()
while inf.threads() and len(EV) < MAX:
    if sreg("rax") == -38:                      # -ENOSYS: syscall ENTRY (args valid)
        record()
    try:
        gdb.execute("continue")
    except gdb.error:
        break
# LYKOS_STATUS separates "ran and made no tracked syscall" from "never ran": an empty trace from
# a target that could not be executed must not read as "does nothing security-relevant".
print("LYKOS_STATUS " + json.dumps({"ran": RAN, "error": ERR}))
print("LYKOS_SYS " + json.dumps(EV))
'''


def supported(arch):
    return arch in ("x86-64", None)            # native GDB backend: x86-64 numbers/ABI


# --- cross-arch backend: qemu-user's own -strace (ABI-aware, any arch qemu supports) ---------
_TRACKED = set(NR.values())
_QLINE = re.compile(r'^\s*(?:\d+\s+)?([a-z_][a-z0-9_]*)\((.*)\)\s*=\s*'
                    r'(-?\d+|0x[0-9a-fA-F]+)?', re.I)
_QSTR = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _q_first_str(args):
    m = _QSTR.search(args)
    return m.group(1) if m else None


def _q_first_int(args):
    tok = args.split(",", 1)[0].strip()
    try:
        return int(tok, 0)
    except ValueError:
        return None


def _parse_qemu_strace(text):
    """Parse qemu-user -strace output into the same event shape as the native GDB backend.
    qemu decodes syscall names + most args per the target ABI; it does NOT decode the connect()
    sockaddr (shown as a raw pointer), so a connection's family is inferred from the fd's prior
    socket() call and the destination is left undecoded."""
    ev, inet_fds = [], set()
    for line in text.splitlines():
        m = _QLINE.match(line)
        if not m:
            continue
        name, args, ret = m.group(1), m.group(2), m.group(3)
        if name not in _TRACKED:
            continue
        rv = None
        if ret is not None:
            try:
                rv = int(ret, 0)
            except ValueError:
                rv = None
        e = {"syscall": name}
        if name in ("execve", "execveat"):
            e["path"] = _q_first_str(args)
        elif name in ("open", "openat"):
            e["path"] = _q_first_str(args)
            e["write"] = any(f in args for f in ("O_WRONLY", "O_RDWR", "O_CREAT"))
        elif name == "socket":
            inet = "PF_INET" in args or "AF_INET" in args
            e["family"] = "inet" if inet else args.split(",", 1)[0].strip()
            if inet and rv is not None and rv >= 0:
                inet_fds.add(rv)
        elif name in ("connect", "sendto"):
            fam = "inet" if _q_first_int(args) in inet_fds else "unknown"
            e["dest"] = {"family": fam, "addr": None, "port": None}   # sockaddr not decoded
        elif name == "mprotect":
            e["exec"] = "PROT_EXEC" in args
        elif name in ("unlink", "unlinkat", "chmod", "fchmodat", "rename"):
            e["path"] = _q_first_str(args)
        elif name == "ptrace":
            e["request"] = _q_first_int(args)          # 0 == PTRACE_TRACEME
        elif name in ("setuid", "setgid"):
            e["id"] = _q_first_int(args)
        elif name == "kill":
            e["pid"] = _q_first_int(args)
        ev.append(e)
        if len(ev) >= 4000:
            break
    return ev


def trace_qemu(exe, arch, *, endianness=None, bits=None, argv=(), stdin=b"", timeout=25):
    """Cross-arch syscall trace via qemu-user's -strace (its log goes to a -D file, kept separate
    from the target's own stdout/stderr). ABI-aware for any arch qemu supports."""
    from ..dynamic import sandbox
    qemu = sandbox._qemu_for(arch, endianness, bits)
    if not qemu:
        return {"ok": False, "note": f"no qemu-user for {arch}"}
    d = Path(tempfile.mkdtemp(prefix="lykos-qsys-"))
    try:
        log = d / "strace.log"
        exe_abs = str(Path(exe).resolve())            # absolute: bwrap chdirs to /tmp
        exedir = str(Path(exe_abs).parent)
        inner = [qemu, "-strace", "-D", str(log), exe_abs, *[str(a) for a in argv]]
        # Contain the (hostile) guest: bwrap read-only root, net unshared, rlimits. qemu writes
        # its -strace log to a file under `d`, so `d` is bound WRITABLE; the exe dir is read-only.
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[str(d)]) + inner
        note = timed_out = None
        try:
            sandbox.run_reaped(cmd, input=stdin, capture_output=True, timeout=timeout,
                               preexec_fn=sandbox._rlimits(4096, int(timeout) + 5, set_as=False,
                                                           nproc=sandbox._nproc_cap(True)))
        except subprocess.TimeoutExpired:
            note, timed_out = "trace timed out", True    # still parse what was logged
        text = log.read_text("latin-1", "ignore") if log.exists() else ""
        if not text.strip() and not timed_out:
            # qemu-user logs the loader's own startup syscalls the instant the guest executes, so
            # an empty log with no timeout means the guest never ran (bad image / arch mismatch)
            # -- not "clean, no behavior".
            return {"ok": False, "note": "the target produced no trace under qemu-user -- it "
                    "did not execute; no behavior was observed"}
        return {"ok": True, "events": _parse_qemu_strace(text), "note": note,
                "timed_out": bool(timed_out)}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def trace(exe, arch, *, argv=(), stdin=b"", timeout=25):
    if not supported(arch):
        return {"ok": False, "note": f"syscall trace is x86-64-only for now (target {arch})"}
    gdb_bin = _locate_gdb()
    if not gdb_bin:
        return {"ok": False, "note": "gdb not found"}
    d = Path(tempfile.mkdtemp(prefix="lykos-sys-"))
    try:
        infile = ""
        if stdin:
            (d / "in.bin").write_bytes(stdin)
            infile = str(d / "in.bin")
        script = _SCRIPT % {"nr": repr(NR), "infile": infile,
                            "runargs": " ".join(shlex.quote(a) for a in argv)}
        (d / "sys.py").write_text(script)
        from ..dynamic import sandbox
        # Contain the (hostile) target under GDB: bwrap read-only root (net unshared -- ptrace
        # needs no loopback) + rlimits. The script/input dir is re-bound read-only for gdb.
        exe_abs = str(Path(exe).resolve())            # absolute: bwrap chdirs to /tmp
        exedir = str(Path(exe_abs).parent)
        inner = [gdb_bin, "-batch", "-nx", "-x", str(d / "sys.py"), exe_abs]
        cmd = sandbox.isolate_prefix(exedir, net=False, ro_binds=[str(d)]) + inner
        proc = sandbox.run_reaped(cmd, capture_output=True, timeout=timeout + 20,
                                  preexec_fn=sandbox._rlimits(2048, int(timeout) + 20,
                                                              set_as=False))
        out = proc.stdout.decode("latin-1", "ignore")
        ev = status = None
        for line in out.splitlines():
            if line.startswith("LYKOS_SYS "):
                ev = json.loads(line[len("LYKOS_SYS "):])
            elif line.startswith("LYKOS_STATUS "):
                status = json.loads(line[len("LYKOS_STATUS "):])
        if ev is None or status is None:
            return {"ok": False, "note": "gdb did not run to completion (no result marker) -- "
                    "the target could not be traced; no behavior was observed"}
        if not status.get("ran"):
            return {"ok": False, "note": "the target never executed under gdb (%s) -- no "
                    "syscalls traced, which is not the same as no behavior"
                    % (status.get("error") or "unknown reason")}
        return {"ok": True, "events": ev}
    except subprocess.TimeoutExpired:
        return {"ok": False, "note": "syscall trace timed out before completing"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
