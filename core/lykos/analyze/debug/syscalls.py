"""Syscall / behavior tracer: run a target under GDB and record the security-relevant syscalls
it makes -- process execution, network, file writes/deletes, permission changes, anti-debug,
and W^X violations. A behavioral capability inventory (what the binary *does*), useful for
backdoors, beacons, anti-analysis and persistence. Deterministic, no strace needed, native x86-64.

GDB `catch syscall` stops at each syscall's entry and exit; at entry the kernel leaves the
return register as -ENOSYS, which we use to read the arguments once. Args come from the syscall
ABI registers (x86-64: rdi, rsi, rdx, r10, r8, r9; number in orig_rax).
"""
from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from pathlib import Path

from .monitor import _locate_gdb

# x86-64 syscall numbers for the curated catch set (stable ABI)
NR = {59: "execve", 322: "execveat", 42: "connect", 41: "socket", 49: "bind", 43: "accept",
      44: "sendto", 2: "open", 257: "openat", 87: "unlink", 263: "unlinkat", 82: "rename",
      90: "chmod", 268: "fchmodat", 101: "ptrace", 56: "clone", 57: "fork", 58: "vfork",
      10: "mprotect", 105: "setuid", 106: "setgid", 62: "kill", 165: "mount", 155: "pivot_root"}
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
try:
    # args inline: `set args X` then `run < file` resets args to empty (gdb quirk) -> argv lost
    gdb.execute("run " + RUN_ARGS + ((" < " + INPUT_FILE) if INPUT_FILE else ""))
except gdb.error:
    pass
inf = gdb.selected_inferior()
while inf.threads() and len(EV) < MAX:
    if sreg("rax") == -38:                      # -ENOSYS: syscall ENTRY (args valid)
        record()
    try:
        gdb.execute("continue")
    except gdb.error:
        break
print("LYKOS_SYS " + json.dumps(EV))
'''


def supported(arch):
    return arch in ("x86-64", None)            # x86-64 numbers/ABI for v1


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
        proc = subprocess.run([gdb_bin, "-batch", "-nx", "-x", str(d / "sys.py"), str(exe)],
                              capture_output=True, timeout=timeout + 20)
        out = proc.stdout.decode("latin-1", "ignore")
        ev = []
        for line in out.splitlines():
            if line.startswith("LYKOS_SYS "):
                ev = json.loads(line[len("LYKOS_SYS "):])
        return {"ok": True, "events": ev}
    except subprocess.TimeoutExpired:
        return {"ok": True, "events": [], "note": "trace timed out"}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
