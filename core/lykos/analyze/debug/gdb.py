"""Optional GDB backend for root-cause capture (graceful when absent).

Drives gdb in batch mode to collect the signal, program counter, fault address, faulting-
instruction bytes and process mappings, plus a symbolized backtrace, and normalizes them to
the same capture dict the ptrace helper produces so `rootcause.analyze` is backend-agnostic.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from ..dynamic import sandbox

_SIG = re.compile(r"received signal (SIG\w+)")
_PC = re.compile(r"LYKOS_PC (0x[0-9a-fA-F]+)")
_FAULT = re.compile(r"si_addr = (0x[0-9a-fA-F]+)")
_FRAME = re.compile(r"^#(\d+)\s+(?:0x0*([0-9a-fA-F]+)\s+in\s+|)")
_XBYTES = re.compile(r"0x[0-9a-fA-F]+(?:\s*<[^>]*>)?:\s+((?:0x[0-9a-fA-F]{2}\s*)+)")
_MAPLINE = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+"
                      r"0x[0-9a-fA-F]+\s+(\S*)\s*(.*)$")


def locate_gdb(config: Optional[str] = None) -> Optional[Path]:
    if config and Path(config).exists():
        return Path(config)
    env = os.environ.get("LYKOS_GDB")
    if env and Path(env).exists():
        return Path(env)
    w = shutil.which("gdb")
    return Path(w) if w else None


def run_gdb(gdb: Path, exe, argv, stdin_file, *, ctx=None, timeout: int = 30) -> dict:
    # Arguments go on gdb's OWN command line via --args, not spliced into the `run` line:
    # that line is parsed as a gdb command, so a binary payload is mangled by quoting long
    # before execve ever sees it.
    run_cmd = "run" + ((" < " + stdin_file) if stdin_file else "")
    cmds = [
        "set pagination off", "set confirm off", "set height 0", "set width 0",
        run_cmd,
        'printf "LYKOS_PC %#lx\\n", $pc',
        "print $_siginfo",
        "x/16xb $pc",
        "info proc mappings",
        "bt",
        "quit",
    ]
    script = tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False)
    script.write("\n".join(cmds) + "\n")
    script.close()
    cmd = ([str(gdb), "-q", "-batch", "-nx", "-x", script.name, "--args", str(exe)]
           + [sandbox.argv_bytes(a) for a in argv])
    try:
        if ctx is not None:
            proc = ctx.run_subprocess(cmd, timeout=timeout + 15)
        else:
            import subprocess
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 15, check=False)
        out = (proc.stdout or b"").decode("latin-1", "ignore")
    finally:
        try:
            os.unlink(script.name)
        except OSError:
            pass
    return _parse(out)


_FORK = re.compile(r"fork to child process (\d+)")
_EXECED = re.compile(r"is executing new program:\s*(\S+)")
_CRASH_THREAD = re.compile(r"Thread (\d+)\.\d+[^\n]*received signal")


def run_gdb_follow(gdb: Path, exe, argv, stdin_file, *, ctx=None, timeout: int = 30) -> dict:
    """Multi-process capture (doc 17.3): follow fork/exec into spawned children and capture
    the fault of whichever process actually crashes. Adds fork/exec attribution to the
    normal `run_gdb` capture dict."""
    # Arguments go on gdb's OWN command line via --args, not spliced into the `run` line:
    # that line is parsed as a gdb command, so a binary payload is mangled by quoting long
    # before execve ever sees it.
    run_cmd = "run" + ((" < " + stdin_file) if stdin_file else "")
    cmds = [
        "set pagination off", "set confirm off", "set height 0", "set width 0",
        "set follow-fork-mode child",     # trace the child on fork...
        "set detach-on-fork on",          # ...detaching the parent
        "set follow-exec-mode new",       # follow through execve into the new image
        run_cmd,
        'printf "LYKOS_PC %#lx\\n", $pc',
        "print $_siginfo",
        "x/16xb $pc",
        "info proc mappings",
        "bt",
        "quit",
    ]
    script = tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False)
    script.write("\n".join(cmds) + "\n")
    script.close()
    cmd = ([str(gdb), "-q", "-batch", "-nx", "-x", script.name, "--args", str(exe)]
           + [sandbox.argv_bytes(a) for a in argv])
    try:
        if ctx is not None:
            proc = ctx.run_subprocess(cmd, timeout=timeout + 15)
        else:
            import subprocess
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 15, check=False)
        out = (proc.stdout or b"").decode("latin-1", "ignore")
    finally:
        try:
            os.unlink(script.name)
        except OSError:
            pass
    cap = _parse(out)
    fork = _FORK.search(out)
    execed = _EXECED.search(out)
    cap["forked"] = bool(fork)
    cap["child_pid"] = int(fork.group(1)) if fork else None
    cap["execed"] = execed.group(1) if execed else None
    cap["multiproc"] = bool(fork or execed)
    return cap


def _parse(out: str) -> dict:
    sig = _SIG.search(out)
    if sig is None:
        return {"ok": False, "reason": "gdb reported no crash", "raw": out[-400:]}
    pc = _PC.search(out)
    fault = _FAULT.search(out)
    pc_bytes = ""
    for m in _XBYTES.finditer(out):
        for tok in m.group(1).split():
            pc_bytes += f"{int(tok, 16):02x}"
        if len(pc_bytes) >= 32:
            break
    maps = []
    for line in out.splitlines():
        m = _MAPLINE.match(line)
        if m:
            perms = m.group(3) if any(c in m.group(3) for c in "rwxp-") else ""
            maps.append({"start": int(m.group(1), 16), "end": int(m.group(2), 16),
                         "perms": perms, "path": m.group(4).strip()})
    # Drop frame #0 BY NUMBER, not by position. gdb omits the address for the innermost
    # frame ("#0  __memcpy_avx512_unaligned_erms () at ..."), so it never parsed, and slicing
    # the first element off the parsed list threw away frame #1 instead -- the caller that
    # actually names the faulting call site.
    frames = []
    for line in out.splitlines():
        m = _FRAME.match(line.strip())
        if m and m.group(2) and m.group(1) != "0":
            frames.append(int(m.group(2), 16))
    return {"ok": True, "source": "gdb", "signal_name": sig.group(1),
            "pc": int(pc.group(1), 16) if pc else None,
            "fault_addr": int(fault.group(1), 16) if fault else None,
            "pc_bytes": pc_bytes[:32], "backtrace": frames, "regs": {}, "maps": maps,
            "gdb_raw": out[-4000:]}
