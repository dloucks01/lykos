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

_SIG = re.compile(r"received signal (SIG\w+)")
_PC = re.compile(r"LYKOS_PC (0x[0-9a-fA-F]+)")
_FAULT = re.compile(r"si_addr = (0x[0-9a-fA-F]+)")
_FRAME = re.compile(r"^#\d+\s+(?:0x0*([0-9a-fA-F]+)\s+in\s+|)")
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
    run_cmd = "run" + ("".join(" " + a for a in argv)) + (
        (" < " + stdin_file) if stdin_file else "")
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
    cmd = [str(gdb), "-q", "-batch", "-nx", "-x", script.name, str(exe)]
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
    frames = [int(m.group(1), 16) for line in out.splitlines()
              if (m := _FRAME.match(line.strip())) and m.group(1)]
    return {"ok": True, "source": "gdb", "signal_name": sig.group(1),
            "pc": int(pc.group(1), 16) if pc else None,
            "fault_addr": int(fault.group(1), 16) if fault else None,
            "pc_bytes": pc_bytes[:32], "backtrace": frames[1:], "regs": {}, "maps": maps,
            "gdb_raw": out[-4000:]}
