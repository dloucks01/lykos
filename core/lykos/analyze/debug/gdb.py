"""Optional GDB backend for root-cause capture (graceful when absent).

When gdb is installed we drive it in batch mode to get a symbolized backtrace, registers, the
fault address, and the faulting instruction, and normalize that to the same capture dict the
ptrace helper produces. When gdb is absent the stage falls back to the ptrace helper.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

_SIG = re.compile(r"received signal (SIG\w+)")
_FRAME = re.compile(r"^#\d+\s+(?:0x([0-9a-fA-F]+)\s+in\s+)?(\S+)")
_PC = re.compile(r"=> 0x([0-9a-fA-F]+)")
_STOP = re.compile(r"0x([0-9a-fA-F]+)\s+in")


def locate_gdb(config: Optional[str] = None) -> Optional[Path]:
    if config and Path(config).exists():
        return Path(config)
    env = os.environ.get("LYKOS_GDB")
    if env and Path(env).exists():
        return Path(env)
    w = shutil.which("gdb")
    return Path(w) if w else None


def run_gdb(gdb: Path, exe, argv, stdin_file, *, ctx=None, timeout: int = 30) -> dict:
    """Run the target under gdb batch, return a normalized capture dict."""
    cmds = ["set pagination off", "set confirm off",
            "run" + ((" < " + stdin_file) if stdin_file else "")
            + ("".join(" " + a for a in argv)),
            "printf \"LYKOS_SIG %d\\n\", $_siginfo.si_signo",
            "info registers", "x/1i $pc", "bt", "quit"]
    script = tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False)
    script.write("\n".join(cmds) + "\n")
    script.close()
    cmd = [str(gdb), "-q", "-batch", "-x", script.name, str(exe)]
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
    frames = []
    for line in out.splitlines():
        m = _FRAME.match(line.strip())
        if m and m.group(1):
            frames.append(int(m.group(1), 16))
    pc = None
    for line in out.splitlines():
        m = _PC.search(line) or _STOP.search(line)
        if m:
            pc = int(m.group(1), 16)
            break
    if sig is None and not frames:
        return {"ok": False, "reason": "gdb produced no crash", "raw": out[-400:]}
    return {"ok": True, "source": "gdb", "signal_name": sig.group(1) if sig else "SIGSEGV",
            "pc": pc, "backtrace": frames[1:] if frames else [], "regs": {}, "maps": [],
            "pc_bytes": "", "fault_addr": None, "gdb_raw": out[-4000:]}
