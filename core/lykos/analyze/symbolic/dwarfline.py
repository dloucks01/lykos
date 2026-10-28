"""Resolve a source file:line to a code ADDRESS in an ELF, from its DWARF line table.

Finding-directed steering needs the address of the SUSPECTED BUG SITE, not the enclosing function:
steering concolic exploration to a function ENTRY stops it before the bug (short-circuiting the magic
gate / length check that guards the defect), whereas steering to the bug LINE is only reachable once
those guards are solved -- so a site-steered input actually triggers the fault on replay. Steering can
only change exploration efficiency; the ASan replay + negative control still gate every confirmation,
so a wrong address never causes a false positive.

Best-effort and stdlib-only at the core: it shells out to `objdump --dwarf=decodedline` (binutils),
which the explore build carries because cmake_build_harnesses configures CMAKE_BUILD_TYPE=Debug. If
objdump is absent, or the binary has no line table, it returns nothing and the caller explores
undirected -- exactly as before.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

# A decoded-line row: "<file>  <line>  0x<addr>  [view] [stmt]". binutils spellings vary a little, so
# match the stable prefix: a filename token, an integer line, then a hex address.
_ROW = re.compile(r"^\s*(\S+)\s+(\d+)\s+(0x[0-9a-fA-F]+)\b")


def resolve_sites(binary, sites, *, timeout: float = 30.0) -> dict:
    """Map each wanted (basename, line) to the LOWEST code address the DWARF line table gives it.

    `sites` is an iterable of (basename, line:int). Returns {(basename, line): addr_int}. Missing
    tool / no debug line info / a site not in the table -> that site is simply absent (never raised)."""
    want = {(os.path.basename(b), int(ln)) for b, ln in sites}
    if not want:
        return {}
    objdump = shutil.which("objdump")
    if objdump is None:
        return {}
    try:
        r = subprocess.run([objdump, "--dwarf=decodedline", str(binary)],
                           capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    out: dict = {}
    for line in (r.stdout or "").splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        key = (os.path.basename(m.group(1)), int(m.group(2)))
        if key in want:
            addr = int(m.group(3), 16)
            if key not in out or addr < out[key]:          # the first (lowest) address for the line
                out[key] = addr
    return out


def site_addrs(binary, sites, *, timeout: float = 30.0) -> list:
    """The de-duplicated list of addresses for `sites` found in `binary`'s DWARF line table."""
    return sorted(set(resolve_sites(binary, sites, timeout=timeout).values()))
