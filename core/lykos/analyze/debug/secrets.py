"""Comparison / secret extraction: breakpoint the comparison functions and dump BOTH operands,
so the constant the program checks our input against falls out -- passwords, magic bytes,
license keys, expected tokens. Classic offensive RE, deterministic, no AI.

We run the target under GDB with a distinctive probe input; at each strcmp/memcmp/... the operand
that is NOT our probe is the *expected* value the program wanted. `run_extract()` returns the
observed comparisons; the stage turns the recovered constants into findings.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from pathlib import Path

from .monitor import _ARGREGS, _locate_gdb

# comparison funcs -> index of the length/limit arg (None = NUL-terminated string compare)
CMP = {
    "strcmp": None, "strcasecmp": None, "strstr": None, "strcmp_ol": None,
    "strncmp": 2, "strncasecmp": 2, "memcmp": 2, "bcmp": 2,
}

_SCRIPT = r'''
import gdb, json
ARGREGS = %(argregs)s
FUNCS = %(funcs)s
INPUT_FILE = %(infile)r
RUN_ARGS = %(runargs)r
HITS, MAX = [], 600

def _u(reg):
    try: return int(gdb.parse_and_eval("$" + reg)) & ((1 << 64) - 1)
    except Exception: return None

def _cstr(reg):
    try: return gdb.parse_and_eval("(char*)$" + reg).string("latin-1")[:512]
    except Exception: return None

def _mem(reg, n):
    try:
        n = min(int(n), 512)
        b = gdb.selected_inferior().read_memory(_u(reg), n)
        return bytes(b).decode("latin-1")
    except Exception: return None

class Cmp(gdb.Breakpoint):
    def __init__(self, name, lenidx):
        super().__init__(name, gdb.BP_BREAKPOINT, internal=True)
        self.fname, self.lenidx = name, lenidx
    def stop(self):
        rec = {"func": self.fname}
        try:
            f = gdb.selected_frame().older()
            rec["caller"] = f.name() if f else None
        except Exception: rec["caller"] = None
        try:
            n = _u(ARGREGS[self.lenidx]) if self.lenidx is not None else None
            rec["n"] = n
            if self.fname in ("memcmp", "bcmp") and n is not None:
                rec["a0"] = _mem(ARGREGS[0], n); rec["a1"] = _mem(ARGREGS[1], n)
            else:
                rec["a0"] = _cstr(ARGREGS[0]); rec["a1"] = _cstr(ARGREGS[1])
        except Exception: pass
        HITS.append(rec)
        return len(HITS) >= MAX

gdb.execute("set breakpoint pending on")   # comparison funcs live in libc (not yet loaded)
for _n, _li in FUNCS.items():
    try: Cmp(_n, _li)
    except Exception: pass
gdb.execute("set pagination off")
gdb.execute("set height 0")
try:
    if RUN_ARGS: gdb.execute("set args " + RUN_ARGS)
    gdb.execute("run" + (" < " + INPUT_FILE if INPUT_FILE else ""))
except gdb.error:
    pass
print("LYKOS_CMP " + json.dumps(HITS))
'''


def supported(arch):
    return arch in _ARGREGS


def run_extract(exe, funcs, arch, *, argv=(), stdin=b"", timeout=20):
    """Run `exe` under GDB, breakpoint the comparison funcs, return observed comparisons."""
    if arch not in _ARGREGS:
        return {"ok": False,
                "note": f"secret extraction is native-arch only (no arg map for {arch})"}
    gdb_bin = _locate_gdb()
    if not gdb_bin:
        return {"ok": False, "note": "gdb not found"}
    d = Path(tempfile.mkdtemp(prefix="lykos-sec-"))
    try:
        infile = ""
        if stdin:
            (d / "in.bin").write_bytes(stdin)
            infile = str(d / "in.bin")
        spec = {n: CMP[n] for n in funcs if n in CMP}
        # embed as Python literals (repr), not JSON -- None must be None, not `null`
        script = _SCRIPT % {"argregs": repr(_ARGREGS[arch]), "funcs": repr(spec),
                            "infile": infile,
                            "runargs": " ".join(shlex.quote(a) for a in argv)}
        (d / "sec.py").write_text(script)
        proc = subprocess.run([gdb_bin, "-batch", "-nx", "-x", str(d / "sec.py"), str(exe)],
                              capture_output=True, timeout=timeout + 15)
        out = proc.stdout.decode("latin-1", "ignore")
        hits = []
        for line in out.splitlines():
            if line.startswith("LYKOS_CMP "):
                hits = json.loads(line[len("LYKOS_CMP "):])
        return {"ok": True, "hits": hits}
    except subprocess.TimeoutExpired:
        return {"ok": True, "hits": [], "note": "extraction run timed out"}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
