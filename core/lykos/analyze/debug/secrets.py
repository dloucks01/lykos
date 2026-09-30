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

def _in_loader(frame):
    # The dynamic linker calls strcmp/strncmp heavily while resolving symbols at startup; those
    # comparisons are noise and, unfiltered, can exhaust MAX before the target's own call runs.
    # Resolve the caller's objfile BY ADDRESS (ld.so carries symbols but no line info, so its
    # frames have no symtab -- keying on symtab would never match).
    try:
        of = gdb.current_progspace().objfile_for_address(frame.pc())
        name = of.filename if of else ""
    except Exception:
        name = ""
    return bool(name) and ("ld-linux" in name or "/ld-2." in name or name.endswith("/ld.so"))

class Cmp(gdb.Breakpoint):
    def __init__(self, location, fname, lenidx):
        # `location` is what gdb breaks on (e.g. "strcmp@plt"); `fname` is the reported name.
        super().__init__(location, gdb.BP_BREAKPOINT, internal=True)
        self.fname, self.lenidx = fname, lenidx
    def stop(self):
        rec = {"func": self.fname}
        f = None
        try:
            f = gdb.selected_frame().older()
            rec["caller"] = f.name() if f else None
        except Exception: rec["caller"] = None
        if f is not None and _in_loader(f):
            return False                       # skip ld.so's own symbol-name comparisons
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
    # On modern glibc, strcmp/strncmp/memcmp/... are GNU IFUNCs: a call in the target dispatches
    # to a CPU-specific SIMD impl (__strcmp_avx2, ...), NOT the generic libc symbol -- so breaking
    # on the bare name MISSES the target's own comparisons (it only catches ld.so's internal use).
    # The target's PLT stub is hit regardless of which impl the GOT resolves to, so break there
    # first; keep the bare name too for statically linked / no-PLT builds. A location that does not
    # exist (e.g. no PLT) just stays an unresolved pending breakpoint -- harmless.
    for _loc in (_n + "@plt", _n):
        try: Cmp(_loc, _n, _li)
        except Exception: pass
gdb.execute("set pagination off")
gdb.execute("set height 0")
RAN, ERR = False, ""
try:
    # args inline: `set args X` then `run < file` resets args to empty (gdb quirk) -> argv lost
    gdb.execute("run " + RUN_ARGS + ((" < " + INPUT_FILE) if INPUT_FILE else ""))
    RAN = True            # the inferior actually executed (run returned no gdb.error)
except gdb.error as _e:
    ERR = str(_e)         # never ran (exec-format / cannot-execute / ptrace-denied)
# LYKOS_STATUS separates "ran and matched no comparison" from "never ran": an empty result from
# a target that could not be executed must not read as "no secrets to recover".
print("LYKOS_STATUS " + json.dumps({"ran": RAN, "error": ERR}))
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
        from ..dynamic import sandbox
        # Contain the (hostile) target: bwrap read-only root (net unshared -- ptrace needs no
        # loopback) + rlimits. The script/input dir is re-bound read-only for gdb to read.
        exe_abs = str(Path(exe).resolve())            # absolute: bwrap chdirs to /tmp
        exedir = str(Path(exe_abs).parent)
        inner = [gdb_bin, "-batch", "-nx", "-x", str(d / "sec.py"), exe_abs]
        cmd = sandbox.isolate_prefix(exedir, net=False, ro_binds=[str(d)]) + inner
        proc = sandbox.run_reaped(cmd, capture_output=True, timeout=timeout + 15,
                                  preexec_fn=sandbox._rlimits(2048, int(timeout) + 15,
                                                              set_as=False))
        out = proc.stdout.decode("latin-1", "ignore")
        hits = status = None
        for line in out.splitlines():
            if line.startswith("LYKOS_CMP "):
                hits = json.loads(line[len("LYKOS_CMP "):])
            elif line.startswith("LYKOS_STATUS "):
                status = json.loads(line[len("LYKOS_STATUS "):])
        if hits is None or status is None:
            return {"ok": False, "hits": [], "note": "gdb did not run to completion (no result "
                    "marker) -- the target could not be run; no comparisons were observed"}
        if not status.get("ran"):
            return {"ok": False, "hits": [], "note": "the target never executed under gdb (%s) "
                    "-- no comparisons observed, which is not the same as none present"
                    % (status.get("error") or "unknown reason")}
        return {"ok": True, "hits": hits}
    except subprocess.TimeoutExpired:
        return {"ok": False, "hits": [], "note": "extraction run timed out before completing"}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
