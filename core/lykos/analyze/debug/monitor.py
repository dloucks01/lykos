"""Instrumented dangerous-call monitor: run a target under GDB with breakpoints on dangerous
sink functions and capture their concrete arguments at runtime (pure tooling, no AI).

Where the static detectors say "there is a call to strcpy" and the fuzzer waits for a crash,
this watches the program actually make the call and records what it passed -- the copy length,
the command string, the size argument. That turns a static candidate into dynamic evidence
(a `system("...")` we watched execute; a `strcpy` of 200 bytes into a 64-byte frame) without
needing a segfault. Deterministic; native-arch only (uses host GDB, like root-cause).

`run_monitor()` generates a GDB-Python script, drives it in batch mode with the given input,
and returns the list of observed calls. The stage maps those to findings.
"""
from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from pathlib import Path

# arg registers by arch (GDB names), in calling-convention order
_ARGREGS = {
    "x86-64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "aarch64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
}

# dangerous sinks -> how to read their args and what class they signal.
#   kind "copy":   dest=arg[dest], length is strlen(arg[strlen]) or the int arg[len_arg]
#   kind "exec":   the command/path string is arg[cmd]  (CWE-78)
#   kind "format": the format string is arg[fmt]         (CWE-134 if attacker-controlled)
CATALOG = {
    "strcpy":   {"kind": "copy", "dest": 0, "strlen": 1, "cwe": "CWE-120", "desc": "strcpy"},
    "strcat":   {"kind": "copy", "dest": 0, "strlen": 1, "cwe": "CWE-120", "desc": "strcat"},
    "stpcpy":   {"kind": "copy", "dest": 0, "strlen": 1, "cwe": "CWE-120", "desc": "stpcpy"},
    "gets":     {"kind": "copy", "dest": 0, "strlen": None, "cwe": "CWE-242", "desc": "gets"},
    "memcpy":   {"kind": "copy", "dest": 0, "len_arg": 2, "cwe": "CWE-120", "desc": "memcpy"},
    "memmove":  {"kind": "copy", "dest": 0, "len_arg": 2, "cwe": "CWE-120", "desc": "memmove"},
    "strncpy":  {"kind": "copy", "dest": 0, "len_arg": 2, "cwe": "CWE-120", "desc": "strncpy"},
    "read":     {"kind": "copy", "dest": 1, "len_arg": 2, "cwe": "CWE-120", "desc": "read"},
    "fgets":    {"kind": "copy", "dest": 0, "len_arg": 1, "cwe": "CWE-120", "desc": "fgets"},
    "sprintf":  {"kind": "format", "dest": 0, "fmt": 1, "cwe": "CWE-134", "desc": "sprintf"},
    "system":   {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "system"},
    "popen":    {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "popen"},
    "execl":    {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "execl"},
    "execlp":   {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "execlp"},
    "execv":    {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "execv"},
    "execve":   {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "execve"},
    "execvp":   {"kind": "exec", "cmd": 0, "cwe": "CWE-78", "desc": "execvp"},
}

_SCRIPT = r'''
import gdb, json
ARGREGS = %(argregs)s
FUNCS = %(funcs)s
INPUT_FILE = %(infile)r
RUN_ARGS = %(runargs)r
HITS, MAX = [], 400

def _u(reg):
    try: return int(gdb.parse_and_eval("$" + reg)) & ((1 << 64) - 1)
    except Exception: return None

def _s(reg, cap=256):
    try:                                  # read to NUL (no length -> gdb won't over-read/fault)
        return gdb.parse_and_eval("(char*)$" + reg).string("latin-1")[:cap]
    except Exception:
        return None

def _slen(reg):
    try:
        return len(gdb.parse_and_eval("(char*)$" + reg).string("latin-1"))
    except Exception:
        return -1

class Hit(gdb.Breakpoint):
    def __init__(self, name, spec):
        super().__init__(name, gdb.BP_BREAKPOINT, internal=True)
        self.fname, self.spec = name, spec
    def stop(self):
        rec = {"func": self.fname, "kind": self.spec["kind"], "cwe": self.spec["cwe"]}
        try:
            f = gdb.selected_frame()
            try:
                older = f.older()
                rec["caller"] = int(older.pc())
                rec["caller_name"] = older.name()      # None if stripped
            except Exception:
                rec["caller"] = rec["caller_name"] = None
        except Exception: pass
        try:
            k = self.spec["kind"]
            if k == "exec":
                rec["cmd"] = _s(ARGREGS[self.spec["cmd"]])
            elif k == "format":
                rec["fmt"] = _s(ARGREGS[self.spec["fmt"]])
            else:  # copy
                rec["dest"] = _u(ARGREGS[self.spec["dest"]])
                if self.spec.get("strlen") is not None:
                    rec["length"] = _slen(ARGREGS[self.spec["strlen"]])
                elif self.spec.get("len_arg") is not None:
                    rec["length"] = _u(ARGREGS[self.spec["len_arg"]])
                else:
                    rec["length"] = None
        except Exception: pass
        HITS.append(rec)
        return len(HITS) >= MAX

gdb.execute("set breakpoint pending on")   # sinks may live in libc (not yet loaded)
for _n, _spec in FUNCS.items():
    try: Hit(_n, _spec)
    except Exception: pass
gdb.execute("set pagination off")
gdb.execute("set height 0")
try:
    # args must be inline on `run`: `set args X` followed by `run < file` makes gdb reset the
    # argument list to empty (the redirect-only form), silently dropping argv.
    gdb.execute("run " + RUN_ARGS + ((" < " + INPUT_FILE) if INPUT_FILE else ""))
except gdb.error:
    pass
print("LYKOS_MON " + json.dumps(HITS))
'''


def supported(arch):
    return arch in _ARGREGS


def run_monitor(exe, funcs, arch, *, argv=(), stdin=b"", timeout=20):
    """Run `exe` under GDB, breakpoint each name in `funcs` (subset of CATALOG present in the
    binary), and return the list of observed call records."""
    if arch not in _ARGREGS:
        return {"ok": False, "note": f"monitor is native-arch only (no GDB arg map for {arch})"}
    gdb_bin = _locate_gdb()
    if not gdb_bin:
        return {"ok": False, "note": "gdb not found"}
    d = Path(tempfile.mkdtemp(prefix="lykos-mon-"))
    try:
        infile = ""
        if stdin:
            (d / "in.bin").write_bytes(stdin)
            infile = str(d / "in.bin")
        spec = {n: CATALOG[n] for n in funcs if n in CATALOG}
        # embed as Python literals (repr), not JSON -- None must be None, not `null`
        script = _SCRIPT % {"argregs": repr(_ARGREGS[arch]),
                            "funcs": repr(spec), "infile": infile,
                            "runargs": " ".join(shlex.quote(a) for a in argv)}
        (d / "mon.py").write_text(script)
        proc = subprocess.run(
            [gdb_bin, "-batch", "-nx", "-x", str(d / "mon.py"), str(exe)],
            capture_output=True, timeout=timeout + 15)
        out = proc.stdout.decode("latin-1", "ignore")
        hits = []
        for line in out.splitlines():
            if line.startswith("LYKOS_MON "):
                hits = json.loads(line[len("LYKOS_MON "):])
        return {"ok": True, "hits": hits}
    except subprocess.TimeoutExpired:
        return {"ok": True, "hits": [], "note": "monitor run timed out"}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def _locate_gdb():
    import shutil
    return shutil.which("gdb")
