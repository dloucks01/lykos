"""Instrumented dangerous-call monitor: run a target under GDB with breakpoints on dangerous
sink functions and capture their concrete arguments at runtime (pure tooling).

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

from . import elfsyms

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
ADDR_SINKS = %(addrsinks)s
STATIC_ENTRY = %(entry)d
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
    def __init__(self, location, fname, spec):
        super().__init__(location, gdb.BP_BREAKPOINT, internal=True)
        self.fname, self.spec = fname, spec
    def stop(self):
        rec = {"func": self.fname, "kind": self.spec["kind"], "cwe": self.spec["cwe"]}
        try:
            f = gdb.selected_frame()
            try:
                older = f.older()
                rec["caller"] = int(older.pc())
                rec["caller_name"] = older.name()      # None if stripped
                # Whether the CALLER is the program or something that ran before it. gdb
                # returns None for the main executable and a path for any shared object, so
                # this is the same attribution winmonitor already uses. Without it the log is
                # dominated by ld.so resolving symbols before main() -- on ncompress every
                # recorded call was _dl_new_object and friends.
                rec["in_target"] = gdb.solib_name(rec["caller"]) is None
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
                    rec["src"] = _s(ARGREGS[self.spec["strlen"]])   # source content (for taint)
                elif self.spec.get("len_arg") is not None:
                    rec["length"] = _u(ARGREGS[self.spec["len_arg"]])
                else:
                    rec["length"] = None
        except Exception: pass
        HITS.append(rec)
        return len(HITS) >= MAX

def _load_base():
    """Load base of the main executable = AT_ENTRY (the kernel-reported runtime entry, which is
    the *executable's* entry even under a dynamic loader) minus the static e_entry. 0 for non-PIE.
    Robust where `starti`'s $pc is not (dynamic PIE stops in ld.so, not the program)."""
    try:
        for line in gdb.execute("info auxv", to_string=True).splitlines():
            if "AT_ENTRY" in line:
                return (int(line.split()[-1], 0) & ((1 << 64) - 1)) - STATIC_ENTRY
    except Exception:
        pass
    return 0

gdb.execute("set breakpoint pending on")   # sinks may live in libc (not yet loaded)
for _n, _spec in FUNCS.items():
    try: Hit(_n, _n, _spec)             # by name (resolves via symbols / PLT)
    except Exception: pass
gdb.execute("set pagination off")
gdb.execute("set height 0")
# args must be inline on `run`/`starti`: `set args X` then `run < file` makes gdb reset the
# argument list to empty (the redirect-only form), silently dropping argv.
_RUN = RUN_ARGS + ((" < " + INPUT_FILE) if INPUT_FILE else "")
RAN, ERR = False, ""
try:
    if ADDR_SINKS:
        # analyst-supplied addresses are static ELF vaddrs -> rebase by the runtime load base
        # (PIE-aware): start at the entry so the process/auxv exist, set the breakpoints, run on.
        gdb.execute("starti " + _RUN)
        _base = _load_base()
        for _n, (_addr, _spec) in ADDR_SINKS.items():
            try: Hit("*" + hex(_addr + _base), _n, _spec)
            except Exception: pass
        gdb.execute("continue")
    else:
        gdb.execute("run " + _RUN)
    RAN = True            # the inferior actually executed (run/continue returned no gdb.error)
except gdb.error as _e:
    ERR = str(_e)         # e.g. exec-format / cannot-execute / ptrace-denied: it never ran
# LYKOS_STATUS lets the caller tell "ran and saw nothing" from "never ran" -- an empty HITS
# from a target that could not be executed must NOT read as a clean, dangerous-call-free run.
print("LYKOS_STATUS " + json.dumps({"ran": RAN, "error": ERR}))
print("LYKOS_MON " + json.dumps(HITS))
'''


def supported(arch):
    return arch in _ARGREGS


def run_monitor(exe, funcs, arch, *, argv=(), stdin=b"", timeout=20, addr_sinks=None):
    """Run `exe` under GDB, breakpoint each name in `funcs` (subset of CATALOG present in the
    binary), and return the list of observed call records. `addr_sinks` is an analyst escape
    hatch -- a {catalog-name: vaddr} map to breakpoint sinks by address in a stripped binary
    whose symbols/PLT names are gone; each is decoded with that name's CATALOG spec."""
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
        addr_spec = {n: (a, CATALOG[n]) for n, a in (addr_sinks or {}).items() if n in CATALOG}
        # static e_entry: analyst addr_sinks are ELF vaddrs, rebased by (AT_ENTRY - e_entry) at
        # runtime so they hit under PIE too. Read it from the ELF (0 -> no rebase).
        entry = elfsyms.read(exe).get("entry") or 0 if addr_spec else 0
        # embed as Python literals (repr), not JSON -- None must be None, not `null`
        script = _SCRIPT % {"argregs": repr(_ARGREGS[arch]),
                            "funcs": repr(spec), "addrsinks": repr(addr_spec),
                            "entry": entry, "infile": infile,
                            "runargs": " ".join(shlex.quote(a) for a in argv)}
        (d / "mon.py").write_text(script)
        from ..dynamic import sandbox
        # Detonate the (hostile) target under GDB with real containment: bwrap read-only root
        # (net unshared -- ptrace needs no loopback), plus rlimits so a fork bomb / runaway
        # allocation cannot take the host down. The script + input dir is re-bound read-only over
        # the tmpfs so gdb can read them; the exe dir is bound by isolate_prefix.
        exe_abs = str(Path(exe).resolve())            # absolute: bwrap chdirs to /tmp
        exedir = str(Path(exe_abs).parent)
        inner = [gdb_bin, "-batch", "-nx", "-x", str(d / "mon.py"), exe_abs]
        cmd = sandbox.isolate_prefix(exedir, net=False, ro_binds=[str(d)]) + inner
        proc = sandbox.run_reaped(
            cmd, capture_output=True, timeout=timeout + 15,
            preexec_fn=sandbox._rlimits(2048, int(timeout) + 15, set_as=False))
        out = proc.stdout.decode("latin-1", "ignore")
        hits = status = None
        for line in out.splitlines():
            if line.startswith("LYKOS_MON "):
                hits = json.loads(line[len("LYKOS_MON "):])
            elif line.startswith("LYKOS_STATUS "):
                status = json.loads(line[len("LYKOS_STATUS "):])
        if hits is None or status is None:
            return {"ok": False, "hits": [], "note": "gdb did not run to completion (no result "
                    "marker) -- the target could not be monitored; nothing was observed"}
        if not status.get("ran"):
            return {"ok": False, "hits": [], "note": "the target never executed under gdb (%s) "
                    "-- nothing was observed, which is not the same as no dangerous calls"
                    % (status.get("error") or "unknown reason")}
        return {"ok": True, "hits": hits}
    except subprocess.TimeoutExpired:
        # We stopped watching; the target did not necessarily stop. A partial/absent result is
        # not a clean run -- report it as unable to complete, not as ok with zero hits.
        return {"ok": False, "hits": [], "note": "monitor run timed out before completing"}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def _locate_gdb():
    import shutil
    return shutil.which("gdb")
