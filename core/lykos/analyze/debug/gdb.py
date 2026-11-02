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
_SICODE = re.compile(r"si_code = (-?\d+)")
# The signals a capture may report as the CRASH. gdb also stops (and prints "received signal")
# on SIGPIPE/SIGUSR1/..., and the script then captured THAT stop: a target writing to a closed
# pipe came back `ok: True, SIGPIPE`, and the classifier filed it as an out-of-bounds read
# [measured]. The non-fatal ones are passed through without stopping (`_PASS_SIGNALS`).
_CRASH_SIGNALS = frozenset({"SIGSEGV", "SIGBUS", "SIGILL", "SIGFPE", "SIGABRT", "SIGTRAP"})
_PASS_SIGNALS = ("SIGPIPE SIGUSR1 SIGUSR2 SIGALRM SIGVTALRM SIGPROF SIGCHLD SIGWINCH SIGURG "
                 "SIGIO SIGHUP SIGTERM SIGCONT SIGXFSZ SIGXCPU")
_HANDLE = f"handle {_PASS_SIGNALS} nostop noprint pass"
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


def _drive_gdb(gdb: Path, exe, argv, stdin_file, cmds, *, ctx, timeout: int,
               rw_dirs=()) -> str:
    """Write `cmds` to a script and run `gdb -batch` on the (hostile) target INSIDE the sandbox
    -- bwrap read-only root with /home,/root masked (net unshared; ptrace needs no loopback) and
    rlimits, so a runaway/forking inferior cannot exhaust or write to the host. Returns gdb's
    stdout as text. Shared by run_gdb / run_gdb_follow.

    The exe dir, the script dir, and the stdin-redirect file's dir are re-bound read-only over
    the tmpfs so gdb can open all three. Reaping (kill the whole process group / namespace on
    timeout) comes from ctx.run_subprocess or, without a ctx, sandbox.run_reaped -- either way a
    ptraced inferior and its fork children cannot outlive the trace."""
    d = Path(tempfile.mkdtemp(prefix="lykos-gdb-"))
    try:
        script = d / "cmd.gdb"
        script.write_text("\n".join(cmds) + "\n")
        exe_abs = str(Path(exe).resolve())            # absolute: bwrap chdirs to /tmp
        exedir = str(Path(exe_abs).parent)
        ro = [str(d)]
        if stdin_file:
            ro.append(str(Path(stdin_file).resolve().parent))
        inner = ([str(gdb), "-q", "-batch", "-nx", "-x", str(script), "--args", exe_abs]
                 + [sandbox.argv_bytes(a) for a in argv])
        # `rw_dirs`: the writable slot a file input sits in -- the target may edit its input in
        # place (jhead -mkexif), and read-only it refuses before reaching the fault.
        cmd = sandbox.isolate_prefix(exedir, net=False, ro_binds=ro,
                                     rw_binds=[str(x) for x in rw_dirs]) + inner
        preexec = sandbox._rlimits(2048, int(timeout) + 15, set_as=False)
        if ctx is not None:
            proc = ctx.run_subprocess(cmd, timeout=timeout + 15, preexec_fn=preexec)
        else:
            proc = sandbox.run_reaped(cmd, capture_output=True, timeout=timeout + 15,
                                      preexec_fn=preexec)
        return (proc.stdout or b"").decode("latin-1", "ignore")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# gdb command block for a single-process fault capture.
def _capture_cmds(stdin_file, preload: str | None = None):
    # Arguments go on gdb's OWN command line via --args, not spliced into the `run` line:
    # that line is parsed as a gdb command, so a binary payload is mangled by quoting long
    # before execve ever sees it.
    pre = []
    if preload:
        # The crash was FOUND under the guard-page allocator (libdislocator); it is SILENT without
        # one. Preload it into the inferior so the capture reproduces the same fault -- otherwise
        # root_cause runs unguarded, sees no crash, and the provisional (maps-free) classification
        # is never corrected. `set environment` seeds the child's env before `run`.
        pre = [f"set environment LD_PRELOAD {preload}"]
    return pre + [
        "set pagination off", "set confirm off", "set height 0", "set width 0",
        "set debuginfod enabled off",     # no network under --unshare-net; avoid the probe
        _HANDLE,
        "run" + ((" < " + stdin_file) if stdin_file else ""),
        'printf "LYKOS_PC %#lx\\n", $pc',
        "print $_siginfo",
        # Dump bytes at $pc -- but $pc after a control-flow hijack is often an UNMAPPED address,
        # and a bare `x` then errors and ABORTS the batch script, so `info proc mappings`/`bt`
        # below never run and gdb exits 1 (reads as an error in the console). Wrap it: on failure
        # record that the PC is unmapped -- which is itself evidence of a hijack -- and carry on.
        "python",
        "try:",
        '    gdb.execute("x/16xb $pc")',
        "except gdb.error as _e:",
        '    gdb.write("x/16xb $pc -> %s (pc unmapped -- control flow redirected to an invalid address)\\n" % _e)',
        "end",
        "info proc mappings",
        "bt",
        "quit",
    ]


def run_gdb(gdb: Path, exe, argv, stdin_file, *, ctx=None, timeout: int = 30,
            preload: str | None = None, rw_dirs=()) -> dict:
    if stdin_file:                                     # absolute: the `run < file` redirect is
        stdin_file = str(Path(stdin_file).resolve())   # resolved before bwrap chdirs to /tmp
    return _parse(_drive_gdb(gdb, exe, argv, stdin_file, _capture_cmds(stdin_file, preload),
                             ctx=ctx, timeout=timeout, rw_dirs=rw_dirs))


_FORK = re.compile(r"fork to child process (\d+)")
_EXECED = re.compile(r"is executing new program:\s*(\S+)")
def run_gdb_follow(gdb: Path, exe, argv, stdin_file, *, ctx=None, timeout: int = 30) -> dict:
    """Multi-process capture (doc 17.3): follow fork/exec into spawned children and capture
    the fault of whichever process actually crashes. Adds fork/exec attribution to the
    normal `run_gdb` capture dict."""
    # Arguments go on gdb's OWN command line via --args, not spliced into the `run` line:
    # that line is parsed as a gdb command, so a binary payload is mangled by quoting long
    # before execve ever sees it.
    if stdin_file:                                     # absolute before bwrap chdirs to /tmp
        stdin_file = str(Path(stdin_file).resolve())
    cmds = [
        "set pagination off", "set confirm off", "set height 0", "set width 0",
        "set debuginfod enabled off",     # no network under --unshare-net; avoid the probe
        "set follow-fork-mode child",     # trace the child on fork...
        "set detach-on-fork on",          # ...detaching the parent
        "set follow-exec-mode new",       # follow through execve into the new image
        _HANDLE,
        "run" + ((" < " + stdin_file) if stdin_file else ""),
        'printf "LYKOS_PC %#lx\\n", $pc',
        "print $_siginfo",
        # Dump bytes at $pc -- but $pc after a control-flow hijack is often an UNMAPPED address,
        # and a bare `x` then errors and ABORTS the batch script, so `info proc mappings`/`bt`
        # below never run and gdb exits 1 (reads as an error in the console). Wrap it: on failure
        # record that the PC is unmapped -- which is itself evidence of a hijack -- and carry on.
        "python",
        "try:",
        '    gdb.execute("x/16xb $pc")',
        "except gdb.error as _e:",
        '    gdb.write("x/16xb $pc -> %s (pc unmapped -- control flow redirected to an invalid address)\\n" % _e)',
        "end",
        "info proc mappings",
        "bt",
        "quit",
    ]
    out = _drive_gdb(gdb, exe, argv, stdin_file, cmds, ctx=ctx, timeout=timeout)
    cap = _parse(out)
    fork = _FORK.search(out)
    execed = _EXECED.search(out)
    cap["forked"] = bool(fork)
    cap["child_pid"] = int(fork.group(1)) if fork else None
    cap["execed"] = execed.group(1) if execed else None
    cap["multiproc"] = bool(fork or execed)
    return cap


def run_gdb_session(gdb: Path, exe, argv, blob: bytes, proto: str = "tcp", *,
                    timeout: int = 30) -> dict:
    """Fault capture for a crash delivered over a SOCKET: start the server under gdb (following a
    forked connection handler into the child), wait for it to listen, deliver the stored session
    message by message, and let gdb report the fault. Contained like `_drive_gdb`, except the
    network namespace is kept (we connect over loopback)."""
    import subprocess
    import time
    from ..fuzz import netfuzz
    from ..fuzz import session as _session
    d = Path(tempfile.mkdtemp(prefix="lykos-gdbsock-"))
    proc = None
    try:
        cmds = [
            "set pagination off", "set confirm off", "set height 0", "set width 0",
            "set debuginfod enabled off", "set follow-fork-mode child", "set detach-on-fork on",
            _HANDLE, "run",
            'printf "LYKOS_PC %#lx\\n", $pc', "print $_siginfo",
            "python", "try:", '    gdb.execute("x/16xb $pc")', "except gdb.error as _e:",
            '    gdb.write("x/16xb $pc -> %s (pc unmapped -- control flow redirected to an '
            'invalid address)\\n" % _e)', "end",
            "info proc mappings", "bt", "quit"]
        script = d / "cmd.gdb"
        script.write_text("\n".join(cmds) + "\n")
        exe_abs = str(Path(exe).resolve())
        inner = ([str(gdb), "-q", "-batch", "-nx", "-x", str(script), "--args", exe_abs]
                 + [sandbox.argv_bytes(a) for a in argv])
        env = dict(os.environ)
        if sandbox._is_sanitizer_exe(exe_abs):
            env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"
        cmd = sandbox.isolate_prefix(str(Path(exe_abs).parent), net=True, ro_binds=[str(d)]) + inner
        out_f = d / "out.txt"
        with open(out_f, "wb") as fo:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=fo,
                                    stderr=subprocess.STDOUT, start_new_session=True, env=env,
                                    preexec_fn=sandbox._rlimits(4096, int(timeout) + 30,
                                                                set_as=False))
            port = None
            end = time.time() + max(10.0, timeout / 2)
            while time.time() < end and proc.poll() is None:
                ports = netfuzz._listening_ports(proc.pid, proto)
                if ports:
                    port = ports[0]
                    break
                time.sleep(0.1)
            if port is None:
                return {"ok": False, "reason": "server did not listen under the debugger"}
            msgs = _session.decode_session(blob)
            try:
                import socket as _s
                if proto == "tcp":
                    s = _s.create_connection(("127.0.0.1", port), timeout=3)
                    s.settimeout(1.0)
                    try:
                        s.recv(65536)
                    except OSError:
                        pass
                    for m in msgs:
                        s.sendall(m)
                        s.settimeout(1.0)
                        try:
                            s.recv(65536)
                        except OSError:
                            pass
                    s.close()
                else:
                    s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
                    for m in msgs:
                        s.sendto(m, ("127.0.0.1", port))
                        time.sleep(0.1)
                    s.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
        text = out_f.read_bytes().decode("latin-1", "ignore")
        return _parse(text)
    finally:
        if proc is not None and proc.poll() is None:
            netfuzz._killtree(proc)
        shutil.rmtree(d, ignore_errors=True)


def _parse(out: str) -> dict:
    sig = _SIG.search(out)
    if sig is None:
        return {"ok": False, "reason": "gdb reported no crash", "raw": out[-400:]}
    if sig.group(1) not in _CRASH_SIGNALS:
        return {"ok": False, "reason": f"stopped on {sig.group(1)}, which is not a crash signal",
                "raw": out[-400:]}
    pc = _PC.search(out)
    fault = _FAULT.search(out)
    code = _SICODE.search(out)
    # si_addr is the faulting address only for a KERNEL-generated fault (si_code > 0). A signal
    # sent with raise()/kill() has si_code <= 0 and the same union bytes hold the sender's
    # pid/uid -- 0x3e80000000c for pid 12, uid 1000 [measured] -- which was then reported as the
    # address the program touched.
    if code is not None and int(code.group(1)) <= 0:
        fault = None
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
