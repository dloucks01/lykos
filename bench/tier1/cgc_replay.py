#!/usr/bin/env python3
"""Minimal py3 port of cb-replay-pov's POV<->CB driver (the cb-multios tooling is python2, which
is not installed). Establishes TIER-1 GROUND TRUTH: does a challenge's reference POV crash the
challenge binary?

A CGC POV is an ELF *driver* that talks to the CB over fd0/fd1 (the CB's stdout/stdin) and
negotiates what it will prove over fd3. Type-1 POVs crash the CB with controlled PC/register;
for a memory-safety benchmark a fatal signal (SIGSEGV/SIGILL/SIGBUS/SIGABRT/SIGFPE) in the CB
during replay is the signal we want. Type-2 (memory disclosure) does not crash and is reported
separately.

replay(cb_path, pov_path) -> (crashed, signal_name). Used by the Tier-1 scorer for the
vuln/patched differential and to confirm the crashable set.
"""
import os
import random
import signal
import socket
import struct
import subprocess
import time

FATAL = {signal.SIGSEGV, signal.SIGILL, signal.SIGBUS, signal.SIGABRT, signal.SIGFPE}


def _read_all(fd, n, deadline):
    b = b""
    while len(b) < n:
        if time.time() > deadline:
            return b
        try:
            r = os.read(fd, n - len(b))
        except OSError:
            return b
        if not r:
            return b
        b += r
    return b


def _negotiate(fd, deadline, out):
    """Play the cb-replay negotiator on fd3 so the POV proceeds to interact with the CB. Records
    the POV type in out["type"] (1 = crash/register-control, 2 = memory disclosure)."""
    data = _read_all(fd, 4, deadline)
    if len(data) < 4:
        return
    pov_type = struct.unpack("<L", data)[0]
    out["type"] = pov_type
    if pov_type == 1:
        d = _read_all(fd, 12, deadline)
        if len(d) < 12:
            return
        ipmask, regmask, regnum = struct.unpack("<LLL", d)
        ip = random.randint(0, 0xFFFFFFFF) & ipmask
        reg = random.randint(0, 0xFFFFFFFF) & regmask
        try:
            os.write(fd, struct.pack("<LL", ip, reg))
        except OSError:
            pass
    elif pov_type == 2:
        try:
            os.write(fd, struct.pack("<LLL", 0x4347C000, 0x1000, 4))
        except OSError:
            return
        _read_all(fd, 4, deadline)


def replay(cb_path, pov_path, *, seed="0" * 16, timeout=10.0):
    deadline = time.time() + timeout
    cb = subprocess.Popen([cb_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL)
    par, child = socket.socketpair()
    pid = os.fork()
    if pid == 0:                                  # POV: fd0=CB stdout, fd1=CB stdin, fd3=negotiate
        try:
            os.dup2(cb.stdout.fileno(), 0)
            os.dup2(cb.stdin.fileno(), 1)
            os.dup2(child.fileno(), 3)
            dn = os.open(os.devnull, os.O_WRONLY)
            os.dup2(dn, 2)
            os.execv(pov_path, [pov_path, "seed=%s" % seed])
        except Exception:
            pass
        os._exit(127)
    child.close()
    cb.stdin.close()
    cb.stdout.close()
    nego = {"type": None}
    try:
        _negotiate(par.fileno(), deadline, nego)
    finally:
        par.close()
    # wait for the CB, honouring the deadline
    sig = None
    while time.time() <= deadline:
        rc = cb.poll()
        if rc is not None:
            if rc < 0 and (-rc) in FATAL:
                sig = signal.Signals(-rc).name
            break
        time.sleep(0.02)
    else:
        rc = None
    if cb.poll() is None:
        cb.kill()
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    try:
        cb.wait(timeout=2)
    except Exception:
        pass
    return (sig is not None), sig, nego["type"]


if __name__ == "__main__":
    import sys
    c, s, t = replay(sys.argv[1], sys.argv[2])
    print("crashed:", c, "signal:", s, "pov_type:", t)
