"""Boundary-driven harnessing (doc 17.4) — drive a consumer through its IPC endpoint.

Instead of feeding stdin/argv/file, launch the consumer and deliver the fuzzed payload over
the actual channel it listens on: a FIFO (named pipe), a Unix-domain socket, or a TCP
loopback socket. This exercises the real receive->sink path a whole-program vector never
reaches. Crash detection reuses the sandbox's signal logic.

Isolation note: channel delivery requires the driver and consumer to share the channel
namespace (filesystem for fifo/unix, loopback for tcp), which is incompatible with the
sandbox's fs/net isolation -- so the consumer runs at the **rlimits-only** tier (CPU/mem/
fsize limits + process-group kill + wall-clock). Whole-system detonation under a microVM
(doc 17.3) is the isolated multi-component path (not yet built).
"""
from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from typing import Optional

from ..dynamic import sandbox
from ..dynamic.sandbox import RunResult

# families this harness can drive (others: report unsupported)
DRIVABLE = {"fifo", "unix", "tcp", "socket"}
_READINESS = 2.0


def _hostport(key):
    if isinstance(key, int):
        return "127.0.0.1", key
    s = str(key)
    if ":" in s:
        h, _, p = s.rpartition(":")
        return (h or "127.0.0.1"), int(p)
    return "127.0.0.1", int(s)


def _connect_retry(sock, addr, deadline):
    last = None
    while time.time() < deadline:
        try:
            sock.connect(addr)
            return True
        except OSError as e:
            last = e
            time.sleep(0.02)
    if last:
        raise last
    return False


def _deliver(family, key, payload, readiness):
    end = time.time() + readiness
    if family == "fifo":
        # opening the write end blocks until the consumer opens the read end -- natural sync
        fd = os.open(key, os.O_WRONLY)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
    elif family == "unix":
        while not os.path.exists(key) and time.time() < end:
            time.sleep(0.02)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            _connect_retry(s, key, end)
            s.sendall(payload)
        finally:
            s.close()
    elif family in ("tcp", "socket"):
        host, port = _hostport(key)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            _connect_retry(s, (host, port), end)
            s.sendall(payload)
        finally:
            s.close()


def _mkfifo(key) -> Optional[str]:
    try:
        if not os.path.exists(key):
            os.mkfifo(key, 0o600)
            return key
    except OSError:
        return None
    return None


def channel_run(exe, family, key, payload: bytes, *, timeout: float = 5.0,
                arch: Optional[str] = None, host: Optional[str] = None,
                readiness: float = _READINESS, mem_mb: int = 2048,
                capture: int = 65536) -> RunResult:
    """Launch the consumer and deliver one payload over its channel; detect a crash."""
    if family not in DRIVABLE:
        return RunResult(isolation="unsupported-channel",
                         note=f"cannot drive {family} channels (try fifo/unix/tcp)")
    host = host or sandbox.host_arch()
    emu = None
    if arch and host and arch != host:
        emu = sandbox._qemu_for(arch)
        if not emu:
            return RunResult(isolation="unsupported-arch",
                             note=f"no qemu-user for {arch} on {host}")
    cmd = ([emu, str(exe)] if emu else [str(exe)])
    preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=(emu is None))

    made_fifo = _mkfifo(key) if family == "fifo" else None
    start = time.monotonic()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             preexec_fn=preexec)
    except Exception as e:
        if made_fifo:
            _rm(made_fifo)
        return RunResult(isolation="rlimits-only(channel)",
                         note=f"spawn failed: {e!r}")

    derr = [None]

    def _run_deliver():
        try:
            _deliver(family, key, payload, readiness)
        except Exception as e:      # delivery best-effort; the consumer may crash mid-read
            derr[0] = repr(e)

    th = threading.Thread(target=_run_deliver, daemon=True)
    th.start()

    timed = False
    try:
        out, err = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        sandbox._killpg(p)
        try:
            out, err = p.communicate(timeout=5)
        except Exception:
            out, err = b"", b""
        rc, timed = None, True
    th.join(timeout=0.5)
    dur = int((time.monotonic() - start) * 1000)
    if made_fifo:
        _rm(made_fifo)

    sig = exit_code = None
    if rc is not None:
        if rc < 0:
            sig = -rc
        elif rc > 128 and (rc - 128) in sandbox.CRASH_SIGNALS:
            sig = rc - 128
        else:
            exit_code = rc
    note = f"channel={family}:{key}"
    if derr[0]:
        note += f"; deliver={derr[0]}"
    return RunResult(
        isolation="rlimits-only(channel)",
        crashed=(sig in sandbox.CRASH_SIGNALS if sig else False), timed_out=timed,
        exit_code=exit_code, signal=sig,
        signal_name=sandbox.CRASH_SIGNALS.get(sig) if sig else None,
        stdout=(out or b"")[:capture], stderr=(err or b"")[:capture],
        duration_ms=dur, cmd=cmd, note=note)


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass
