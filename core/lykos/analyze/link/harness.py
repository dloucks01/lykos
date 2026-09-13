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
# Datagram channels matter for a whole class of target this platform is pointed at: a
# receiver that joins a multicast group and parses a video stream never reads stdin, a file or
# argv, so every existing channel delivers nothing and the campaign starves. It is also a
# channel the stream CONTROLS -- an MPEG-TS adaptation-field length or an RTP header comes
# straight off the wire -- which is exactly where the bugs are.
DRIVABLE = {"fifo", "unix", "tcp", "socket", "udp", "multicast"}
_DGRAM = {"udp", "multicast"}
# How often to repeat a datagram while waiting for the receiver to bind. Short
# enough that a fast target gets its packet promptly, long enough not to flood.
_DGRAM_INTERVAL = 0.05
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
    elif family in _DGRAM:
        # A datagram receiver is not "listening" in the TCP sense: there is no connect to
        # retry against and nothing that reports readiness, and a datagram sent before the
        # socket is bound is dropped with nobody told. So REPEAT across the readiness window
        # rather than guessing an interval -- measured, the target needs appreciably longer to
        # bind and join a group than a single short sleep allows, and a one-shot send arrives
        # to nothing and reads exactly like a channel the target ignores.
        host, port = _hostport(key)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == "multicast":
                # loopback on, so a receiver on this host sees it; TTL 1 so nothing leaves it
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            while True:
                s.sendto(payload, (host, port))
                if time.time() >= end:
                    break
                time.sleep(_DGRAM_INTERVAL)
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
                capture: int = 65536, argv=()) -> RunResult:
    """Launch the consumer and deliver one payload over its channel; detect a crash."""
    if family not in DRIVABLE:
        return RunResult(isolation="unsupported-channel",
                         note=f"cannot drive {family} channels "
                              f"(try {'/'.join(sorted(DRIVABLE))})")
    host = host or sandbox.host_arch()
    # Substrate BEFORE architecture, the order sandbox.run uses. A jar's recorded arch is
    # "jvm", which is not a processor and has no qemu -- so asking for an emulator first
    # rejected every Java target with "no qemu-user for jvm on x86-64" before the JVM branch
    # below could run it. The campaign then reported 30 executions at 24,000/second, because
    # each one returned that error immediately without starting anything.
    jvm = sandbox._is_jvm(exe)
    emu = None
    if not jvm and arch and host and arch != host:
        emu = sandbox._qemu_for(arch)
        if not emu:
            return RunResult(isolation="unsupported-arch",
                             note=f"no qemu-user for {arch} on {host}")
    # A listener needs to be told what to listen ON. Launched bare, a multicast receiver
    # prints its usage and exits, and every payload is delivered to a process that is already
    # gone -- which looks exactly like a channel the target ignores. The flags come from the
    # same invocation discovery the fuzzer uses.
    # A jar is not executable and the JVM is not the target: exec'ing it directly starts
    # nothing, and the run comes back with no exit code, no output and no crash -- which is
    # indistinguishable from a channel the target ignores. Java multicast receivers are a real
    # target class here, so the runtime has to be named, exactly as sandbox.run does.
    if jvm:
        launch = [sandbox._java() or "java", *sandbox._JVM_FLAGS, "-jar", str(exe)]
    elif emu:
        launch = [emu, str(exe)]
    else:
        launch = [str(exe)]
    cmd = launch + [str(a) for a in (argv or ())]
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
    crashed = sig in sandbox.CRASH_SIGNALS if sig else False
    signame = sandbox.CRASH_SIGNALS.get(sig) if sig else None
    fault_pc = None
    if jvm and not crashed:
        # A Java program does not segfault, it throws -- so the wait status says nothing and
        # an uncaught ArrayIndexOutOfBoundsException would have been recorded as a clean run.
        kind, detail, frames = sandbox.jvm_exception(err or b"", exit_code, out or b"")
        if kind:
            crashed, signame = True, kind
            fault_pc = sandbox.jvm_site(frames)
            note += f"; {detail}"
    return RunResult(
        isolation="rlimits-only(channel)" + ("+jvm" if jvm else ""),
        crashed=crashed, timed_out=timed,
        exit_code=exit_code, signal=sig, signal_name=signame, fault_pc=fault_pc,
        stdout=(out or b"")[:capture], stderr=(err or b"")[:capture],
        duration_ms=dur, cmd=cmd, note=note)


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass
