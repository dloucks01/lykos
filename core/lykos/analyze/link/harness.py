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

import errno
import fcntl
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
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
        # Open the write end NON-BLOCKING with a bounded retry against the readiness deadline.
        # A blocking O_WRONLY open on a FIFO hangs until a reader appears -- and when the
        # consumer never opens the read end (it crashed/failed at startup) that open never
        # returns, wedging this delivery. Under the one-shot channel_run each such delivery is
        # a daemon thread, so a campaign leaked one stuck thread (and fd) PER execution.
        # O_NONBLOCK makes the open return ENXIO instead of blocking when there is no reader
        # yet; we retry until one appears or the window closes, which is the same rendezvous
        # the blocking open used to give, minus the unbounded hang.
        fd = None
        while True:
            try:
                fd = os.open(key, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as e:
                if e.errno != errno.ENXIO:
                    raise
                if time.time() >= end:
                    return                             # no reader opened the fifo in time
                time.sleep(0.02)
        try:
            # switch back to blocking for the write, so a large payload is delivered whole
            # rather than risking EAGAIN on a full pipe buffer
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
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


def _deliver_once(family, key, payload):
    """One delivery, no waiting. `_deliver` repeats across the readiness window because a
    fresh process may not have bound yet; inside a session the listener is already up, so the
    repeat is pure cost -- and a duplicate datagram would make the next payload's attribution
    ambiguous."""
    _deliver(family, key, payload, 0.0)


def _mkfifo(key) -> Optional[str]:
    try:
        if not os.path.exists(key):
            os.mkfifo(key, 0o600)
            return key
    except OSError:
        return None
    return None


def _launch_cmd(exe, arch, argv, host=None, trace_log=None):
    """(cmd, jvm, error) -- how to start this target, shared by the one-shot and session
    paths so the two cannot drift on substrate dispatch. Substrate BEFORE architecture.

    `trace_log` asks an EMULATED target for its basic-block log, which is the only way to get
    coverage out of a listener: there is no instrumented rebuild of a binary we were handed,
    and the process is not restarted per input, so qemu's own `-d exec` log is the signal.
    It is ignored for a native or JVM target, which have no emulator to ask.
    """
    jvm = sandbox._is_jvm(exe)
    emu = None
    host = host or sandbox.host_arch()
    if not jvm and arch and host and arch != host:
        emu = sandbox._qemu_for(arch)
        if not emu:
            return None, jvm, f"no qemu-user for {arch} on {host}"
    if jvm:
        launch = [sandbox._java() or "java", *sandbox._JVM_FLAGS, "-jar", str(exe)]
    elif emu:
        launch = [emu] + (["-d", "exec", "-D", str(trace_log)] if trace_log else []) + [str(exe)]
    else:
        launch = [str(exe)]
    return launch + [str(a) for a in (argv or ())], jvm, None


def _classify(jvm, rc, out, err):
    """(crashed, signal, signal_name, exit_code, fault_pc, detail) from one finished run.

    Signal classification goes through the shared `sandbox.classify_rc` so the one-shot and
    session paths cannot disagree (they used to: this function synthesised a signal from ANY
    positive returncode without the CRASH_SIGNALS filter `channel_run` applied, so a target
    that merely exits with a status like 139 or 200 was recorded as a crash and, worse, lost
    its exit code). A NEGATIVE returncode is -signum; a positive one is a signal only in the
    128+signum wrapper form AND only when that signum is a real crash signal; every other
    positive value is a plain exit status, never a fabricated crash.
    """
    crashed, sig, signame, exit_code = sandbox.classify_rc(rc)
    fault_pc = detail = None
    if jvm and not crashed:
        kind, why, frames = sandbox.jvm_exception(err or b"", exit_code, out or b"")
        if kind:
            crashed, signame = True, kind
            fault_pc, detail = sandbox.jvm_site(frames), why
    return crashed, sig, signame, exit_code, fault_pc, detail


class ChannelSession:
    """One listener process, many payloads.

    Restarting the target per input is what makes network fuzzing slow: a JVM receiver costs
    ~1 execution/second because every packet pays process startup, group join and then the
    full timeout, since a listener does not exit when it is finished with an input -- only a
    crash ends it. Keeping the process alive and sending the next datagram turns that into a
    settle delay.

    The trade is attribution: when the process dies, the payload in flight is the SUSPECT, not
    a proven cause -- an earlier packet may have left it primed. That is why the session marks
    itself dead on a crash, so the campaign's own re-run starts a fresh process and delivers
    only that payload. A crash that does not survive that is not recorded.
    """

    def __init__(self, exe, family, key, *, argv=(), arch=None, readiness=2.0,
                 settle=0.15, mem_mb=2048, capture=65536, blocks=()):
        self.exe, self.family, self.key = exe, family, key
        self.argv, self.arch = list(argv or ()), arch
        self.readiness, self.settle = float(readiness), float(settle)
        self.mem_mb, self.capture = mem_mb, capture
        self.proc = None
        self.jvm = False
        self.error = None
        self.restarts = 0
        # Coverage on a persistent listener, for an emulated target. One process serves many
        # payloads, so the block log is cumulative and a whole-file read would credit every
        # payload with everything reached before it -- which is not coverage, it is a running
        # total that only ever grows. Reading only what the log gained since the last send is
        # what makes it per-payload.
        self.blocks = tuple(blocks or ())
        self._tdir = tempfile.mkdtemp(prefix="lykos-chtrace-") if self.blocks else None
        self._trace_log = str(Path(self._tdir) / "exec.log") if self._tdir else None
        self._log_pos = 0

    def _start(self):
        cmd, jvm, err = _launch_cmd(self.exe, self.arch, self.argv,
                                    trace_log=self._trace_log)
        self.jvm = jvm
        if err:
            self.error = err
            return False
        # Only an emulator writes the exec log. A native or JVM launch never will, so drop the
        # trace here: _new_blocks then reports None ("no coverage available") instead of ()
        # ("reached nothing"), which is what lets the campaign fall back to behaviour novelty.
        emu = not (jvm or (cmd and cmd[0] == str(self.exe)))
        if not emu and self._tdir:
            shutil.rmtree(self._tdir, ignore_errors=True)
            self._tdir = self._trace_log = None
        preexec = sandbox._rlimits(self.mem_mb, int(self.readiness) + 30, set_as=False)
        self.proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, preexec_fn=preexec)
        self.cmd = cmd
        self.restarts += 1
        self._log_pos = 0                   # a fresh qemu truncates the log it writes
        time.sleep(self.readiness)          # no readiness signal on a datagram socket
        return self.proc.poll() is None

    def send(self, payload: bytes) -> RunResult:
        if self.error:
            return RunResult(isolation="unsupported-arch", note=self.error)
        if self.proc is not None and self.proc.poll() is not None:
            # It died since the last send and the settle window closed before it did -- a slow
            # or loaded machine, an emulated target, a JVM. This used to be swallowed: the
            # next send saw a dead process, restarted it, and the crash was never reported at
            # all. Report it as the suspect for THIS payload instead and let the campaign's
            # re-run adjudicate, which is the same bargain the in-window case already makes.
            return self._dead_result(note="died after the previous payload")
        if self.proc is None:
            self._reap()
            if not self._start():
                return self._dead_result(note="target exited during startup")
        try:
            _deliver_once(self.family, self.key, payload)
        except OSError as e:
            return RunResult(isolation="rlimits-only(session)", note=f"deliver failed: {e}")
        end = time.time() + self.settle
        while time.time() < end:
            if self.proc.poll() is not None:
                return self._dead_result()
            time.sleep(0.01)
        return RunResult(isolation="rlimits-only(session)" + ("+jvm" if self.jvm else ""),
                         crashed=False, exit_code=None, blocks_hit=self._new_blocks(),
                         note=f"channel={self.family}:{self.key} (session)")

    def _new_blocks(self):
        """Which of the wanted blocks appeared in the log SINCE THE LAST SEND.

        None when coverage was not asked for, so the campaign can tell "no coverage available"
        from "this payload reached nothing" -- the first means fall back to behaviour novelty,
        the second means the payload was genuinely uninteresting, and treating them alike
        would have every native target look like a target that never reaches new code.
        """
        if not self._trace_log:
            return None
        try:
            with open(self._trace_log, "rb") as fh:
                fh.seek(self._log_pos)
                data = fh.read()
                self._log_pos = fh.tell()
        except OSError:
            return None                     # log unreadable -> no coverage, not "reached nothing"
        want = set(self.blocks)
        return tuple(sorted({int(m.group(1), 16)
                             for m in sandbox._TRACE_PC.finditer(data)} & want))

    def _dead_result(self, note="") -> RunResult:
        try:
            out, err = self.proc.communicate(timeout=3)
        except Exception:
            out, err = b"", b""
        rc = self.proc.returncode
        self.proc = None
        crashed, sig, signame, exit_code, fault_pc, detail = _classify(self.jvm, rc, out, err)
        n = f"channel={self.family}:{self.key} (session)"
        if detail:
            n += f"; {detail}"
        if note:
            n += f"; {note}"
        return RunResult(isolation="rlimits-only(session)" + ("+jvm" if self.jvm else ""),
                         crashed=crashed, exit_code=exit_code, signal=sig,
                         signal_name=signame, fault_pc=fault_pc, blocks_hit=self._new_blocks(),
                         stdout=(out or b"")[:self.capture], stderr=(err or b"")[:self.capture],
                         cmd=getattr(self, "cmd", []), note=n)

    def _reap(self):
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None

    def close(self):
        self._reap()
        if self._tdir:
            shutil.rmtree(self._tdir, ignore_errors=True)
            self._tdir = self._trace_log = None


def channel_run(exe, family, key, payload: bytes, *, timeout: float = 5.0,
                arch: Optional[str] = None, host: Optional[str] = None,
                readiness: float = _READINESS, mem_mb: int = 2048,
                capture: int = 65536, argv=(), blocks=()) -> RunResult:
    """Launch the consumer and deliver one payload over its channel; detect a crash.

    `blocks` asks for coverage, and is only answerable for an emulated target -- see
    `_launch_cmd`. A fresh process per payload means the block log IS this payload's coverage.
    """
    if family not in DRIVABLE:
        return RunResult(isolation="unsupported-channel",
                         note=f"cannot drive {family} channels "
                              f"(try {'/'.join(sorted(DRIVABLE))})")
    host = host or sandbox.host_arch()
    # Substrate BEFORE architecture, and via _launch_cmd so the one-shot and session paths
    # cannot disagree about it. A jar's recorded arch is "jvm", which is not a processor and
    # has no qemu -- so asking for an emulator first rejected every Java target with "no
    # qemu-user for jvm on x86-64" before the JVM branch could run it, and the campaign
    # reported 30 executions at 24,000/second because each returned that error immediately
    # without starting anything. This function used to carry its own copy of that dispatch:
    # _launch_cmd's docstring promised the two could not drift while nothing here called it.
    #
    # A listener also needs to be told what to listen ON. Launched bare, a multicast receiver
    # prints its usage and exits, and every payload is delivered to a process that is already
    # gone -- which looks exactly like a channel the target ignores. The flags come from the
    # same invocation discovery the fuzzer uses.
    tdir = tempfile.mkdtemp(prefix="lykos-chtrace-") if blocks else None
    trace_log = str(Path(tdir) / "exec.log") if tdir else None
    cmd, jvm, err = _launch_cmd(exe, arch, argv, host=host, trace_log=trace_log)
    if err:
        if tdir:
            shutil.rmtree(tdir, ignore_errors=True)
        return RunResult(isolation="unsupported-arch", note=err)
    emu = None if (jvm or cmd[0] == str(exe)) else cmd[0]
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
        if tdir:
            shutil.rmtree(tdir, ignore_errors=True)
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

    # Shared with the session path via sandbox.classify_rc: a negative returncode is -signum,
    # a positive one is a signal only in the 128+signum wrapper form for an actual crash
    # signal, and any other positive value stays an exit code (never a fabricated crash).
    crashed, sig, signame, exit_code = sandbox.classify_rc(rc)
    note = f"channel={family}:{key}"
    if derr[0]:
        note += f"; deliver={derr[0]}"
    fault_pc = None
    if jvm and not crashed:
        # A Java program does not segfault, it throws -- so the wait status says nothing and
        # an uncaught ArrayIndexOutOfBoundsException would have been recorded as a clean run.
        kind, detail, frames = sandbox.jvm_exception(err or b"", exit_code, out or b"")
        if kind:
            crashed, signame = True, kind
            fault_pc = sandbox.jvm_site(frames)
            note += f"; {detail}"
    blocks_hit = None
    # Only an emulator writes the exec log; a native or JVM launch (emu is None) never
    # produces one, so `blocks_hit` must stay None -- "no coverage available" -- rather than
    # become () -- "reached nothing" -- which would make every native payload look
    # uninteresting and stop the campaign falling back to behaviour novelty (see stage.py).
    if trace_log and emu:
        reached, last = sandbox._qemu_reached(trace_log, blocks, want_last=True)
        blocks_hit = tuple(reached)
        # An emulated listener has no ptrace tracer either, so the last block qemu translated
        # is the only fault locus available -- the same bargain sandbox.run makes.
        if crashed and fault_pc is None:
            fault_pc = last
    if tdir:
        shutil.rmtree(tdir, ignore_errors=True)
    return RunResult(
        isolation="rlimits-only(channel)" + ("+jvm" if jvm else ""),
        crashed=crashed, timed_out=timed,
        exit_code=exit_code, signal=sig, signal_name=signame, fault_pc=fault_pc,
        stdout=(out or b"")[:capture], stderr=(err or b"")[:capture],
        duration_ms=dur, cmd=cmd, note=note, blocks_hit=blocks_hit)


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass
