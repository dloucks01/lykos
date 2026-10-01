"""Network / socket fuzzing: the input channel for a server that reads from a socket.

Every other channel (stdin / file / argv / menu / command) feeds a program that runs once and
exits. A network server is different: it binds a port, loops, and reads from connections -- so to
reach its parser you must SPAWN it, wait for it to listen, connect, and send. That attack surface
(FreeRTOS+TCP, any daemon) was unreachable before.

This spawns the target, discovers the port it listens on from /proc (no guessing), then drives a
mutation loop over a real socket, attributing a crash to the payload that preceded the server's
death. Single-process servers are handled directly; a forking server whose PARENT survives a
child crash is a documented limitation (the parent-death signal is what we observe).

It runs rlimits-only, NOT in a network namespace -- a netns would isolate the server from our
connect(). Traffic is localhost-only (we dial 127.0.0.1). Pure stdlib.
"""
from __future__ import annotations

import logging
import os
import random
import signal
import socket
import subprocess
import time
from pathlib import Path

from ..detect.catalog import normalize
from ..dynamic import sandbox
from .mutator import Mutator

_log = logging.getLogger(__name__)

# Imports that mark a socket server. A TCP server binds+listens (or accepts); a UDP server binds
# and recvfrom's without listen.
_TCP_SERVER = {"listen", "accept", "accept4"}
_BIND = {"bind"}
_UDP_RECV = {"recvfrom", "recvmsg"}


def detect_server(call_edges) -> "tuple[str, bool]":
    """(proto, is_server): 'tcp'/'udp'/'' from the target's imports. A listen/accept => tcp; a
    bind with recvfrom but no listen => udp."""
    names = {normalize(e.dst_name) for e in call_edges if e.dst_name}
    if names & _TCP_SERVER:
        return "tcp", True
    if names & _BIND and names & _UDP_RECV:
        return "udp", True
    if names & _BIND:                       # bind alone: most likely a server, assume tcp
        return "tcp", True
    return "", False


def _proc_socket_inodes(pid: int) -> set:
    """The socket inodes the process actually owns (its /proc/<pid>/fd/* -> socket:[inode])."""
    inodes = set()
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                tgt = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if tgt.startswith("socket:["):
                inodes.add(tgt[len("socket:["):-1])
    except OSError:
        pass
    return inodes


def _listening_ports(pid: int, proto: str) -> list:
    """Ports the process is listening on. /proc/<pid>/net/{tcp,udp}[6] is NETWORK-NAMESPACE-wide
    (it lists every listener on the host), so results are filtered to sockets this process owns
    by matching the inode (field 9) against its own fds. TCP LISTEN is state 0A; a bound UDP
    socket is state 07."""
    want_state = "0A" if proto == "tcp" else "07"
    inodes = _proc_socket_inodes(pid)
    ports, seen = [], set()
    for fam in (proto, proto + "6"):
        try:
            with open(f"/proc/{pid}/net/{fam}") as f:
                next(f, None)                        # header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local, st, inode = parts[1], parts[3], parts[9]
                    if st != want_state or inode not in inodes:
                        continue
                    port = int(local.rsplit(":", 1)[-1], 16)
                    if port and port not in seen:
                        seen.add(port)
                        ports.append(port)
        except (OSError, ValueError, StopIteration):
            continue
    return ports


def _spawn_server(exe: str, argv: list, mem_mb: int = 1024) -> "subprocess.Popen | None":
    preexec = sandbox._rlimits(mem_mb, 60, set_as=True, nproc=64)
    try:
        return subprocess.Popen([exe] + [str(a) for a in argv],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, preexec_fn=preexec,
                                start_new_session=True)
    except OSError:
        _log.debug("failed to spawn server %s", exe, exc_info=True)
        return None


def _wait_for_port(proc, proto: str, want_port: "int | None", timeout: float) -> "int | None":
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:                 # died before listening
            return None
        ports = _listening_ports(proc.pid, proto)
        if ports:
            return want_port if (want_port and want_port in ports) else ports[0]
        time.sleep(0.05)
    return None


def _send_once(proto: str, port: int, payload: bytes, timeout: float = 1.0) -> None:
    fam = socket.AF_INET
    if proto == "tcp":
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            s.sendall(payload)
            try:
                s.recv(256)                          # let the server process it
            except socket.timeout:
                pass
        finally:
            s.close()
    else:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(payload, ("127.0.0.1", port))
            try:
                s.recvfrom(256)
            except socket.timeout:
                pass
        finally:
            s.close()


def _poll_death(proc, timeout: float = 0.6) -> "int | None":
    """Return the process's exit code if it dies within `timeout`, else None. A crash happens
    just AFTER the payload is delivered, so a single poll right after send races the kernel;
    give it a short window."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc = proc.poll()
        if rc is not None:
            return rc
        time.sleep(0.02)
    return None


def _killtree(proc) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=2)
    except Exception:
        pass


def _default_corpus() -> list:
    """Protocol-shaped seeds for a network parser. Beyond raw overflows, these target the bug
    classes that dominate embedded network stacks (FreeRTOS+TCP, lwIP): a length/size field that
    lies about the body (header says huge, body is short -> over-read), oversized option/TLV and
    extension fields, and format specifiers reaching a logging printf."""
    import struct
    out = [
        b"GET / HTTP/1.0\r\n\r\n",                     # a benign request to pass a protocol gate
        b"A" * 64, b"A" * 1024, b"A" * 8192,           # escalating overflow
        b"\x00" * 16,
        b"%s%s%s%s%n", b"%p" * 32,                     # format string into a log line
    ]
    # length-prefixed: a 2- and 4-byte length header that claims far more than follows.
    for lam in (struct.pack(">H", 0xFFFF), struct.pack("<H", 0xFFFF),
                struct.pack(">I", 0x7FFFFFFF), struct.pack("<I", 0x0FFFFFFF)):
        out.append(lam + b"A" * 8)                     # header lies: says huge, body tiny
        out.append(lam + b"A" * 2048)
    # TLV / option storms: many type-length-value records, and one with an oversized length.
    out.append(b"".join(bytes([1, 4]) + b"opt" + b"\x00" for _ in range(64)))
    out.append(bytes([3, 0xFF]) + b"B" * 16)           # TLV length 255, 16 bytes present
    # an IPv6-RA-ish prefix/option length field (the CVE-2026-7426 class): oversized length byte.
    out.append(b"\x86\x00" + b"\x00" * 6 + bytes([0x03, 0xFF]) + b"C" * 8)
    return out


class NetFuzzResult:
    def __init__(self, crashed, payload=None, signal_name=None, signal_num=None,
                 execs=0, port=None, note=None):
        self.crashed = crashed
        self.payload = payload
        self.signal_name = signal_name
        self.signal = signal_num
        self.execs = execs
        self.port = port
        self.note = note


def fuzz_server(exe: str, proto: str, *, argv=(), seeds=(), port: "int | None" = None,
                max_execs: int = 1500, seed: int = 1337,
                listen_timeout: float = 5.0) -> NetFuzzResult:
    """Spawn `exe`, find its listening port, and fuzz it over a socket until a payload crashes it
    or the budget runs out. On a crash, respawn to CONFIRM the same payload reproduces before
    reporting it (kills one-off flakes). Returns a NetFuzzResult."""
    rng = random.Random(seed)
    mut = Mutator(rng)
    corpus = [s for s in seeds if s] or _default_corpus()
    found = {"port": port}

    def _run_campaign(confirm_payload=None):
        proc = _spawn_server(exe, list(argv))
        if proc is None:
            return None, None, "spawn-failed", 0
        try:
            p = _wait_for_port(proc, proto, port, listen_timeout)
            if p is None:
                return None, None, "no-listen", 0
            found["port"] = p
            payloads = [confirm_payload] if confirm_payload else list(corpus)
            n = 0
            while confirm_payload or n < max_execs:
                for data in payloads:
                    n += 1
                    try:
                        _send_once(proto, p, data)
                    except OSError:
                        # connection refused/reset -> the server may have just died; check below
                        pass
                    # a crash lands just after delivery; wait a beat so we don't race the kernel.
                    rc = _poll_death(proc, timeout=(0.6 if confirm_payload else 0.15))
                    if rc is not None:
                        crashed, _sig, sig_name, _ = sandbox.classify_rc(rc)
                        return (data if crashed else None), (-rc if rc < 0 else None), \
                            (sig_name if crashed else f"exit{rc}"), n
                    if confirm_payload:
                        return None, None, "survived", n   # confirm pass: it did NOT re-crash
                payloads = [mut.mutate(rng.choice(corpus), corpus) for _ in range(32)]
            return None, None, "no-crash", n
        finally:
            _killtree(proc)
        return None, None, "no-crash", 0

    crash_payload, signum, sig_name, execs = _run_campaign()
    if crash_payload is None:
        return NetFuzzResult(False, execs=execs, port=found["port"], note=sig_name)
    # Confirm the crash reproduces on a fresh server instance.
    conf_payload, csig, cname, _ = _run_campaign(confirm_payload=crash_payload)
    if conf_payload is None:
        return NetFuzzResult(False, execs=execs, port=found["port"],
                             note=f"crash on {sig_name} did not reproduce (flaky)")
    return NetFuzzResult(True, payload=crash_payload, signal_name=cname or sig_name,
                         signal_num=csig or signum, execs=execs, port=found["port"])
