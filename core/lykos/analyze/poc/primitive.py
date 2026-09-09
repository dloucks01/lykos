"""L2 exploitation-primitive analysis (Phase 6, zero-AI).

L1 proves a crash reproduces. L2 proves the crash yields a *controllable* primitive -- most
importantly instruction-pointer control: attacker input lands in the program counter at a
precise offset. The method is the classic cyclic-pattern (De Bruijn) technique combined with
register/stack capture at the fault (see ptrace_capture.py):

  1. detonate a De Bruijn pattern; at the fault, the saved return address the CPU tried to
     load sits at [SP] (a `ret` into a non-canonical address rolls the pop back, so SP still
     points at the slot). Its position in the pattern is the control offset.
  2. confirm: place a *canonical* sentinel at that offset and re-detonate; if the program
     counter equals the sentinel, instruction-pointer control is proven, not merely inferred.

Pure stdlib and deterministic. The actual register capture is done by the ptrace helper on
native-architecture targets only.
"""
from __future__ import annotations

import struct

_ALPHA = b"abcdefghijklmnopqrstuvwxyz"
# a canonical (< 2**47) sentinel address, so `ret` loads it and the fetch faults *at* it,
# making PC==MARKER definitive proof of control. Reads as "1337c0de1337".
MARKER = 0x1337C0DE1337


def cyclic(length: int, n: int = 4, alphabet: bytes = _ALPHA) -> bytes:
    """First `length` bytes of a De Bruijn sequence: every n-byte window is unique."""
    k = len(alphabet)
    a = [0] * (k * n)
    out = bytearray()

    def db(t, p):
        if len(out) >= length:
            return True
        if t > n:
            if n % p == 0:
                for j in a[1:p + 1]:
                    out.append(alphabet[j])
                    if len(out) >= length:
                        return True
        else:
            a[t] = a[t - p]
            if db(t + 1, p):
                return True
            for j in range(a[t - p] + 1, k):
                a[t] = j
                if db(t + 1, t):
                    return True
        return False

    db(1, 1)
    return bytes(out[:length])


def cyclic_find(sub: bytes, length: int, n: int = 4) -> int:
    """Byte offset of the n-byte window `sub` within cyclic(length), or -1."""
    if len(sub) < n:
        return -1
    return cyclic(length, n).find(sub[:n])


def _le4(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def _stack_words(cap: dict):
    """Yield (relative_offset_to_sp, 8-byte-word) from the captured stack window."""
    stack = bytes.fromhex(cap.get("stack", ""))
    base = cap.get("stack_base")
    sp = cap.get("sp")
    if not stack or base is None or sp is None:
        return
    for i in range(0, len(stack) - 8 + 1, 8):
        yield (base + i) - sp, stack[i:i + 8]


def recover_ip_offset(cap: dict, length: int, n: int = 4):
    """Recover the instruction-pointer-control offset from a cyclic-pattern crash capture.

    Checks the program counter itself (canonical case), then the return-address slot the
    stack pointer indexes at the fault, then adjacent slots. Returns (offset, source) or None.
    """
    pc = cap.get("pc")
    if pc is not None:
        off = cyclic_find(_le4(pc), length, n)
        if off != -1:
            return off, "pc"
    # prefer the slot SP points at (the return address the ret tried to load), then neighbors
    words = dict(_stack_words(cap))
    for rel in (0, -8, 8, -16, 16):
        w = words.get(rel)
        if w:
            off = cyclic_find(w[:4], length, n)
            if off != -1:
                return off, f"stack[sp{rel:+d}]"
    return None


def controlled_registers(cap: dict, length: int, n: int = 4) -> dict:
    """Which general registers hold attacker-controlled (cyclic) data -> {reg: offset}."""
    out = {}
    for name, val in (cap.get("regs") or {}).items():
        if name in ("cs", "ss", "ds", "es", "fs", "gs", "eflags", "orig_rax", "pstate"):
            continue
        off = cyclic_find(_le4(int(val)), length, n)
        if off != -1:
            out[name] = off
    return out


def control_input(offset: int, length: int) -> bytes:
    """cyclic filler up to `offset`, the sentinel at the control slot, padding to `length`."""
    body = bytearray(cyclic(offset))
    body += struct.pack("<Q", MARKER)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


def marker_confirmed(cap: dict) -> bool:
    """True if the fault shows the program counter (or the SP slot) equal to the sentinel."""
    if cap.get("pc") == MARKER:
        return True
    want = struct.pack("<Q", MARKER)
    for _rel, w in _stack_words(cap):
        if w == want:
            return True
    return False
