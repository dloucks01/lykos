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

import re
import struct

_ALPHA = b"abcdefghijklmnopqrstuvwxyz"
# a canonical (< 2**47) sentinel address, so `ret` loads it and the fetch faults *at* it,
# making PC==MARKER definitive proof of control. Reads as "1337c0de1337".
MARKER = 0x1337C0DE1337
# 32-bit targets truncate a 48-bit PC, so IP control on i386/arm/mips uses a 4-byte sentinel
# (an unmapped user address, so the fetch faults at it). Reads as "1337c0de".
MARKER32 = 0x1337C0DE
# return-address registers across link-register ABIs, checked as IP-control sources
_RA_REGS = ("lr", "x30", "r31", "ra")


def _ip_marker(word: int) -> int:
    return MARKER if word >= 8 else MARKER32


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


def _reg_window(value: int, word: int, endian: str, n: int = 4) -> bytes:
    """The first `n` input bytes that produced a controlled register value. A register is an
    integer; the bytes an attacker placed in memory become that integer in target byte order,
    so the search key is the value rendered in the target's endianness (big MSB-first == the
    input order; little LSB-first == the input order too). Works for 4- and 8-byte registers."""
    order = "big" if endian == "big" else "little"
    return (int(value) & ((1 << (word * 8)) - 1)).to_bytes(word, order)[:n]


def _marker_bytes(marker: int, word: int, endian: str) -> bytes:
    """Marker rendered so that, loaded from memory into a register, it reconstructs `marker`."""
    order = "big" if endian == "big" else "little"
    return marker.to_bytes(word, order)


def _stack_words(cap: dict):
    """Yield (relative_offset_to_sp, 8-byte-word) from the captured stack window."""
    stack = bytes.fromhex(cap.get("stack", ""))
    base = cap.get("stack_base")
    sp = cap.get("sp")
    if not stack or base is None or sp is None:
        return
    for i in range(0, len(stack) - 8 + 1, 8):
        yield (base + i) - sp, stack[i:i + 8]


def recover_ip_offset(cap: dict, length: int, n: int = 4, endian: str = "little", word: int = 8):
    """Recover the instruction-pointer-control offset from a cyclic-pattern crash capture.

    Checks the program counter itself (canonical case), then the return-address slot the
    stack pointer indexes at the fault, then adjacent slots. `endian`/`word` describe the
    target so the PC's bytes are read in the right order (a big-endian PC's bytes are MSB
    first). Stack-slot bytes are raw memory, already in input order. Returns (offset, source)
    or None."""
    pc = cap.get("pc")
    if pc is not None:
        off = cyclic_find(_reg_window(pc, word, endian, n), length, n)
        if off != -1:
            return off, "pc"
    # link-register ABIs (PPC lr, ARM/aarch64 lr/x30, MIPS $ra): the branch target the epilogue
    # loads. On PPC the fetched pc is lr with the low bits masked by aligned fetch, so the pc
    # search misses but the RA register holds the exact controlled value.
    regs = cap.get("regs") or {}
    for rn in _RA_REGS:
        if rn in regs:
            off = cyclic_find(_reg_window(regs[rn], word, endian, n), length, n)
            if off != -1:
                return off, rn
    # prefer the slot SP points at (the return address the ret tried to load), then neighbors
    words = dict(_stack_words(cap))
    for rel in (0, -8, 8, -16, 16):
        w = words.get(rel)
        if w:
            off = cyclic_find(w[:n], length, n)      # raw memory bytes -> already input order
            if off != -1:
                return off, f"stack[sp{rel:+d}]"
    return None


def frame_offset_candidates(frames: dict, word: int = 8) -> list:
    """Predict instruction-pointer-control offsets from recovered stack frames (static RE).

    For a linear stack-buffer overflow, attacker bytes that reach the saved return address
    start at the buffer and run to the return slot. In Ghidra's stack-frame coordinates that
    distance is `ret_offset - buffer_offset` (the frame base sits at the return address, so
    ret_offset is typically 0 and locals are negative); when ret_offset is unavailable we fall
    back to `|buffer_offset| + word`. Each recovered stack buffer yields one candidate; these
    corroborate the dynamic cyclic offset and seed a direct control attempt when the dynamic
    slot heuristic is ambiguous. `word` is the pointer size (8 on 64-bit, 4 on 32-bit).

    Returns candidates sorted by offset (smallest/tightest first), deduped by offset:
    [{offset, buffer, size, function_addr}].
    """
    by_off = {}
    for addr, fr in (frames or {}).items():
        ret = fr.get("ret_offset")
        for v in (fr.get("vars") or []):
            if not v.get("is_buffer") or v.get("offset") is None:
                continue
            o = int(v["offset"])
            dist = (ret - o) if ret is not None else (abs(o) + word)
            if dist <= 0:
                continue
            cand = {"offset": dist, "buffer": v.get("name"), "size": v.get("size"),
                    "function_addr": addr}
            # when several buffers predict the same offset, keep the largest (the plausible
            # overflow target, not a coincidental small local at the same frame distance)
            cur = by_off.get(dist)
            if cur is None or (cand["size"] or 0) > (cur["size"] or 0):
                by_off[dist] = cand
    return sorted(by_off.values(), key=lambda c: c["offset"])


def match_frame_candidate(offset: int, candidates: list, word: int = 8):
    """Match a dynamically-recovered control offset to a static stack-buffer prediction,
    allowing one saved-frame-pointer word of slack. ABIs that save the frame pointer and
    return address as a pair below the locals (aarch64 stp x29,x30; and similar) put the
    controllable return address a word past the buffer's distance to the frame base, which
    x86-64's Ghidra offsets already fold in. The saved slot can be a word above (aarch64
    stp x29,x30) or below (mips saves $ra a word under Ghidra's frame base), so we allow
    +/- one word of slack. Among candidates within a word, prefer the largest buffer and then
    the closest -- a linear overflow that reaches the return address came through the biggest
    buffer at that frame distance, not a coincidental small local that happens to land at the
    same offset. Returns (candidate, slack) or (None, 0)."""
    best, best_key, best_slack = None, None, 0
    for c in candidates:
        d = offset - c["offset"]
        if abs(d) <= word:
            key = (-int(c.get("size") or 0), abs(d))     # largest buffer first, then closest
            if best is None or key < best_key:
                best, best_key, best_slack = c, key, d
    return (best, best_slack) if best is not None else (None, 0)


def seed_offsets(candidates: list, word: int = 8, cap=None):
    """Offsets to try for static-seeded confirmation: each buffer's distance to the frame base
    and that +/- a saved-register word (the return-address slot sits within a word of the
    frame base across ABIs), smallest first, deduped and within `cap`.
    Yields (offset, candidate, slack)."""
    seen, out = set(), []
    for c in candidates:
        for slack in (0, word, -word):
            o = c["offset"] + slack
            if o <= 0 or o in seen or (cap is not None and o + word > cap):
                continue
            seen.add(o)
            out.append((o, c, slack))
    out.sort(key=lambda t: t[0])
    return out


def controlled_registers(cap: dict, length: int, n: int = 4, endian: str = "little",
                         word: int = 8) -> dict:
    """Which general registers hold attacker-controlled (cyclic) data -> {reg: offset}."""
    out = {}
    for name, val in (cap.get("regs") or {}).items():
        if name in ("cs", "ss", "ds", "es", "fs", "gs", "eflags", "orig_rax", "pstate"):
            continue
        off = cyclic_find(_reg_window(int(val), word, endian, n), length, n)
        if off != -1:
            out[name] = off
    return out


def control_input(offset: int, length: int, word: int = 8, endian: str = "little") -> bytes:
    """cyclic filler up to `offset`, the sentinel at the control slot, padding to `length`.
    `word` is the pointer size (8 on 64-bit, 4 on 32-bit); `endian` places the sentinel bytes
    so a big-endian target loads them back as the sentinel value."""
    body = bytearray(cyclic(offset))
    body += _marker_bytes(_ip_marker(word), word, endian)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


def marker_confirmed(cap: dict, word: int = 8, endian: str = "little") -> bool:
    """True if the fault shows the program counter (or the SP slot) equal to the sentinel.
    The PC is compared as an integer (already parsed in target byte order); the stack-slot
    bytes are raw memory, compared against the sentinel rendered in target byte order.
    `word` selects the 64- or 32-bit sentinel (a 32-bit PC truncates the 48-bit marker)."""
    m = _ip_marker(word)
    pc = cap.get("pc")
    # exact PC, or an alignment-masked PC (PPC clears the low 2 bits of a branch target; a
    # thumb target sets bit 0) -- the branch reached the sentinel either way.
    if pc == m or pc in (m & ~0b11, m & ~0b1, m | 1):
        return True
    regs = cap.get("regs") or {}
    for rn in _RA_REGS:                              # link-register ABIs: LR/x30/$ra holds it
        if regs.get(rn) == m:
            return True
    want = _marker_bytes(m, word, endian)
    for _rel, w in _stack_words(cap):
        if w[:len(want)] == want:
            return True
    return False


# --------------------------------------------------------------------- L2 memory primitives
# A second canonical sentinel for the *value* half of a write-what-where.
MARKER_VALUE = 0x0B16B00B5157

# 32/16/8-bit register names -> their 64-bit container, so a disasm operand like `edx`
# resolves to the `rdx` value the ptrace capture reports.
_SUBREG = {}
# rax/rbx/rcx/rdx with e**/**/**l aliases
for _q, _b in (("rax", "a"), ("rbx", "b"), ("rcx", "c"), ("rdx", "d")):
    for _alias in (_q, "e" + _b + "x", _b + "x", _b + "l", _b + "h"):
        _SUBREG[_alias] = _q
# rsi/rdi/rbp/rsp with e**/**/**l aliases
for _q, _b in (("rsi", "si"), ("rdi", "di"), ("rbp", "bp"), ("rsp", "sp")):
    for _alias in (_q, "e" + _b, _b, _b + "l"):
        _SUBREG[_alias] = _q
# r8..r15 with d/w/b aliases
for _n in range(8, 16):
    for _sfx in ("", "d", "w", "b"):
        _SUBREG[f"r{_n}{_sfx}"] = f"r{_n}"


def _reg64(name):
    return _SUBREG.get(name.strip().lower())


def _first_reg_in_brackets(operand):
    """The base register named inside a `[...]` memory operand, as a 64-bit name."""
    i, j = operand.find("["), operand.find("]")
    if i < 0 or j < 0:
        return None
    inner = operand[i + 1:j]
    for tok in re.split(r"[+*\-\s]", inner):
        r = _reg64(tok)
        if r:
            return r
    return None


def parse_mem_access(disasm: str):
    """From an Intel-syntax instruction, return {is_write, base, value} for its memory operand,
    or None if it does not dereference memory. `base` is the address register (64-bit name),
    `value` the source register for a store (else None)."""
    if not disasm or "[" not in disasm:
        return None
    parts = disasm.split(None, 1)
    if len(parts) < 2:
        return None
    ops = parts[1]
    dest, _, src = ops.partition(",")
    if "[" in dest:                                  # memory is the destination -> a store
        return {"is_write": True, "base": _first_reg_in_brackets(dest),
                "value": _reg64(src.strip()) if src.strip() else None}
    return {"is_write": False, "base": _first_reg_in_brackets(src), "value": None}


def analyze_memory_primitive(cap: dict, length: int, disasm, n: int = 4):
    """Classify an attacker-controlled memory access at the fault: write-what-where (address
    and stored value both controlled), controlled-write (address only), or controlled-read
    (arbitrary read address). Returns a primitive dict or None.

    The controlled address is read from the base register (not si_addr): a non-canonical
    controlled address raises #GP, for which the kernel reports si_addr as 0, so the register
    value is the reliable signal."""
    if not disasm:
        return None
    acc = parse_mem_access(disasm)
    if acc is None or not acc["base"]:
        return None
    regs = cap.get("regs") or {}
    if acc["base"] not in regs:
        return None
    addr_off = cyclic_find(_le4(int(regs[acc["base"]])), length, n)
    if addr_off == -1:                               # dereferenced address is not attacker data
        return None
    value_off = -1
    if acc["is_write"] and acc["value"] and acc["value"] in regs:
        value_off = cyclic_find(_le4(int(regs[acc["value"]])), length, n)
    if acc["is_write"]:
        kind = "write-what-where" if value_off != -1 else "controlled-write"
    else:
        kind = "controlled-read"
    return {"type": kind, "access": "write" if acc["is_write"] else "read",
            "addr_reg": acc["base"], "addr_offset": addr_off, "value_reg": acc["value"],
            "value_offset": (value_off if value_off != -1 else None),
            "fault_addr": cap.get("fault_addr"), "disasm": disasm}


def two_marker_input(addr_offset: int, value_offset, length: int) -> bytes:
    """Place the address sentinel at `addr_offset` and (for write-what-where) the value
    sentinel at `value_offset`, over cyclic filler, padded to `length`."""
    body = bytearray(cyclic(length))
    body[addr_offset:addr_offset + 8] = struct.pack("<Q", MARKER)
    if value_offset is not None:
        body[value_offset:value_offset + 8] = struct.pack("<Q", MARKER_VALUE)
    return bytes(body[:length])


def memory_primitive_confirmed(cap: dict, prim: dict):
    """After re-running with `two_marker_input`, verify we steered the dereferenced address to
    the sentinel (WHERE control) and, for a write, the stored-value register to its sentinel
    (WHAT control). Returns (addr_ok, value_ok). The address is checked on the base register
    (robust to non-canonical #GP where si_addr reads 0), falling back to si_addr."""
    regs = cap.get("regs") or {}
    addr_ok = (int(regs.get(prim.get("addr_reg"), -1)) == MARKER
               or cap.get("fault_addr") == MARKER)
    value_ok = True
    if prim.get("value_offset") is not None and prim.get("value_reg"):
        value_ok = int(regs.get(prim["value_reg"], 0)) == MARKER_VALUE
    return addr_ok, value_ok
