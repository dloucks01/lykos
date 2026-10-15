"""L2 exploitation-primitive analysis (Phase 6).

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

_ALPHA = b"abcdefghijklmnopqrstuvwxyz"
# a canonical (< 2**47) sentinel address, so `ret` loads it and the fetch faults *at* it,
# making PC==MARKER definitive proof of control. Reads as "1337c0de1337".
MARKER = 0x1337C0DE1337
# 32-bit targets truncate a 48-bit PC, so IP control on i386/arm/mips uses a 4-byte sentinel
# (an unmapped user address, so the fetch faults at it). Reads as "1337c0de".
MARKER32 = 0x1337C0DE
# Return-address registers across link-register ABIs, checked as IP-control sources.
# Fallback list, used when the capture does not say which ISA it came from.
_RA_REGS = ("lr", "x30", "r31", "ra")

# Per-ISA return-address register, named the way that ISA's gdbstub layout names it. A single
# shared list cannot be right: r14 is the LINK register on s390 and ARM but an ordinary
# callee-saved register on PowerPC and MIPS, so guessing globally would attribute
# instruction-pointer control to a register that merely happens to hold cyclic bytes.
# s390's absence here was why it recovered a nonsense offset (2004) and never reached L2.
_RA_BY_ARCH = {
    "aarch64": ("x30",),
    "arm": ("lr", "r14"),
    "ppc": ("lr",),
    "ppc64": ("lr",),
    "mips": ("r31",),
    "riscv": ("x1", "ra"),                 # the RISC-V layout names ra as x1
    "riscv64": ("x1", "ra"),
    "s390": ("r14",),
    "loongarch": ("r1", "ra"),
    "sparcv9": ("i7", "o7"),
    "sh": ("pr",),                         # SuperH link register
    "m68k": (),                            # m68k keeps the return address on the stack
    "x86": (),
    "x86-64": (),
}


def ra_regs(cap: dict) -> tuple:
    """Return-address registers to check for this capture's ISA."""
    arch = (cap or {}).get("arch")
    if arch in _RA_BY_ARCH:
        return _RA_BY_ARCH[arch]
    return _RA_REGS


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
    for rn in ra_regs(cap):
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
    for rn in ra_regs(cap):                          # link-register ABIs: LR/x30/$ra holds it
        if regs.get(rn) == m:
            return True
    want = _marker_bytes(m, word, endian)
    # ONLY the return-address slot the stack pointer indexes (and the word a `ret` just popped),
    # never the whole captured window. The overflow payload we sent CONTAINS the sentinel and
    # itself lands on the stack, so scanning every slot would "confirm" a WRONG offset guess whose
    # sentinel merely sits somewhere in the copied buffer -- a false instruction-pointer-control
    # claim, which the product must never make. The sentinel is only meaningful at the slot the
    # epilogue actually loaded into the program counter.
    words = dict(_stack_words(cap))
    for rel in (0, -word):
        w = words.get(rel)
        if w and w[:len(want)] == want:
            return True
    return False


# --------------------------------------------------------------------- L2 memory primitives
# A second canonical sentinel for the *value* half of a write-what-where.
MARKER_VALUE = 0x0B16B00B5157
# 32-bit targets truncate a 48-bit sentinel, so the value half needs a 4-byte variant too --
# otherwise a genuine write-what-where on i386/arm/mips could never confirm (the register can
# never hold a 48-bit value). Reads as "b00b5157".
MARKER_VALUE32 = 0xB00B5157


def _value_marker(word: int) -> int:
    return MARKER_VALUE if word >= 8 else MARKER_VALUE32

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


def analyze_memory_primitive(cap: dict, length: int, disasm, n: int = 4,
                             endian: str = "little", word: int = 8):
    """Classify an attacker-controlled memory access at the fault: write-what-where (address
    and stored value both controlled), controlled-write (address only), or controlled-read
    (arbitrary read address). Returns a primitive dict or None.

    The controlled address is read from the base register (not si_addr): a non-canonical
    controlled address raises #GP, for which the kernel reports si_addr as 0, so the register
    value is the reliable signal. `word`/`endian` describe the TARGET so the register bytes are
    matched in the cyclic pattern in its width and byte order (a 32-bit target's address
    register is 4 bytes, not 8)."""
    if not disasm:
        return None
    acc = parse_mem_access(disasm)
    if acc is None or not acc["base"]:
        return None
    regs = cap.get("regs") or {}
    if acc["base"] not in regs:
        return None
    addr_off = cyclic_find(_reg_window(int(regs[acc["base"]]), word, endian, n), length, n)
    if addr_off == -1:                               # dereferenced address is not attacker data
        return None
    value_off = -1
    if acc["is_write"] and acc["value"] and acc["value"] in regs:
        value_off = cyclic_find(_reg_window(int(regs[acc["value"]]), word, endian, n), length, n)
    if acc["is_write"]:
        kind = "write-what-where" if value_off != -1 else "controlled-write"
    else:
        kind = "controlled-read"
    return {"type": kind, "access": "write" if acc["is_write"] else "read",
            "addr_reg": acc["base"], "addr_offset": addr_off, "value_reg": acc["value"],
            "value_offset": (value_off if value_off != -1 else None),
            "fault_addr": cap.get("fault_addr"), "disasm": disasm}


def two_marker_input(addr_offset: int, value_offset, length: int,
                     word: int = 8, endian: str = "little") -> bytes:
    """Place the address sentinel at `addr_offset` and (for write-what-where) the value
    sentinel at `value_offset`, over cyclic filler, padded to `length`. `word`/`endian` are the
    TARGET's, so a 32-bit or big-endian target loads the bytes back as the sentinel value."""
    body = bytearray(cyclic(length))
    addr_bytes = _marker_bytes(_ip_marker(word), word, endian)
    body[addr_offset:addr_offset + word] = addr_bytes
    if value_offset is not None:
        val_bytes = _marker_bytes(_value_marker(word), word, endian)
        body[value_offset:value_offset + word] = val_bytes
    return bytes(body[:length])


def memory_primitive_confirmed(cap: dict, prim: dict, word: int = 8, endian: str = "little"):
    """After re-running with `two_marker_input`, verify we steered the dereferenced address to
    the sentinel (WHERE control) and, for a write, the stored-value register to its sentinel
    (WHAT control). Returns (addr_ok, value_ok). The address is checked on the base register
    (robust to non-canonical #GP where si_addr reads 0), falling back to si_addr. Comparisons
    are masked to the target's pointer width so a 32-bit register (which cannot hold a 48-bit
    sentinel) confirms against the 32-bit sentinel rather than always failing."""
    marker = _ip_marker(word)
    vmarker = _value_marker(word)
    mask = (1 << (word * 8)) - 1
    regs = cap.get("regs") or {}
    fault = cap.get("fault_addr")
    addr_ok = ((int(regs.get(prim.get("addr_reg"), -1)) & mask) == (marker & mask)
               or (fault is not None and (int(fault) & mask) == (marker & mask)))
    value_ok = True
    if prim.get("value_offset") is not None and prim.get("value_reg"):
        value_ok = (int(regs.get(prim["value_reg"], 0)) & mask) == (vmarker & mask)
    return addr_ok, value_ok


#: The sanitizer classes whose report describes an access OUTSIDE an object's bounds. A
#: use-after-free is deliberately not here: its distance field measures an offset INSIDE a freed
#: region, which says nothing about how far an attacker can reach.
OOB_CLASSES = frozenset({
    "heap-buffer-overflow", "stack-buffer-overflow", "dynamic-stack-buffer-overflow",
    "global-buffer-overflow", "stack-buffer-underflow",
})


def oob_access_primitive(observations: list) -> dict | None:
    """What an out-of-bounds ACCESS the sanitizer reported is worth as an exploitation primitive.

    This closes the hole the chain's PRIMITIVE link had: on a sanitizer build the process aborts
    inside the ASan runtime, so the fault-time registers belong to the reporting machinery and
    both register-based steps (instruction-pointer control, write-what-where) can say nothing.
    The stage then reported "crash reproduced but no controllable primitive found" -- technically
    true and completely empty -- and a heap out-of-bounds READ, which is what libtiff's
    `putRGBcontig8bittile` defect is, got no verdict at all. Information disclosure is a
    demonstrable effect; it just is not one a register capture can see.

    `observations` is a list of `(label, report)` pairs, `report` being a `parse_asan_report`
    result from detonating one input variant and `label` naming what was varied ("orig",
    "len+64", "byte@0x1a=0xff"). The question asked of them is the one that separates a bug from
    a primitive: does the attacker CHOOSE how far out of bounds the access goes? If the distance
    past the end moves when the input moves, the reach is attacker-controlled and the disclosure
    is parameterised rather than incidental. A label, not a length, because on a structured input
    (a TIFF, a packet) the field that sets the read length is a VALUE, not the file's size, and
    truncating such a file usually just stops it crashing.

    Returns None when the observations do not describe one out-of-bounds access class.
    """
    seen = [(lbl, r) for lbl, r in observations
            if isinstance(r, dict) and r.get("class") in OOB_CLASSES
            and r.get("access") and r.get("distance") is not None]
    if not seen:
        return None
    cls = seen[0][1]["class"]
    access = seen[0][1]["access"]
    # Mixing classes or directions means the variants provoked DIFFERENT defects, and averaging
    # them would describe a bug that does not exist. Keep only the first one's shape.
    seen = [(lbl, r) for lbl, r in seen if r["class"] == cls and r["access"] == access]
    dists = sorted({r["distance"] for _lbl, r in seen})
    pairs = [{"variant": lbl, "distance": r["distance"], "region_size": r.get("region_size"),
              "access_size": r.get("access_size")} for lbl, r in seen]
    controlled = len(dists) > 1
    prim = {
        "type": ("controlled-oob-" if controlled else "oob-") + access,
        "sanitizer_class": cls,
        "access": access,
        "access_size": seen[0][1].get("access_size"),
        "region_size": seen[0][1].get("region_size"),
        "side": seen[0][1].get("side"),
        "distance": dists[-1],
        "distance_min": dists[0],
        "distance_max": dists[-1],
        "observations": pairs,
        # Confirmed means the claim was DEMONSTRATED, not merely observed once. A distance that
        # tracks the input is a demonstration (the variants are the experiment); a single fixed
        # distance is a reproducible fault whose reach we have not shown to be ours to pick.
        "confirmed": controlled,
        "offset": None,
    }
    return prim


def oob_effect(prim: dict) -> str:
    """The demonstrable effect of an out-of-bounds access primitive, stated without inflation."""
    access, region, size = prim.get("access"), prim.get("region_size"), prim.get("access_size")
    far = prim.get("distance_max")
    where = f"{far} bytes {prim.get('side') or 'past'} a {region}-byte object" \
        if region is not None else f"{far} bytes out of bounds"
    if access == "read":
        what = (f"discloses {size} bytes of adjacent memory" if size
                else "discloses adjacent memory")
        reach = ("the distance tracks the input, so the attacker chooses how far to read"
                 if prim.get("confirmed") else
                 "the distance did not move with the input in this run")
        return f"out-of-bounds read {where}: {what} or crashes the process -- {reach}"
    reach = ("the distance tracks the input, so the attacker chooses where to write"
             if prim.get("confirmed") else
             "the distance did not move with the input in this run")
    return f"out-of-bounds write {where}: corrupts adjacent memory -- {reach}"


#: LIFETIME defects: the object is dead, and the question is no longer "how far past the end".
#: Split in two because the two halves are answerable by different evidence -- a USE-side defect
#: has an access to describe (direction, width, where in the dead object it landed), a FREE-side
#: defect has no access at all and is about the allocator's own bookkeeping.
UAF_CLASSES = frozenset({
    "heap-use-after-free", "use-after-poison", "stack-use-after-return",
    "stack-use-after-scope",
})
FREE_CLASSES = frozenset({"double-free", "bad-free", "alloc-dealloc-mismatch"})
LIFETIME_CLASSES = UAF_CLASSES | FREE_CLASSES


def lifetime_primitive(observations: list) -> dict | None:
    """What a use-after-free or a double free is worth as an exploitation primitive.

    The out-of-bounds verdict asks "does the attacker choose how FAR past the end the access
    goes". That question has no meaning here: a use-after-free's distance is an offset INSIDE a
    freed region, and a double free has no access to measure at all. So this link said nothing
    about either class -- `poc_primitive` reported "crash reproduced but no instruction-pointer /
    memory primitive found" for every lifetime defect on every sanitizer build, which is the
    same empty verdict an out-of-bounds read used to get.

    Two different questions make a lifetime defect exploitable, and the report answers both:

      * **which part of the dead object is touched** -- the offset inside the freed chunk. If it
        tracks the input, the attacker picks WHICH FIELD of whatever reclaims the chunk is read
        or written: a function pointer, a length, a reference count.
      * **how big the dead chunk is** -- the region size. If that tracks the input, the attacker
        picks the SIZE CLASS the dangling pointer lands in, which is the grooming step every
        use-after-free exploit and every tcache-dup double free needs: you choose the size so
        that an allocation you control reclaims the chunk.

    Either one moving is a demonstration that the defect is PARAMETERISED rather than incidental,
    and that is what `confirmed` means here. What it does NOT mean is that reuse was shown:
    ASan quarantines a freed chunk precisely so the use is caught instead of succeeding, so no
    reclaim happens under the build that produces this evidence. `lifetime_effect` says so.

    `observations` is the same `(label, report)` list the out-of-bounds verdict takes.
    Returns None when the observations do not describe one lifetime defect class.
    """
    seen = [(lbl, r) for lbl, r in observations
            if isinstance(r, dict) and r.get("class") in LIFETIME_CLASSES
            # TSan uses ASan's class name for its own lifetime report and provides none of the
            # evidence this verdict reads (no offset inside the chunk, no chunk size). It is the
            # race verdict's business; see `race_primitive`.
            and r.get("sanitizer") != TSAN]
    if not seen:
        return None
    cls = seen[0][1]["class"]
    access = seen[0][1].get("access")
    # Mixing classes or directions means the variants provoked DIFFERENT defects, and averaging
    # them would describe a bug that does not exist -- the same rule the out-of-bounds verdict
    # follows, and for the same reason.
    seen = [(lbl, r) for lbl, r in seen
            if r["class"] == cls and r.get("access") == access]
    if cls in UAF_CLASSES and not access:
        return None                                      # a use with no access is not evidence
    offsets = sorted({r["distance"] for _l, r in seen
                      if r.get("distance") is not None and r.get("side") == "inside"})
    sizes = sorted({r["region_size"] for _l, r in seen if r.get("region_size") is not None})
    offset_controlled = len(offsets) > 1
    size_controlled = len(sizes) > 1
    confirmed = offset_controlled or size_controlled
    kind = f"uaf-{access}" if cls in UAF_CLASSES else cls
    first = seen[0][1]
    return {
        "type": ("controlled-" if confirmed else "") + kind,
        "sanitizer_class": cls,
        "lifetime": True,
        "access": access,
        "access_size": first.get("access_size"),
        "region_size": sizes[-1] if sizes else first.get("region_size"),
        "region_size_min": sizes[0] if sizes else None,
        "region_size_max": sizes[-1] if sizes else None,
        "region_offset": offsets[-1] if offsets else first.get("distance"),
        "region_offset_min": offsets[0] if offsets else None,
        "region_offset_max": offsets[-1] if offsets else None,
        "offset_controlled": offset_controlled,
        "size_controlled": size_controlled,
        # The three places a lifetime defect lives. A report that names only the use tells the
        # reader the one thing the stack trace already showed them.
        "used_at": first.get("source"),
        "freed_at": first.get("freed_at"),
        "allocated_at": first.get("allocated_at"),
        "observations": [{"variant": lbl, "region_offset": r.get("distance"),
                          "region_size": r.get("region_size")} for lbl, r in seen],
        "confirmed": confirmed,
        "offset": None,                                  # not an INPUT offset; see region_offset
    }


#: What the experiment showed about control, stated as what it is and not as more than it is.
def _lifetime_control(prim: dict) -> str:
    if prim.get("offset_controlled") and prim.get("size_controlled"):
        return ("both the offset inside the chunk and the chunk size track the input, so the "
                "attacker chooses the size class that reclaims it AND which field is touched")
    if prim.get("offset_controlled"):
        return (f"the offset inside the chunk tracks the input "
                f"({prim.get('region_offset_min')}..{prim.get('region_offset_max')}), so the "
                f"attacker chooses which field of the reclaiming object is touched")
    if prim.get("size_controlled"):
        return (f"the chunk SIZE tracks the input "
                f"({prim.get('region_size_min')}..{prim.get('region_size_max')} bytes), so the "
                f"attacker chooses which size class the dangling pointer lands in -- the "
                f"grooming step this class of defect needs")
    return "neither the offset nor the chunk size moved with the input in this run"


#: The quarantine is why this evidence exists AND why it stops where it does. Said in the effect
#: text rather than left for the reader to know, because "controlled use-after-free write" reads
#: like a completed overwrite if nobody says that nothing reclaimed the chunk.
_QUARANTINE = ("ASan holds the freed chunk in quarantine, so nothing reclaimed it here: what is "
               "shown is that the defect is attacker-parameterised, not a completed overwrite")


def lifetime_effect(prim: dict) -> str:
    """The demonstrable effect of a lifetime defect, stated without inflation."""
    cls = prim.get("sanitizer_class")
    size, off = prim.get("region_size"), prim.get("region_offset")
    where = (f"at offset {off} inside a {size}-byte freed chunk"
             if size is not None and off is not None else "inside a freed chunk")
    sites = [f"{k} {prim[v]}" for k, v in (("used at", "used_at"), ("freed at", "freed_at"),
                                           ("allocated at", "allocated_at")) if prim.get(v)]
    trail = (" [" + ", ".join(sites) + "]") if sites else ""
    if cls in UAF_CLASSES:
        width = f"{prim.get('access_size')} bytes" if prim.get("access_size") else "memory"
        if prim.get("access") == "write":
            what = (f"use-after-free WRITE of {width} {where}: the write lands in memory the "
                    f"allocator has released, corrupting whatever object reclaims the chunk")
        else:
            what = (f"use-after-free READ of {width} {where}: returns whatever now occupies "
                    f"released memory -- a disclosure of the heap's current contents")
    elif cls == "alloc-dealloc-mismatch":
        what = (f"the {size}-byte chunk is released through the wrong deallocator: the allocator "
                f"applies bookkeeping for a different kind of object")
    elif cls == "bad-free":
        what = ("an address the allocator never handed out is freed: the allocator applies its "
                "bookkeeping to memory it does not own")
    else:
        what = (f"the same {size}-byte chunk is freed twice: the second free operates on the "
                f"allocator's own free-list entry for a chunk it has already released")
    return f"{what} -- {_lifetime_control(prim)}. {_QUARANTINE}{trail}"


#: The marker the reclaim experiment writes into the allocation that takes the dead chunk. ALL
#: DIGITS on purpose: a menu target that case-folds stored text ("funkify", toupper) mangles
#: letters, and `identify_heap_ops` learned the same lesson probing for the view option.
RECLAIM_MARKER = b"4718295036471829"


def reclaim_verdict(stale_view: bytes, control_view: bytes, *, marker: bytes = RECLAIM_MARKER,
                    size: int | None = None) -> dict | None:
    """Did the attacker's own allocation take the freed chunk, and did the program then read it?

    This is the question the lifetime verdict deliberately does NOT answer. `lifetime_primitive`
    works from a sanitizer report, and ASan holds a freed chunk in QUARANTINE -- that is how the
    use is caught at all -- so under the build that produces that evidence nothing can ever
    reclaim the chunk. The reclaim half therefore cannot be shown there, and was documented as
    the open end of chain link 5.

    It can be shown without a sanitizer, through the target's own output. Drive
    `add(victim); add(guard); free(victim); add(attacker, same size class, MARKER); view(victim)`
    and the question becomes one bit: does the view of the FREED entry print the marker the
    LATER allocation carried? If it does, the attacker's bytes occupy the chunk the stale pointer
    addresses and the program read them through it -- reclaim, controlled contents, and a use,
    each observed rather than modelled.

    `control_view` is the same sequence with the attacker's allocation in a DIFFERENT size class,
    so no reclaim is possible. It exists because the oracle has an obvious failure mode: a target
    that echoes recent input out of a shared buffer would print the marker whatever the allocator
    did. If the control prints it too, the oracle is unsound on this target and the result is
    INCONCLUSIVE -- which is reported, not quietly dropped and not counted as a demonstration.

    Returns None when the marker never came back.
    """
    hit = marker in (stale_view or b"")
    control = marker in (control_view or b"")
    if not hit:
        return None
    confirmed = not control
    return {
        "type": "controlled-reclaim" if confirmed else "reclaim-inconclusive",
        "lifetime": True,
        "reclaim": True,
        "confirmed": confirmed,
        "size": size,
        "marker": marker.decode("latin-1"),
        "control_echoed": control,
        "offset": None,
    }


def reclaim_verdict_traced(observation: dict, *, marker: bytes = RECLAIM_MARKER) -> dict | None:
    """The same question, answered by READING THE CHUNK instead of by the program's output.

    The output route above needs a `view` option that prints a stored entry, and most targets
    have none -- a service, a parser, a library harness. For those the only reclaim evidence was
    the tracer's "the chunk came back", which says nothing about whose bytes are in it.

    The ptrace tracer can read the tracee's memory, so it samples the chunk TWICE: once when it is
    freed (the marker must not already be there) and again after a later allocation is handed the
    same address. Marker absent before, present after, is a stricter control than the output route
    can offer -- a program that echoes recent input cannot fool a read of the chunk itself.

    `observation` is a `reclaim-controlled` event from the tracer. Returns None when the marker
    was already in the chunk before the free, because then it proves nothing about who put it
    there.
    """
    if not observation:
        return None
    if observation.get("marker_before_free"):
        return None
    use = observation.get("use") or None
    eff = observation.get("effect") or None
    kind = (eff or {}).get("kind")
    return {
        "type": ("controlled-reclaim-exec" if observation.get("exec") else
                 "controlled-reclaim-hijack" if kind == "control-flow-hijack" else
                 "controlled-reclaim-deref" if kind == "dereference" else
                 "controlled-reclaim-used" if use else "controlled-reclaim"),
        # WHAT the program did with the value it read. The three earlier facts are states of
        # memory and an access; this is a consequence, and it comes from where the process
        # FAULTED -- the pc became the attacker's bytes (it called through them) or the faulting
        # address did (it dereferenced them). Never inferred from the signal alone.
        "effect_kind": kind,
        "effect_pc": (eff or {}).get("pc"),
        "effect_fault_addr": (eff or {}).get("fault_addr"),
        "effect_signal": (eff or {}).get("signal"),
        # The register that carried the attacker's bytes into the control transfer, when the
        # hijack showed itself that way rather than as a pc.
        "effect_via": (eff or {}).get("via"),
        # CODE EXECUTION: the hijack was aimed at a function the analysis chose, and the program
        # arrived there. The end of the chain, and the only claim here that is about an effect
        # rather than about a state of memory or a transfer.
        "executed": bool(observation.get("exec")),
        "exec_function": (observation.get("exec") or {}).get("function"),
        "exec_addr": (observation.get("exec") or {}).get("addr"),
        "exec_aslr": (observation.get("exec") or {}).get("aslr"),
        "lifetime": True,
        "reclaim": True,
        "confirmed": True,
        "oracle": "traced-memory",
        # The READING half: the program touched the reclaimed chunk from its own code, at this
        # pc, after the attacker's bytes were in it. Without this the verdict shows a state of
        # memory; with it, a use.
        "use_pc": (use or {}).get("pc"),
        "used": bool(use),
        "size": observation.get("size"),
        "addr": observation.get("addr"),
        "chunk_offset": observation.get("offset"),
        "marker": marker.decode("latin-1"),
        "control_echoed": False,
        "offset": None,
    }


def reclaim_effect(prim: dict) -> str:
    """What a demonstrated reclaim is worth, stated without inflation."""
    size = f"{prim.get('size'):#x}-byte " if prim.get("size") else ""
    if not prim.get("confirmed"):
        return ("the marker came back from the view of a freed entry AND from the control run "
                "where no reclaim was possible, so this target echoes recent input and the "
                "experiment cannot distinguish a reclaim from an echo -- reported as "
                "inconclusive rather than as a demonstration")
    if prim.get("oracle") == "traced-memory":
        at = prim.get("chunk_offset")
        head = (f"use-after-free with a DEMONSTRATED reclaim, read out of the process's own "
                f"memory: a later allocation took the freed {size}chunk at {prim.get('addr')} "
                f"and the attacker's bytes are in it"
                + (f" at offset {at}" if at is not None else "")
                + ". The chunk was sampled before the free as well -- the marker was not there "
                "-- so the bytes arrived with the reclaiming allocation.")
        if prim.get("executed"):
            return (head + f" AND THE PROGRAM EXECUTED CODE OF THE ANALYSIS'S CHOOSING: with the "
                    f"sentinel replaced by the address of `{prim.get('exec_function')}` "
                    f"({prim.get('exec_addr')}) in bytes already shown to be attacker-chosen, "
                    f"the program called through the dead object and ARRIVED at that function "
                    f"-- observed at a breakpoint on it, not inferred from the absence of a "
                    f"crash. That is code execution. Two limits travel with it: the function is "
                    f"one the binary already contains (a redirect, not injected code), and the "
                    f"address is absolute, which is knowable here only because this tracer "
                    f"disables ASLR ({prim.get('exec_aslr')}) -- against a live PIE target the "
                    f"same step needs a leak, which is a different capability")
        if prim.get("effect_kind") == "control-flow-hijack":
            how = (f"it executed an indirect call/jump through `{prim['effect_via']}`, which "
                   f"held the attacker's bytes, and faulted at {prim.get('effect_pc')}"
                   if prim.get("effect_via") else
                   f"the instruction pointer became the attacker's own bytes "
                   f"({prim.get('effect_pc')})")
            return (head + f" AND THE PROGRAM CALLED THROUGH THEM: it read the chunk at pc "
                    f"{prim.get('use_pc')} and then {how} -- a DEMONSTRATED control-flow "
                    f"hijack, because the value it read was a function pointer and it called it. "
                    f"What is still NOT shown is code execution: eight printable bytes make a "
                    f"NON-CANONICAL address, so the transfer faults immediately here, and "
                    f"turning it into a chosen target is the exploit stage's claim to make")
        if prim.get("effect_kind") == "dereference":
            return (head + f" AND THE PROGRAM DEREFERENCED THEM: it read the chunk at pc "
                    f"{prim.get('use_pc')} and then touched the address those bytes spell "
                    f"({prim.get('effect_fault_addr')}), so the attacker chooses an address the "
                    f"program reads or writes through. What is NOT shown is which of the two it "
                    f"would have been with a MAPPED address, nor what it would do there")
        if prim.get("used"):
            return (head + f" AND THE PROGRAM THEN READ THEM: its own code touched the chunk at "
                    f"pc {prim.get('use_pc')} after the reclaim, through a pointer it should "
                    f"have stopped using -- so the attacker's bytes reached a consumer, not just "
                    f"a dead object. It did not fault afterwards, so what the program DOES with "
                    f"the value is still not shown: a function pointer among those bytes would "
                    f"be a hijack, and that is the exploit stage's claim to make")
        return (head + " This target has no output path to read the stale pointer back through, "
                "and no operation in the driven surface touched the chunk after the reclaim, so "
                "what is NOT shown is heavier here than on the output route: not only what the "
                "program does with those bytes, but whether it reads them at all")
    return (f"use-after-free with a DEMONSTRATED reclaim: a later allocation of the same "
            f"{size}size class took the freed chunk, and reading the stale entry returned the "
            f"bytes that allocation carried -- so the attacker chooses the contents of an object "
            f"the program still believes it owns. The control run, whose allocation was in a "
            f"different size class, did not return them. What is NOT shown is what the program "
            f"then does with those bytes: a function pointer among them would be a hijack, and "
            f"that is the exploit stage's claim to make, not this one's")


#: Classes whose report states a MAGNITUDE rather than an access: what the magnitude means, the
#: effect kind it belongs to, and whether the sanitizer OBSERVED the consequence or prevented it.
#:
#: `status` is the honest half. A refused allocation really was requested and a leak really did
#: leak, so those effects are DEMONSTRATED. A negative size handed to `memcpy` was intercepted
#: before the copy, and an out-of-bounds index is undefined rather than executed, so for those the
#: effect is POTENTIAL with its magnitude recorded -- the consequence is an inference about a build
#: without the sanitizer, and an inference is not a demonstration.
QUANTITY_CLASSES = {
    "allocation-size-too-big": ("dos", "demonstrated",
                                "the program asks its allocator for a region this big"),
    "out-of-memory": ("dos", "demonstrated", "the program allocates this much"),
    "memory-leak": ("dos", "demonstrated", "the program leaks this much and never frees it"),
    "negative-size-param": ("memory-corruption", "potential",
                            "a negative length reaches a memory routine, which without the "
                            "sanitizer is an enormous unsigned one"),
    "array-index-out-of-bounds": ("memory-corruption", "potential",
                                  "the program indexes this far outside the array"),
    "bad-shift": ("dos", "potential", "the program shifts by this much"),
}


def quantity_primitive(observations: list) -> dict | None:
    """What a defect whose report states a QUANTITY is worth, and whether the quantity is ours.

    Neither of the other two verdicts applies to these classes. There is no distance past the end
    of an object (nothing went out of bounds) and no offset inside a dead one (nothing died), so
    `oob_access_primitive` and `lifetime_primitive` both return None and the stage fell through to
    "crash reproduced but no instruction-pointer / memory primitive found" -- which for a 35 TB
    allocation request is not a near-miss but an answer to a question nobody asked.

    What the report does state is a magnitude: the size requested, the bytes leaked, the index
    used, the shift applied. The experiment is the one the other two verdicts already run -- vary
    the input, see whether the number follows -- and a number that follows the input is a defect
    the attacker parameterises rather than one this input happened to reach.

    This verdict CANNOT reach L2 (`max_level` 1), whatever the experiment shows. L2 means a
    confirmed exploitation primitive; an attacker-chosen allocation size is an availability
    defect, and calling a controlled denial of service an exploitation primitive would inflate
    the one number in a report that is supposed to resist inflation.
    """
    seen = [(lbl, r) for lbl, r in observations
            if isinstance(r, dict) and r.get("class") in QUANTITY_CLASSES
            and r.get("quantity") is not None]
    if not seen:
        return None
    cls = seen[0][1]["class"]
    seen = [(lbl, r) for lbl, r in seen if r["class"] == cls]
    kind, status, meaning = QUANTITY_CLASSES[cls]
    values = sorted({r["quantity"] for _l, r in seen})
    first = seen[0][1]
    controlled = len(values) > 1
    return {
        "type": ("controlled-" if controlled else "") + cls,
        "sanitizer_class": cls,
        "quantity": True,
        "effect_kind": kind,
        "effect_status": status,
        "meaning": meaning,
        "quantity_name": first.get("quantity_name") or "value",
        "quantity_min": values[0],
        "quantity_max": values[-1],
        "quantity_limit": first.get("quantity_limit"),
        "quantity_limit_name": first.get("quantity_limit_name") or "limit",
        # The class the SANITIZER named, which is more specific than any signal-derived one: a
        # SIGABRT from a refused allocation resolves to CWE-787 (out-of-bounds write) from the
        # signal alone, and the report says CWE-789 (uncontrolled allocation size).
        "cwe": first.get("cwe"),
        "observations": [{"variant": lbl, "quantity": r.get("quantity")} for lbl, r in seen],
        "confirmed": controlled,
        # The ladder stops at L1 for this class of claim. See the docstring.
        "max_level": 1,
        "offset": None,
    }


def quantity_effect(prim: dict) -> str:
    """The effect of a quantity-shaped defect, with the magnitude and nothing more."""
    name = prim.get("quantity_name")
    lo, hi = prim.get("quantity_min"), prim.get("quantity_max")
    span = f"{name} {lo}" if lo == hi else f"{name} {lo}..{hi}"
    lim = (f" against a {prim.get('quantity_limit_name')} of {prim.get('quantity_limit')}"
           if prim.get("quantity_limit") is not None else "")
    reach = ("the number tracks the input, so the attacker chooses it"
             if prim.get("confirmed") else
             "the number did not move with the input in this run, so it is not shown to be the "
             "attacker's to pick")
    tail = ("" if prim.get("effect_status") == "demonstrated" else
            " The consequence itself is an inference about a build without the sanitizer, which "
            "is why it is recorded as potential rather than demonstrated.")
    return (f"{prim.get('sanitizer_class')}: {prim.get('meaning')} -- {span}{lim}. "
            f"{reach}.{tail}")


#: Classes this stage can say nothing useful about, and WHY -- so the run reports a reason instead
#: of the generic "no instruction-pointer / memory primitive found", which reads as if the right
#: question had been asked and answered.
NO_VERDICT_REASON = {
    "use-of-uninitialized-value": "an uninitialised READ is only a disclosure if the value "
                                  "reaches an output, which is `mem_oracle`'s verdict (CWE-457/"
                                  "CWE-200) and not this stage's to duplicate",
}
# The concurrency classes used to live in the table above, excused on the grounds that their
# exploitability is a timing property and this stage only varies the input. The first half was
# right and the conclusion was not: a concurrency defect has a measurable property that needs no
# input variation at all, which is how OFTEN the same input shows it. See `race_primitive`.


def no_verdict_reason(sanitizer_class: str | None) -> str | None:
    """Why this stage has nothing to say about `sanitizer_class`, or None if it should have."""
    return NO_VERDICT_REASON.get(str(sanitizer_class or ""))


#: The ThreadSanitizer classes. What they have in common is not the defect but the EVIDENCE: a
#: detector that reports what it happened to observe, so the same input reports a race on some
#: runs and not others.
RACE_CLASSES = frozenset({
    "data-race", "thread-leak", "lock-order-inversion", "destroy-of-a-locked-mutex",
    "signal-unsafe-call",
    # TSan reports a lifetime error too, under the SAME class name ASan uses. Which verdict
    # applies is decided by who reported it (`sanitizer`), not by the name: only ASan's version
    # carries an offset inside a freed chunk to reason about, and TSan's is a consequence of the
    # race rather than of the input.
    "heap-use-after-free",
})
TSAN = "ThreadSanitizer"

#: How many times the same input is detonated to measure the reproduction rate. Each one is a
#: full sandbox run, so this buys the one number the verdict is about and no more: with 8 runs a
#: 1-in-8 race is still seen, and the rate it reports (1/8) is the honest precision of 8 samples.
RACE_RUNS = 8


def race_primitive(observations: list) -> dict | None:
    """What a concurrency defect is worth, measured the only way it can be: by REPEATING.

    Every other verdict in this file varies the INPUT and watches a number move. That experiment
    says nothing about a race, whose outcome does not depend on the bytes at all -- which is why
    this stage used to decline the whole family by name. The question a race actually raises for
    whoever has to act on it is different, and it is measurable: **does the same input fault every
    time, or only sometimes, and how often?**

    That number decides what the finding is worth. A defect that reports on 1 run in 8 is real and
    needs retries; one that reports on 8 of 8 is reliable here. And a fault that reproduces on NONE
    of the repeats is the most important of the three to say out loud, because the alternative is a
    single-shot reproducer that the operator runs once, sees nothing, and concludes the tool lied
    -- the "verified L1 whose bundle did not reproduce" failure this project opens its own chain
    document with.

    `observations` is `(label, report)` for N detonations of the SAME input (not of variants).
    Returns None when no run produced a concurrency report AND none was expected.
    """
    runs = [(lbl, r if isinstance(r, dict) else {}) for lbl, r in observations]
    if not runs:
        return None
    hits = [(lbl, r) for lbl, r in runs
            if r.get("sanitizer") == TSAN and r.get("class") in RACE_CLASSES]
    if not hits:
        return None
    cls = hits[0][1]["class"]
    hits = [(lbl, r) for lbl, r in hits if r["class"] == cls]
    n, k = len(runs), len(hits)
    first = hits[0][1]
    intermittent = 0 < k < n
    # How many attempts a reproducer should make to be confident of seeing it. Three expected
    # hits, bounded so a 1-in-8 observation does not ask the operator for hundreds of runs.
    retries = min(60, max(3, int(round(3 * n / k)))) if k else 60
    return {
        "type": ("intermittent-" if intermittent else "") + cls,
        "sanitizer_class": cls,
        "race": True,
        "runs": n,
        "hits": k,
        "rate": round(k / n, 3),
        "intermittent": intermittent,
        "retries": retries,
        # A race has no single site: these are the accesses that collide, where each one is, and
        # what the object IS. Naming one frame describes half the defect, and the half it names is
        # whichever thread the detector happened to see second.
        "accesses": first.get("accesses") or [],
        "race_sites": [x for x in (first.get("race_sites") or []) if x],
        "location": first.get("location"),
        "cwe": first.get("cwe"),
        "observations": [{"variant": lbl,
                          "reported": r.get("sanitizer") == TSAN
                          and r.get("class") in RACE_CLASSES} for lbl, r in runs],
        # Confirmed means the fault was REPRODUCED, which for this class is the claim that was
        # missing. It does not mean a primitive: see max_level.
        "confirmed": k > 0,
        # A concurrency verdict is never an L2. Nothing here controls memory or execution; what is
        # measured is whether and how often the defect shows itself.
        "max_level": 1,
        "offset": None,
    }


def race_effect(prim: dict) -> str:
    """What a measured concurrency defect is worth, stated without inflation."""
    k, n = prim.get("hits"), prim.get("runs")
    where = (" at " + " / ".join(prim["race_sites"][:2])) if prim.get("race_sites") else ""
    what = (f"{' and '.join(prim.get('accesses') or ['two accesses'])} to "
            f"{prim.get('location') or 'the same location'}")
    if prim.get("intermittent"):
        how = (f"reproduced on {k} of {n} runs of the SAME input, so it is a retry away rather "
               f"than a coin that has to land: a reproducer has to loop, and the one in this "
               f"bundle makes {prim.get('retries')} attempts")
    else:
        how = (f"reproduced on all {n} runs of the same input, so it is reliable in this harness "
               f"-- which is a fact about this harness, not a guarantee about another machine, "
               f"and the bundle loops anyway")
    widened = (" " + widening_effect(prim["widening"]) + ".") if prim.get("widening") else ""
    return (f"{prim.get('sanitizer_class')}: {what}{where} -- {how}.{widened} What the race "
            f"CAUSES is not shown here: that depends on what the unsynchronised value is used "
            f"for, and this stage does not determine it")


#: How many variants the widening experiment measures, and how many runs each one gets. Both are
#: small on purpose: this is the most expensive experiment in the stage (every run is a process),
#: and the question it answers is directional -- did the rate go UP -- not a precise rate.
WIDEN_VARIANTS = 4
WIDEN_RUNS = 6
#: The chance of seeing a variant's hits under the BASELINE rate, below which the rise is called
#: real. One-sided exact binomial; 5% is the conventional line and it is stated rather than tuned.
WIDEN_ALPHA = 0.05


def binomial_tail(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p). Exact, stdlib only.

    Used to answer one question: if the defect really reports at the baseline rate, how surprising
    is this variant's count? A rate that goes from 1-in-8 to 6-of-6 is not a coincidence (p ~ 4e-6)
    and a rate that goes from 1-in-8 to 2-of-6 might easily be one (p ~ 0.2). Without this the
    verdict would be comparing two small fractions by eye and calling the bigger one control.
    """
    from math import comb
    if n <= 0 or k <= 0:
        return 1.0
    p = min(max(float(p), 0.0), 1.0)
    k = min(k, n)
    return min(1.0, sum(comb(n, i) * (p ** i) * ((1 - p) ** (n - i)) for i in range(k, n + 1)))


def widening_verdict(base_hits: int, base_runs: int, trials: list) -> dict | None:
    """Can the attacker make an intermittent defect RELIABLE by changing the input?

    `trials` is `(label, hits, runs)` per variant. This is the step that separates a race that
    exists from a race that can be used: a 1-in-8 defect is a curiosity to anyone who has to
    reproduce it, and the same defect at 6-of-6 is a tool. Widening the window is how that is
    done in practice -- a longer input to parse, a larger count to iterate -- so the experiment
    is to vary the input and measure the RATE, not just whether a single run reported.

    Returns the best widening with its exact one-sided p-value, or None when no variant's count
    is surprising under the baseline rate. Pure: the caller does the running.
    """
    if base_runs <= 0 or not trials:
        return None
    base_rate = base_hits / base_runs
    scored = []
    for label, hits, runs in trials:
        if not runs:
            continue
        rate = hits / runs
        if rate <= base_rate:
            continue
        scored.append((binomial_tail(hits, runs, base_rate), -rate, label, hits, runs))
    if not scored:
        return None
    scored.sort()
    p, negrate, label, hits, runs = scored[0]
    if p >= WIDEN_ALPHA:
        return None
    return {"variant": label, "hits": hits, "runs": runs, "rate": round(-negrate, 3),
            "p_value": float(f"{p:.3g}"), "baseline_rate": round(base_rate, 3),
            # Reliable ENOUGH to stop retrying: three expected hits at the widened rate.
            "retries": min(60, max(3, int(round(3 * runs / hits)))) if hits else 60}


def widening_effect(w: dict) -> str:
    """What a demonstrated widening is worth, with the caveat the sample size demands."""
    return (f"the window is the attacker's to WIDEN: variant `{w['variant']}` reported "
            f"{w['hits']} of {w['runs']} runs ({w['rate']}) against a baseline of "
            f"{w['baseline_rate']} -- a count that has a {w['p_value']} chance of arising at the "
            f"baseline rate, so the defect is reliable on demand rather than a retry away, and "
            f"the bundle ships THAT input. The baseline rate is itself an 8-sample estimate, so "
            f"this is a directional result and not a published p-value")
