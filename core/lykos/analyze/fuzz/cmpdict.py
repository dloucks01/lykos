"""Static input-to-state dictionary: fuzzer tokens mined from P-Code comparison operands.

RedQueen and AFL++ CmpLog learn the magic values, tags, length/version numbers and checksums a
program tests its input against by watching comparisons AT RUNTIME, then splicing the observed
operand into the input where the bytes line up ("input-to-state correspondence"). When the
decompiler already recovered P-Code (pypcode / rz-ghidra), the SAME constants are visible
STATICALLY: every ``INT_EQUAL const:0x47464923 reg`` is a 4-byte value (`#IFG` here) that some
branch wants to see, and every ``INT_SLESS const:0x400 len`` is a size gate. Mining those
constants into the fuzzer's dictionary lets lykos's existing token mutator plant them directly, so
a magic-gated or length-gated branch is reached in the first havoc rounds instead of never.

Why this is worth a stage even though lykos ships CmpLog:
  * CmpLog needs a second *instrumented* build (source) or afl-qemu cmplog; it is unavailable for
    a stripped cross-architecture binary fuzzed black-box under plain qemu -- which is a case lykos
    explicitly supports. Static mining works from the P-Code alone, on ANY architecture.
  * Even where CmpLog runs, seeding the dictionary with the constants up front reaches the first
    comparison sooner and gives CmpLog/the havoc splicer material immediately.
  * It costs nothing at fuzz time (pure static pass over IR lykos has already paid for) and adds
    no dependency: no model, no network, deterministic.

This complements -- does not replace -- CmpLog and the concolic solver: a checksum whose expected
value is *computed* from the input (not a constant) still needs those. Constants are the cheap 80%.
"""
from __future__ import annotations

import logging
from typing import Iterable

from ... import observe

_log = logging.getLogger(__name__)

# P-Code comparison opcodes whose constant operand is a value the input is tested against. The
# unsigned/signed equality and ordering tests cover magic bytes, tags, enum/opcode dispatch and
# length/bounds gates. INT_SUB is included because a `sub reg, K` immediately feeding a
# zero/sign test (the common `cmp` lowering on several ISAs) carries K as the compared value.
_CMP_OPS = frozenset({
    "INT_EQUAL", "INT_NOTEQUAL",
    "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL",
    "INT_SUB",
})

# Tokens outside this range are noise: 0 is the ubiquitous null/empty test, +/-1 are loop and
# sentinel bumps, and a lone small byte value the byte-level mutator already covers for free.
_TRIVIAL = frozenset({0, 1, 2, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})
_MAX_TOKEN = 32           # a dictionary token longer than this is not a comparison immediate
_DEFAULT_LIMIT = 400      # keep the dictionary small enough that token insertion stays frequent


def _parse_const(tok: str):
    """(value, size_bytes) for a ``const:0xNN:SIZE`` varnode token, else None."""
    if not tok.startswith("const:"):
        return None
    parts = tok.split(":")
    if len(parts) != 3:
        return None
    try:
        return int(parts[1], 16), int(parts[2])
    except ValueError:
        return None


def _printable(b: bytes) -> bool:
    # Tab/newline/CR count as printable structure (delimiters parsers compare against).
    return all(0x20 <= c < 0x7F or c in (0x09, 0x0A, 0x0D) for c in b)


def _norm_size(size: int) -> int:
    """A varnode size as a compare width in bytes: out-of-range (0, negative, >8) reads as 8."""
    return size if 0 < size <= 8 else 8


def _encode(value: int, size: int) -> list[bytes]:
    """Byte encodings of a comparison constant, widest-useful first.

    A constant compared at width W may be matched against an input field of width W or a narrower
    field the compiler widened, so we emit the value at its own width AND at each narrower
    power-of-two width it still fits in, in BOTH byte orders (the target architecture's
    endianness is not the input's). The printable form is emitted verbatim because a 4-byte tag
    like ``GET `` reads as a string in the corpus.

    "Fits" covers BOTH widenings. Zero-extension: ``cmp eax, 0x8950`` after a movzx is a u16.
    Sign-extension: ``char c = in[0]; if (c == -2)`` compiles to movsx + ``cmp eax, 0xfffffffe``,
    and the input byte that passes it is 0xFE -- a token the zero-extension-only rule never
    emitted, so every signed-char/short gate was invisible. And the compare's OWN width is always
    emitted, power of two or not: a 3-byte varnode (packed fields, some ISAs' immediates) used to
    yield nothing at all, because only 8/4/2/1 were tried and it fits none of them.
    """
    out: list[bytes] = []
    size = _norm_size(size)
    # Interpret negatives (two's complement at the compare width) as their unsigned byte pattern:
    # `cmp al, -1` and `cmp al, 0xFF` are the same bytes and the same input match.
    uval = value & ((1 << (8 * size)) - 1)
    sval = uval - (1 << (8 * size)) if uval >> (8 * size - 1) else uval
    for w in sorted({size} | {w for w in (8, 4, 2, 1) if w <= size}, reverse=True):
        if w == size:
            v = uval
        elif not uval >> (8 * w):
            v = uval                      # zero-extended from w bytes
        elif sval < 0 and sval >= -(1 << (8 * w - 1)):
            v = sval & ((1 << (8 * w)) - 1)   # sign-extended from w bytes
        else:
            continue                      # does not fit in this narrower width without truncation
        le = v.to_bytes(w, "little")
        be = v.to_bytes(w, "big")
        for enc in (le, be):
            if enc and enc not in out:
                out.append(enc)
    return out


def cmp_tokens(pcode_ops: Iterable[str]) -> set[bytes]:
    """Comparison-constant tokens from an iterable of P-Code op strings (see module docstring).

    Each op is ``<OPCODE> <in varnode> <in varnode> ... [-> <out varnode>]`` and a varnode is
    ``const:0xNN:SIZE`` / ``reg:name:SIZE`` / ``space:0xNN:SIZE``. We pull the const operand of a
    comparison and, for INT_SUB, only when the subtrahend is a non-trivial constant.
    """
    toks: set[bytes] = set()
    for op in pcode_ops or ():
        if not op:
            continue
        left = op.split(" -> ", 1)[0]
        parts = left.split()
        if not parts or parts[0] not in _CMP_OPS:
            continue
        for operand in parts[1:]:
            cv = _parse_const(operand)
            if cv is None:
                continue
            value, size = cv
            # the SAME width normalization `_encode` uses: a size-0 varnode was masked to one
            # byte here and encoded at eight there, so the trivial filter judged another value
            uval = value & ((1 << (8 * _norm_size(size))) - 1)
            if uval in _TRIVIAL:
                continue
            for enc in _encode(value, size):
                if 1 <= len(enc) <= _MAX_TOKEN:
                    toks.add(enc)
    return toks


def _iter_func_pcode(ir) -> Iterable[str]:
    """Every P-Code op string in a hydrated function IR (blocks -> instructions -> pcode)."""
    for b in (ir or {}).get("blocks") or ():
        for i in b.get("instructions", []) or []:
            for pc in i.get("pcode", []) or []:
                yield pc


def mine_cmp_dictionary(func_irs: dict, *, is_addr=None,
                        limit: int = _DEFAULT_LIMIT) -> list[bytes]:
    """Input-to-state dictionary tokens from every function's comparison constants.

    ``func_irs`` maps function address -> hydrated IR (the same structure the detect stage builds).
    ``is_addr(value)`` -- when given -- drops a constant that falls inside the binary's own code or
    data (a pointer comparison, not an input token); pass ``program_ranges``-backed predicate to
    filter those out. Tokens are returned longest-first (a 4-byte magic is worth more to splice
    than the 1-byte fragments it also yields) and capped at ``limit``.
    """
    raw: set[bytes] = set()
    addr_dropped: set[tuple] = set()
    for ir in (func_irs or {}).values():
        ops = list(_iter_func_pcode(ir))              # one walk of the IR, not two
        # Collect the address-typed constants to drop, so an 0x401080 pointer compare does not
        # leak its bytes into the dictionary as a bogus token.
        if is_addr is not None:
            for op in ops:
                if not op:
                    continue
                p = op.split(" -> ", 1)[0].split()
                if not p or p[0] not in _CMP_OPS:
                    continue
                for operand in p[1:]:
                    cv = _parse_const(operand)
                    if cv is not None and cv[1] >= 4 and _is_addrlike(cv[0], is_addr):
                        addr_dropped.add(cv)
        raw |= cmp_tokens(ops)
    if addr_dropped:
        drop_bytes = set()
        for v, size in addr_dropped:
            # at the width it was COMPARED at -- the bytes cmp_tokens actually emitted for it
            drop_bytes.update(_encode(v, size))
        raw -= drop_bytes
    # Longest tokens first: a full magic/tag is more discriminating than a byte of it.
    ordered = sorted(raw, key=lambda t: (-len(t), not _printable(t), t))
    return ordered[:limit]


def _is_addrlike(value: int, is_addr) -> bool:
    try:
        return bool(is_addr(value))
    except Exception:
        observe.absorbed(_log, "answering no")
        return False
