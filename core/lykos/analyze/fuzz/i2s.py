"""Input-to-state checksum/length repair (REDQUEEN, NDSS'19) — get fuzzing PAST integrity gates.

lykos already mines a static input-to-state dictionary (`cmpdict`) and recovers comparison constants
(`extract_secrets`), so magic bytes against fixed values are handled. REDQUEEN's harder, higher-value
contribution is solving *nested checksum and length tests*: a parser that rejects any input whose
embedded checksum/length field does not match the rest keeps the fuzzer stuck at the front door — no
mutation reaching the code behind the check is ever accepted, so the bugs there are unreachable.

This module repairs those fields deterministically (no model, no instrumentation): given a mutated
input and an ACCEPT predicate (the program stopped rejecting at the integrity gate — a coverage or
output signal the caller supplies), it searches a small space of (field offset, width, endianness,
algorithm, covered range) layouts, recomputes the field, and keeps the layout that flips reject ->
accept. Once a layout is learned it is reused for every later mutation, so the fuzzer mutates the
body freely and this keeps the checksum consistent -- exactly REDQUEEN's nested-checksum handling.

Pure/deterministic. The checksum algorithms are the common ones real parsers use.
"""
from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from typing import Callable, Optional

#: checksum/length algorithms over a byte range -> the field value.
_ALGOS: dict = {
    "sum8":   lambda b: sum(b) & 0xFF,
    "sum16":  lambda b: sum(b) & 0xFFFF,
    "sum32":  lambda b: sum(b) & 0xFFFFFFFF,
    "xor8":   lambda b: _xor(b),
    "len":    lambda b: len(b),
    "crc32":  lambda b: binascii.crc32(b) & 0xFFFFFFFF,
    "adler32": lambda b: _adler(b),
}


def _xor(b: bytes) -> int:
    v = 0
    for x in b:
        v ^= x
    return v & 0xFF


def _adler(b: bytes) -> int:
    return binascii.adler32(b) & 0xFFFFFFFF


def _pack(value: int, width: int, big: bool) -> bytes:
    fmt = {1: "B", 2: "H", 4: "I"}[width]
    return struct.pack((">" if big else "<") + fmt, value & ((1 << (8 * width)) - 1))


@dataclass
class ChecksumLayout:
    """A learned integrity-field layout: `field` at [off:off+width], big/little endian, computed by
    `algo` over the body (everything except the field itself, or an explicit [body_lo:body_hi))."""
    off: int
    width: int
    big: bool
    algo: str
    body_lo: int
    body_hi: Optional[int]      # None = to end of input

    def apply(self, data: bytes) -> bytes:
        b = bytearray(data)
        hi = len(b) if self.body_hi is None else self.body_hi
        body = bytes(b[self.body_lo:self.off]) + bytes(b[self.off + self.width:hi])
        val = _ALGOS[self.algo](body)
        b[self.off:self.off + self.width] = _pack(val, self.width, self.big)
        return bytes(b)


def learn_layout(data: bytes, accept: Callable[[bytes], bool], *, widths=(1, 2, 4),
                 max_off: int = 64, deadline: Optional[float] = None,
                 verify: Optional[Callable[["ChecksumLayout"], bool]] = None) -> Optional[ChecksumLayout]:
    """Find an integrity-field layout that, when recomputed, makes `accept(repaired)` true. Tries
    each (offset, width, endianness, algorithm) with the body = the rest of the input; the common
    'field is a checksum/length of everything after it' and 'of everything except it' shapes. Returns
    the first layout that flips reject -> accept, or None. Bounded by `max_off` and, when given, a
    `deadline` (time.monotonic() value) -- each candidate may be a target execution, so the search
    is capped in wall-clock time, not just in count. `verify(layout)`, when given, must also hold for
    a layout to be returned; a candidate that is accepted but fails verification is skipped and the
    search continues (an `accept` driven by output can be fooled by an echoing target)."""
    import time as _time
    n = len(data)
    if accept(data):
        return None                                       # already accepted -> nothing to repair
    for off in range(0, min(max_off, n)):
        for width in widths:
            if off + width > n:
                continue
            for big in (False, True):
                for algo in _ALGOS:
                    for body_lo, body_hi in ((off + width, None), (0, None)):
                        if deadline is not None and _time.monotonic() > deadline:
                            return None
                        lay = ChecksumLayout(off, width, big, algo, body_lo, body_hi)
                        try:
                            if accept(lay.apply(data)) and (verify is None or verify(lay)):
                                return lay
                        except Exception:                 # noqa: BLE001
                            continue
    return None


def repair(data: bytes, layout: ChecksumLayout) -> bytes:
    """Recompute the integrity field for a (freely mutated) body using a learned layout."""
    return layout.apply(data)


def solve_integrity_gate(runner: Callable[[bytes], bytes], seed: bytes, *, pass_marker: bytes,
                         widths=(1, 2, 4), max_off: int = 64) -> "tuple[Optional[ChecksumLayout], Optional[bytes]]":
    """Convenience: learn the layout against a runner that returns the target's output. The signal is
    POSITIVE -- the gate is passed only when the output contains `pass_marker` (the code BEHIND the
    integrity check ran). A positive signal is what makes the search sound: a layout that escapes the
    checksum gate by corrupting some OTHER field (e.g. the magic) trips a different rejection and
    never shows `pass_marker`, so it is not accepted. In the fuzzer the equivalent positive signal is
    new coverage past the gate. Returns (layout, a passing input) or (None, None)."""
    def accept(d: bytes) -> bool:
        return pass_marker in (runner(d) or b"")
    lay = learn_layout(seed, accept, widths=widths, max_off=max_off)
    if lay is None:
        return None, None
    return lay, lay.apply(seed)


# ---- runtime input-to-state OFFSET LOCALIZATION (colorization) ----------------------------------
# The static dictionary plants a magic value but not WHERE it must go; a fuzzer then sweeps offsets.
# REDQUEEN localizes the offset directly via input-to-state correspondence: run a COLORIZED input
# (every window self-identifying), and when a comparison operand equals a colorized window you know
# exactly which input offset reached that comparison -> place the recovered constant there, not by a
# sweep. lykos already CAPTURES both comparison operands (extract_secrets hooks strcmp/memcmp/..),
# so this consumes those observations -- no new instrumentation.
_COLOR_TAG = 0xC0DE0000


def colorize(n: int) -> bytes:
    """A length-n colorized input: each 4-byte window at a 4-aligned offset o encodes o as
    (_COLOR_TAG | o) little-endian, so any 4+ bytes of it observed in a comparison decode back to
    their source offset. Tag bytes stay printable-ish and collision-free for offsets < 0x10000."""
    out = bytearray()
    o = 0
    while len(out) < n:
        out += struct.pack("<I", (_COLOR_TAG | (o & 0xFFFF)))
        o += 4
    return bytes(out[:n])


def decode_offset(observed: bytes) -> Optional[int]:
    """If `observed` contains a colorized dword, return the input offset it came from, else None."""
    b = bytes(observed or b"")
    for i in range(0, len(b) - 3):
        v = struct.unpack_from("<I", b, i)[0]
        if (v & 0xFFFF0000) == _COLOR_TAG:
            return (v & 0xFFFF) - i                        # subtract the position within the window
    return None


def localize(observations) -> list:
    """Given comparison observations [(probe_operand_bytes, expected_bytes), ...] captured while the
    target ran on a COLORIZED input, return [(offset, expected), ...]: for each comparison whose
    probe-side operand is a colorized window, the exact input offset the compared bytes came from and
    the value the program expected there. The fuzzer then places `expected` at `offset` -- input-to-
    state replacement, no sweep. Deterministic."""
    out = []
    seen = set()
    for probe, expected in observations:
        off = decode_offset(probe)
        if off is not None and off >= 0 and (off, bytes(expected)) not in seen:
            seen.add((off, bytes(expected)))
            out.append((off, bytes(expected)))
    return out


def localized_seeds(seed: bytes, observations) -> list:
    """Convenience: from comparison observations captured on a COLORIZED run, produce localized seed
    variants with each recovered constant placed at its decoded offset (input-to-state replacement).
    One seed per distinct placement plus one with all placements applied. The fuzzer consumes these
    the way it consumes the dispatch/gate seeds."""
    placements = localize(observations)
    out = []
    for pl in placements:
        out.append(place(seed, [pl]))
    if len(placements) > 1:
        out.append(place(seed, placements))
    return out


def place(seed: bytes, placements) -> bytes:
    """Apply input-to-state replacements [(offset, value), ...] to a seed (extending if needed)."""
    b = bytearray(seed)
    for off, val in placements:
        if off < 0:
            continue
        if off + len(val) > len(b):
            b.extend(b"\x00" * (off + len(val) - len(b)))
        b[off:off + len(val)] = val
    return bytes(b)


def _body_variant(seed: bytes, lay: "ChecksumLayout") -> Optional[bytes]:
    """The seed with one BODY byte changed (never the integrity field), so the field is now stale."""
    hi = len(seed) if lay.body_hi is None else lay.body_hi
    for i in range(hi - 1, lay.body_lo - 1, -1):
        if not (lay.off <= i < lay.off + lay.width):
            b = bytearray(seed)
            b[i] ^= 0x01
            return bytes(b)
    return None


def repaired_corpus_seeds(exe: str, seeds, *, run, max_seeds: int = 8, max_off: int = 64,
                          deadline_s: Optional[float] = None):
    """Fuzz-campaign booster: for each seed that an integrity gate rejects, learn a checksum/length
    layout and return the repaired seed so the fuzzer starts EXPLORING behind the gate. `run(data)`
    returns a set of behaviour identifiers (coverage blocks, or output tokens).

    A layout is kept only when it GENERALIZES, which is what separates a real integrity field from an
    output that merely reflects the input: (1) the repaired seed shows behaviour the raw seed does
    not; (2) a DIFFERENT body, repaired with the same layout, shows that same new behaviour; and (3)
    that different body with its field left STALE does not; and (4) a different WRONG value in the
    field reproduces the seed's original reject exactly. An echoing or value-printing target
    ('got 0x12 want 0x34') fails (2)-(4); rewriting the magic instead of the checksum fails (4). Bounded by `deadline_s` over all seeds. Never raises."""
    import time as _time
    deadline = (_time.monotonic() + deadline_s) if deadline_s else None
    out = []
    try:
        for seed in list(seeds)[:max_seeds]:
            if deadline is not None and _time.monotonic() > deadline:
                break
            seed = bytes(seed)
            base = set(run(seed) or ())
            if not base:
                continue

            def accept(d: bytes, _base=base) -> bool:
                return bool(set(run(d) or ()) - _base)   # reached behaviour the raw seed did not

            def verify(lay, _seed=seed, _base=base) -> bool:
                var = _body_variant(_seed, lay)
                if var is None:
                    return False
                new = set(run(lay.apply(_seed)) or ()) - _base
                new &= set(run(lay.apply(var)) or ())       # (2) generalizes to another body
                new -= set(run(var) or ())                  # (3) the stale-field variant misses it
                if not new:
                    return False
                # (4) the field IS the gate: a different WRONG value in it reproduces the seed's own
                # reject exactly. Rejects layouts that rewrite gate-earlier bytes (corrupting the
                # magic trades BADSUM for BADMAGIC -- new, but backwards) and value-rendering output.
                rep = bytearray(lay.apply(_seed))
                for i in range(lay.off, lay.off + lay.width):
                    rep[i] ^= 0x5A
                return set(run(bytes(rep)) or ()) == _base

            lay = learn_layout(seed, accept, max_off=max_off, deadline=deadline, verify=verify)
            if lay is not None:
                rep = lay.apply(seed)
                if rep != seed:
                    out.append(rep)
    except Exception:                                        # noqa: BLE001
        return out
    return out
    return out
