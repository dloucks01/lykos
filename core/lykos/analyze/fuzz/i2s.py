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
                 max_off: int = 64) -> Optional[ChecksumLayout]:
    """Find an integrity-field layout that, when recomputed, makes `accept(repaired)` true. Tries
    each (offset, width, endianness, algorithm) with the body = the rest of the input; the common
    'field is a checksum/length of everything after it' and 'of everything except it' shapes. Returns
    the first layout that flips reject -> accept, or None. Bounded: a few hundred cheap candidates."""
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
                        lay = ChecksumLayout(off, width, big, algo, body_lo, body_hi)
                        try:
                            if accept(lay.apply(data)):
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


def repaired_corpus_seeds(exe: str, seeds, *, run, max_seeds: int = 8, max_off: int = 64):
    """Fuzz-campaign booster: for each seed that an integrity gate rejects, learn a checksum/length
    layout and return the repaired seed so the fuzzer starts EXPLORING behind the gate. The past-gate
    signal is `run(data) -> reached_blocks` (a set/collection of coverage identifiers); a repair is
    kept only when it reaches blocks the raw seed did not -- a sound 'got further' signal (new
    coverage), not a guess. Best-effort and bounded; returns a list of repaired seed bytes. Never
    raises. `run` is supplied by the harness (it already measures coverage per execution)."""
    out = []
    try:
        for seed in list(seeds)[:max_seeds]:
            seed = bytes(seed)
            base = set(run(seed) or ())
            if not base:
                continue

            def accept(d: bytes, _base=base) -> bool:
                return bool(set(run(d) or ()) - _base)   # reached a block the raw seed did not

            lay = learn_layout(seed, accept, max_off=max_off)
            if lay is not None:
                rep = lay.apply(seed)
                if rep != seed:
                    out.append(rep)
    except Exception:                                        # noqa: BLE001
        return out
    return out
