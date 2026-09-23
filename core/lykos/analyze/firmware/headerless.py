"""Headerless-blob loader (doc 04.6) — identify a bare-metal firmware blob's CPU
architecture, endianness, load/base address and entry point, deterministically.

Two signals:
  1. ARM Cortex-M **reset vector table**: word0 is the initial stack pointer (points into
     SRAM), word1.. are exception-handler addresses (Thumb, i.e. odd) clustered in the flash
     region -- a strong, near-unambiguous fingerprint that also yields base + entry.
  2. **Instruction-pattern scoring**: count common function-prologue encodings for ARM / Thumb
     / MIPS / PPC across the blob and take the best-scoring architecture.

No emulator, no ML. Reports a confidence and the evidence behind each call.
"""
from __future__ import annotations

import struct
from typing import Optional

# plausible SRAM windows for the initial stack pointer (word0 of a Cortex-M vector table)
_SRAM = [(0x20000000, 0x20080000), (0x10000000, 0x10020000), (0x1FFF0000, 0x20080000)]
# common Cortex-M flash bases the reset vector may point into
_FLASH_BASES = [0x08000000, 0x00000000, 0x00200000, 0x0C000000, 0x1FFF0000]


def _in(v, lo, hi):
    return lo <= v <= hi


def detect_cortex_m(data: bytes) -> Optional[dict]:
    if len(data) < 64:
        return None
    for endc, endian in (("<", "little"), (">", "big")):
        sp = struct.unpack_from(endc + "I", data, 0)[0]
        if not any(_in(sp, lo, hi) for lo, hi in _SRAM):
            continue
        vectors = [struct.unpack_from(endc + "I", data, 4 * i)[0]
                   for i in range(1, min(16, len(data) // 4))]
        nonzero = [v for v in vectors if v]
        if len(nonzero) < 4:
            continue
        odd = [v for v in nonzero if v & 1]                 # Thumb handlers are odd
        if len(odd) < max(4, len(nonzero) * 3 // 4):
            continue
        for base in _FLASH_BASES:
            span = base, base + len(data)
            inrange = [v for v in odd if _in(v & ~1, span[0], span[1])]
            if len(inrange) >= max(4, len(odd) * 3 // 4):
                reset = vectors[0]
                conf = round(min(0.98, 0.6 + 0.03 * len(inrange)), 2)
                return {
                    "arch": "arm", "sub": "cortex-m", "bits": 32, "endianness": endian,
                    "base_addr": base, "entry": reset & ~1, "load_addr": base,
                    "confidence": conf,
                    "evidence": (f"ARM Cortex-M vector table: SP={hex(sp)}, reset={hex(reset)}, "
                                 f"{len(inrange)}/{len(nonzero)} Thumb handlers in "
                                 f"[{hex(base)}, {hex(span[1])})"),
                }
    return None


# aligned 32-bit prologue patterns (value, mask) per arch, matched on aligned words.
# ARM: push {..,lr}; mov ip,sp.  MIPS: addiu sp,sp,-x; sw ra.  PPC: stwu r1,-x(r1); mflr r0.
# AArch64: stp x29,x30,[sp,#-N]!; mov x29,sp; ret.  RISC-V: addi sp,sp,-N; ret (jalr x0,ra,0).
# The AArch64 and RISC-V patterns are near-exact (32-bit fixed encodings), so their false-positive
# rate in random data is ~2^-32 -- they never trip the "dominant, dense" gate by chance.
_PATTERNS = {
    ("arm", "little"): [(0xE92D4000, 0xFFFFC000), (0xE1A0C00D, 0xFFFFFFFF)],
    ("arm", "big"):    [(0xE92D4000, 0xFFFFC000)],
    ("mips", "little"): [(0x27BD0000, 0xFFFF0000), (0xAFBF0000, 0xFFFF0000)],
    ("mips", "big"):    [(0x27BD0000, 0xFFFF0000), (0xAFBF0000, 0xFFFF0000)],
    ("ppc", "big"):     [(0x9421FF00, 0xFFFFFF00), (0x7C0802A6, 0xFFFFFFFF)],
    ("ppc", "little"):  [(0x00FF2194, 0x00FFFFFF), (0xA602087C, 0xFFFFFFFF)],   # ppc64le byte-swapped
    ("aarch64", "little"): [(0xA9BF7BFD, 0xFFFFFFFF),                            # stp x29,x30,[sp,#-16]!
                            (0xA9800000, 0xFFE003FF),                            # stp ..,[sp,#-N]! family
                            (0x910003FD, 0xFFFFFFFF),                            # mov x29, sp
                            (0xD65F03C0, 0xFFFFFFFF)],                           # ret
    ("riscv", "little"): [(0x00010113, 0x000FFFFF),                             # addi sp, sp, imm
                          (0x00008067, 0xFFFFFFFF),                             # ret (jalr x0, ra, 0)
                          (0x00113023, 0x01FFFFFF)],                            # sd ra, N(sp) family
}
_BITS = {"aarch64": 64, "riscv": 64}                    # the rest default to 32
# Thumb: 16-bit `push {..,lr}` = 0xB5xx
_THUMB_PUSH = (0xB500, 0xFF00)
# RISC-V compressed (RVC, 16-bit) prologue/epilogue -- modern RISC-V firmware is RVC-heavy, so the
# 32-bit patterns above rarely fire. c.addi16sp (adjust sp) and `ret` (= c.jr ra, 0x8082).
_RVC = [(0x6101, 0xEF83), (0x8082, 0xFFFF)]
# arches scanned as 16-bit half-words (density is measured per half-word, not per word)
_HALFWORD = ("thumb", "riscv")


def score_arch(data: bytes) -> dict:
    """Instruction-prologue scores per (arch, endianness); higher = more likely."""
    n = len(data)
    scores: dict = {}
    for (arch, endian), pats in _PATTERNS.items():
        endc = "<" if endian == "little" else ">"
        cnt = 0
        for off in range(0, n - 3, 4):          # `n - 4` never scanned the final word
            w = struct.unpack_from(endc + "I", data, off)[0]
            for val, mask in pats:
                if (w & mask) == val:
                    cnt += 1
                    break
        scores[f"{arch}/{endian}"] = cnt
    # 16-bit little-endian scans: Thumb push, and RISC-V compressed (RVC) prologues.
    tcnt = rvc = 0
    for off in range(0, n - 1, 2):              # likewise the final halfword
        h = struct.unpack_from("<H", data, off)[0]
        if (h & _THUMB_PUSH[1]) == _THUMB_PUSH[0]:
            tcnt += 1
        for val, mask in _RVC:
            if (h & mask) == val:
                rvc += 1
                break
    scores["thumb/little"] = tcnt
    # RISC-V wins from its RVC signal when that dominates the sparse 32-bit hits
    scores["riscv/little"] = max(scores.get("riscv/little", 0), rvc)
    return scores


def analyze_blob(data: bytes) -> dict:
    """Best-effort headerless identification. Cortex-M wins outright when its vector table is
    present; otherwise the highest instruction-prologue score, if meaningfully above noise."""
    cm = detect_cortex_m(data)
    if cm:
        return {**cm, "method": "cortex-m-vector-table"}
    scores = score_arch(data)
    best = max(scores, key=scores.get) if scores else None
    best_n = scores.get(best, 0) if best else 0
    second = sorted(scores.values(), reverse=True)[1] if len(scores) > 1 else 0
    # Density has to be measured against the population the score was COLLECTED from. The
    # 32-bit patterns are counted once per word; the Thumb pattern is 16-bit and counted once
    # per halfword, so there are twice as many chances to hit it. Dividing both by the word
    # count doubled Thumb's apparent density and let pure noise through the "dominant, dense"
    # gate this function exists to enforce: 16 KB of random bytes scored 33 Thumb hits where
    # chance predicts 32.0, measured as 0.806% against words (over the 0.6% floor) where the
    # honest figure is 0.403% (under it). The blob came back as ARM/Thumb at 0.32 confidence
    # -- and a headerless verdict is load-bearing, because everything after it is addresses
    # computed from a base this guess invented.
    positions = max(1, len(data) // (2 if best and best.split("/")[0] in _HALFWORD else 4))
    density = best_n / positions
    # require a dominant, dense prologue signal -- real code has one; random data is uniform
    # noise (16-bit Thumb patterns especially are frequent by chance)
    if best and best_n >= 16 and best_n >= 2 * second + 4 and density >= 0.006:
        arch, endian = best.split("/")
        norm = "arm" if arch == "thumb" else arch
        return {
            "arch": norm, "sub": ("thumb" if arch == "thumb" else None), "bits": _BITS.get(norm, 32),
            "endianness": endian, "base_addr": None, "entry": None, "load_addr": None,
            "confidence": round(min(0.8, density * 40), 2), "method": "prologue-scoring",
            "evidence": (f"prologue scoring: {best} matched {best_n} times "
                         f"({density:.3%} of {'halfwords' if arch == 'thumb' else 'words'}); "
                         f"scores={scores}"),
        }
    return {"arch": None, "endianness": None, "base_addr": None, "entry": None,
            "confidence": 0.0, "method": "inconclusive", "evidence": f"scores={scores}"}
