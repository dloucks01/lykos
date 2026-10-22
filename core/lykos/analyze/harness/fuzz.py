"""T2 (doc 46) -- the coverage-guided fuzz loop over the single-function executor.

Given a function and seed inputs, mutate inputs, run each through `emulate.run_function`, keep the
ones that reach new basic blocks (coverage feedback), and collect the inputs that fault. This is
the bug-finding half of the binary libFuzzer: `rank` (T1) picks the function, `run_function` (T2)
drives it, this loop searches its input space. A crashing input it returns is a concrete reproducer
the existing L0->L1->L3 ladder can take over.

Deterministic by default (seeded RNG) so a run is reproducible and the conformance gate is stable.
"""
from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .emulate import HarnessResult, run_function

# T4 (doc 46): the binary's OWN comparison constants, fed back as a fuzzing dictionary. A parser
# gates on magic values, length limits and opcodes it checks the input against (`cmp eax,
# 0xcafebabe`); a blind mutator has to invent each one byte by byte and never does. Reading them
# off the function's compare/load instructions and splicing them in gets past the gate with the
# program's own knowledge of its format.
_CMP_MNEMS = ("cmp", "test", "sub", "add", "and", "or", "xor", "mov", "movz", "movs", "lea",
              "cmovz", "cmovnz")
_IMM = re.compile(r"(?<![\w\[.])0x([0-9a-fA-F]{2,16})\b")   # a bare hex immediate (not a memory ref)


def dictionary_from_ir(ir, *, limit: int = 96) -> list:
    """Byte-words from the function's own constant operands (T4). Little- AND big-endian (a length
    or opcode field is often network byte order), 4- and 8-byte. Trivial small values are left to
    byte mutation. Best-effort over the recovered disassembly text."""
    vals: set = set()
    for b in (ir or {}).get("blocks", []):
        for ins in b.get("instructions", []):
            txt = ins.get("text") or ""
            if not txt:
                continue
            if txt.split(None, 1)[0].rstrip("bwlq") not in _CMP_MNEMS:
                continue
            bare = re.sub(r"\[[^\]]*\]", " ", txt)        # drop bracketed memory operands (addresses)
            for m in _IMM.finditer(bare):
                try:
                    vals.add(int(m.group(1), 16))
                except ValueError:
                    continue
    out: list = []
    for v in sorted(vals):
        if v < 0x100:                                     # byte/short mutation already covers these
            continue
        for width in (4, 8):
            if v < (1 << (width * 8)):
                out.append(v.to_bytes(width, "little"))
                out.append(v.to_bytes(width, "big"))
    # dedupe, preserve order, cap
    seen: set = set()
    uniq = []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq[:limit]

#: "interesting" little-endian words a mutator should try -- boundaries and large magnitudes that
#: turn a benign index/length/size into an out-of-range one (the fault a parser hides).
_INTERESTING = [
    (0).to_bytes(4, "little"), (0xFFFFFFFF).to_bytes(4, "little"),
    (0x7FFFFFFF).to_bytes(4, "little"), (0x80000000).to_bytes(4, "little"),
    (0x40000000).to_bytes(4, "little"), (0x100000).to_bytes(4, "little"),
    (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"), (0x4141414141414141).to_bytes(8, "little"),
    (0xDEADBEEF).to_bytes(8, "little"),
]


@dataclass
class FuzzResult:
    execs: int = 0
    crashes: list = field(default_factory=list)       # [{"input": bytes, "result": HarnessResult}]
    corpus: list = field(default_factory=list)        # coverage-increasing inputs kept
    blocks: set = field(default_factory=set)          # cumulative coverage reached
    elapsed: float = 0.0
    note: str = ""

    @property
    def crashing_inputs(self) -> list:
        return [c["input"] for c in self.crashes]


def _mutate(rng: random.Random, data: bytes, words: list) -> bytes:
    b = bytearray(data) if data else bytearray(b"\x00")
    op = rng.randrange(6)
    if op == 0 and b:                                     # bit flip
        i = rng.randrange(len(b)); b[i] ^= (1 << rng.randrange(8))
    elif op == 1 and b:                                   # byte set
        b[i := rng.randrange(len(b))] = rng.randrange(256)
    elif op == 2:                                         # splice an interesting/dictionary word in
        w = rng.choice(words)                             # words = _INTERESTING + the function's constants (T4)
        at = rng.randrange(len(b) + 1)
        b[at:at + len(w)] = w
    elif op == 3 and len(b) > 1:                          # shrink
        at = rng.randrange(len(b)); n = rng.randrange(1, len(b) - at + 1)
        del b[at:at + n]
    elif op == 4:                                         # grow
        b[len(b):] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16)))
    else:                                                 # havoc: overwrite a run with 0xff / 0x00
        if b:
            at = rng.randrange(len(b)); n = rng.randrange(1, min(32, len(b) - at) + 1)
            b[at:at + n] = bytes([rng.choice((0x00, 0xFF, 0x41))]) * n
    return bytes(b[:0x10000])


def fuzz_function(elf_bytes: bytes, func_addr: int, seeds: Optional[list] = None, *,
                  arg_shape: str = "ptr_len", budget_execs: int = 20000,
                  budget_seconds: float = 60.0, max_crashes: int = 8,
                  dictionary: Optional[list] = None, seed: int = 1337) -> FuzzResult:
    """Coverage-guided fuzz of one function. Returns crashing inputs + the corpus it built.

    `dictionary` (T4): the function's own constant operands -- magic values, length limits, opcodes
    it compares the input against. They are spliced during mutation AND placed verbatim at offset 0
    of a seed input (the common gate position), so the campaign gets past a magic/length gate a
    blind mutator would have to invent byte by byte."""
    rng = random.Random(seed)
    fr = FuzzResult()
    corpus = [bytes(s) for s in (seeds or [b"\x00\x00\x00\x00\x00\x00\x00\x00"]) if s is not None]
    if not corpus:
        corpus = [b"\x00" * 8]
    dict_words = [bytes(w) for w in (dictionary or []) if w]
    words = _INTERESTING + dict_words
    seen_crash_sites: set = set()
    t0 = time.time()
    # seed the corpus + coverage from the initial inputs, then from each dictionary constant placed
    # at the buffer's start (where a header magic/length field sits) -- a direct gate pass to try.
    pending = list(corpus) + [w + b"\x00" * 16 for w in dict_words]
    corpus = []
    deadline = t0 + budget_seconds
    while (fr.execs < budget_execs and time.time() < deadline
           and len(fr.crashes) < max_crashes):
        data = (pending.pop() if pending
                else _mutate(rng, rng.choice(corpus) if corpus else b"\x00" * 8, words))
        r: HarnessResult = run_function(elf_bytes, func_addr, data, arg_shape=arg_shape)
        fr.execs += 1
        new = r.blocks - fr.blocks
        if new:
            fr.blocks |= r.blocks
            corpus.append(data)                           # it reached new code: keep it
        if r.crashed:
            site = (r.fault_pc, r.access)                 # dedupe by faulting instruction + kind
            if site not in seen_crash_sites:
                seen_crash_sites.add(site)
                fr.crashes.append({"input": data, "result": r})
    fr.corpus = corpus
    fr.elapsed = round(time.time() - t0, 2)
    return fr
