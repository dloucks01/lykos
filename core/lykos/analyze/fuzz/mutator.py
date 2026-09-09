"""Black-box mutational input generator (deterministic, seeded RNG).

Havoc-style mutations over a seed/corpus with a dictionary mined from the target's strings.
No coverage guidance (that needs instrumentation / AFL++ qemu-mode, a later step); this is
the portable, zero-dependency first cut that drives the sandbox executor.
"""
from __future__ import annotations

import struct

_INTERESTING8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
_INTERESTING16 = [0, 1, 128, 255, 256, 512, 1000, 4096, 32767, 65535]
_INTERESTING32 = [0, 1, 65535, 65536, 100000, 0x7FFFFFFF, 0xFFFFFFFF]
_MAX_LEN = 8192


class Mutator:
    def __init__(self, rng, dictionary=None):
        self.rng = rng
        self.dict = [d for d in (dictionary or []) if d]

    def mutate(self, data: bytes, corpus) -> bytes:
        b = bytearray(data) if data else bytearray(b"A")
        for _ in range(self.rng.randint(1, 8)):
            self._op(b, corpus)
            if len(b) > _MAX_LEN:
                del b[_MAX_LEN:]
        return bytes(b)

    def _op(self, b: bytearray, corpus):
        r = self.rng.random()
        n = len(b)
        if r < 0.20:                                   # bit flip
            i = self.rng.randrange(n)
            b[i] ^= 1 << self.rng.randrange(8)
        elif r < 0.38:                                 # set random byte
            b[self.rng.randrange(n)] = self.rng.randrange(256)
        elif r < 0.50:                                 # interesting byte
            b[self.rng.randrange(n)] = self.rng.choice(_INTERESTING8)
        elif r < 0.62:                                 # arithmetic +/-
            i = self.rng.randrange(n)
            b[i] = (b[i] + self.rng.randint(-35, 35)) & 0xFF
        elif r < 0.72:                                 # interesting 16/32 overwrite
            self._overwrite_int(b)
        elif r < 0.82 and self.dict:                   # insert dictionary token
            tok = self.rng.choice(self.dict)
            pos = self.rng.randrange(n + 1)
            b[pos:pos] = tok
        elif r < 0.88:                                 # duplicate a chunk
            i = self.rng.randrange(n)
            ln = self.rng.randint(1, min(64, n))
            b[i:i] = bytes(b[i:i + ln])
        elif r < 0.94 and n > 1:                       # truncate
            cut = self.rng.randrange(1, n)
            del b[cut:]
        else:                                          # splice with another corpus entry
            other = self.rng.choice(corpus) if corpus else b""
            if other:
                cut1 = self.rng.randrange(n + 1)
                cut2 = self.rng.randrange(len(other) + 1)
                spliced = bytes(b[:cut1]) + bytes(other[cut2:])
                b[:] = bytearray(spliced or b"A")

    def _overwrite_int(self, b: bytearray):
        n = len(b)
        choice = self.rng.random()
        if choice < 0.5 and n >= 2:
            v = self.rng.choice(_INTERESTING16)
            i = self.rng.randrange(n - 1)
            b[i:i + 2] = struct.pack("<H", v & 0xFFFF)
        elif n >= 4:
            v = self.rng.choice(_INTERESTING32)
            i = self.rng.randrange(n - 3)
            b[i:i + 4] = struct.pack("<I", v & 0xFFFFFFFF)
