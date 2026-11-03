"""Derive a message grammar from a parser's own stream reads -- capability #4 (structure-aware input).

Blind bytes bounce off a parser's length/magic/sequence guards and never reach the deep state where
the bug lives (the ClearCodec OOB write needed a valid ClearCodec bitstream: header + a residual run
with an escalated run-length). The parser itself is the grammar: the ORDER and WIDTH of its
`Stream_Read_*` calls define the wire layout. This module reads that sequence out of the source and
emits a structurally-valid message, with per-field overrides so a detector/solver can drive one
field to a trigger value (e.g. a count that overflows an allocation) while the rest of the message
stays well-formed enough to reach the sink.

Pure string/byte work -- no build, no execution -- so it is deterministic and unit-testable. The
field model is deliberately small (the WinPR stream idiom used across FreeRDP and similar C
protocol/codec parsers); it is a reach aid, not a full protocol spec.
"""
from __future__ import annotations

import re
import struct

#: `Stream_Read_UINT<W>(s, var)` and `Stream_Read_INT<W>` -> a fixed-width little-endian field. The
#: destination may be a struct member (`pdu.bitmapDataLength`, `hdr->len`), so the whole dotted/arrow
#: name is captured -- otherwise `pdu.surfaceId` and `pdu.bitmapDataLength` both collapse to `pdu`,
#: making distinct fields indistinguishable and a per-field override impossible.
_READ_INT = re.compile(r"\bStream_Read_U?INT(8|16|32|64)\s*\(\s*\w+\s*,\s*([A-Za-z_][\w.\->]*)")
#: `Stream_Read(s, dst, len)` -> a variable blob whose length is the 3rd argument (a prior field).
_READ_BLOB = re.compile(r"\bStream_Read\s*\(\s*\w+\s*,\s*[^,]+,\s*([^)]+)\)")
#: `Stream_Seek_UINT<W>(s)` / `Stream_Seek(s, n)` -> skipped (reserved/ignored) bytes.
_SEEK_W = re.compile(r"\bStream_Seek_U?INT(8|16|32|64)\s*\(")
_SEEK_N = re.compile(r"\bStream_Seek\s*\(\s*\w+\s*,\s*([^)]+)\)")
_NUM = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+)$")


class Field:
    """One wire element: a fixed-width int (`width` in bytes, `name` the variable it fills), a
    skipped run (`kind='skip'`), or a variable blob (`kind='blob'`, `length_var` the field that
    sizes it)."""
    __slots__ = ("kind", "width", "name", "length_var")

    def __init__(self, kind, width=0, name=None, length_var=None):
        self.kind = kind; self.width = width; self.name = name; self.length_var = length_var

    def __repr__(self):
        return f"Field({self.kind},w={self.width},name={self.name},len={self.length_var})"

    def __eq__(self, o):
        return (isinstance(o, Field) and self.kind == o.kind and self.width == o.width
                and self.name == o.name and self.length_var == o.length_var)


def _blob_field(lv: str) -> Field:
    lv = lv.strip()
    return Field("blob", name=None, length_var=(None if _NUM.match(lv) else lv),
                 width=(int(lv, 0) if _NUM.match(lv) else 0))


def extract_fields(body: str, *, limit: int = 64) -> list:
    """The ordered wire fields a parser body reads, by scanning its stream reads in SOURCE ORDER
    (every read, even several on one line). A loop is NOT unrolled -- the fields inside it appear
    once; `generate` fills a single iteration, which is enough to reach most sinks and the guard
    checks before them. `Stream_Read` (blob) is matched after excluding the `Stream_Read_UINT`
    forms so the two never collide."""
    hits = []                                            # (pos, Field)
    for m in _READ_INT.finditer(body):
        hits.append((m.start(), Field("int", int(m.group(1)) // 8, name=m.group(2))))
    for m in _SEEK_W.finditer(body):
        hits.append((m.start(), Field("skip", int(m.group(1)) // 8)))
    for m in _SEEK_N.finditer(body):
        n = m.group(1).strip()
        hits.append((m.start(), Field("skip", int(n) if _NUM.match(n) else 4)))
    for m in _READ_BLOB.finditer(body):
        # skip the `Stream_Read_UINT*`/`Stream_Read_INT*` forms (handled above): a real blob read is
        # `Stream_Read(` not `Stream_Read_`.
        if body[m.start():m.start() + 12].startswith("Stream_Read_"):
            continue
        hits.append((m.start(), _blob_field(m.group(1))))
    hits.sort(key=lambda t: t[0])
    return [f for _p, f in hits[:limit]]


def generate(fields: list, overrides: "dict | None" = None, *, blob_len: int = 4) -> bytes:
    """A structurally-valid message for `fields`. Integer fields default to 0 and are little-endian;
    `overrides` sets a named field to a chosen value (the trigger). A blob's length comes from the
    overridden value of its `length_var` when present, else `blob_len`, so a length field and its
    blob stay consistent. Every width is honored, so the parser's `CheckAndLogRequiredLength` and
    field reads all succeed up to the point a trigger value diverts it."""
    overrides = overrides or {}
    out = bytearray()
    for f in fields:
        if f.kind == "int":
            val = int(overrides.get(f.name, 0)) & ((1 << (f.width * 8)) - 1)
            out += val.to_bytes(f.width, "little")
        elif f.kind == "skip":
            out += b"\x00" * f.width
        elif f.kind == "blob":
            n = f.width if f.width else int(overrides.get(f.length_var, blob_len)) if f.length_var else blob_len
            out += (b"A" * max(0, int(n)))
    return bytes(out)


def overflow_values(expr_vars: list, width_bits: int, factor: int = 1) -> "dict | None":
    """Capability #3 helper -- values that make a UINT<width_bits> product of `expr_vars` (optionally
    times a constant `factor`, e.g. bytes-per-pixel) WRAP just past the modulus, yielding a tiny
    result while each variable stays within a 16-bit wire field (so it is actually sendable). Returns
    {var: value} or None when no in-range solution exists. This is the ClearCodec class:
    (w+16)*(h+16)*4 as UINT32 wraps to a small size -> undersized buffer. Here we solve directly for
    sendable field values rather than brute-forcing a fuzzer into the wrap."""
    mod = 1 << width_bits
    factor = max(1, factor)
    if len(expr_vars) != 2:
        return None
    # For each a (<=0xFFFF), the b that lands a*b*factor NEAREST above a multiple k*mod minimises the
    # wrapped remainder. Search a range of a and k=1..4; keep the smallest wrapped remainder with
    # both fields in a 16-bit wire field. The real ClearCodec dims wrap at k=2 (a*b*4 ~ 2*2^32 + 8),
    # which a k=1-only search misses -- that is why this searches k.
    best = None                                          # (wrapped, a, b)
    lo = max(1, mod // (0xFFFF * factor))                # below this, b overflows 0xFFFF
    for a in range(lo, min(lo + 20000, 0x10000)):
        af = a * factor
        for k in (1, 2, 3, 4):
            b = round(k * mod / af)
            for bb in (b, b + 1, b - 1):
                if not (0 < bb <= 0xFFFF):
                    continue
                full = a * bb * factor
                if full <= mod:
                    continue                             # no wrap
                wrapped = full & (mod - 1)
                if best is None or wrapped < best[0]:
                    best = (wrapped, a, bb)
        if best is not None and best[0] < 0x1000:
            break                                        # tiny buffer found, good enough
    if best is None:
        return None
    return {expr_vars[0]: best[1], expr_vars[1]: best[2]}
