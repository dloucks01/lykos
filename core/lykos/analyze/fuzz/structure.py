"""Structure-aware mutation (format-grammar fuzzing).

Byte-level havoc rarely reaches deep parser code: it breaks the magic, and it cannot
*coordinate* related fields -- e.g. set a length field large AND grow the data it sizes, the
classic length-driven overflow. This mutator parses an input against a small declared format
model (magic, integer fields, length-prefixed blobs), mutates it field-aware while keeping the
structure valid enough to pass format gates, and deliberately drives length/blob relationships
to the edges that break parsers.

The model is data (a list of field dicts), so an analyst can describe any format without code;
`builtin()` ships a couple of common ones. It plugs into the fuzz campaign with the same
`mutate(data, corpus) -> bytes` interface as the byte-level Mutator, and falls back to it when
the input does not parse.
"""
from __future__ import annotations

import struct

from .mutator import Mutator

_INT = {"u8": (1, "B"), "u16": (2, "H"), "u32": (4, "I"), "u64": (8, "Q")}
# values that break length/count fields: zero, off-by-one, and huge (overflow/overread)
_EDGE = [0, 1, 63, 64, 65, 127, 128, 255, 256, 1024, 4096, 0x7FFFFFFF, 0xFFFFFFFF]
_MAXBLOB = 8192


def _as_bytes(v):
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode("latin-1", "ignore")
    return bytes(v)


class FormatModel:
    """A format = an ordered list of field dicts. Field `type`:
      * "magic" -- fixed bytes, {"value": <bytes|str>} (kept to pass the format gate)
      * "u8"|"u16"|"u32"|"u64" -- integer, {"name", "endian":"little"|"big",
        "length_of": <blob name>} (length_of ties it to the blob it sizes)
      * "blob" -- variable data, {"name"}; the trailing blob consumes the rest.
    """
    def __init__(self, spec: list):
        self.spec = spec

    def parse(self, data: bytes):
        pos, fields = 0, []
        for f in self.spec:
            t = f["type"]
            if t == "magic":
                v = _as_bytes(f["value"])
                fields.append({"f": f, "val": data[pos:pos + len(v)]})
                pos += len(v)
            elif t in _INT:
                sz, code = _INT[t]
                end = "<" if f.get("endian", "little") == "little" else ">"
                raw = data[pos:pos + sz]
                val = struct.unpack(end + code, raw.ljust(sz, b"\0"))[0] if raw else 0
                fields.append({"f": f, "val": val})
                pos += sz
            else:                                       # blob: take the remainder
                fields.append({"f": f, "val": data[pos:]})
                pos = len(data)
        return fields

    def serialize(self, fields) -> bytes:
        out = bytearray()
        for fd in fields:
            f, t = fd["f"], fd["f"]["type"]
            if t == "magic":
                out += _as_bytes(fd["val"] if fd["val"] else f["value"])
            elif t in _INT:
                sz, code = _INT[t]
                end = "<" if f.get("endian", "little") == "little" else ">"
                out += struct.pack(end + code, int(fd["val"]) & ((1 << (sz * 8)) - 1))
            else:
                out += _as_bytes(fd["val"] or b"")
        return bytes(out)


class StructMutator:
    """Field-aware mutator with the byte Mutator's interface. Falls back to byte havoc when the
    input does not fit the model."""
    def __init__(self, rng, model: FormatModel, dictionary=None):
        self.rng = rng
        self.model = model
        self.byte = Mutator(rng, dictionary)

    def mutate(self, data: bytes, corpus=()) -> bytes:
        try:
            fields = self.model.parse(data or b"")
        except Exception:
            return self.byte.mutate(data, corpus)
        if not fields:
            return self.byte.mutate(data, corpus)
        for _ in range(self.rng.randint(1, 3)):
            self._mutate_field(fields)
        try:
            return self.model.serialize(fields)
        except Exception:
            return self.byte.mutate(data, corpus)

    def _blob_by_name(self, fields, name):
        return next((fd for fd in fields if fd["f"].get("name") == name), None)

    def _mutate_field(self, fields):
        fd = self.rng.choice(fields)
        t = fd["f"]["type"]
        if t == "magic":
            if self.rng.random() < 0.08:               # usually KEEP so the format gate passes
                fd["val"] = self.byte.mutate(fd["val"] or b"", ())
        elif t in _INT:
            fd["val"] = self.rng.choice(_EDGE)
            target = fd["f"].get("length_of")
            if target and self.rng.random() < 0.6:      # coordinate: grow the sized blob to match
                blob = self._blob_by_name(fields, target)
                if blob is not None:
                    want = min(int(fd["val"]), _MAXBLOB)
                    base = bytes(blob["val"] or b"A")
                    blob["val"] = (base * (want // max(1, len(base)) + 1))[:want] if want else base
        else:                                           # blob: byte-level havoc on the data
            fd["val"] = self.byte.mutate(fd["val"] or b"A", ())


# a few ready-made models (analyst can also pass a custom spec)
_BUILTINS = {
    # generic "magic + u32-LE length + payload" container (matches many toy/real headers)
    "lv32": [{"type": "magic", "value": "\x00"},        # placeholder magic, override via params
             {"type": "u32", "endian": "little", "name": "len", "length_of": "data"},
             {"type": "blob", "name": "data"}],
    # PNG: 8-byte signature, then the mutator drives the first chunk's length/type
    "png": [{"type": "magic", "value": b"\x89PNG\r\n\x1a\n"},
            {"type": "u32", "endian": "big", "name": "clen", "length_of": "cdata"},
            {"type": "magic", "value": "IHDR"},
            {"type": "blob", "name": "cdata"}],
}


def builtin(name: str):
    spec = _BUILTINS.get(name)
    return FormatModel([dict(f) for f in spec]) if spec else None


def from_spec(spec) -> FormatModel:
    """Build a model from an analyst-supplied spec (list of field dicts, e.g. from JSON)."""
    return FormatModel(list(spec))
