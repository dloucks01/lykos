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


def _fix_covers(model, fields) -> None:
    """Recompute every `covers: "rest"` length so the structure stays parseable."""
    for i, fd in enumerate(fields):
        if fd["f"].get("covers") != "rest":
            continue
        before = model.serialize(fields[:i])
        fd["val"] = len(model.serialize(fields)) - len(before)


def seed_for_name(name: str) -> bytes | None:
    """A valid seed for a builtin, using that format's own tail when it declares one."""
    entry = _BUILTINS.get(name)
    if not entry:
        return None
    model = FormatModel([dict(f) for f in entry["spec"]])
    return seed_for(model, entry.get("seed") or b"A" * 64)


def seed_for(model: "FormatModel", payload: bytes = b"A" * 64) -> bytes:
    """A minimal input the format's own gate accepts.

    The model already declares the magic and which integer sizes which blob, so a valid
    skeleton falls straight out of `serialize` -- there is no need for an analyst to attach a
    sample before a campaign can start doing work.
    """
    fields = []
    for f in model.spec:
        t = f["type"]
        if t == "magic":
            fields.append({"f": f, "val": _as_bytes(f["value"])})
        elif t in _INT:
            # A count that must agree with the seed's own payload -- an IFD entry count of 0
            # alongside one entry is rejected before the parser reaches anything interesting.
            fields.append({"f": f, "val": f.get("seed_value", 0)})
        else:
            fields.append({"f": f, "val": payload})
    # length fields describe the blob they name, so the skeleton parses rather than truncating
    by_name = {fd["f"].get("name"): fd for fd in fields}
    for fd in fields:
        ln = fd["f"].get("length_of")
        if ln and ln in by_name:
            fd["val"] = len(_as_bytes(by_name[ln]["val"]))
    # `covers: "rest"` is the other length shape real formats use: a JPEG segment length spans
    # the length field itself and everything after it, not one named blob. Getting it wrong is
    # not cosmetic -- the parser reads a short segment and treats the remainder as padding,
    # so the seed never reaches the structure the rest of the model describes.
    _fix_covers(model, fields)
    return model.serialize(fields)


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
        drove_cover = False
        for _ in range(self.rng.randint(1, 3)):
            drove_cover |= self._mutate_field(fields) == "cover"
        if not drove_cover:
            # Keep "covers: rest" lengths honest unless this round deliberately drove one.
            # A segment length that no longer spans the segment is not a bug the parser will
            # chase: it reads a short segment and discards the mutated tail as padding, so
            # every other mutation in the round is thrown away before it is ever parsed.
            _fix_covers(self.model, fields)
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
            if fd["f"].get("covers") == "rest":
                return "cover"                          # driving it IS the interesting case
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
# A model is a spec plus the printable tokens that betray a parser for it in a binary's
# strings. Byte magic (0xFFD8) never survives into a string table; the format's textual
# markers do, which is what makes auto-detection possible at all.
# One well-formed IFD entry (ASCII "Make"), the next-IFD terminator and an EOI, so the seed
# lands inside ProcessExifDir rather than being rejected at the alignment marker.
def _exif_entry(tag, typ, count, value):
    """One 12-byte IFD entry. A value of four bytes or fewer sits INLINE; anything larger is
    stored as an offset, and a parser rejects the entry if the two disagree."""
    raw = value if isinstance(value, bytes) else struct.pack("<I", value)
    return struct.pack("<HHI", tag, typ, count) + raw


def _jpeg_seed_tail():
    """An EXIF payload that reaches the GPS parser, not merely the front door.

    A seed has to exercise a format's FEATURES, not just satisfy its magic. Reaching
    `ProcessExifDir` is not enough to find jhead's bug: that lives in `ProcessGpsInfo`, behind
    a GPS sub-directory pointer (tag 0x8825) and a sub-IFD at a valid offset. Random mutation
    does not invent a 16-bit tag number and a self-consistent offset, so a campaign that starts
    without one never executes the function at all.

    Offsets are relative to the TIFF header, which the model emits as a magic: an 8-byte header
    then IFD0 at offset 8 (its count comes from the model's `nent` field).
    """
    ifd0_off, ifd0_len = 8, 2 + 12 + 4          # one entry: the GPS pointer, then next-IFD
    gps_off = ifd0_off + ifd0_len
    gps_len = 2 + 12 * 2 + 4
    rat_off = gps_off + gps_len
    ifd0_rest = _exif_entry(0x8825, 4, 1, gps_off) + struct.pack("<I", 0)
    gps = (struct.pack("<H", 2)
           + _exif_entry(0x0001, 2, 2, b"N\x00\x00\x00")     # GPSLatitudeRef
           + _exif_entry(0x0002, 5, 3, rat_off)                # GPSLatitude: 3 rationals
           + struct.pack("<I", 0))
    rationals = b"".join(struct.pack("<II", n, d) for n, d in ((51, 1), (30, 1), (0, 1)))
    return ifd0_rest + gps + rationals + b"\xff\xd9"


_JPEG_SEED_TAIL = _jpeg_seed_tail()

_BUILTINS = {
    # generic "magic + u32-LE length + payload" container (matches many toy/real headers)
    "lv32": {"tokens": (), "spec": [
        {"type": "magic", "value": "\x00"},          # placeholder magic, override via params
        {"type": "u32", "endian": "little", "name": "len", "length_of": "data"},
        {"type": "blob", "name": "data"}]},
    # PNG: 8-byte signature, then the mutator drives the first chunk's length/type
    "png": {"tokens": ("IHDR", "IEND", "PNG"), "spec": [
        {"type": "magic", "value": b"\x89PNG\r\n\x1a\n"},
        {"type": "u32", "endian": "big", "name": "clen", "length_of": "cdata"},
        {"type": "magic", "value": "IHDR"},
        {"type": "blob", "name": "cdata"}]},
    # JPEG/EXIF: SOI + APP1, a BIG-endian segment length, then the Exif header the EXIF
    # parsers key on. This is the shape jhead reads, and the length field is exactly the
    # length-driven relationship the structure mutator exists to drive.
    "jpeg": {"tokens": ("Exif", "JFIF", "JPEG"),
             # The TIFF header and the IFD entry count are part of the GATE, not the payload:
             # an EXIF reader rejects the file before either unless both are well formed, and
             # the entry count is one of the most productive fields a parser fuzzer can drive.
             "seed": _JPEG_SEED_TAIL,
             "spec": [
                 {"type": "magic", "value": b"\xff\xd8\xff\xe1"},
                 {"type": "u16", "endian": "big", "name": "seglen", "covers": "rest"},
                 {"type": "magic", "value": b"Exif\x00\x00"},
                 {"type": "magic", "value": b"II*\x00\x08\x00\x00\x00"},
                 {"type": "u16", "endian": "little", "name": "nent", "seed_value": 1},
                 {"type": "blob", "name": "seg"}]},
    "gif": {"tokens": ("GIF87a", "GIF89a"), "spec": [
        {"type": "magic", "value": b"GIF89a"},
        {"type": "u16", "endian": "little", "name": "w"},
        {"type": "u16", "endian": "little", "name": "h"},
        {"type": "blob", "name": "data"}]},
    "bmp": {"tokens": ("BM",), "spec": [
        {"type": "magic", "value": b"BM"},
        {"type": "u32", "endian": "little", "name": "size", "length_of": "data"},
        {"type": "blob", "name": "data"}]},
    "riff": {"tokens": ("RIFF", "WAVE", "fmt "), "spec": [
        {"type": "magic", "value": b"RIFF"},
        {"type": "u32", "endian": "little", "name": "size", "length_of": "data"},
        {"type": "magic", "value": b"WAVE"},
        {"type": "blob", "name": "data"}]},
    "zip": {"tokens": ("PK\x03\x04", "End of central directory"), "spec": [
        {"type": "magic", "value": b"PK\x03\x04\x14\x00\x00\x00\x00\x00"},
        {"type": "u32", "endian": "little", "name": "crc"},
        {"type": "u32", "endian": "little", "name": "csize", "length_of": "data"},
        {"type": "blob", "name": "data"}]},
}


def builtin(name: str):
    entry = _BUILTINS.get(name)
    return FormatModel([dict(f) for f in entry["spec"]]) if entry else None


def builtin_names() -> list:
    return sorted(_BUILTINS)


def detect_format(strings) -> str | None:
    """Which builtin format this binary looks like a parser for, by its own strings.

    A blind mutator cannot invent four valid magic bytes, so a parser rejects everything it is
    given and the campaign does no work: jhead ran 98,500 executions for zero finds against a
    bug AFL++ reached in 60 seconds WITH a valid seed. The binary itself says which format it
    reads -- an EXIF reader carries the string "Exif" -- so the model and the seed can both be
    chosen without an analyst supplying either.
    """
    blob = "\n".join(s for s in strings if s)
    best, score = None, 0
    for name, entry in _BUILTINS.items():
        hits = sum(1 for t in entry["tokens"] if t and t in blob)
        if hits > score:
            best, score = name, hits
    return best


def from_spec(spec) -> FormatModel:
    """Build a model from an analyst-supplied spec (list of field dicts, e.g. from JSON).
    Magic values may arrive as plain strings or as {"b64": ...} from the GUI builder."""
    out = []
    for f in spec:
        f = dict(f)
        if f.get("type") == "magic":
            f["value"] = _coerce_value(f.get("value", b""))
        out.append(f)
    return FormatModel(out)


# ---------------------------------------------------------------------------
# Spec builder support: detect a format from a real sample, auto-find the
# length field, and describe how a spec carves a sample. Powers the GUI's
# custom-format builder so the analyst never has to guess the raw bytes.
# ---------------------------------------------------------------------------

# (name, magic bytes) -- longest/most specific first
_SIGNATURES = [
    ("PDF", b"%PDF-"), ("PNG", b"\x89PNG\r\n\x1a\n"), ("GIF", b"GIF89a"),
    ("GIF", b"GIF87a"), ("JPEG", b"\xff\xd8\xff"), ("BMP", b"BM"),
    ("GZIP", b"\x1f\x8b"), ("ZIP", b"PK\x03\x04"), ("ELF", b"\x7fELF"),
    ("RIFF", b"RIFF"), ("TIFF", b"II*\x00"), ("TIFF", b"MM\x00*"),
    ("CLASS", b"\xca\xfe\xba\xbe"), ("OGG", b"OggS"), ("FLAC", b"fLaC"),
    ("7Z", b"7z\xbc\xaf\x27\x1c"), ("XZ", b"\xfd7zXZ\x00"), ("WASM", b"\x00asm"),
    ("CAB", b"MSCF"), ("MACHO", b"\xcf\xfa\xed\xfe"), ("SQLITE", b"SQLite format 3\x00"),
]


def detect_magic(sample: bytes):
    """Return (name, magic_bytes) for the first known signature the sample starts with."""
    for name, sig in _SIGNATURES:
        if sample.startswith(sig):
            return name, sig
    return None, b""


def find_length_fields(sample: bytes, *, max_off: int = 64):
    """Heuristic: scan header offsets for an integer whose value equals the number of
    bytes that follow it (data-length) or the total size -- i.e. a real length field.
    Returns candidates sorted best-first, each {offset,size,endian,value,kind}."""
    out = []
    n = len(sample)
    for size, code in ((4, "I"), (2, "H"), (8, "Q")):
        for off in range(0, min(max_off, max(0, n - size)) + 1):
            for endian, sym in (("little", "<"), ("big", ">")):
                val = struct.unpack(sym + code, sample[off:off + size])[0]
                after = n - (off + size)
                if val == after and after > 0:
                    out.append({"offset": off, "size": size, "endian": endian,
                                "value": val, "kind": "data-length"})
                elif val == n:
                    out.append({"offset": off, "size": size, "endian": endian,
                                "value": val, "kind": "total-size"})
    # prefer data-length matches, then smaller offsets, then 4-byte fields
    rank = {"data-length": 0, "total-size": 1}
    out.sort(key=lambda c: (rank[c["kind"]], c["offset"], 0 if c["size"] == 4 else 1))
    return out


_INTNAME = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}


def suggest_spec(sample: bytes) -> dict:
    """Build a starting spec from a real sample: fix the detected header as magic, put a
    length field where the bytes say one is, and let the rest be the sized blob."""
    sample = sample or b""
    name, sig = detect_magic(sample)
    cands = find_length_fields(sample)
    notes = []
    if cands:
        c = cands[0]
        prefix = sample[:c["offset"]] or sig      # everything before the length int is fixed
        spec = [{"type": "magic", "value": _b64safe(prefix)}]
        spec.append({"type": _INTNAME[c["size"]], "endian": c["endian"],
                     "name": "len", "length_of": "data"})
        spec.append({"type": "blob", "name": "data"})
        notes.append(f"auto-found a {c['size']*8}-bit {c['endian']}-endian length field at "
                     f"offset {c['offset']} (value {c['value']} == trailing bytes)")
    else:
        prefix = sig or sample[:min(8, len(sample))]
        spec = [{"type": "magic", "value": _b64safe(prefix)},
                {"type": "blob", "name": "data"}]
        notes.append("no length field auto-found -- add an integer field and watch the "
                     "preview's length match, or fuzz the blob as-is")
    return {"detected": name, "magic_len": len(sig), "spec": spec, "notes": notes,
            "sample_size": len(sample)}


def _b64safe(b: bytes):
    """Represent magic bytes so they survive JSON: latin-1 str if printable-ish, else base64."""
    import base64
    try:
        s = b.decode("latin-1")
        # keep it a plain string only if it round-trips and is mostly printable
        if all(32 <= c < 127 or c in (9, 10, 13) for c in b):
            return s
    except Exception:
        pass
    return {"b64": base64.b64encode(b).decode("ascii")}


def _coerce_value(v):
    """Accept a magic value as str, bytes, or {"b64": ...} from the builder."""
    import base64
    if isinstance(v, dict) and "b64" in v:
        return base64.b64decode(v["b64"])
    return v


def describe(spec, sample: bytes) -> dict:
    """Parse a sample against a spec and report how it carves -- per-field offset/size/value,
    whether each length field matches the real blob length, and roundtrip fidelity. This is
    exactly the model the fuzzer uses, so the preview is truthful."""
    spec = [dict(f) for f in spec]
    for f in spec:                                # normalize magic values from the builder
        if f.get("type") == "magic":
            f["value"] = _coerce_value(f.get("value", b""))
    model = FormatModel(spec)
    fields_out = []
    ok = True
    err = None
    try:
        parsed = model.parse(sample or b"")
        pos = 0
        # index blobs by name for length checks
        blob_len = {fd["f"].get("name"): len(fd["val"])
                    for fd in parsed if fd["f"]["type"] not in _INT and fd["f"]["type"] != "magic"}
        for fd in parsed:
            f = fd["f"]
            t = f["type"]
            if t == "magic":
                raw = _as_bytes(fd["val"])
                want = _as_bytes(f.get("value", b""))
                size = len(want)
                fields_out.append({"type": "magic", "name": f.get("name", "magic"),
                                   "offset": pos, "size": size,
                                   "value": _preview_bytes(raw),
                                   "match": raw == want})
                if raw != want:
                    ok = False
                pos += size
            elif t in _INT:
                size = _INT[t][0]
                lo = f.get("length_of")
                match = None
                if lo is not None:
                    match = (int(fd["val"]) == blob_len.get(lo))
                fields_out.append({"type": t, "name": f.get("name", t),
                                   "offset": pos, "size": size, "int": int(fd["val"]),
                                   "endian": f.get("endian", "little"),
                                   "length_of": lo, "length_match": match})
                pos += size
            else:
                data = _as_bytes(fd["val"])
                fields_out.append({"type": "blob", "name": f.get("name", "data"),
                                   "offset": pos, "size": len(data),
                                   "value": _preview_bytes(data)})
                pos += len(data)
        roundtrip = model.serialize(parsed) == (sample or b"")
    except Exception as e:                        # noqa: BLE001 - report parse failure to UI
        ok = False
        err = str(e)
        roundtrip = False
    return {"fields": fields_out, "ok": ok, "roundtrip": roundtrip,
            "consumed": sum(f["size"] for f in fields_out), "sample_size": len(sample or b""),
            "error": err}


def _preview_bytes(b: bytes, cap: int = 24):
    import base64
    head = b[:cap]
    printable = "".join(chr(c) if 32 <= c < 127 else "." for c in head)
    return {"hex": head.hex(), "ascii": printable, "b64": base64.b64encode(b[:64]).decode("ascii"),
            "truncated": len(b) > cap}
