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
import zlib

from .mutator import Mutator

_INT = {"u8": (1, "B"), "u16": (2, "H"), "u32": (4, "I"), "u64": (8, "Q")}
# values that break length/count fields: zero, off-by-one, and huge (overflow/overread)
_EDGE = [0, 1, 63, 64, 65, 127, 128, 255, 256, 1024, 4096, 0x7FFFFFFF, 0xFFFFFFFF]
# offsets a parser will happily add to a base pointer and then read from
_FAR = [0, 1, 0x40, 0xFF, 0x100, 0xFFFF, 0x10000, 0x00FFFFFF, 0x7FFFFFFF, 0xFFFFFFF0, 0xFFFFFFFF]
_MAXBLOB = 8192
_MAXREC = 4096          # an array's count field is attacker data: parse it, but bound it


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
        fields, _pos = self._parse_spec(self.spec, data, 0)
        return fields

    def _parse_spec(self, spec, data: bytes, pos: int, covered=None):
        """Parse one SCOPE. Groups and arrays recurse, so a format inside a format is fields
        rather than opaque bytes -- which is what lets a mutation change one of them and leave
        every other field intact."""
        fields: list = []
        # Shared with nested scopes: a PNG chunk's length sits OUTSIDE the group its data is
        # in, so a scope-local map left the blob unbounded and it swallowed the whole file.
        covered = {} if covered is None else covered
        seen: dict = {}                  # name -> value, for an array's count field
        for f in spec:
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
                cov = f.get("covers")
                if cov and cov != "rest":
                    covered[cov] = (val, pos)
                ln = f.get("length_of")
                if ln and ln not in covered:
                    # `length_of` sizes the blob exactly, where `covers` spans from the length
                    # field itself. Both have to bound the blob on the way back IN, or the
                    # blob eats the remainder and nothing can follow it -- a GIF's sub-block
                    # is followed by the block terminator and the trailer, which is what
                    # decides whether the file is a GIF at all.
                    covered[ln] = (val, None)
                seen[f.get("name")] = val
                fields.append({"f": f, "val": val})
                pos += sz
            elif t == "shadow":
                # Bytes that exist for DERIVATION and are never written: a ZIP stores the CRC
                # of the UNCOMPRESSED data, which appears nowhere in the file. Without this a
                # checksum field can only name bytes the format happens to contain.
                fields.append({"f": f, "val": _as_bytes(f.get("seed_value", b""))})
            elif t == "group":
                sub, pos = self._parse_spec(f["spec"], data, pos, covered)
                fields.append({"f": f, "val": sub})
            elif t == "array":
                # However many the count field claims -- but only as many as the data holds. A
                # count that outruns its own records is a mutation worth making, not a reason
                # to give up on the input.
                want = min(int(seen.get(f.get("count"), 0) or 0), _MAXREC)
                recs = []
                for _ in range(want):
                    if pos >= len(data):
                        break
                    sub, nxt = self._parse_spec(f["spec"], data, pos, covered)
                    if nxt > len(data):
                        break
                    recs.append(sub)
                    pos = nxt
                fields.append({"f": f, "val": recs})
            else:
                # A blob NAMED by a length field ends where that length says, so the fields
                # after it can be parsed. Without this every blob ate the remainder, so a
                # model could describe at most one variable region -- which is not enough for
                # a real container: a JPEG's EXIF segment is followed by the frame and scan
                # headers that decide whether the file parses at all.
                name = f.get("name")
                if name in covered:
                    total, start = covered[name]
                    # `length_of` sizes the blob from its own start; `covers` spans from the
                    # length field itself, so the blob ends at that field's start plus the span
                    stop = pos + int(total) if start is None else max(start + int(total), pos)
                    stop = min(max(stop, pos), len(data))
                else:
                    stop = len(data)
                fields.append({"f": f, "val": data[pos:stop]})
                pos = stop
        return fields, pos

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
            elif t == "shadow":
                continue
            elif t == "group":
                out += self.serialize(fd["val"])
            elif t == "array":
                for rec in fd["val"]:
                    out += self.serialize(rec)
            else:
                out += _as_bytes(fd["val"] or b"")
        return bytes(out)


def _serialize_field(model, fd) -> bytes:
    """The bytes one field contributes, whether it is a leaf, a group or an array."""
    t = fd["f"]["type"]
    if t == "shadow":
        return _as_bytes(fd["val"] or b"")
    if t == "group":
        return model.serialize(fd["val"])
    if t == "array":
        return b"".join(model.serialize(rec) for rec in fd["val"])
    return model.serialize([fd])


def _layout(model, fields, pos=0, out=None, names=None):
    """Absolute (offset, length) of every field, including nested ones, plus a name index.

    Derived fields have to be computed over the whole tree, not one scope: a ZIP's central
    directory entry names a size that lives in the local header, and the end-of-central-
    directory record names an offset into the file, not into its own group.
    """
    out = {} if out is None else out
    names = {} if names is None else names
    for fd in fields:
        t, start = fd["f"]["type"], pos
        if t == "group":
            _, _, pos = _layout(model, fd["val"], pos, out, names)
        elif t == "array":
            for rec in fd["val"]:
                _, _, pos = _layout(model, rec, pos, out, names)
        elif t == "shadow":
            pass                                       # occupies no bytes in the output
        else:
            pos += len(model.serialize([fd]))
        out[id(fd)] = (start, pos - start)
        nm = fd["f"].get("name")
        if nm and nm not in names:
            names[nm] = fd
    return out, names, pos


def _every_field(fields):
    for fd in fields:
        yield fd
        t = fd["f"]["type"]
        if t == "group":
            yield from _every_field(fd["val"])
        elif t == "array":
            for rec in fd["val"]:
                yield from _every_field(rec)


def _fix_covers(model, fields, lengths: bool = False) -> None:
    """Recompute every derived field so the structure stays parseable.

    `covers: "rest"` spans to the end of the input; `covers: <field>` spans from the length
    field's own start through the end of that field, which is what a JPEG segment length
    actually means; `offset_of: <field>` is where that field starts, which is how every
    archive format finds its directory.

    `length_of` is recomputed only when generating a SEED. During mutation a length that no
    longer matches what it sizes is the whole point -- driving it is how a length-prefixed
    parser gets tested -- so the fixup must not quietly put it back.
    """
    for _ in range(2):            # an offset depends on lengths that may themselves have moved
        spans, names, total = _layout(model, fields)
        for fd in _every_field(fields):
            f = fd["f"]
            if f["type"] not in _INT:
                continue
            # A format that checksums its own chunks cannot be fuzzed blind: a parser rejects
            # a bad CRC before reading anything else, so every mutation is thrown away at the
            # door. Derived like a length, and drivable for the same reason -- a deliberately
            # wrong checksum is its own test.
            crc = f.get("crc32_of")
            if crc:
                mate = names.get(crc)
                if mate is not None:
                    fd["val"] = zlib.crc32(_serialize_field(model, mate)) & 0xFFFFFFFF
                continue
            target = f.get("offset_of") or (f.get("length_of") if lengths else None)
            if target:
                mate = names.get(target)
                if mate is not None:
                    off, ln = spans[id(mate)]
                    fd["val"] = off if f.get("offset_of") else ln
                continue
            cov = f.get("covers")
            if not cov:
                continue
            start = spans[id(fd)][0]
            if cov == "rest":
                stop = total
            else:
                mate = names.get(cov)
                if mate is None:
                    continue
                stop = sum(spans[id(mate)])
            fd["val"] = max(0, stop - start)


def seed_for_name(name: str) -> bytes | None:
    """A valid seed for a builtin, using that format's own tail when it declares one."""
    entry = _BUILTINS.get(name)
    if not entry:
        return None
    model = FormatModel([dict(f) for f in entry["spec"]])
    seed = entry.get("seed")
    return seed_for(model, seed if seed is not None else b"A" * 64,
                    tail=entry.get("tail"))


def _seed_spec(spec, payload):
    """A seed for one scope, returning its fields and the blobs in it (outermost first)."""
    fields: list = []
    blobs: list = []
    for f in spec:
        t = f["type"]
        if t == "magic":
            fields.append({"f": f, "val": _as_bytes(f["value"])})
        elif t in _INT:
            # A count that must agree with the seed's own payload -- an IFD entry count of 0
            # alongside one entry is rejected before the parser reaches anything interesting.
            fields.append({"f": f, "val": f.get("seed_value", 0)})
        elif t == "shadow":
            fields.append({"f": f, "val": _as_bytes(f.get("seed_value", b""))})
        elif t == "group":
            sub, sub_blobs = _seed_spec(f["spec"], payload)
            fields.append({"f": f, "val": sub})
            blobs += sub_blobs
        elif t == "array":
            # Records differ from one another -- two IFD entries are two different tags -- so
            # the model names each one's field values rather than repeating a single template.
            recs = []
            for values in f.get("seed_records") or []:
                sub, sub_blobs = _seed_spec(f["spec"], payload)
                for fd in sub:
                    if fd["f"].get("name") in values:
                        fd["val"] = values[fd["f"]["name"]]
                recs.append(sub)
                blobs += sub_blobs
            fields.append({"f": f, "val": recs})
        else:
            # the LAST blob gets the format's tail when it declares one (a JPEG's entropy data
            # and end-of-image marker); earlier blobs get the payload, unless the model gives
            # one its own value -- a ZIP's "extra field" and comment have to start EMPTY, or
            # their length fields describe bytes the format says are not there
            val = f["seed_value"] if "seed_value" in f else payload
            fields.append({"f": f, "val": _as_bytes(val)})
            if "seed_value" not in f:
                blobs.append(fields[-1])
    return fields, blobs


def seed_for(model: "FormatModel", payload: bytes = b"A" * 64, tail: bytes = None) -> bytes:
    """A minimal input the format's own gate accepts.

    The model already declares the magic and which integer sizes which blob, so a valid
    skeleton falls straight out of `serialize` -- there is no need for an analyst to attach a
    sample before a campaign can start doing work.
    """
    fields, blobs = _seed_spec(model.spec, payload)

    # `covers: "rest"` is the other length shape real formats use: a JPEG segment length spans
    # the length field itself and everything after it, not one named blob. Getting it wrong is
    # not cosmetic -- the parser reads a short segment and treats the remainder as padding,
    # so the seed never reaches the structure the rest of the model describes.
    if tail is not None and blobs:
        blobs[-1]["val"] = tail
    _fix_covers(model, fields, lengths=True)
    return model.serialize(fields)


def _scopes(fields):
    """Every scope in a parsed input: the top level, and each group and array record.

    A mutation picks a scope and then a field in it, so a leaf buried in a sub-structure is as
    reachable as a top-level one -- and, crucially, changing it leaves every other field
    exactly as it was. Byte havoc over the same bytes cannot do that: measured on jhead, it
    produced the value that triggers the bug 259 times in 20,000 mutations and crashed on none
    of them, because the same havoc wrecked the surrounding directory and the parser gave up
    before reaching the code that reads the value.
    """
    out = [fields]
    for fd in fields:
        t = fd["f"]["type"]
        if t == "group":
            out += _scopes(fd["val"])
        elif t == "array":
            for rec in fd["val"]:
                out += _scopes(rec)
    return out


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
        scopes = _scopes(fields)
        for _ in range(self.rng.randint(1, 3)):
            drove_cover |= self._mutate_field(self.rng.choice(scopes)) == "cover"
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

    def _drive_pair(self, fields, fd, role):
        """Drive a record's offset and size TOGETHER.

        A parser that reads `size` bytes from `base + offset` usually checks the pair first,
        and the check is where the bug is: computing `offset + size` in the field's own width
        wraps, so a sum that looks tiny passes while the offset still points far outside the
        buffer. That is jhead's GPS read -- 0x00ffffff + 0xff000002 is 1 in 32 bits -- and
        neither half does it alone: a huge size is refused, a far offset is refused, and only
        the pair gets through. Guessing both independently effectively never lands it, so the
        complementary value is CONSTRUCTED.
        """
        mate = next((x for x in fields
                     if x["f"].get("role") == ("offset" if role == "size" else "size")
                     and x is not fd), None)
        if mate is None:
            return
        off_fd, siz_fd = (fd, mate) if role == "offset" else (mate, fd)
        width = min(_INT[off_fd["f"]["type"]][0], _INT[siz_fd["f"]["type"]][0]) * 8
        mask = (1 << width) - 1
        if self.rng.random() < 0.5:
            off = self.rng.choice([x for x in _FAR if 0xFFFF < x <= mask]) & mask
            # the wrapped sum has to survive the check too, so aim it just past zero
            off_fd["val"] = off
            siz_fd["val"] = (mask + 1 - off + self.rng.choice((0, 1, 2, 4, 8, 16))) & mask
        else:
            off_fd["val"] = self.rng.choice(_FAR) & mask
            siz_fd["val"] = self.rng.choice(_EDGE) & mask

    def _blob_by_name(self, fields, name):
        return next((fd for fd in fields if fd["f"].get("name") == name), None)

    def _mutate_field(self, fields):
        fd = self.rng.choice(fields)
        t = fd["f"]["type"]
        if t in ("group", "array"):
            return None                                 # its own fields are a scope of their own
        if t == "magic":
            if self.rng.random() < 0.08:               # usually KEEP so the format gate passes
                fd["val"] = self.byte.mutate(fd["val"] or b"", ())
        elif t in _INT:
            fd["val"] = self.rng.choice(_EDGE)
            if (fd["f"].get("covers") == "rest" or fd["f"].get("offset_of")
                    or fd["f"].get("crc32_of")):
                return "cover"                          # driving it IS the interesting case
            # A record that says WHERE data is and HOW MUCH of it there is is the classic
            # out-of-bounds read, and it needs both halves at once: jhead survives a GPS entry
            # with a four-billion-byte count, and survives one pointing off the end of the
            # segment, but reading that many bytes FROM there walks off the mapping. Driving
            # one field at a time never lands both, so the roles are declared and driven
            # together -- the same coordination `length_of` already does for a sized blob.
            role = fd["f"].get("role")
            if role in ("size", "offset") and self.rng.random() < 0.6:
                self._drive_pair(fields, fd, role)
            target = fd["f"].get("length_of")
            if target and self.rng.random() < 0.6:      # coordinate: grow the sized blob to match
                # a length can now name a GROUP as well -- a ZIP's central-directory size --
                # and a group's value is its fields, not bytes, so there is nothing to grow
                blob = self._blob_by_name(fields, target)
                if blob is not None and blob["f"]["type"] not in ("group", "array"):
                    want = min(int(fd["val"]), _MAXBLOB)
                    base = bytes(blob["val"] or b"A")
                    blob["val"] = (base * (want // max(1, len(base)) + 1))[:want] if want else base
        else:                                           # blob: byte-level havoc on the data
            fd["val"] = self.byte.mutate(fd["val"] or b"A", ())


# a few ready-made models (analyst can also pass a custom spec)
# A model is a spec plus the printable tokens that betray a parser for it in a binary's
# strings. Byte magic (0xFFD8) never survives into a string table; the format's textual
# markers do, which is what makes auto-detection possible at all.
def _jpeg_frame():
    """DQT + SOF0 + DHT + SOS: the smallest tail that makes jhead call the file complete."""
    def seg(marker, body):
        return b"\xff" + bytes([marker]) + struct.pack(">H", len(body) + 2) + body
    dqt = seg(0xDB, b"\x00" + bytes(range(1, 65)))
    sof0 = seg(0xC0, b"\x08" + struct.pack(">HH", 8, 8) + b"\x01" + b"\x01\x11\x00")
    dht = seg(0xC4, b"\x00" + bytes(16))
    sos = seg(0xDA, b"\x01" + b"\x01\x00" + b"\x00\x3f\x00")
    return dqt + sof0 + dht + sos


_JPEG_FRAME = _jpeg_frame()


# Offsets inside an EXIF payload are relative to the TIFF header, which the model emits as a
# magic: an 8-byte header, then IFD0 starts at offset 8 -- exactly where the model's `nent`
# field sits. Everything after it follows from the entry counts the seed declares.
_IFD0_OFF = 8
_GPS_OFF = _IFD0_OFF + 2 + 12 + 4                 # count + one entry (the GPS pointer) + next
_RAT_OFF = _GPS_OFF + 2 + 12 * 2 + 4              # count + two entries + next
_RATIONALS = b"".join(struct.pack("<II", n, d) for n, d in ((51, 1), (30, 1), (0, 1)))
# A ZIP whose only entry is STORED never reaches the decompressor, and unzip is mostly
# decompressor: the campaign covered 1,162 of 3,705 blocks and found nothing. This is a real
# raw-deflate stream, so method 8 is exercised, and with the CRC derived `unzip -t` verifies
# it instead of stopping at "bad CRC".
_ZIP_PLAIN = b"lykos test payload, compressible compressible compressible\n"


def _deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)        # raw: no zlib header, as ZIP stores it
    return c.compress(data) + c.flush()


_ZIP_DEFLATED = _deflate(_ZIP_PLAIN)

# A one-pixel GIF never runs the LZW decoder, which is most of what a GIF reader IS: the
# campaign covered 377 of gif2rgb's 1,340 blocks. This is a real 16x16 image -- four-entry
# colour table, a genuine compressed stream -- so decoding actually happens.
_GIF_GCT = b"\x00\x00\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00"
_GIF_LZW_MIN = 8
_GIF_LZW = (b"\x00\x01\x08\x1cH\xb0\xa0\xc1\x83\x08\x13*\\\xc8\xb0\xa1\xc3\x87\t\x03"
            b"\x00\x90Hq\xa2\xc5\x8a\x18/j\xcc\xc8q\xa3\xc7\x8e ?\x8a\x0cIr\xe4\xc6\x80")

_PNG_IHDR = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
_PNG_IDAT = zlib.compress(b"\x00\x00")      # one filter byte + one greyscale pixel

_IFD_ENTRY = [{"type": "u16", "endian": "little", "name": "tag"},
              {"type": "u16", "endian": "little", "name": "fmt"},
              {"type": "u32", "endian": "little", "name": "count", "role": "size"},
              {"type": "u32", "endian": "little", "name": "value", "role": "offset"}]



_BUILTINS = {
    # generic "magic + u32-LE length + payload" container (matches many toy/real headers)
    "lv32": {"tokens": (), "spec": [
        {"type": "magic", "value": "\x00"},          # placeholder magic, override via params
        {"type": "u32", "endian": "little", "name": "len", "length_of": "data"},
        {"type": "blob", "name": "data"}]},
    # PNG: every chunk is length + type + data + CRC32 over type AND data, and a decoder
    # checks the CRC before it reads anything -- so a model that stops at the signature
    # generates a file that is rejected at the door. The chunk body is a GROUP precisely so
    # the checksum can name it.
    "png": {"tokens": ("IHDR", "IEND", "PNG"), "spec": [
        {"type": "magic", "value": b"\x89PNG\r\n\x1a\n"},
        {"type": "group", "name": "ihdr", "spec": [
            {"type": "u32", "endian": "big", "name": "ihdr_len", "length_of": "ihdr_data"},
            {"type": "group", "name": "ihdr_body", "spec": [
                {"type": "magic", "value": b"IHDR"},
                # 1x1, 8-bit greyscale, no interlace
                {"type": "blob", "name": "ihdr_data", "seed_value": _PNG_IHDR}]},
            {"type": "u32", "endian": "big", "name": "ihdr_crc", "crc32_of": "ihdr_body"}]},
        {"type": "group", "name": "idat", "spec": [
            {"type": "u32", "endian": "big", "name": "idat_len", "length_of": "idat_data"},
            {"type": "group", "name": "idat_body", "spec": [
                {"type": "magic", "value": b"IDAT"},
                {"type": "blob", "name": "idat_data", "seed_value": _PNG_IDAT}]},
            {"type": "u32", "endian": "big", "name": "idat_crc", "crc32_of": "idat_body"}]},
        {"type": "group", "name": "iend", "spec": [
            {"type": "u32", "endian": "big", "name": "iend_len", "length_of": "iend_data"},
            {"type": "group", "name": "iend_body", "spec": [
                {"type": "magic", "value": b"IEND"},
                {"type": "blob", "name": "iend_data", "seed_value": b""}]},
            {"type": "u32", "endian": "big", "name": "iend_crc", "crc32_of": "iend_body"}]}]},
    # JPEG/EXIF: SOI + APP1, a BIG-endian segment length, then the Exif header the EXIF
    # parsers key on. This is the shape jhead reads, and the length field is exactly the
    # length-driven relationship the structure mutator exists to drive.
    "jpeg": {"tokens": ("Exif", "JFIF", "JPEG"),
             # The TIFF header and the IFD entry count are part of the GATE, not the payload:
             # an EXIF reader rejects the file before either unless both are well formed, and
             # the entry count is one of the most productive fields a parser fuzzer can drive.
             "seed": _RATIONALS, "tail": b"\x00" * 8 + b"\xff\xd9",
             "spec": [
                 {"type": "magic", "value": b"\xff\xd8\xff\xe1"},
                 # the APP1 length spans itself through the end of the EXIF payload, which is
                 # also what bounds `gpsdata` on the way back in
                 {"type": "u16", "endian": "big", "name": "seglen", "covers": "gpsdata"},
                 {"type": "magic", "value": b"Exif\x00\x00"},
                 {"type": "magic", "value": b"II*\x00\x08\x00\x00\x00"},
                 # IFD0 and the GPS sub-directory it points at are FIELDS, not payload. As one
                 # opaque blob the mutator could only flip bytes in them, which produces a
                 # broken directory and a bad value at the same time -- and jhead rejects the
                 # directory long before it reads the value. Described, a mutation changes one
                 # entry's count and leaves every other field exactly as it was, which is the
                 # single edit that crashes it.
                 {"type": "u16", "endian": "little", "name": "nent", "seed_value": 1},
                 {"type": "array", "name": "ifd0", "count": "nent", "spec": _IFD_ENTRY,
                  "seed_records": [{"tag": 0x8825, "fmt": 4, "count": 1, "value": _GPS_OFF}]},
                 {"type": "u32", "endian": "little", "name": "next_ifd"},
                 {"type": "group", "name": "gps", "spec": [
                     {"type": "u16", "endian": "little", "name": "ngps", "seed_value": 2},
                     {"type": "array", "name": "gpsent", "count": "ngps", "spec": _IFD_ENTRY,
                      "seed_records": [
                          # GPSLatitudeRef: two ASCII bytes, "N", stored inline
                          {"tag": 0x0001, "fmt": 2, "count": 2, "value": 0x4E},
                          # GPSLatitude: three rationals, too big to inline, so an offset
                          {"tag": 0x0002, "fmt": 5, "count": 3, "value": _RAT_OFF}]},
                     {"type": "u32", "endian": "little", "name": "next_gps"}]},
                 {"type": "blob", "name": "gpsdata"},
                 # Everything past EXIF is what makes the file COMPLETE. jhead rejects a file
                 # with no frame and scan header as "Unexpected end of file" and never reaches
                 # ShowImageInfo -- 210 blocks, its largest function -- nor anything gated
                 # behind an option, because those run downstream of a successful parse.
                 # Measured minimum: SOF0 + SOS. DQT and DHT are not required but reach
                 # process_DQT and process_DHT, another 69 blocks.
                 {"type": "magic", "value": _JPEG_FRAME},
                 {"type": "blob", "name": "scan"}]},
    # GIF: the real block structure, not just the signature. A stub model (magic, width,
    # height, payload) generates a seed the target rejects outright -- giflib's gif2rgb
    # answers "Image of width or height 0" and stops -- so the campaign never reaches the
    # decoder. This is a complete 35-byte GIF89a: screen descriptor, global colour table, an
    # image descriptor and one LZW sub-block, which gif2rgb decodes.
    "gif": {"tokens": ("GIF87a", "GIF89a"), "seed": _GIF_LZW,
            "spec": [
                {"type": "magic", "value": b"GIF89a"},
                # the screen says how big the canvas is; the image descriptor says how big the
                # image is, and a decoder that trusts one while indexing the other is the
                # classic GIF bug -- so both are fields
                {"type": "u16", "endian": "little", "name": "sw", "seed_value": 16},
                {"type": "u16", "endian": "little", "name": "sh", "seed_value": 16},
                # bit 7: a global colour table follows; bits 0-2 = 1 -> four entries
                {"type": "u8", "name": "packed", "seed_value": 0x81},
                {"type": "u8", "name": "bg"},
                {"type": "u8", "name": "aspect"},
                {"type": "magic", "value": _GIF_GCT},
                {"type": "magic", "value": b"\x2c"},              # image separator
                {"type": "u16", "endian": "little", "name": "left"},
                {"type": "u16", "endian": "little", "name": "top"},
                {"type": "u16", "endian": "little", "name": "iw", "seed_value": 16},
                {"type": "u16", "endian": "little", "name": "ih", "seed_value": 16},
                {"type": "u8", "name": "ipacked"},
                {"type": "u8", "name": "lzwmin", "seed_value": _GIF_LZW_MIN},
                {"type": "u8", "name": "blen", "length_of": "lzw"},
                {"type": "blob", "name": "lzw"},
                {"type": "magic", "value": b"\x00\x3b"}]},        # terminator + trailer
    # NOT "BM": a two-character token matches as a substring of anything, and it picked BMP
    # for unzip, which then fuzzed a ZIP tool with bitmaps. A format's token has to be a
    # string only a parser for that format would carry.
    # BMP: a file header whose `off` says where the pixels start and a DIB header that says
    # how many there are. A decoder indexes pixels using width/height/bpp while trusting the
    # offset, which is exactly the pair that goes wrong -- so both are fields.
    "bmp": {"tokens": ("BITMAPINFOHEADER", "BITMAPFILEHEADER", ".bmp"), "seed": b"\x00" * 4,
            "spec": [
                {"type": "magic", "value": b"BM"},
                {"type": "u32", "endian": "little", "name": "filesize", "covers": "rest"},
                {"type": "magic", "value": b"\x00\x00\x00\x00"},      # reserved
                {"type": "u32", "endian": "little", "name": "pixoff",
                 "offset_of": "pixels", "role": "offset"},
                {"type": "group", "name": "dib", "spec": [
                    {"type": "u32", "endian": "little", "name": "dibsize", "seed_value": 40},
                    {"type": "u32", "endian": "little", "name": "width", "seed_value": 1},
                    {"type": "u32", "endian": "little", "name": "height", "seed_value": 1},
                    {"type": "u16", "endian": "little", "name": "planes", "seed_value": 1},
                    {"type": "u16", "endian": "little", "name": "bpp", "seed_value": 24},
                    {"type": "u32", "endian": "little", "name": "compression"},
                    {"type": "u32", "endian": "little", "name": "imgsize",
                     "length_of": "pixels", "role": "size"},
                    {"type": "u32", "endian": "little", "name": "xppm", "seed_value": 2835},
                    {"type": "u32", "endian": "little", "name": "yppm", "seed_value": 2835},
                    {"type": "u32", "endian": "little", "name": "ncolours"},
                    {"type": "u32", "endian": "little", "name": "nimportant"}]},
                {"type": "blob", "name": "pixels"}]},
    # RIFF/WAVE: a container of chunks, each `fourcc + size + data`, inside an outer chunk
    # whose own size covers everything after it. A decoder walks them by trusting those sizes.
    "riff": {"tokens": ("RIFF", "WAVE", "fmt "), "seed": b"\x00" * 4,
             "spec": [
                 {"type": "magic", "value": b"RIFF"},
                 {"type": "u32", "endian": "little", "name": "riffsize", "covers": "rest"},
                 {"type": "magic", "value": b"WAVE"},
                 {"type": "group", "name": "fmt", "spec": [
                     {"type": "magic", "value": b"fmt "},
                     {"type": "u32", "endian": "little", "name": "fmtsize",
                      "length_of": "fmtdata", "role": "size"},
                     {"type": "blob", "name": "fmtdata",
                      # PCM, mono, 8 kHz, 8-bit
                      "seed_value": struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)}]},
                 {"type": "group", "name": "data", "spec": [
                     {"type": "magic", "value": b"data"},
                     {"type": "u32", "endian": "little", "name": "datasize",
                      "length_of": "samples", "role": "size"},
                     {"type": "blob", "name": "samples"}]}]},
    # ZIP: a local header is not an archive. Every tool finds the files through the central
    # directory, located by absolute offset from the end-of-central-directory record, so a
    # model that stops at the local header generates something unzip refuses before parsing
    # anything: "End-of-central-directory signature not found". Described in full, the
    # directory's offsets and lengths are derived -- which is what makes them mutable: a
    # directory that points at the wrong place is a real archive with one field wrong, not
    # a file the parser discards.
    # byte magic never survives into a string table, and unzip writes the phrase hyphenated,
    # so the old tokens matched nothing at all and the strongest accidental match won instead
    "zip": {"tokens": ("End-of-central-directory", "central directory", "zipfile"), "seed": b"A",
            "spec": [
                {"type": "group", "name": "local", "spec": [
                    {"type": "magic", "value": b"PK\x03\x04"},
                    # version, flags, and method 8 -- DEFLATE, so the decompressor runs
                    {"type": "magic", "value": b"\x14\x00\x00\x00\x08\x00"},
                    {"type": "magic", "value": b"\x00\x00\x00\x00"},      # mod time, date
                    {"type": "u32", "endian": "little", "name": "crc", "crc32_of": "plain"},
                    {"type": "u32", "endian": "little", "name": "csize", "length_of": "data"},
                    {"type": "u32", "endian": "little", "name": "usize",
                     "seed_value": len(_ZIP_PLAIN)},
                    {"type": "u16", "endian": "little", "name": "namelen",
                     "length_of": "lname"},
                    {"type": "u16", "endian": "little", "name": "extralen",
                     "length_of": "lextra"},
                    {"type": "blob", "name": "lname"},
                    {"type": "blob", "name": "lextra", "seed_value": b""},
                    {"type": "blob", "name": "data", "seed_value": _ZIP_DEFLATED},
                    # never serialised: the uncompressed bytes, so the CRC field can name
                    # what a decompressor will actually check it against
                    {"type": "shadow", "name": "plain", "seed_value": _ZIP_PLAIN}]},
                {"type": "group", "name": "cd", "spec": [
                    {"type": "magic", "value": b"PK\x01\x02"},
                    {"type": "magic", "value": b"\x14\x00\x14\x00\x00\x00\x08\x00"},
                    {"type": "magic", "value": b"\x00\x00\x00\x00"},      # mod time, date
                    {"type": "u32", "endian": "little", "name": "ccrc", "crc32_of": "plain"},
                    {"type": "u32", "endian": "little", "name": "ccsize", "length_of": "data"},
                    {"type": "u32", "endian": "little", "name": "cusize",
                     "seed_value": len(_ZIP_PLAIN)},
                    {"type": "u16", "endian": "little", "name": "cnamelen",
                     "length_of": "cname"},
                    {"type": "u16", "endian": "little", "name": "cextralen",
                     "length_of": "cextra"},
                    {"type": "u16", "endian": "little", "name": "ccommentlen",
                     "length_of": "ccomment"},
                    {"type": "magic", "value": b"\x00\x00\x00\x00\x00\x00\x00\x00"},
                    # where the file's local header is -- derived, and therefore drivable
                    {"type": "u32", "endian": "little", "name": "localoff",
                     "offset_of": "local"},
                    {"type": "blob", "name": "cname"},
                    {"type": "blob", "name": "cextra", "seed_value": b""},
                    {"type": "blob", "name": "ccomment", "seed_value": b""}]},
                {"type": "magic", "value": b"PK\x05\x06"},
                {"type": "magic", "value": b"\x00\x00\x00\x00\x01\x00\x01\x00"},
                {"type": "u32", "endian": "little", "name": "cdsize", "length_of": "cd"},
                {"type": "u32", "endian": "little", "name": "cdoff", "offset_of": "cd"},
                {"type": "magic", "value": b"\x00\x00"}]},
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
        # a longer token is stronger evidence: "GIF89a" in a binary means something, two
        # characters mean nothing, so weight each hit by the length of what matched
        hits = sum(len(t) for t in entry["tokens"] if t and t in blob)
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
