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

import logging
import re
import struct
import zlib

from ... import observe
from .mutator import Mutator

_log = logging.getLogger(__name__)

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
                # An explicit length field is authoritative and caps the blob even when a
                # delimiter or size_from is ALSO present: a belt-and-suspenders shape (a length
                # AND a terminator) must never overrun the declared region, so `until`/
                # `size_from` may only end the blob EARLIER, never later, than the length says.
                cap = len(data)
                if name in covered:
                    total, start = covered[name]
                    # `length_of` sizes the blob from its own start; `covers` spans from the
                    # length field itself, so the blob ends at that field's start plus the span
                    cap = pos + int(total) if start is None else max(start + int(total), pos)
                    cap = min(max(cap, pos), len(data))
                if f.get("reserve"):
                    # A blob with no length field at all, followed by a FIXED-SIZE TRAILER:
                    # gzip's deflate stream runs to eight bytes before the end of the member,
                    # where its CRC32 and uncompressed size sit. Without this the trailing
                    # blob ate the trailer (every blob consumes the rest by default), so the
                    # model did not round-trip its own seed: parse swallowed the CRC, serialize
                    # wrote zeros back, and the decoder then rejected the baseline as corrupt.
                    cap = min(cap, max(pos, len(data) - int(f["reserve"])))
                if f.get("until") is not None:
                    # A blob that ends at a DELIMITER rather than at a length. H.264 in
                    # Annex-B framing has no length field at all -- a NAL unit runs until the
                    # next 00 00 00 01 start code -- and without this the first NAL body ate
                    # the whole stream, so the model described three NAL units and the
                    # mutator could only ever reach the first one's header.
                    delim = _as_bytes(f["until"])
                    nxt = data.find(delim, pos, cap) if delim else -1
                    stop = nxt if nxt >= 0 else cap
                elif f.get("size_from"):
                    # A blob whose length lives in part of ANOTHER field: RTP's CSRC list is
                    # four bytes per unit of CC, and CC is the low nibble of byte 0. `covers`
                    # and `length_of` both need a whole integer field to point at, so a count
                    # packed into a bitfield -- which is most of how binary network protocols
                    # are shaped -- could not be expressed at all.
                    sf = f["size_from"]
                    raw = int(seen.get(sf.get("field")) or 0)
                    n = ((raw >> int(sf.get("shift", 0))) & int(sf.get("mask", 0xFFFFFFFF))
                         ) * int(sf.get("scale", 1))
                    stop = min(pos + max(n, 0), cap)
                else:
                    stop = cap
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


def boundary_seeds(name: str) -> list:
    """The valid seed PLUS crash-shaped variants for a builtin format: each record carrying an
    offset/size ROLE pair is set to the wrap-the-sum values that pass a 32-bit bounds check while
    the offset still points out of bounds (jhead's GPS read -- 0x00ffffff + 0xff000002 is 1 in 32
    bits -- and the shape of many offset+length OOB reads). Seeding these puts the bug in the
    corpus, so the campaign's calibration pass detonates it on the FIRST executions instead of
    waiting on a byte/field mutator to construct both halves by luck -- exactly what
    textconf.boundary_seeds does for a config. Base seed first, then one variant per pair; just the
    base when the format declares no offset/size pair. Best-effort -- any failure yields fewer."""
    base = seed_for_name(name)
    if base is None:
        return []
    out = [base]
    entry = _BUILTINS.get(name)
    try:
        model = FormatModel([dict(f) for f in entry["spec"]])
        fields = model.parse(base)
        for scope in _scopes(fields):
            o = next((x for x in scope if x["f"].get("role") == "offset"), None)
            s = next((x for x in scope if x["f"].get("role") == "size"), None)
            if o is None or s is None:
                continue
            w = min(_INT[o["f"]["type"]][0], _INT[s["f"]["type"]][0]) * 8
            mask = (1 << w) - 1
            if mask < 0xFFFF:                            # too narrow to point far AND wrap the sum
                continue
            save = (o["val"], s["val"])
            o["val"] = 0x00FFFFFF & mask                 # a far offset that still fits the field
            s["val"] = ((1 << w) + 1 - o["val"]) & mask  # complement: offset + size wraps to 1
            try:
                out.append(model.serialize(fields))
            except Exception:                            # noqa: BLE001
                pass
            o["val"], s["val"] = save                    # restore: each variant wraps ONE pair
    except Exception:                                    # noqa: BLE001
        pass
    out += _record_variant_seeds(entry, base)
    seen, uniq = set(), []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq


def _array_records(fields):
    """Every RECORD (one array element's parsed fields) at any nesting depth."""
    for x in fields:
        val, kind = x.get("val"), x["f"].get("type")
        if kind == "group" and isinstance(val, list):
            yield from _array_records(val)
        elif kind == "array" and isinstance(val, list):
            for rec in val:
                if isinstance(rec, list):
                    yield rec
                    yield from _array_records(rec)


def _record_variant_seeds(entry, base: bytes) -> list:
    """One extra seed per declared `record_variants` value.

    A format whose behaviour is SELECTED by one field in one record needs a seed per value of
    that field, or the campaign only ever exercises the default. TIFF is the measured case: the
    baseline sets Compression=1 (none), so 27,458 executions of a libtiff tool never entered a
    single codec decoder -- which is where 4.0.3's CVEs are. See `_TIFF_CODECS`.

    Declared, not hardcoded: `{"key": ..., "match": ..., "field": ..., "values": (...)}` means
    "in the record whose `key` field equals `match`, set `field` to each of `values`".
    Best-effort -- a format that declares none, or a serialize that fails, yields nothing.
    """
    rv = (entry or {}).get("record_variants")
    if not rv:
        return []
    out = []
    for variant in rv.get("values", ()):
        # An int is shorthand for "set the declared field on the declared record"; a sequence of
        # (key, value) pairs sets several records, for a selector its companions must agree with.
        pairs = ((rv["match"], variant),) if isinstance(variant, int) else tuple(variant)
        try:
            model = FormatModel([dict(f) for f in entry["spec"]])
            fields = model.parse(base)                   # re-parse per variant: one change each
            recs = list(_array_records(fields))
            applied = 0
            for key_val, set_val in pairs:
                for rec in recs:
                    k = next((y for y in rec if y["f"].get("name") == rv["key"]), None)
                    if k is None or k.get("val") != key_val:
                        continue
                    tgt = next((y for y in rec if y["f"].get("name") == rv["field"]), None)
                    if tgt is not None:
                        tgt["val"] = set_val
                        applied += 1
                    break
            if not applied:
                return out                               # the key is absent: no variant applies
            out.append(model.serialize(fields))
        except Exception:                                # noqa: BLE001 -- best effort per variant
            continue
    return out


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
            if "seed_value" in f:
                val = f["seed_value"]
            elif f.get("size_from"):
                # its length is whatever the seeded count field says, which for a baseline is
                # zero -- handing it the payload would contradict the count and the parser
                # would reject the seed it was given to start from
                val = b""
            else:
                val = payload
            fields.append({"f": f, "val": _as_bytes(val)})
            if "seed_value" not in f and not f.get("size_from"):
                blobs.append(fields[-1])
    return fields, blobs


def seed_for(model: "FormatModel", payload: bytes = b"A" * 64,
             tail: bytes | None = None) -> bytes:
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
            _log.debug("struct-mutate: model.parse failed; falling back to byte havoc",
                       exc_info=True)
            return self.byte.mutate(data, corpus)
        if not fields:
            return self.byte.mutate(data, corpus)
        # The whole mutate-and-serialize path degrades to byte havoc on any error, not just a
        # serialize failure: a field-driver on an analyst-supplied spec can hit an edge the
        # model did not anticipate, and one bad draw must not take the campaign down with it.
        try:
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
            return self.model.serialize(fields)
        except Exception:
            _log.debug("struct-mutate: field mutate/serialize failed; falling back to byte havoc",
                       exc_info=True)
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
        # Candidates for the wrap-the-sum attack: a far offset that still fits the field. For a
        # narrow field (u8/u16) `mask <= 0xFFFF` and there are none, so `rng.choice([])` would
        # raise -- take the plain far/edge branch instead of driving an empty choice.
        far = [x for x in _FAR if 0xFFFF < x <= mask]
        if far and self.rng.random() < 0.5:
            off = self.rng.choice(far) & mask
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

# --- TIFF -------------------------------------------------------------------------------
# A TIFF is a header pointing at a directory of 12-byte entries, and the entries point at the
# pixel data by ABSOLUTE file offset. That is the whole reason this format produces so many
# OOB reads: StripOffsets says where the data is and StripByteCounts says how much of it there
# is, both chosen by the file, and a decoder that trusts either walks off the end.
#
# The baseline is a real 1x1 8-bit greyscale image (verified accepted by tiffinfo), so the
# campaign starts INSIDE the decoder rather than at the magic check; the two fields above are
# the ones `boundary_seeds` then drives to the wrap-the-sum values.
_TIFF_IFD_OFF = 8                                  # header is II*\0 + the 4-byte IFD offset
_TIFF_NENT = 8
# where the strip data lands in the baseline: header + count + entries + next-IFD pointer
_TIFF_STRIP_OFF = _TIFF_IFD_OFF + 2 + 12 * _TIFF_NENT + 4
_TIFF_ENTRIES = [
    {"tag": 256, "fmt": 3, "count": 1, "value": 1},        # ImageWidth
    {"tag": 257, "fmt": 3, "count": 1, "value": 1},        # ImageLength
    {"tag": 258, "fmt": 3, "count": 1, "value": 8},        # BitsPerSample
    {"tag": 259, "fmt": 3, "count": 1, "value": 1},        # Compression: none
    {"tag": 262, "fmt": 3, "count": 1, "value": 1},        # Photometric: min-is-black
    # StripOffsets: an absolute file offset, which is what makes it the format's sharp edge
    {"tag": 273, "fmt": 4, "count": 1, "value": _TIFF_STRIP_OFF},
    {"tag": 278, "fmt": 3, "count": 1, "value": 1},        # RowsPerStrip
    {"tag": 279, "fmt": 4, "count": 1, "value": 1},        # StripByteCounts
]

# One seed per CODEC, and this is the difference between fuzzing a TIFF reader and fuzzing its
# directory parser. The baseline sets Compression=1 (none), so every mutant decodes with the
# null codec and NONE of libtiff 4.0.3's codec decoders is ever entered -- while that is exactly
# where its CVEs live (OJPEG, LZW, PixarLog, NeXT, ThunderScan, CCITT fax). Changing the tag is
# enough to get there: libtiff dispatches on Compression when it sets up the decoder, so the
# strip bytes reach that codec's own setup/predictor path, which is where the inconsistent-tag
# defects are. The streams are NOT valid for the codec, deliberately -- a decoder handed
# incoherent input is the condition under test, and the mutator starts from inside it.
# A codec that its COMPANION TAGS contradict is refused in setup, which reaches the decoder's
# door and no further -- measured: "Fax3SetupState: Bits/sample must be 1", "ThunderSetupDecode:
# Wrong bitspersample value (8)", "LogLuvSetupDecode: Inappropriate photometric interpretation
# 1". A variant may therefore set several tags, so the configuration is coherent enough to get
# past setup and into the decode loop that the campaign is there to mutate.
_TIFF_CODECS = (
    5,                                   # LZW
    6,                                   # OJPEG (old-style JPEG): densest CVE cluster in 4.0.3
    7,                                   # JPEG
    8,                                   # Adobe Deflate
    ((259, 4), (258, 1)),                # CCITT G4 -- 1 bit/sample
    32766,                               # NeXT RLE
    32773,                               # PackBits
    ((259, 32809), (258, 4)),            # ThunderScan -- 4 bits/sample only
    32909,                               # PixarLog
    ((259, 34676), (262, 32845), (258, 16)),   # SGILog -- photometric LOGLUV, 16 bits
)

# --- PDF --------------------------------------------------------------------------------
# PDF's cross-reference offsets are ASCII DECIMAL, which the spec language cannot express
# (`offset_of` writes a binary integer), so the body is one blob seeded with a complete,
# verified-parsable document rather than a field-by-field model. That is still the difference
# between a campaign that reaches the object parser and one that is rejected at byte 0: the
# header stays `magic`, so every mutant is still a PDF, and the havoc lands on objects,
# stream lengths and the xref table instead of on "%PDF".
def _pdf_body() -> bytes:
    objs = [b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj",
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj",
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 99 99]/Contents 4 0 R>>endobj",
            b"4 0 obj<</Length 44>>stream\nBT /F1 12 Tf 10 50 Td (lykos) Tj ET\nendstream endobj"]
    out, offs = b"", []
    for o in objs:
        offs.append(len(_PDF_HEADER) + len(out))
        out += o + b"\n"
    xref = len(_PDF_HEADER) + len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs:
        out += b"%010d 00000 n \n" % o
    out += b"trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


_PDF_HEADER = b"%PDF-1.4\n"
_PDF_BODY = _pdf_body()

# --- XML --------------------------------------------------------------------------------
# Text format, so there are no lengths to keep coherent; what matters is that the seed
# declares the constructs the bugs live in -- a DOCTYPE, an internal entity, an attribute --
# because an XML parser's interesting code is entity expansion and encoding handling, and a
# document with none of it exercises the element loop only.
_XML_DOC = (b'<!DOCTYPE r [<!ENTITY e "lykos"><!ENTITY f "&e;&e;">]>\n'
            b'<r a="1" xmlns:n="urn:x"><n:c>&f;</n:c><![CDATA[<raw>]]></r>\n')

# --- gzip -------------------------------------------------------------------------------
# A 10-byte header, a raw DEFLATE stream, then a CRC32 of the UNCOMPRESSED bytes and their
# length. The CRC is why a blind mutator gets nowhere past the inflate call: a decoder checks
# it and reports corruption. `crc32_of` a `shadow` lets the model carry the plain bytes it is
# a checksum OF without serialising them, exactly as the ZIP model does.
_GZ_PLAIN = b"lykos test payload, compressible compressible compressible\n"


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


_GZ_DEFLATED = _raw_deflate(_GZ_PLAIN)

# --- bzip2 ------------------------------------------------------------------------------
# bzip2's block is Huffman-coded and bit-packed: nothing in the spec language can emit a valid
# one, so the baseline is a real compressed block kept as the seed value and the magic/level
# stay fields. The level byte ("1".."9") is a field because it sets the block size a decoder
# allocates from, and the randomised/blocksize bits are where its historical overflows are.
def _bz2_block():
    """A real compressed block, split at the two fields that are byte-aligned in it.

    Everything in a bzip2 block after its header is Huffman-coded and BIT-packed, so no
    byte-field model can emit one -- but the FIRST block's 48-bit magic and its 32-bit CRC sit
    immediately after the 4-byte stream header, which is byte-aligned, so those two are real
    fields rather than part of the opaque payload. The CRC is NOT derived: bzip2 uses the
    non-reflected CRC-32/BZIP2 polynomial, and `crc32_of` computes zlib's reflected one, so
    deriving it would quietly produce a stream every decoder rejects.
    """
    import bz2
    raw = bz2.compress(b"lykos test payload\n" * 4, 9)[4:]        # strip "BZh9"
    return raw[:6], int.from_bytes(raw[6:10], "big"), raw[10:]


_BZ2_MAGIC, _BZ2_CRC, _BZ2_BODY = _bz2_block()

# --- ELF --------------------------------------------------------------------------------
# The format every binary-analysis tool parses, and the one whose header is nothing but
# counts and offsets a reader has to trust: e_shoff/e_shnum/e_shentsize say where the section
# table is and how big, and a tool that multiplies them and reads gets an OOB read out of a
# 64-byte file. readelf/objdump/nm/strip are all reachable this way, which is why the seed is
# a real loadable ELF rather than a stub: a tool that rejects the header never reaches the
# section walker.
_ELF_SHSTR = b"\x00.shstrtab\x00"
_ELF_EHSIZE = 64
_ELF_SHENT = 64
_ELF_NSHDR = 3                                     # NULL, .shstrtab, one PROGBITS
def _elf_shdrs() -> bytes:
    def sh(name, typ, off, size, link=0, entsize=0, flags=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, 0, off, size, link, 0, 1, entsize)
    return (sh(0, 0, 0, 0)                                      # SHT_NULL
            + sh(1, 3, _ELF_EHSIZE, len(_ELF_SHSTR))            # .shstrtab (SHT_STRTAB)
            + sh(1, 1, _ELF_EHSIZE, 0))                         # SHT_PROGBITS


_ELF_SHDRS = _elf_shdrs()




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
    # MPEG transport stream: the shape a multicast video receiver parses, and one where blind
    # mutation is worse than useless. A TS packet is 188 bytes beginning with sync byte 0x47,
    # and a parser drops anything that does not -- so byte mutation destroys the packet before
    # any parsing code sees it. Measured on a receiver with a planted overflow: 60 executions
    # over multicast produced 3 distinct behaviours and no crash, because almost every mutant
    # was rejected at the sync byte.
    #
    # The field that matters is the adaptation-field length: it is one byte, it is chosen by
    # the STREAM, and a receiver that trusts it copies that many bytes out of a 188-byte
    # packet. Keeping the sync byte fixed and driving that length is the whole game.
    # NOT "PAT"/"PMT": they are real MPEG-TS terms and useless as evidence, because a
    # three-character substring matches anything. "PAT" hit "MAX_PATHS reached" and detected
    # xmllint as a transport-stream parser -- which is worse than detecting nothing, since the
    # campaign would then generate TS packets for an XML parser.
    "mpegts": {"tokens": ("mpegts", "MPEG-TS", "adaptation_field", "transport_stream"),
               "seed": b"\x00" * 164,
               "spec": [
                   {"type": "magic", "value": b"\x47"},          # sync byte: never mutate
                   # transport_error / payload_unit_start / priority, then the 13-bit PID
                   {"type": "u8", "name": "pid_hi", "seed_value": 0x00},
                   {"type": "u8", "name": "pid_lo", "seed_value": 0x21},
                   # scrambling control, adaptation_field_control, continuity counter
                   {"type": "u8", "name": "afc", "seed_value": 0x20},
                   {"type": "group", "name": "adaptation", "spec": [
                       # The field the bug lives behind: one byte, chosen by the STREAM, and a
                       # receiver that trusts it copies that many bytes out of a 188-byte
                       # packet. `covers` lets the mutator keep it coherent most rounds and
                       # deliberately drive it out of range on the others.
                       {"type": "u8", "name": "af_len", "covers": "rest", "role": "size"},
                       {"type": "u8", "name": "af_flags", "seed_value": 0x10},
                       # PCR, when the flags say it is present: 33-bit base + extension,
                       # carried as six bytes
                       {"type": "u32", "endian": "big", "name": "pcr_base", "seed_value": 0},
                       {"type": "u16", "endian": "big", "name": "pcr_ext", "seed_value": 0},
                       {"type": "blob", "name": "af_stuffing"},
                   ]},
                   {"type": "blob", "name": "payload"},
               ]},
    # RTP (RFC 3550): the packet a network video receiver actually gets, and the one place
    # the mpegts model does not reach -- an RTP receiver parses the RTP header BEFORE it ever
    # sees a TS packet, so a bug in that header is hit first and by every stream.
    #
    # Two fields here are the classic shape: chosen by the sender, trusted by the receiver,
    # and used as a count.
    #   * CC, the low nibble of byte 0, says how many 4-byte CSRC identifiers follow. A
    #     receiver that reads CC and then reads CC*4 bytes -- without checking them against
    #     the datagram it actually received -- walks off the end. Byte 0 is a whole u8 here
    #     rather than a bitfield because the spec language has no bitfields; mutating the
    #     byte drives CC through its whole 0..15 range, which is the point.
    #   * the extension length, which counts 32-bit WORDS of header extension.
    #
    # Both are `size_from` rather than `covers`, because both are counts in a unit that is
    # not bytes -- four bytes per CC, four bytes per extension word -- and `covers` is bytes.
    # `size_from` bounds the blob on the way back IN without forcing the field to agree on
    # the way out, which is the whole point: the baseline stays a packet the receiver
    # accepts, and the mutator is still free to drive the count past what the datagram holds.
    # Without a bound the blob after each of them swallowed the rest of the packet, so the
    # payload was unreachable and the extension fields only ever moved when something before
    # them shifted.
    #
    # Seeded X=1 (byte 0 = 0x90) so the extension path is parsed at all, and PT=33/MP2T
    # (byte 1 = 0x21) with a real TS packet as the payload, which is how video over RTP is
    # carried in practice -- so a receiver that demuxes reaches its TS parser too.
    "rtp": {"tokens": ("RTP/AVP", "rtpmap", "rtcp", "ssrc", "rtp"),
            "seed": b"\x47\x00\x21\x10" + b"\x00" * 184,
            "spec": [
                # V=2, P=0, X=1, CC=0
                {"type": "u8", "name": "v_p_x_cc", "seed_value": 0x90},
                # M=0, PT=33 (MP2T)
                {"type": "u8", "name": "m_pt", "seed_value": 0x21},
                {"type": "u16", "endian": "big", "name": "seq", "seed_value": 1},
                {"type": "u32", "endian": "big", "name": "timestamp", "seed_value": 0},
                {"type": "u32", "endian": "big", "name": "ssrc", "seed_value": 0xDEADBEEF},
                # present only when CC > 0; the mutator grows this as it drives byte 0
                # four bytes per unit of CC, which is the low nibble of byte 0
                {"type": "blob", "name": "csrc",
                 "size_from": {"field": "v_p_x_cc", "mask": 0x0F, "scale": 4}},
                {"type": "group", "name": "ext", "spec": [
                    # 0xBEDE: the one-byte-header extension profile of RFC 5285
                    {"type": "u16", "endian": "big", "name": "ext_profile",
                     "seed_value": 0xBEDE},
                    # in 32-bit WORDS, which is why `covers` cannot express it:
                    # covers is measured in bytes, so it would make the baseline four times
                    # too large and the receiver would reject every unmutated packet
                    {"type": "u16", "endian": "big", "name": "ext_len", "seed_value": 1,
                     "role": "size"},
                    {"type": "blob", "name": "ext_data",
                     "size_from": {"field": "ext_len", "scale": 4},
                     "seed_value": b"\x00" * 4}]},
                {"type": "blob", "name": "payload"},
            ]},
    # H.264 in Annex-B framing: the elementary stream inside an RTP or TS payload, and what a
    # decoder is handed once the transport is stripped. There is no length field in Annex-B --
    # a NAL unit runs until the next start code -- so unlike every other model here the value
    # is not in keeping a length coherent. It is in keeping the START CODES intact: a decoder
    # scans for 00 00 01 and discards everything before it, so blind byte mutation destroys
    # the framing and the decoder never parses anything. Exactly the mpegts sync-byte
    # argument, which is why the start codes are `magic` and the NAL bodies are not.
    #
    # The seeded SPS and PPS are real (baseline, 16x16): a decoder that rejects a malformed
    # parameter set never reaches slice decoding, so the interesting code is only reachable
    # if the stream is valid up to that point. The IDR slice body is the mutable blob.
    "h264": {"tokens": ("h264", "H.264", "nal_unit_type", "avcC", "AVC"),
             "seed": b"\x88\x80\x10\x00",
             "spec": [
                 {"type": "magic", "value": b"\x00\x00\x00\x01"},
                 # nal_ref_idc=3, nal_unit_type=7 (SPS)
                 {"type": "u8", "name": "sps_hdr", "seed_value": 0x67},
                 {"type": "blob", "name": "sps", "until": b"\x00\x00\x00\x01",
                  "seed_value": b"\x42\x00\x0a\xf8\x41\xa2"},
                 {"type": "magic", "value": b"\x00\x00\x00\x01"},
                 # nal_ref_idc=3, nal_unit_type=8 (PPS)
                 {"type": "u8", "name": "pps_hdr", "seed_value": 0x68},
                 {"type": "blob", "name": "pps", "until": b"\x00\x00\x00\x01",
                  "seed_value": b"\xce\x3c\x80"},
                 {"type": "magic", "value": b"\x00\x00\x00\x01"},
                 # nal_ref_idc=3, nal_unit_type=5 (IDR slice) -- mutating this byte walks the
                 # decoder's nal_unit_type dispatch, which is where the reserved and
                 # unhandled types live
                 {"type": "u8", "name": "idr_hdr", "seed_value": 0x65},
                 {"type": "blob", "name": "idr_slice", "until": b"\x00\x00\x00\x01",
                  "seed_value": b"\x88\x80\x10\x00"},
                 {"type": "magic", "value": b"\x00\x00\x00\x01"},
                 # nal_ref_idc=2, nal_unit_type=1 (non-IDR slice): a real stream is one IDR
                 # followed by P-slices, and a decoder only reaches its inter-prediction and
                 # reference-list code on a non-IDR one -- an IDR-only stream leaves the
                 # larger half of the slice decoder unvisited
                 {"type": "u8", "name": "slice_hdr", "seed_value": 0x41},
                 {"type": "blob", "name": "slice"},
             ]},
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
    # TIFF: measured on this corpus, libtiff's tools were detected as "jpeg" (they link
    # libjpeg, so they carry its strings) and handed a JPEG seed their TIFF reader rejects at
    # the magic. The format's own markers are its tag NAMES and its error strings, which only
    # a TIFF implementation carries -- and `TIFFOpen` is in the import table of anything that
    # reads one through the shared library, where there are no strings to mine at all.
    "tiff": {"tokens": ("TIFFReadDirectory", "StripByteCounts", "SamplesPerPixel",
                        "TIFF Directory", "PlanarConfiguration", "TIFFOpen"),
             "imports": ("TIFFOpen", "TIFFClientOpen", "TIFFRead*", "TIFFGetField"),
             "seed": b"\x80",
             "spec": [
                 {"type": "magic", "value": b"II*\x00"},
                 {"type": "u32", "endian": "little", "name": "ifd_off",
                  "offset_of": "ifd", "role": "offset"},
                 {"type": "group", "name": "ifd", "spec": [
                     # the entry count: a reader allocates and walks `nent` 12-byte entries,
                     # and this is the field that makes it walk past the end of the file
                     {"type": "u16", "endian": "little", "name": "nent",
                      "seed_value": _TIFF_NENT, "role": "size"},
                     {"type": "array", "name": "ifd0", "count": "nent", "spec": _IFD_ENTRY,
                      "seed_records": _TIFF_ENTRIES},
                     {"type": "u32", "endian": "little", "name": "next_ifd"}]},
                 {"type": "blob", "name": "strip"}],
     # one extra seed per codec: find the IFD record whose `tag` is 259 (Compression) and set
     # its `value` to each codec in turn. See `_TIFF_CODECS`.
     "record_variants": {"key": "tag", "match": 259, "field": "value",
                         "values": _TIFF_CODECS}},
    # PDF: mupdf's mutool was detected as "zip" (it reads epub/xps, so it carries ZIP's
    # strings) and never got a PDF seed at all. The body is a blob for the reason given at
    # `_pdf_body`: the xref offsets are ASCII decimal and the spec language has no such field.
    "pdf": {"tokens": ("%PDF-", "startxref", "/MediaBox", "endobj", "/Pages",
                       "xref", "/Catalog"),
            "imports": ("pdf_open_document", "FPDF_LoadDocument", "poppler_document_new"),
            "spec": [
                {"type": "magic", "value": _PDF_HEADER},
                {"type": "blob", "name": "body", "seed_value": _PDF_BODY}]},
    # XML: the thin-CLI case in its purest form -- xmlwf carries NO xml strings of its own,
    # because every one of them lives in the libexpat it links against. Its IMPORT table says
    # `XML_ParserCreate` in plain text, which is why detection reads imports as well as
    # strings; with strings alone this target was undetectable in principle, not by accident.
    "xml": {"tokens": ("<?xml", "not well-formed", "XML_ParserCreate", "xmlns",
                       "DOCTYPE", "encoding specified"),
            # expat exports `XML_*`; libxml2 exports several hundred `xml*` functions, so
            # the prefix is the marker rather than a list that would always be incomplete
            "imports": ("XML_Parse*", "XML_SetElementHandler", "xmlParse*", "xmlRead*",
                        "xmlCtxt*", "xmlNewParserCtxt", "xmlCreatePushParserCtxt"),
            "spec": [
                {"type": "magic", "value": b'<?xml version="1.0" encoding="UTF-8"?>\n'},
                {"type": "blob", "name": "doc", "seed_value": _XML_DOC}]},
    # gzip: deliberately NOT keyed on "inflate" or "incorrect header check". Every PNG reader
    # links zlib and carries both, so those tokens detect a PNG decoder as a gzip reader and
    # the campaign then generates gzip members for a PNG parser. `gz*` is the gzip-FILE API,
    # which only a program that reads .gz files calls.
    "gzip": {"tokens": ("gzopen", "gzread", "gzdopen", "gzip", ".gz"),
             "imports": ("gzopen", "gzread", "gzdopen", "gzgets", "gzbuffer"),
             "spec": [
                 {"type": "magic", "value": b"\x1f\x8b"},
                 {"type": "u8", "name": "cm", "seed_value": 8},        # deflate
                 # FEXTRA | FNAME. Seeded with both OPTIONAL members present on purpose: an
                 # extra field is a length a decoder trusts, and a stored filename is a
                 # NUL-terminated string it copies -- the two places gzip readers have
                 # historically gone wrong -- and neither exists to be parsed unless the flag
                 # byte says so. A seed with FLG=0 leaves that code unreachable for the whole
                 # campaign; mutating the flag byte then walks the decoder's member dispatch.
                 {"type": "u8", "name": "flg", "seed_value": 0x0C},
                 {"type": "u32", "endian": "little", "name": "mtime"},
                 {"type": "u8", "name": "xfl"},
                 {"type": "u8", "name": "os", "seed_value": 3},
                 {"type": "u16", "endian": "little", "name": "xlen",
                  "length_of": "extra", "role": "size"},
                 # one well-formed subfield: SI1 SI2 then its own 16-bit length
                 {"type": "blob", "name": "extra", "seed_value": b"lk\x04\x00seed"},
                 {"type": "blob", "name": "fname", "until": b"\x00",
                  "seed_value": b"lykos.bin"},
                 {"type": "magic", "value": b"\x00"},                 # the NAME terminator
                 # stops eight bytes short of the end: the CRC and size trailer live there,
                 # and the format gives the stream no length field to stop it earlier
                 {"type": "blob", "name": "data", "seed_value": _GZ_DEFLATED, "reserve": 8},
                 {"type": "u32", "endian": "little", "name": "crc", "crc32_of": "plain"},
                 # the decompressed SIZE, which an extractor may believe before it has the
                 # bytes to back it up -- the allocation-from-the-file shape
                 {"type": "u32", "endian": "little", "name": "isize",
                  "seed_value": len(_GZ_PLAIN), "role": "size"},
                 {"type": "shadow", "name": "plain", "seed_value": _GZ_PLAIN}]},
    # bzip2: "BZh" + a level digit that sets the block size the decoder allocates from.
    "bzip2": {"tokens": ("bzip2", "bzlib", "BZ2_bzDecompress", "libbzip2", ".bz2"),
              "imports": ("BZ2_bzDecompress", "BZ2_bzRead", "BZ2_bzReadOpen",
                          "BZ2_bzDecompressInit", "BZ2_bzopen"),
              "spec": [
                  {"type": "magic", "value": b"BZh"},
                  # "1".."9": the 100k-block multiplier, and the number a decoder sizes its
                  # buffers from before it has seen any of the data they will hold
                  {"type": "u8", "name": "level", "seed_value": 0x39, "role": "size"},
                  {"type": "magic", "value": _BZ2_MAGIC},            # 48-bit block magic
                  # the block CRC a decoder checks before it trusts the block it just
                  # decompressed: described so the mutator can drive the corruption path
                  {"type": "u32", "endian": "big", "name": "blk_crc",
                   "seed_value": _BZ2_CRC},
                  {"type": "blob", "name": "block", "seed_value": _BZ2_BODY}]},
    # ELF: readelf was detected as "h264" -- a coincidence of three-letter tokens -- and fuzzed
    # with 37 bytes of video. Binary-analysis tools are a real attack surface and their input
    # is nothing but counts and offsets: e_shoff + e_shnum * e_shentsize is a multiplication
    # the reader performs on attacker numbers, which is this model's whole point.
    "elf": {"tokens": ("Section Headers:", "Program Headers:", "ELF Header:", "PT_LOAD",
                       "section headers", "SHT_PROGBITS", "Elf64_Shdr"),
            "imports": ("elf_begin", "elf_getshdrnum", "gelf_getshdr", "elf64_getshdr",
                        "bfd_openr", "bfd_get_section_contents"),
            "spec": [
                {"type": "magic", "value": b"\x7fELF\x02\x01\x01\x00"},
                {"type": "magic", "value": b"\x00" * 8},            # e_ident padding
                {"type": "u16", "endian": "little", "name": "e_type", "seed_value": 1},
                {"type": "u16", "endian": "little", "name": "e_machine", "seed_value": 62},
                {"type": "u32", "endian": "little", "name": "e_version", "seed_value": 1},
                {"type": "u64", "endian": "little", "name": "e_entry"},
                {"type": "u64", "endian": "little", "name": "e_phoff", "role": "offset"},
                # where the section table is: derived here, so a mutation that moves it is a
                # real ELF with one wrong offset rather than a file the reader discards
                {"type": "u64", "endian": "little", "name": "e_shoff",
                 "offset_of": "shdrs", "role": "offset"},
                {"type": "u32", "endian": "little", "name": "e_flags"},
                {"type": "u16", "endian": "little", "name": "e_ehsize",
                 "seed_value": _ELF_EHSIZE},
                {"type": "u16", "endian": "little", "name": "e_phentsize", "seed_value": 56},
                {"type": "u16", "endian": "little", "name": "e_phnum"},
                # entsize * num is the multiplication; both halves are fields on purpose
                {"type": "u16", "endian": "little", "name": "e_shentsize",
                 "seed_value": _ELF_SHENT, "role": "size"},
                {"type": "u16", "endian": "little", "name": "e_shnum",
                 "seed_value": _ELF_NSHDR, "role": "size"},
                {"type": "u16", "endian": "little", "name": "e_shstrndx", "seed_value": 1},
                {"type": "blob", "name": "shstr", "seed_value": _ELF_SHSTR},
                {"type": "blob", "name": "shdrs", "seed_value": _ELF_SHDRS}]},
}


#: Formats whose LAYOUT the spec language cannot express. The entry exists to DETECT the
#: format and emit a VALID specimen, not to drive field-aware mutation:
#:
#:   * ``pdf``   -- its cross-reference offsets are ASCII DECIMAL; `offset_of` writes a binary
#:                  integer, so the xref table cannot be a derived field.
#:   * ``xml``   -- a grammar rather than a byte layout. `xmlgrammar.XmlMutator` mutates it;
#:                  this entry's job is to put a well-formed document in the corpus, which is
#:                  what makes that mutator reachable on a target nobody seeded.
#:   * ``bzip2`` -- everything after the block header is Huffman-coded and bit-packed.
#:
#: These are exempt from the ">= 10 described fields" invariant (`test_format_models`), and
#: that is a narrow exemption rather than a loophole: the invariant exists because a STUB
#: model emits a file the target rejects, and each of these is tested against a real parser
#: for its format instead. A new entry belongs here only when the spec language genuinely
#: cannot describe the format -- not when describing it is merely work.
SEED_ONLY = frozenset({"pdf", "xml", "bzip2"})


def builtin(name: str):
    entry = _BUILTINS.get(name)
    return FormatModel([dict(f) for f in entry["spec"]]) if entry else None


def builtin_names() -> list:
    return sorted(_BUILTINS)


#: An imported symbol is a LINKAGE FACT, not a coincidence: a binary that calls
#: `XML_ParserCreate` reads XML, where a binary that merely contains the string "xml" may be
#: printing a usage line. Measured need for it: `xmlwf` has no XML strings at all.
#:
#: A FLAT weight, and capped. Weighting an import by the length of its name (the first version
#: here) says `BZ2_bzDecompressInit` is four times the evidence of `gzread`, which is not a
#: claim about anything -- and it ranked `unzip` as a bzip2 reader, because unzip imports four
#: long bzlib symbols to decompress members INSIDE a zip. A linkage fact is strong but it is
#: one fact, and a library's symbol count is an implementation detail of that library.
_IMPORT_HIT = 10
_IMPORT_CAP = 3

#: A parser's strings are SATURATED with its format's vocabulary -- unzip says "zipfile"
#: dozens of times -- while a codec it merely supports is named once or twice. Bounded at
#: three so a help text cannot swamp the ranking.
_TOKEN_CAP = 3


def detect_formats(strings, imports=()) -> list:
    """Every builtin this binary looks like a parser for, strongest first.

    A blind mutator cannot invent four valid magic bytes, so a parser rejects everything it is
    given and the campaign does no work: jhead ran 98,500 executions for zero finds against a
    bug AFL++ reached in 60 seconds WITH a valid seed. The binary itself says which format it
    reads, so the model and the seed can both be chosen without an analyst supplying either.

    Two things this corpus forced, both measured rather than anticipated:

    * **A list, not a winner.** Real readers read several formats -- mupdf's mutool takes PDF,
      XPS, EPUB (zip), PNG, GIF and JPEG -- and picking one makes the other seeds unreachable.
      Scoring them all and seeding the top few removes the ranking problem instead of trying
      to win it: mutool was ranked "zip", which is not even wrong, and got no PDF seed.
    * **Imports, not only strings.** `xmlwf` carries no XML strings at all; they live in the
      libexpat it links against. String evidence cannot see through a shared library in
      principle, and its import table says `XML_ParserCreate` in plain text.
    """
    blob = "\n".join(s for s in strings if s)
    imps = {str(s) for s in (imports or ()) if s}
    scored = []
    for name, entry in _BUILTINS.items():
        # a longer token is stronger evidence: "GIF89a" in a binary means something, two
        # characters mean nothing, so weight each hit by the length of what matched -- times
        # how often it occurs, bounded, because a parser repeats its format's vocabulary
        score = sum(len(t) * min(_TOKEN_CAP, _token_count(t, blob))
                    for t in entry["tokens"] if t)
        score += _IMPORT_HIT * min(_IMPORT_CAP, _import_hits(entry.get("imports", ()), imps))
        if score:
            scored.append((score, name))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [n for _s, n in scored]


def detect_format(strings, imports=()) -> str | None:
    """The single strongest candidate -- `detect_formats`'s first row."""
    ranked = detect_formats(strings, imports)
    return ranked[0] if ranked else None


# Below this, a substring match is not evidence of anything -- it is a coincidence waiting to
# happen. Short tokens have to match as WORDS: "PNG" in "PNG image" is a signal, "PAT" inside
# "MAX_PATHS" is not, and the difference is a word boundary rather than a length.
_SHORT_TOKEN = 5
_WORD_CACHE: dict = {}


def _import_hits(tokens, imps) -> int:
    """How many of a format's import markers this binary links. A token ending in `*` is a
    PREFIX, which is how a library is recognised without enumerating its API: libxml2 exports
    several hundred `xml*` entry points and a binary that calls any of them reads XML."""
    n = 0
    for t in tokens or ():
        if not t:
            continue
        if t.endswith("*"):
            pre = t[:-1]
            if any(s.startswith(pre) for s in imps):
                n += 1
        elif t in imps:
            n += 1
    return n


def _token_count(token: str, blob: str) -> int:
    """How many times a token occurs, under the same word-boundary rule as `_token_hit`."""
    if len(token) >= _SHORT_TOKEN:
        return blob.count(token)
    rx = _WORD_CACHE.get(token)
    if rx is None:
        rx = _WORD_CACHE[token] = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])"
                                             % re.escape(token))
    return len(rx.findall(blob))


def _token_hit(token: str, blob: str) -> bool:
    if len(token) >= _SHORT_TOKEN:
        return token in blob
    rx = _WORD_CACHE.get(token)
    if rx is None:
        rx = _WORD_CACHE[token] = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])"
                                             % re.escape(token))
    return rx.search(blob) is not None


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
    ("H264", b"\x00\x00\x00\x01"),

]


def _looks_like_h264(sample: bytes) -> bool:
    """`00 00 00 01` is only four bytes -- a big-endian 1 at offset 0, which is common in
    firmware dumps, TLV/record containers and serialized formats -- so a bare start code is
    not enough to claim H.264. Require Annex-B structure: a NAL header byte whose
    forbidden_zero_bit is clear and whose nal_unit_type is not the reserved 0, plus a SECOND
    start code later in the sample (a stream is more than one NAL unit)."""
    if len(sample) < 6 or not sample.startswith(b"\x00\x00\x00\x01"):
        return False
    nal = sample[4]
    if nal & 0x80 or (nal & 0x1F) == 0:      # forbidden_zero_bit set, or unspecified type
        return False
    return sample.find(b"\x00\x00\x01", 4) >= 0


def detect_magic(sample: bytes):
    """Return (name, magic_bytes) for the first known signature the sample starts with."""
    for name, sig in _SIGNATURES:
        if sample.startswith(sig):
            # `00 00 00 01` is too generic to trust on the prefix alone -- verify NAL structure
            # before claiming H.264, or the real length-field discovery is skipped for a file
            # that merely opens with a big-endian 1.
            if name == "H264" and not _looks_like_h264(sample):
                continue
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


def _jsonable_spec(spec):
    """A builtin's field list, safe to put in a JSON response (magic values are bytes)."""
    out = []
    for f in spec:
        g = dict(f)
        if "value" in g and isinstance(g["value"], (bytes, bytearray)):
            g["value"] = _b64safe(bytes(g["value"]))
        if isinstance(g.get("fields"), list):
            g["fields"] = _jsonable_spec(g["fields"])
        out.append(g)
    return out


# Line-oriented text is not a byte grammar, and offering to carve it into magic + blob invites
# the operator to build a spec that cannot describe it. The campaign already picks the
# key=value mutator for these on its own.
def _looks_like_text_config(sample: bytes) -> bool:
    head = sample[:2048]
    if not head or b"\x00" in head:
        return False
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if len(lines) < 2:
        return False
    return sum(1 for ln in lines if "=" in ln or ":" in ln) >= max(2, len(lines) // 2)


def suggest_spec(sample: bytes) -> dict:
    """Build a starting spec from a real sample.

    A builtin model FIRST, when one matches. The generic path below derives magic and hunts a
    length field from the bytes alone, which for a JPEG produced two fields -- magic and a
    blob -- while `builtin("jpeg")` describes the segment chain and the nested IFD arrays and
    is what the campaign would choose anyway. Two places answered "what is this format" and
    the one the builder called was the weaker.
    """
    sample = sample or b""
    name, sig = detect_magic(sample)
    key = (name or "").lower()
    if key in _BUILTINS:
        entry = _BUILTINS[key]
        return {"detected": name, "magic_len": len(sig), "builtin": key,
                "spec": _jsonable_spec(entry["spec"]),
                "notes": [f"{name} is a built-in model: this is the full grammar the fuzzer "
                          f"uses, not a guess from the bytes. Edit it if this file is a "
                          f"dialect, or leave it and the campaign keeps lengths and offsets "
                          f"coherent while it mutates."],
                "sample_size": len(sample)}
    if _looks_like_text_config(sample):
        return {"detected": "line-oriented text", "magic_len": 0, "builtin": "keyvalue",
                "spec": [],
                "notes": ["this is key=value text, not a byte grammar -- a magic/length/blob "
                          "spec cannot describe it. The campaign detects this and uses the "
                          "key=value mutator automatically, mining the keys from the target's "
                          "own strings; there is nothing to build here."],
                "sample_size": len(sample)}
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
        observe.absorbed(_log, "continuing")
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
