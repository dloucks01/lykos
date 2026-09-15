"""Can the fuzzer get past a format gate?

A blind mutator cannot invent four valid magic bytes, so a parser rejects everything it is
handed and the campaign does no work at all: jhead ran 98,500 executions for zero finds while
AFL++ reached the same bug in 60 seconds WITH a valid sample. `advise` already diagnosed this
-- it exists to sit there saying "this is a parser, attach a seed and use a structure model" --
but nothing acted on it: there were two builtin models, nothing selected one, and nothing could
produce a seed.
"""

import pytest
from lykos.analyze.fuzz import structure as S


def test_a_parser_is_recognised_from_its_own_strings():
    """Byte magic never survives into a string table; a format's textual markers do."""
    assert S.detect_format(["Exif", "JFIF", "unrelated"]) == "jpeg"
    assert S.detect_format(["IHDR", "IEND"]) == "png"
    assert S.detect_format(["GIF89a"]) == "gif"


def test_a_non_parser_is_not_forced_into_a_format():
    """Guessing a model for a program that reads no format would seed every campaign with
    inputs its target rejects."""
    assert S.detect_format(["usage: %s", "cannot open", "/lib64/ld-linux"]) is None
    assert S.detect_format([]) is None


def test_every_builtin_produces_a_seed_that_matches_its_own_magic():
    for name in S.builtin_names():
        seed = S.seed_for_name(name)
        assert seed, name
        first = S.builtin(name).spec[0]
        if first["type"] == "magic":
            assert seed.startswith(S._as_bytes(first["value"])), name


def test_a_covers_field_length_ends_where_the_next_segment_begins():
    """A JPEG APP1 length covers the length field itself through the end of the EXIF payload --
    and then the frame follows. Getting it wrong is not cosmetic in either direction: too short
    and the parser treats the rest of EXIF as padding, too long and it swallows the frame, and
    either way the seed never reaches the structure the model describes."""
    seed = S.seed_for_name("jpeg")
    seglen = int.from_bytes(seed[4:6], "big")
    assert seed[4 + seglen:4 + seglen + 2] == b"\xff\xdb", \
        "the APP1 length must end exactly where the frame starts"


def test_the_jpeg_seed_is_a_complete_file():
    """jhead rejects a file with no frame and scan header as "Unexpected end of file" before it
    reaches ShowImageInfo -- its largest function, 210 blocks -- and before anything gated on an
    option, since those run downstream of a successful parse. Measured: a skeleton seed reaches
    41/114 functions, a complete one 83/114."""
    seed = S.seed_for_name("jpeg")
    for marker, what in ((b"\xff\xdb", "quantisation table"), (b"\xff\xc0", "frame header"),
                         (b"\xff\xc4", "huffman table"), (b"\xff\xda", "scan header")):
        assert marker in seed, f"a complete JPEG needs a {what}"
    assert seed.endswith(b"\xff\xd9"), "and an end-of-image marker"


def test_the_model_round_trips_a_sized_blob():
    """A blob bounded by a length field is what lets fields FOLLOW a variable region. If parse()
    hands it the remainder instead, everything after it is swallowed and the model silently
    describes a shorter file than it generates."""
    model = S.builtin("jpeg")
    seed = S.seed_for_name("jpeg")
    fields = model.parse(seed)
    assert model.serialize(fields) == seed
    seg = next(f for f in fields if f["f"].get("name") == "gpsdata")
    assert len(seg["val"]) < len(seed) - 20, "the blob must be sized, not the whole remainder"


def test_the_jpeg_seed_carries_a_gps_subdirectory():
    """A seed has to exercise a format's FEATURES, not just satisfy its magic. jhead's bug
    lives in ProcessGpsInfo, behind a GPS pointer (tag 0x8825) and a sub-IFD at a valid offset
    -- random mutation does not invent a tag number and a self-consistent offset, so a campaign
    without one never executes the function."""
    assert b"\x25\x88" in S.seed_for_name("jpeg"), "GPS IFD pointer tag, little-endian"


def test_mutation_keeps_the_structure_parseable():
    """Unless a round deliberately drives the length field, the length must still delimit the
    EXIF segment -- otherwise every other mutation in that round is discarded as padding, or
    eats the frame that makes the file complete, before the parser sees it."""
    import random
    rng = random.Random(11)
    model = S.builtin("jpeg")
    mut = S.StructMutator(rng, model)
    seed = S.seed_for_name("jpeg")
    intact = 0
    for _ in range(300):
        d = mut.mutate(seed, [seed])
        n = int.from_bytes(d[4:6], "big") if len(d) >= 6 else 0
        if d[4 + n:4 + n + 2] == b"\xff\xdb":
            intact += 1
    assert intact > 120, f"only {intact}/300 mutants kept a consistent segment length"


def test_a_mutant_is_still_recognisably_the_format():
    import random
    rng = random.Random(3)
    mut = S.StructMutator(rng, S.builtin("jpeg"))
    seed = S.seed_for_name("jpeg")
    kept = sum(1 for _ in range(200) if mut.mutate(seed, [seed]).startswith(b"\xff\xd8"))
    assert kept > 150, "the magic is usually kept so the format gate passes"


def _jpeg_gps_entries(fields, model):
    gps = next(f for f in fields if f["f"].get("name") == "gps")["val"]
    return next(f for f in gps if f["f"].get("name") == "gpsent")["val"]


def test_a_format_inside_a_format_is_fields_not_payload():
    """EXIF's directories used to sit inside one opaque blob, so the only way to change an
    entry was byte havoc over the whole region -- which alters the entry AND wrecks the
    directory around it. jhead then rejects the directory before it ever reads the entry."""
    model = S.builtin("jpeg")
    seed = S.seed_for_name("jpeg")
    fields = model.parse(seed)
    ents = _jpeg_gps_entries(fields, model)
    assert len(ents) == 2, "the GPS sub-directory's entries are addressable"
    names = [f["f"]["name"] for f in ents[0]]
    assert names == ["tag", "fmt", "count", "value"]
    assert model.serialize(fields) == seed, "and it all round-trips byte for byte"


def test_changing_one_nested_field_leaves_every_other_byte_alone():
    """The whole point of describing a sub-structure: an edit is surgical. If a change to one
    entry's count moves or corrupts anything else, the parser rejects the file for the other
    reason and the value under test is never reached."""
    model = S.builtin("jpeg")
    seed = S.seed_for_name("jpeg")
    fields = model.parse(seed)
    ent = _jpeg_gps_entries(fields, model)[0]
    next(f for f in ent if f["f"]["name"] == "count")["val"] = 0xFF000002
    out = model.serialize(fields)
    assert len(out) == len(seed)
    differing = [i for i, (a, b) in enumerate(zip(out, seed)) if a != b]
    assert len(differing) <= 4, f"one u32 should change, {len(differing)} bytes did"


def test_an_array_reads_as_many_records_as_its_count_claims():
    model = S.builtin("jpeg")
    seed = bytearray(S.seed_for_name("jpeg"))
    fields = model.parse(bytes(seed))
    ifd0 = next(f for f in fields if f["f"].get("name") == "ifd0")
    assert len(ifd0["val"]) == 1
    next(f for f in fields if f["f"].get("name") == "nent")["val"] = 3
    grown = model.parse(model.serialize(fields))
    assert len(next(f for f in grown if f["f"].get("name") == "ifd0")["val"]) == 3, \
        "a count field drives how many records are read back"


def test_a_count_field_cannot_make_the_parser_read_forever():
    """An array's count is attacker data -- a four-billion entry claim must not be believed."""
    model = S.builtin("jpeg")
    fields = model.parse(S.seed_for_name("jpeg"))
    next(f for f in fields if f["f"].get("name") == "nent")["val"] = 0xFFFFFFFF
    again = model.parse(model.serialize(fields))
    got = next(f for f in again if f["f"].get("name") == "ifd0")["val"]
    assert len(got) <= S._MAXREC


def test_an_offset_and_its_size_are_driven_together_to_overflow():
    """A parser that reads `size` bytes from `base + offset` checks the pair first, and the
    check is the bug: computed in the field's own width it WRAPS, so a sum that looks tiny
    passes while the offset still points far outside the buffer. jhead's GPS read is exactly
    this -- 0x00ffffff + 0xff000002 is 1 in 32 bits. Neither half does it alone (both are
    refused), and guessing both independently never lands it, so it has to be constructed."""
    import random
    model = S.builtin("jpeg")
    seed = S.seed_for_name("jpeg")
    mut = S.StructMutator(random.Random(9), model)
    wrapped = 0
    for _ in range(400):
        d = mut.mutate(seed, [seed])
        try:
            fields = model.parse(d)
            ents = _jpeg_gps_entries(fields, model)
        except (StopIteration, IndexError, KeyError):
            continue
        for rec in ents:
            v = {f["f"]["name"]: f["val"] for f in rec}
            if v["value"] > 0xFFFF and (v["value"] + v["count"]) & 0xFFFFFFFF <= 0x20:
                wrapped += 1
                break
    assert wrapped > 10, f"only {wrapped}/400 mutants carried a wrapping offset/size pair"


def test_a_pair_is_only_driven_when_the_model_says_it_is_one():
    """The roles are declared. Driving any two integers that happen to sit next to each other
    would wreck formats where they are unrelated."""
    import random
    spec = [{"type": "u32", "endian": "little", "name": "a"},
            {"type": "u32", "endian": "little", "name": "b"}]
    model = S.FormatModel(spec)
    mut = S.StructMutator(random.Random(1), model)
    fields = model.parse(b"\x01\x00\x00\x00\x02\x00\x00\x00")
    mut._drive_pair(fields, fields[0], "size")          # no role declared anywhere
    assert [f["val"] for f in fields] == [1, 2], "nothing to pair with, nothing changed"


def test_a_narrow_offset_size_pair_does_not_crash_the_mutator():
    """A u8/u16 size+offset pair leaves the wrap-the-sum branch with no far-offset candidate
    that fits the field, so `rng.choice([])` used to raise -- and because the mutation loop was
    not guarded, that IndexError propagated straight out of `mutate` and took the whole campaign
    down. An analyst spec must never be able to do that: the driver falls back, and any residual
    error degrades to byte havoc like a parse/serialize failure already does."""
    import random
    spec = [{"type": "magic", "value": b"HH"},
            {"type": "u8", "name": "off", "role": "offset"},
            {"type": "u8", "name": "siz", "role": "size"},
            {"type": "blob", "name": "data"}]
    model = S.FormatModel(spec)
    mut = S.StructMutator(random.Random(0), model)
    seed = b"HH\x01\x01payload"
    for _ in range(500):
        out = mut.mutate(seed, [seed])                   # must never raise
        assert isinstance(out, (bytes, bytearray))
    # and the driver itself, called directly, is safe when the field is too narrow to wrap
    fields = model.parse(seed)
    leaves = [f for f in fields if f["f"].get("role") in ("offset", "size")]
    for _ in range(200):
        mut._drive_pair(fields, leaves[0], "offset")     # u8 offset: no candidate > 0xFFFF


def test_every_builtin_survives_its_own_mutations():
    """A model that parses its seed but throws on a mutant silently falls back to byte havoc
    -- or takes the stage down. `length_of` naming a GROUP (a ZIP's central directory) hit the
    "grow the sized blob" path, which assumed bytes and got a list of fields."""
    import random
    for name in S.builtin_names():
        model, seed = S.builtin(name), S.seed_for_name(name) or b""
        mut = S.StructMutator(random.Random(3), model)
        for _ in range(200):
            mut.mutate(seed, [seed])
        assert model.serialize(model.parse(seed)) == seed, f"{name} must round-trip its seed"


def test_an_archive_directory_is_found_by_a_derived_offset():
    """A ZIP is not a local header: every tool finds the files through the central directory,
    located by absolute offset from the end-of-central-directory record. A model that stops at
    the local header generates something unzip refuses outright, so the campaign never starts."""
    model = S.builtin("zip")
    seed = S.seed_for_name("zip")
    fields = model.parse(seed)
    cdoff = next(f for f in fields if f["f"].get("name") == "cdoff")["val"]
    assert seed[cdoff:cdoff + 4] == b"PK\x01\x02", "the offset must land on the directory"
    localoff = next(f for f in next(f for f in fields if f["f"].get("name") == "cd")["val"]
                    if f["f"].get("name") == "localoff")["val"]
    assert seed[localoff:localoff + 4] == b"PK\x03\x04", "and its entry on the local header"


def test_a_derived_offset_is_computed_across_nesting():
    """The offset is into the FILE, not into the group the field happens to live in."""
    model = S.builtin("zip")
    fields = model.parse(S.seed_for_name("zip"))
    # make the stored file bigger; everything after it must shift
    next(f for f in next(f for f in fields if f["f"].get("name") == "local")["val"]
         if f["f"].get("name") == "data")["val"] = b"B" * 100
    S._fix_covers(model, fields, lengths=True)
    out = model.serialize(fields)
    cdoff = next(f for f in fields if f["f"].get("name") == "cdoff")["val"]
    assert out[cdoff:cdoff + 4] == b"PK\x01\x02"


def test_a_length_prefixed_blob_does_not_eat_what_follows_it():
    """`length_of` has to bound the blob on the way back IN too. A GIF's sub-block is followed
    by the block terminator and the trailer, and those decide whether it is a GIF at all."""
    model = S.builtin("gif")
    seed = S.seed_for_name("gif")
    fields = model.parse(seed)
    lzw = next(f for f in fields if f["f"].get("name") == "lzw")
    blen = next(f for f in fields if f["f"].get("name") == "blen")
    assert len(lzw["val"]) == blen["val"]
    assert seed.endswith(b"\x00\x3b"), "terminator and trailer survive the blob"


def test_a_two_character_token_does_not_claim_a_binary():
    """"BM" appears as a substring of all sorts of things; it picked BMP for unzip, which then
    fuzzed a ZIP tool with bitmaps -- 354 blocks against 1,162 with the right model."""
    unzipish = ["End-of-central-directory", "central directory", "zipfile", "SUBMIT", "BM"]
    assert S.detect_format(unzipish) == "zip"


def test_a_generated_seed_is_accepted_by_a_real_decoder(tmp_path):
    """The point of a model is a seed the TARGET accepts. jhead, gif2rgb and unzip accept the
    jpeg, gif and zip seeds; these three are checked against decoders that ship with the
    system, so the assertion does not depend on a fixture being built."""
    import wave
    seeds = {n: S.seed_for_name(n) for n in ("png", "bmp", "riff")}

    w = tmp_path / "t.wav"
    w.write_bytes(seeds["riff"])
    with wave.open(str(w)) as fh:
        assert fh.getnchannels() == 1 and fh.getframerate() == 8000

    try:
        import PIL.Image as Image
    except ImportError:
        pytest.skip("Pillow not installed; RIFF checked above")
    for name, mode in (("png", "L"), ("bmp", "RGB")):
        f = tmp_path / f"t.{name}"
        f.write_bytes(seeds[name])
        with Image.open(f) as im:
            im.load()
            assert im.size == (1, 1) and im.mode == mode, name


def test_a_checksum_is_derived_so_the_parser_gets_past_the_door():
    """A format that checksums its own chunks cannot be fuzzed blind: a decoder rejects a bad
    CRC before reading anything else, so every other mutation in the round is discarded at the
    door. PNG's CRC covers the chunk TYPE as well as its data, which is why the body is a group
    -- the checksum names it."""
    import struct
    import zlib
    seed = S.seed_for_name("png")
    body = seed[8:]
    checked = 0
    while len(body) >= 12:
        (ln,) = struct.unpack(">I", body[:4])
        chunk, crc = body[4:8 + ln], struct.unpack(">I", body[8 + ln:12 + ln])[0]
        assert zlib.crc32(chunk) & 0xFFFFFFFF == crc, chunk[:4]
        checked += 1
        body = body[12 + ln:]
    assert checked == 3, "IHDR, IDAT and IEND"


def test_every_builtin_describes_more_than_its_magic():
    """A stub model -- signature plus a payload blob -- generates a file the target rejects
    outright, so the campaign never reaches a parser. gif2rgb answered "Image of width or
    height 0" and unzip "End-of-central-directory signature not found"."""
    def described(spec):
        """Fields anywhere in the tree -- PNG's structure lives inside its chunk groups."""
        n = 0
        for f in spec:
            n += 1
            if f["type"] in ("group", "array"):
                n += described(f["spec"])
        return n

    for name in S.builtin_names():
        if name == "lv32":
            continue            # deliberately generic: a magic + length + payload container
        n = described(S.builtin(name).spec)
        assert n >= 10, f"{name} is still a stub: {n} fields"


# --- delimited and derived-size blobs, and the two video models built on them ----------

def test_a_blob_can_end_at_a_delimiter_instead_of_a_length():
    """Annex-B framing has no length field: a NAL unit runs until the next start code.
    Without `until` the first blob ate the whole stream, so a model could describe three NAL
    units and the mutator could still only ever reach the first one."""
    m = S.FormatModel([
        {"type": "magic", "value": b"##"},
        {"type": "blob", "name": "first", "until": b"##"},
        {"type": "magic", "value": b"##"},
        {"type": "blob", "name": "second"}])
    fields = m.parse(b"##abc##defgh")
    vals = {f["f"].get("name"): f["val"] for f in fields if f["f"].get("name")}
    assert vals["first"] == b"abc"
    assert vals["second"] == b"defgh"
    assert m.serialize(fields) == b"##abc##defgh"


def test_a_delimited_blob_with_no_delimiter_left_takes_the_rest():
    m = S.FormatModel([{"type": "blob", "name": "only", "until": b"##"}])
    fields = m.parse(b"nothing here")
    assert fields[0]["val"] == b"nothing here"


def test_a_blob_can_take_its_length_from_a_bitfield_of_another_field():
    """RTP's CSRC list is four bytes per unit of CC, and CC is the low nibble of byte 0.
    `covers` and `length_of` both need a whole integer field to point at, so a count packed
    into a bitfield -- most of how binary network protocols are shaped -- had no expression."""
    spec = [{"type": "u8", "name": "flags"},
            {"type": "blob", "name": "list",
             "size_from": {"field": "flags", "mask": 0x0F, "scale": 4}},
            {"type": "blob", "name": "rest"}]
    m = S.FormatModel(spec)
    fields = m.parse(b"\x02" + b"AAAABBBB" + b"tail")
    vals = {f["f"].get("name"): f["val"] for f in fields if f["f"].get("name")}
    assert vals["list"] == b"AAAABBBB"          # CC=2 -> 8 bytes
    assert vals["rest"] == b"tail"
    # the high nibble is masked off, not read as part of the count
    fields = m.parse(b"\x92" + b"AAAABBBB" + b"tail")
    vals = {f["f"].get("name"): f["val"] for f in fields if f["f"].get("name")}
    assert vals["list"] == b"AAAABBBB"


def test_a_derived_size_that_outruns_the_input_is_clamped_not_fatal():
    """A count past the end of the datagram is the bug being hunted, so parsing it has to
    survive: the mutator drives CC to 15 on purpose."""
    m = S.FormatModel([{"type": "u8", "name": "flags"},
                       {"type": "blob", "name": "list",
                        "size_from": {"field": "flags", "mask": 0x0F, "scale": 4}},
                       {"type": "blob", "name": "rest"}])
    fields = m.parse(b"\x0f" + b"AAAA")
    vals = {f["f"].get("name"): f["val"] for f in fields if f["f"].get("name")}
    assert vals["list"] == b"AAAA" and vals["rest"] == b""


def test_a_derived_size_blob_seeds_empty_so_the_baseline_agrees_with_its_count():
    """Seeding it with the payload would contradict the count field and the parser would
    reject the very input the campaign starts from."""
    m = S.FormatModel([{"type": "u8", "name": "flags", "seed_value": 0},
                       {"type": "blob", "name": "list",
                        "size_from": {"field": "flags", "mask": 0x0F, "scale": 4}},
                       {"type": "blob", "name": "rest"}])
    assert S.seed_for(m, b"PAYLOAD") == b"\x00PAYLOAD"


def _named_fields(fields, pre=""):
    out = {}
    for fd in fields:
        f = fd["f"]
        name = pre + (f.get("name") or f["type"])
        if f["type"] == "group":
            out.update(_named_fields(fd["val"], name + "."))
        else:
            out[name] = fd["val"]
    return out


def test_the_rtp_seed_is_a_packet_a_receiver_accepts():
    m = S.builtin("rtp")
    seed = S.seed_for_name("rtp")
    v = _named_fields(m.parse(seed))
    assert v["v_p_x_cc"] >> 6 == 2          # RFC 3550 version
    assert v["v_p_x_cc"] & 0x10             # X=1, so the extension is parsed at all
    assert v["v_p_x_cc"] & 0x0F == 0        # CC=0, so CSRC is legitimately empty
    assert v["csrc"] == b""
    assert v["ext.ext_profile"] == 0xBEDE
    assert v["ext.ext_len"] * 4 == len(v["ext.ext_data"])
    # PT 33 is MP2T, and the payload really is a transport-stream packet
    assert v["m_pt"] & 0x7F == 33
    assert v["payload"][:1] == b"\x47"


def test_the_rtp_mutator_reaches_the_payload_behind_both_variable_regions():
    """The regression this guards: an unbounded CSRC list or extension swallowed everything
    after it, so the payload -- the transport-stream packet a video receiver demuxes -- was
    parsed as empty and never mutated once."""
    import random
    m = S.builtin("rtp")
    seed = S.seed_for_name("rtp")
    base = _named_fields(m.parse(seed))
    mut = S.StructMutator(random.Random(11), m)
    touched = {k: 0 for k in base}
    for _ in range(600):
        out = mut.mutate(seed)
        for k, val in _named_fields(m.parse(out)).items():
            if k in base and val != base[k]:
                touched[k] += 1
    assert all(touched[k] > 0 for k in base), \
        f"never mutated: {[k for k in base if not touched[k]]}"


def test_the_h264_model_keeps_its_start_codes_and_reaches_every_nal():
    import random
    m = S.builtin("h264")
    seed = S.seed_for_name("h264")
    assert seed.startswith(b"\x00\x00\x00\x01")
    assert seed.count(b"\x00\x00\x00\x01") == 4      # SPS, PPS, IDR, non-IDR
    base = _named_fields(m.parse(seed))
    mut = S.StructMutator(random.Random(3), m)
    kept = 0
    touched = {k: 0 for k in base if k != "magic"}
    for _ in range(600):
        out = mut.mutate(seed)
        if out.startswith(b"\x00\x00\x00\x01"):
            kept += 1
        for k, val in _named_fields(m.parse(out)).items():
            if k in touched and val != base[k]:
                touched[k] += 1
    # a decoder scans for a start code and discards everything before it, so mutation that
    # destroys the framing is mutation the decoder never parses
    assert kept > 500, kept
    assert all(v > 0 for v in touched.values()), \
        f"never mutated: {[k for k, v in touched.items() if not v]}"


def test_a_video_receivers_own_strings_pick_the_right_model():
    assert S.detect_format(["rtpmap", "a=RTP/AVP 33", "ssrc"]) == "rtp"
    assert S.detect_format(["nal_unit_type", "avcC", "h264 decoder"]) == "h264"
    assert S.detect_format(["transport_stream", "adaptation_field"]) == "mpegts"


def test_an_annex_b_sample_suggests_the_h264_model_to_the_builder():
    spec = S.suggest_spec(S.seed_for_name("h264"))
    assert spec["builtin"] == "h264"
    assert any("h264" in n.lower() or "H264" in n for n in [spec["detected"]])
