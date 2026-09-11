"""Can the fuzzer get past a format gate?

A blind mutator cannot invent four valid magic bytes, so a parser rejects everything it is
handed and the campaign does no work at all: jhead ran 98,500 executions for zero finds while
AFL++ reached the same bug in 60 seconds WITH a valid sample. `advise` already diagnosed this
-- it exists to sit there saying "this is a parser, attach a seed and use a structure model" --
but nothing acted on it: there were two builtin models, nothing selected one, and nothing could
produce a seed.
"""

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
