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


def test_a_covers_rest_length_spans_the_rest():
    """A JPEG segment length covers the length field itself and everything after it -- not one
    named blob. Getting it wrong is not cosmetic: the parser reads a short segment and treats
    the remainder as padding, so the seed never reaches the structure the model describes."""
    seed = S.seed_for_name("jpeg")
    seglen = int.from_bytes(seed[4:6], "big")
    assert seglen == len(seed) - 4, "the length must span from itself to the end of the segment"


def test_the_jpeg_seed_carries_a_gps_subdirectory():
    """A seed has to exercise a format's FEATURES, not just satisfy its magic. jhead's bug
    lives in ProcessGpsInfo, behind a GPS pointer (tag 0x8825) and a sub-IFD at a valid offset
    -- random mutation does not invent a tag number and a self-consistent offset, so a campaign
    without one never executes the function."""
    assert b"\x25\x88" in S.seed_for_name("jpeg"), "GPS IFD pointer tag, little-endian"


def test_mutation_keeps_the_structure_parseable():
    """Unless a round deliberately drives the length field, the segment must still span the
    segment -- otherwise every other mutation in that round is discarded as padding before the
    parser sees it."""
    import random
    rng = random.Random(11)
    model = S.builtin("jpeg")
    mut = S.StructMutator(rng, model)
    seed = S.seed_for_name("jpeg")
    intact = 0
    for _ in range(300):
        d = mut.mutate(seed, [seed])
        if len(d) >= 6 and int.from_bytes(d[4:6], "big") == len(d) - 4:
            intact += 1
    assert intact > 120, f"only {intact}/300 mutants kept a consistent segment length"


def test_a_mutant_is_still_recognisably_the_format():
    import random
    rng = random.Random(3)
    mut = S.StructMutator(rng, S.builtin("jpeg"))
    seed = S.seed_for_name("jpeg")
    kept = sum(1 for _ in range(200) if mut.mutate(seed, [seed]).startswith(b"\xff\xd8"))
    assert kept > 150, "the magic is usually kept so the format gate passes"
