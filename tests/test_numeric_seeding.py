"""Seeding the VALUES a numeric reader needs, not the lengths a byte mutator produces.

`int_overflow_alloc` was a documented KNOWN GAP in the conformance gate, and the note said why:
"the wrap needs a decimal input above 2**28, which blind mutation does not reach". That is not a
budget problem. A byte mutator emits bytes; the target reads `scanf("%u")`, so reaching the bug
requires the DECIMAL TEXT of a nine-digit number, which random mutation effectively never
produces however long it runs.

The subtle part is which numbers. The type boundary a fuzzer would reach for is useless here:

    n = 4294967295 -> n*16 wraps to 4294967280, still an enormous size, malloc FAILS,
                      the program takes its `if (!p) return` path and exits cleanly.
    n = 268435456  -> n*16 wraps to 0, malloc(0) SUCCEEDS, and the loop then writes
                      16 bytes 268435456 times.

So the values that matter are the wrap thresholds `2**bits // elem_size`, where the product
lands on something small enough to allocate. Those are derived from the element size, not
guessed per target, because elem_size is almost always a small power of two or a small struct.
"""
import pytest

from lykos.analyze.fuzz import textconf
from lykos.analyze.fuzz.stage import _NUMERIC_READERS, _reads_a_number


def _as_ints(seeds):
    return [int(s.strip()) for s in seeds]


# ---- the values ---------------------------------------------------------------------------

@pytest.mark.parametrize("elem", [2, 4, 8, 16])
def test_a_seed_makes_the_product_wrap_to_an_ALLOCATABLE_size(elem):
    """The whole point: the wrapped product must be small enough that malloc succeeds, or the
    program never reaches the loop that overflows."""
    ok = [n for n in _as_ints(textconf.numeric_boundary_seeds())
          if n > 0 and (n * elem) % (1 << 32) < 4096 and n > 1000]
    assert ok, f"no seed makes a *{elem} allocation wrap to a small size"


def test_the_type_boundary_a_fuzzer_would_try_does_not_suffice():
    """Stated as a test so the reason these extra values exist cannot be lost: 4294967295 is the
    obvious thing to try and it does not work, because its wrapped product is still huge."""
    assert (4294967295 * 16) % (1 << 32) > (1 << 20)


def test_the_bare_number_path_leads_with_the_wrap_thresholds():
    """Calibration detonates the corpus IN ORDER, and a short budget may never reach the tail."""
    first = _as_ints(textconf.numeric_boundary_seeds(4))
    assert first[0] == 1 << 28, first
    assert all(n > 1 << 20 for n in first), first


def test_the_config_path_still_leads_with_the_type_boundaries():
    """A numeric field in a config usually hides an INDEX or a bound, where -1 and 0 are what
    reach the bug -- and existing callers pass limit=5. Those five must not change."""
    assert textconf._BOUNDARY_VALUES[:5] == (b"0", b"-1", b"2147483647", b"2147483648",
                                             b"4294967295")


def test_both_orderings_draw_on_the_same_pool():
    """One vocabulary, two orderings -- not two vocabularies that can drift apart."""
    assert set(textconf._BOUNDARY_VALUES) == {str(v).encode() for v in textconf._WRAP_FIRST}


def test_each_threshold_ships_with_its_successor():
    """`base` wraps the product to 0 and `base+1` wraps it to exactly elem_size -- the smallest
    allocation that still enters the loop. Both are worth an exec."""
    vals = set(_as_ints(textconf.numeric_boundary_seeds(64)))
    for elem in (2, 4, 8, 16):
        base = (1 << 32) // elem
        assert base in vals and base + 1 in vals, elem


def test_the_seeds_are_terminated_so_a_line_reader_sees_them():
    """scanf stops at whitespace, but a getchar/fgets loop needs the newline."""
    assert all(s.endswith(b"\n") for s in textconf.numeric_boundary_seeds())


def test_a_limit_of_zero_is_not_an_error():
    assert textconf.numeric_boundary_seeds(0) == []


# ---- the evidence gate --------------------------------------------------------------------

class _Edge:
    def __init__(self, name):
        self.dst_name = name


class _Ctx:
    """Enough of a stage context for the detector: it only reads call edges."""

    def __init__(self, names):
        self._names = names
        self.conn = self

    # stand in for CallEdgeDAO(conn).list_by_target(...)
    def execute(self, *a, **k):
        raise AssertionError("should not reach SQL in this test")


@pytest.fixture()
def edges(monkeypatch):
    holder = {}

    class FakeDAO:
        def __init__(self, conn):
            pass

        def list_by_target(self, _tid):
            return [_Edge(n) for n in holder.get("names", ())]

    import lykos.db.dao as dao
    monkeypatch.setattr(dao, "CallEdgeDAO", FakeDAO)
    return holder


class _T:
    id = "t" * 32


def test_a_scanf_target_is_recognised_as_a_numeric_reader(edges):
    edges["names"] = ["__isoc99_scanf", "printf", "malloc", "memset"]
    assert _reads_a_number(_Ctx(None), _T())


@pytest.mark.parametrize("fn", ["scanf", "sscanf", "strtoul", "strtol", "atoi", "atoll"])
def test_the_whole_conversion_family_counts(edges, fn):
    edges["names"] = [fn, "puts"]
    assert _reads_a_number(_Ctx(None), _T())


def test_a_printf_only_target_is_not_a_numeric_reader(edges):
    """A `%u` in .rodata proves nothing -- `printf("ok %u", n)` has one. The question is asked of
    the imports for the same reason the channel ranking is."""
    edges["names"] = ["printf", "puts", "fgets", "strcpy", "malloc"]
    assert not _reads_a_number(_Ctx(None), _T())


def test_the_gate_never_raises_into_the_campaign(edges):
    """Seeding is an optimisation. If the lookup fails the campaign must still run."""
    import lykos.db.dao as dao

    class Boom:
        def __init__(self, conn):
            raise RuntimeError("no db")
    object.__setattr__(dao, "CallEdgeDAO", Boom)
    assert _reads_a_number(_Ctx(None), _T()) is False


def test_the_reader_set_holds_conversion_functions_only():
    """A length-taking reader (fgets/read) says nothing about VALUES, so it must not trigger
    numeric seeding -- that would spend calibration execs on every target in the suite."""
    for not_a_converter in ("fgets", "read", "fread", "gets", "memcpy", "strcpy", "printf"):
        assert not_a_converter not in _NUMERIC_READERS


# --- specimens the binary documents for itself ------------------------------------------

def test_a_documented_example_becomes_a_seed():
    """Many CLI tools and prompt-driven services write their input grammar into a usage line or
    a prompt. That example is a valid input BY CONSTRUCTION -- the author of the parser wrote it
    -- and nothing was reading it: the strings mined for seeds were the program's ERROR messages,
    which name the gate without passing it.

    Measured on the HTB target `replaceme`, whose 192-byte stack buffer is overflowed by
    `s/a/<long>/`: 63,234 blind and directed executions never constructed the expression, because
    a mutator has to invent `s/`, two `/` delimiters and a long field at once. The binary's own
    prompt says "in SED format (e.g. s/old/new/)".
    """
    from lykos.analyze.fuzz import textconf
    seeds = textconf.example_seeds([
        "Now, please enter the replacement string in SED format (e.g. s/old/new/).",
        "Missing 's/' at the beginning of the replacement string.",
    ])
    assert b"s/old/new/" in seeds, seeds
    # ...and the same shape with one field grown past any plausible buffer, which is the defect
    # the example's own format hides
    assert any(s.startswith(b"s/old/A") and len(s) > 200 for s in seeds), seeds


def test_a_prose_string_is_not_mistaken_for_an_example():
    """An example has to carry STRUCTURE -- a delimiter, an operator, a path. A bare word after
    "e.g." is a value, which `keys_from` already mines, and seeding every such word would crowd
    the corpus with noise."""
    from lykos.analyze.fuzz import textconf
    assert textconf.example_seeds(["pick a colour, e.g. red"]) == []
    assert textconf.example_seeds(["say hello", "no examples here"]) == []
    assert textconf.example_seeds([]) == []


def test_the_symbol_table_is_not_mined_for_examples():
    """A loose `e\\.?\\s?g\\.?` matched the bare "eg" inside "register_tm_clones" and the "e.g"
    inside ".note.gnu.property", and offered "ister_tm_clones" and "nu.property" as examples of
    the program's input format. Both dots and a separator are required."""
    from lykos.analyze.fuzz import textconf
    for junk in ("register_tm_clones", ".note.gnu.property", "__register_frame_info",
                 "deregister_tm_clones", "e.gnu.something/x"):
        assert textconf.example_seeds([junk]) == [], junk
    # and the real thing still parses
    assert b"s/old/new/" in textconf.example_seeds(
        ["Now, enter the replacement string in SED format (e.g. s/old/new/)."])


def test_documented_examples_are_bounded():
    """Seeding is an optimisation, never a precondition: a binary that documents a hundred
    examples must not displace the corpus."""
    from lykos.analyze.fuzz import textconf
    many = [f"e.g. k{i}=v{i}/x" for i in range(50)]
    assert len(textconf.example_seeds(many)) <= 8
