"""Can the blind fuzzer reach a length-triggered bug at all?

It could not. Growth was a single operator that duplicated at most 64 bytes at 6% probability,
cancelled by an equally likely truncate, so from seeds of 0-16 bytes the length random-walked
around nothing: 20,000 mutations never passed 109 bytes, p99 = 32. Measured consequences --
ncompress 4.2.4 faults at an argv length of ~1050 and a campaign found 0 crashes in 3,000
execs; jhead ran 98,500 execs for 0 unique finds.

That is the class the L2/L3 ladder exists to exploit: a stack overflow needs kilobytes, and
the fuzzer in front of it could not produce them.
"""
import random

from lykos.analyze.fuzz.mutator import Mutator
from lykos.analyze.fuzz.stage import _DEFAULT_SEEDS


def _lengths(n=20000, seed=1234):
    rng = random.Random(seed)
    m = Mutator(rng)
    corpus = list(_DEFAULT_SEEDS)
    return sorted(len(m.mutate(rng.choice(corpus), corpus)) for _ in range(n))


def test_the_mutator_can_reach_a_kilobyte():
    """ncompress faults at ~1050 bytes. Before the extend operator, 0 of 20,000 mutations got
    there; the longest was 109."""
    lens = _lengths()
    assert lens[-1] >= 4096, f"longest mutation was only {lens[-1]}"
    assert sum(1 for x in lens if x >= 1050) > 100, "a kilobyte must be routinely reachable"


def test_short_inputs_are_still_the_common_case():
    """Growth must not become the whole strategy -- most bugs are not length-triggered, and
    every exec spent on a 4 KiB input is one not spent exploring structure."""
    lens = _lengths()
    assert lens[len(lens) // 2] < 256, "the median mutation should stay small"


def test_growth_survives_from_an_empty_seed():
    """The corpus starts with b"" and a blind campaign retains nothing, so a single mutation
    has to be able to grow from nothing."""
    rng = random.Random(7)
    m = Mutator(rng)
    assert max(len(m.mutate(b"", [b""])) for _ in range(4000)) >= 256


def test_a_long_seed_is_available_from_the_first_exec():
    """A blind mutator keeps nothing it finds, so without a long seed the overflow class is
    only reachable by growing into it -- and the campaign gets one mutation per exec."""
    assert max(len(s) for s in _DEFAULT_SEEDS) >= 4096


def test_the_mutator_respects_its_length_cap():
    from lykos.analyze.fuzz import mutator as M
    assert max(_lengths()) <= M._MAX_LEN
