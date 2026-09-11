"""Does the campaign learn anything, and does it aim at the right channel?

Two things kept the built-in fuzzer from ever getting deeper than its seeds.

It was purely BLIND: the corpus grew only on a crash, so an input that reached new parser code
without crashing was discarded and the search random-walked around its seeds forever. `unique:
0` on every jhead run was that, not bad luck.

And it committed to ONE input channel. Being right about what a program reads is not the same
as being right about where its bug is: ncompress genuinely parses files, and its overflow is in
the filename handed to it on the command line. A campaign aimed at the wrong channel does no
work and reports a clean zero -- it found 0 crashes where sweeping the channels finds 302.
"""
from lykos.analyze.fuzz.stage import behaviour_of


class _R:
    def __init__(self, out=b"", err=b"", code=0, sig=None, crashed=False):
        self.stdout, self.stderr, self.exit_code = out, err, code
        self.signal_name, self.crashed = sig, crashed


def test_the_same_path_is_one_behaviour():
    """A parser announces which path it took, and the numbers in that message are detail:
    "Extraneous 16 padding bytes" and "Extraneous 56" are the same code, not two discoveries."""
    a = behaviour_of(_R(err=b"Extraneous 16 padding bytes before section D9"))
    b = behaviour_of(_R(err=b"Extraneous 56 padding bytes before section D9"))
    assert a == b


def test_different_paths_are_different_behaviours():
    a = behaviour_of(_R(err=b"Illegal subdirectory link in Exif header"))
    b = behaviour_of(_R(err=b"Invalid Exif alignment marker"))
    assert a != b


def test_the_exit_status_is_part_of_the_signature():
    """A program that says nothing can still take a different path."""
    assert behaviour_of(_R(code=0)) != behaviour_of(_R(code=1))


def test_a_signal_is_part_of_the_signature():
    assert behaviour_of(_R(sig="SIGSEGV")) != behaviour_of(_R(sig="SIGABRT"))


def test_output_beyond_the_cap_does_not_split_a_behaviour():
    """A program that dumps its input back would otherwise make every single exec 'new'."""
    a = behaviour_of(_R(out=b"x" * 600 + b"A" * 4000))
    b = behaviour_of(_R(out=b"x" * 600 + b"B" * 4000))
    assert a == b, "only the first 512 bytes of output shape the signature"
    # and content INSIDE the cap still separates them, which is the point of having one
    assert behaviour_of(_R(out=b"A" * 64)) != behaviour_of(_R(out=b"B" * 64))


# ---------------------------------------------------------------- the channel sweep
def test_every_plausible_channel_is_fuzzed():
    """ncompress reads files AND has an argv-only overflow. Committing to the top-ranked
    channel found nothing; sweeping finds it."""
    from lykos.analyze.poc.capture import MODES, modes_for

    class _E:
        def __init__(self, n):
            self.dst_name = n
    ranked = modes_for([_E("fopen"), _E("fread")])
    assert ranked[0] == "file", "ranked by what the binary imports"
    assert set(ranked) == set(MODES), "but every channel is still attempted"


def test_an_explicit_channel_is_honoured_alone():
    """An analyst who names the channel does not want two thirds of the budget elsewhere."""
    from lykos.analyze.poc.capture import modes_for
    assert modes_for([], "arg") == ["arg"]
