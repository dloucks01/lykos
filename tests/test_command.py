"""Text-command interface fuzzing: a line-oriented service dispatched on WORDS, not menu numbers.

`strncmp(cmd, "free", 4)` is a state machine like a numbered menu, but its verbs are the comparison
literals -- often too short for the string table -- so the numbered-menu path never sees it. These
tests pin the verb mining (gated on a string-compare + a line reader), the sequence shapes a heap
bug takes (double, triple, pair), and the mutator that keeps every line a valid command.
"""
import random

from lykos.analyze.fuzz import command


def _elf_with(tokens):
    """A minimal blob carrying the given NUL-terminated tokens. mine_verbs reads raw strings, not a
    real ELF, so a bag of tokens is a faithful stand-in for what the scanner extracts."""
    return b"\x7fELF" + b"\x00" * 60 + b"".join(t.encode() + b"\x00" for t in tokens)


def test_verbs_need_a_string_compare_and_a_line_reader():
    # a bag of plausible verbs but NO strncmp/strcmp -> not a command dispatcher
    assert command.mine_verbs(_elf_with(["fgets", "alpha", "beta", "gamma"])) == []
    # strncmp present but NO line reader -> not line-oriented, so no command interface
    assert command.mine_verbs(_elf_with(["strncmp", "alpha", "beta", "gamma"])) == []
    # both gates satisfied -> the non-runtime tokens are verbs
    verbs = command.mine_verbs(_elf_with(["strncmp", "fgets", "alpha", "beta", "gamma"]))
    assert set(verbs) == {"alpha", "beta", "gamma"}


def test_short_verbs_below_the_string_table_minimum_are_mined():
    # "use" is 3 chars -- below the 4-char string-table floor -- yet it is the command literal.
    verbs = command.mine_verbs(_elf_with(["strncmp", "fgets", "use", "free", "new"]))
    assert "use" in verbs and "new" in verbs


def test_runtime_and_compiler_symbols_are_not_verbs():
    verbs = command.mine_verbs(_elf_with(
        ["strncmp", "fgets", "printf", "malloc", "frame_dummy", "register_tm_clones", "run"]))
    assert "run" in verbs
    for junk in ("printf", "malloc", "frame_dummy", "register_tm_clones"):
        assert junk not in verbs


def test_sequences_cover_double_triple_and_pair_shapes():
    seqs = command.command_seeds(["new", "del", "run"])
    assert b"new\ndel\nrun\n" in seqs        # create -> free -> use (the use-after-free triple)
    assert b"del\ndel\n" in seqs             # double-free / double-use
    assert b"new\ndel\n" in seqs             # an ordered pair
    # a single verb is not a sequence
    assert command.command_seeds(["only"]) == []


def test_mutator_emits_only_valid_command_lines():
    mut = command.CommandMutator(random.Random(1), ["new", "del", "run"])
    verbset = {b"new", b"del", b"run"}
    saw_verb = False
    for _ in range(50):
        out = mut.mutate()
        assert out.endswith(b"\n")
        for line in out.split(b"\n"):
            if line in verbset:
                saw_verb = True
            elif line and set(line) != {ord("A")}:      # else only a data/overflow line
                raise AssertionError(f"unexpected line {line!r}")
    assert saw_verb


def test_a_verb_written_with_its_separator_is_mined_with_it():
    """`strncmp(line, "show=", 5)` makes the dispatch token `show=`, not `show`.

    The miner matched pure-alpha tokens only, so a literal carrying its own argument separator was
    discarded outright -- and the bare word would not have helped, because that very strncmp
    rejects `show`. Measured on a target whose commands are `show=` and `name=`: neither was
    mined, while `buf`, `std`, `uptr` and `data_` were, so the dispatcher was never entered.
    """
    verbs = command.mine_verbs(_elf_with(["strncmp", "fgets", "show=", "name=", "quit"]))
    assert "show=" in verbs and "name=" in verbs
    # keyed tokens lead: a literal with `=` baked in exists because the program compares against
    # it, whereas a bare lowercase word is any identifier that survived the scan
    assert verbs[0].endswith("=") and verbs[1].endswith("=")
    # the separator is not part of the NAME, so noise filtering still applies through it
    assert "printf=" not in command.mine_verbs(
        _elf_with(["strncmp", "fgets", "printf=", "show=", "quit"]))


def test_a_keyed_verb_gets_its_argument_on_the_same_line():
    """A `verb=<value>` dispatcher reads one line, so the argument cannot be the next one.

    `command_seeds` only ever emitted `verb` and `verb` + a data LINE, which is right for a
    two-step console (`write`, then the data) and wrong for this shape -- the handler is reached
    only when the value follows the separator on the verb's own line.
    """
    seeds = command.command_seeds(["show=", "name="])
    same_line = [x for x in seeds if x.startswith(b"show=") and x.count(b"\n") == 1
                 and len(x) > len(b"show=\n")]
    assert same_line, seeds[:8]
    # and a single keyed verb is still worth driving -- nothing to sequence, but a value to vary
    assert command.command_seeds(["show="])
    # ...while a single BARE verb remains not a sequence, as before
    assert command.command_seeds(["only"]) == []


def test_the_length_arguments_that_actually_fault_lead():
    """For a LENGTH argument the productive magnitude is moderate, not maximal.

    Measured on a handler reading n bytes from a 64-byte buffer: every value from 65 to
    4294967295 reports a heap-buffer-overflow, and `-1`, LONG_MAX and SIZE_MAX report nothing at
    all -- the C library rejects an operation that large before touching any memory, so the read
    never happens. Leading with the biggest value is the intuitive choice and spends the budget on
    precisely the values that cannot work; this asserts the measured order instead.
    """
    order = [int(v) for v in command._dangerous_first(8)]
    assert all(0 < v <= 0xFFFFFFFF for v in order[:5]), order
    # the extremes are kept but demoted, because they do fault other shapes
    full = [int(v) for v in command._dangerous_first(64)]
    assert -1 in full and 0 in full
    assert full.index(0) > full.index(4096), "zero cannot over-read; it must not lead"
    assert full.index(-1) > full.index(4096)


def test_no_seed_family_is_starved_by_the_triple_enumeration():
    """The triples are n*(n-1)*(n-2), so taken in order they consume the whole budget.

    With the 16 verbs the miner returns that is 3,360 sequences against a 96-seed cap, and the
    seeds were 16 doubles plus 80 triples -- the overflow and single families never appeared at
    all **[measured]**. A family always truncated to nothing is a family that is not tested.
    """
    verbs = [f"v{i}" for i in range(16)]
    seeds = command.command_seeds(verbs)
    assert len(seeds) == 96
    lines = {x.count(b"\n") for x in seeds}
    assert {1, 2, 3} <= lines, f"missing a shape: {sorted(lines)}"
    assert any(b"A" * 64 in x for x in seeds), "the overflow family was starved"
    assert any(x.count(b"\n") == 1 and b"A" not in x for x in seeds), "the singles were starved"
