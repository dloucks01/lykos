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
