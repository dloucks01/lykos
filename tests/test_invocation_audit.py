"""Audit regressions for analyze/invocation.py: usage parsing that lost real flags, invented verbs,
fed the fuzzed input into an OUTPUT slot, or went quadratic on hostile help text."""
import time

from lykos.analyze import invocation as I


def test_next_flag_is_not_the_previous_flags_value():
    flags, _ = I.from_usage(["usage: prog -v -c <config>"])
    assert flags == {"-v": False, "-c": True}
    found = I.discover(["usage: prog -v -c <config>"])
    assert I.propose_argv(found) == ["-c", "@@"]


def test_generic_options_word_is_not_a_flag_value():
    flags, _ = I.from_usage(["usage: prog -d [options] file"])
    assert flags["-d"] is False


def test_metavar_verb_slot_is_not_a_literal_verb():
    assert I.verb_subcommand("usage: tool <command> <file>") is None
    assert I.discover(["usage: tool <command> <file>"])["subcommand"] is None


def test_file_ish_positionals_are_not_verbs():
    assert I.verb_subcommand("usage: tool src_file dst_file") is None
    assert I.verb_subcommand("usage: tool input_file") is None


def test_flag_value_before_the_verb_is_skipped():
    assert I.verb_subcommand("usage: tool -c <config> parse <file>") == "parse"


def test_flag_values_are_not_converter_positionals():
    assert I.output_positional("usage: prog -o <outfile> -c <config>") is False
    found = I.discover(["usage: prog -o <outfile> -c <config>"])
    assert I.propose_argv(found)[:2] == ["-c", "@@"]
    # a real converter is unchanged
    assert I.output_positional("usage: conv [options] input output") is True
    assert I.output_positional("usage: tool -v INPUT OUTPUT") is True


def test_input_never_goes_behind_an_output_or_directory_flag():
    for usage in ("usage: prog -o <outfile> <input>", "usage: prog -d <dir> <input>",
                  "usage: prog --log <logfile> <input>"):
        argv = I.propose_argv(I.discover([usage]))
        assert "@@" not in argv, (usage, argv)       # runner appends the input positionally
    # a required config flag still carries the input
    assert I.propose_argv(I.discover(["usage: prog -c <config>"])) == ["-c", "@@"]


def test_materialize_gives_a_directory_slot_a_directory(tmp_path):
    found = I.discover(["usage: prog -d <dir> <input>"])
    argv = I.materialize(found, tmp_path)
    assert argv[0] == "-d"
    assert (tmp_path / "lykos.dir").is_dir() and argv[1] == str(tmp_path / "lykos.dir")


def test_hostile_blank_line_runs_are_linear():
    blob = "\n" * 200000
    t = time.monotonic()
    I.from_subcommands(blob)
    I.is_multicall(blob)
    I.multicall_self_name("\n".join([" " * 8] * 50000))
    I._REFUSED.search(blob + "x")
    assert time.monotonic() - t < 2.0


def test_huge_whitespace_command_row_is_bounded():
    text = "usage: x <command>\n  ab  x" + " " * 200000 + "y\n  cd  -- read it\n  ef  -- dump it\n"
    t = time.monotonic()
    I.from_subcommands(text)
    assert time.monotonic() - t < 2.0


def test_exec_name_for_whitespace_padding_is_fast():
    data = (b" " * 8 + b"\0") * 60000
    t = time.monotonic()
    assert I.exec_name_for(data) == ""
    assert time.monotonic() - t < 3.0
