"""Does the fuzzer ever try the program's own options?

It did not. A campaign passed exactly one thing -- the input -- so every path behind a flag was
unreachable by construction. On jhead that is ~200 blocks across six functions, and `DoCommand`
among them is where CVE-2020-6624 lives. Real CLI tools put most of their behaviour behind
options; a fuzzer that only hands over a filename explores the parser and nothing else.

The flags are in the binary. Measured on jhead: mining the extracted string table finds 40% of
its 42 real options, because the usage blob where the short ones live is truncated; mining the
raw bytes finds all 42.
"""
from lykos.analyze.fuzz.stage import mine_flags


def test_flags_are_recovered_from_raw_bytes():
    data = b"\x00\x01usage: -purejpg -autorot -cmd <command> -st\x00binary\x00"
    got = mine_flags(data)
    assert {"-purejpg", "-autorot", "-cmd", "-st"} <= set(got)


def test_a_very_short_isolated_string_is_a_known_blind_spot():
    """Only printable runs of 4+ are scanned. A flag stored ALONE as a 3-byte string is
    therefore missed -- measured on jhead this costs nothing (all 42 of its options also
    appear inside its usage text, so recall is 100%), and scanning shorter runs only adds
    false positives: 11 at length 4, 14 at 3, 19 at 2."""
    assert mine_flags(b"\x00-st\x00") == []


def test_long_options_are_recovered():
    assert "--verbose" in mine_flags(b"    --verbose   print more    ")


def test_a_path_is_not_an_option():
    """A build string carries paths and a command template carries other tools' flags; a
    token glued to a path separator is neither."""
    got = mine_flags(b"/usr/lib/gcc-13/x86-64-linux/cc1 -o /tmp/x-y/z.o    ")
    assert not any("/" in g for g in got)
    assert "-y" not in got


def test_a_format_specifier_is_not_an_option():
    """`jpegtran -trim -%s -outfile` appears verbatim in jhead; `-%s` is not a flag."""
    assert "-%s" not in mine_flags(b"jpegtran -trim -%s -outfile &o &i    ")


def test_a_negative_number_is_not_an_option():
    assert mine_flags(b"value was -1234 and -5.5 out of range    ") == []


def test_nothing_is_invented_for_a_binary_with_no_options():
    assert mine_flags(b"\x00\x01\x02hello world this has no flags at all\x00") == []


def test_the_mined_set_is_capped():
    """An arbitrary binary can contain a lot of hyphenated text; a campaign should not spend
    its budget permuting hundreds of made-up options."""
    data = b" ".join(("-opt%d" % i).encode() for i in range(500))
    assert len(mine_flags(data)) <= 64


def test_the_most_repeated_options_come_first():
    """A real flag is mentioned in usage text AND compared at parse time; an incidental one is
    mentioned once, so frequency is a usable ordering."""
    data = b"-real -real -real other text -incidental more text    "
    assert mine_flags(data)[0] == "-real"
