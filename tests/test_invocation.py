"""Discovering how a target has to be INVOKED, from the binary's own strings.

The failure these tests exist to prevent is the quiet one: a service that needs `-c <config>`
runs 8,000 times with no arguments, prints its usage line 8,000 times, and is reported as a
clean campaign. Everything here is about proposing a command line that is *checked* rather
than guessed.
"""
from lykos.analyze import invocation

# a real service's strings: getopt string, usage line, and a lot of surrounding noise
SVC = [
    "c:d:j:i:v",
    "usage: %s -c <config> -d <display-id> -j <app.jar> -i <cslid>",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789ABCDEF",
    "/lib64/ld-linux-x86-64.so.2",
    "GLIBC_2.2.5",
]


def test_usage_line_names_the_flags_and_getopt_says_which_take_values():
    found = invocation.discover(SVC)
    assert found["confidence"] == "high"
    assert [f["flag"] for f in found["flags"]] == ["-c", "-d", "-i", "-j"]
    assert all(f["takes_value"] for f in found["flags"])
    assert "usage" in found["sources"] and "getopt" in found["sources"]


def test_placeholders_become_plausible_values_and_the_config_slot_is_the_input():
    argv = invocation.propose_argv(invocation.discover(SVC))
    # the input goes where the config goes -- that is the file the campaign will mutate
    assert argv[argv.index("-c") + 1] == "@@"
    assert argv[argv.index("-d") + 1] == ":0"
    assert argv[argv.index("-j") + 1] == "app.jar"
    assert argv[argv.index("-i") + 1].count("-") == 4       # a uuid shape, not "x"


def test_the_alphabet_is_not_an_option_string():
    """Every static binary carries "abcdefghijklmnopqrstuvwxyz". Matching it as an option
    string invented sixty flags for a program with five, and a command line full of invented
    flags is worse than none: the target rejects it and the campaign looks clean again."""
    assert invocation.from_optstring(["abcdefghijklmnopqrstuvwxyz",
                                      "0123456789ABCDEF"]) == {}


def test_no_signal_at_all_says_so_rather_than_guessing():
    found = invocation.discover(["just a message", "%s: %s\n", "cannot open"])
    assert found["confidence"] == "none"
    assert found["flags"] == []
    assert invocation.propose_argv(found) == []


def test_an_option_string_alone_is_usable_but_less_certain():
    found = invocation.discover(["hvc:f:"])
    assert found["confidence"] == "medium"
    assert {f["flag"]: f["takes_value"] for f in found["flags"]} == {
        "-h": False, "-v": False, "-c": True, "-f": True}


def test_switches_are_never_turned_on_by_the_proposal():
    """A flag we were not asked for is not ours to set: -v may be verbose, or it may be
    --overwrite."""
    argv = invocation.propose_argv(invocation.discover(["hvc:f:"]))
    assert "-h" not in argv and "-v" not in argv
    # ...and with no usage line there is no placeholder to say WHICH value is the input, so
    # no slot is claimed: every flag gets a concrete value and the runner appends the input
    # positionally. Guessing that -c is the file would be a guess dressed as a finding.
    assert argv == ["-c", "x", "-f", "x"]
    assert "@@" not in argv


def test_long_flags_from_the_usage_line():
    found = invocation.discover(["usage: tool --config=FILE --workers=N --verbose"])
    got = {f["flag"]: f["kind"] for f in found["flags"]}
    assert got["--config"] == "config"
    assert got["--workers"] == "number"


def test_a_caller_supplied_usage_line_is_accepted_as_a_hint():
    found = invocation.discover(["nothing useful"],
                                usage_hint="usage: svc -k <keyfile> -p <port>")
    assert found["confidence"] == "high"
    assert {f["flag"] for f in found["flags"]} == {"-k", "-p"}
    assert dict((f["flag"], f["default"]) for f in found["flags"])["-p"] == "8080"


class _R:
    def __init__(self, rc, out=b"", crashed=False):
        self.exit_code, self.stdout, self.stderr, self.crashed = rc, out, b"", crashed


def test_verify_accepts_an_invocation_the_target_actually_runs():
    def run(argv):
        if not argv:
            return _R(2, b"usage: svc -c <config>\n")
        return _R(0, b"serving\n")
    got = invocation.verify(run, "svc", ["-c", "@@"], "/tmp/cfg")
    assert got["accepted"] and got["bare_rejected"]
    assert got["argv"] == ["-c", "@@"]


def test_verify_rejects_a_wrong_proposal_and_quotes_the_target():
    """unzip needs no flags at all; `-d <dir> -x x` is a worse command line than none. A
    proposal is a hypothesis, and this is what stops a bad one being applied silently."""
    def run(argv):
        if not argv:
            return _R(9, b"usage: unzip [-opts] file[.zip]\n")
        return _R(9, b"unzip:  cannot find or open x, x.zip or x.ZIP.\n")
    got = invocation.verify(run, "unzip", ["-d", "/tmp/d", "-x", "x"], "/tmp/s")
    assert not got["accepted"]
    assert "cannot find or open x" in got["why"]


def test_a_crash_counts_as_getting_past_the_argument_gate():
    """Reaching a segfault means the arguments were good enough to reach real code -- which
    is the entire question being asked."""
    def run(argv):
        return _R(None, b"", crashed=True) if argv else _R(2, b"usage: svc -c <cfg>\n")
    assert invocation.verify(run, "svc", ["-c", "@@"], "/tmp/cfg")["accepted"]
