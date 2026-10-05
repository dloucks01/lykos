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


def test_a_flag_that_names_a_file_gets_a_real_file(tmp_path):
    """A service required to be given `-j <app.jar>` was handed the literal string "app.jar",
    refused it because no such file exists, and the run concluded the whole invocation was
    wrong -- leaving the operator exactly where they started. The proposal cannot be tested
    until the files it names are real."""
    import zipfile
    found = invocation.discover(
        ["usage: svc -c <config> -d <display-id> -j <app.jar> -i <cslid>", "c:d:j:i:v"])
    argv = invocation.materialize(found, tmp_path)
    jar = argv[argv.index("-j") + 1]
    assert jar.startswith(str(tmp_path)) and zipfile.is_zipfile(jar)
    # ...and `@@` is untouched, because the campaign substitutes its own mutated input there
    assert argv[argv.index("-c") + 1] == "@@"
    # a display id or an instance id names nothing on disk and stays a literal
    assert argv[argv.index("-d") + 1] == ":0"


def test_shape_template_value_matches_the_placeholder_format():
    """A placeholder written as a literal format -- a session id NNN-NNN-NNN-NNN, a time HH:MM --
    is rendered to a concrete value of that exact shape, so a service that VALIDATES the shape
    (`-s <NNN-NNN-NNN-NNN>`, `-csid 111-111-222-222`) accepts it and runs. An ordinary descriptive
    word is left to the keyword hints."""
    assert invocation._shape_value("NNN-NNN-NNN-NNN") == "111-111-111-111"
    assert invocation._shape_value("<NNN-NNN-NNN-NNN>") == "111-111-111-111"
    assert invocation._shape_value("HH:HH:HH") == "aa:aa:aa"
    assert invocation._shape_value("config") is None          # a real word, not a template
    assert invocation._shape_value("IP") is None              # too short to be a template
    assert invocation._shape_value("session-id") is None      # letters -> not a pure shape


def test_structured_id_flag_gets_a_shape_matching_value():
    """The gap that hid a parameter-driven bug: `-s <NNN-NNN-NNN-NNN>` used to get the generic
    "x", which a strict validator rejects, so the app never ran. It must now get a value of the
    documented shape."""
    import re
    found = invocation.discover(
        ["t:s:c:", "usage: %s -t <seconds> -s <NNN-NNN-NNN-NNN> -c <config>"])
    byflag = {f["flag"]: f for f in found["flags"]}
    assert re.fullmatch(r"\d{3}-\d{3}-\d{3}-\d{3}", byflag["-s"]["default"]), byflag["-s"]
    assert byflag["-t"]["kind"] == "number"                   # <seconds> is numeric
    assert byflag["-c"]["default"] == "@@"                    # the config is the fuzzed input


def test_numeric_placeholders_get_a_number_default():
    assert invocation._hint_for("-t", "seconds") == ("number", "0")
    assert invocation._hint_for("-n", "timeout") == ("number", "0")


def test_from_help_mines_flags_and_value_shapes():
    """--help option tables name flags the terse .rodata usage omits, and their value shapes.
    Synonyms on one row collapse to one canonical flag; a single-spaced description is not a
    value."""
    help_txt = (
        "Options:\n"
        "  -t, --timeout N          seconds\n"
        "  -s <NNN-NNN-NNN-NNN>     session id\n"
        "  -c, --config FILE        config file\n"
        "  -v, --verbose            be loud and wordy here\n")
    takes, ph, names = invocation.from_help(help_txt.splitlines())
    assert takes["-t"] and takes["-s"] and takes["-c"]       # value flags
    assert takes.get("-v") is False                          # switch, not a value
    assert "--timeout" not in takes and "--config" not in takes   # synonyms collapsed to short
    assert ph["-s"] == "NNN-NNN-NNN-NNN" and ph["-c"] == "FILE" and ph["-t"] == "N"
    assert names["-c"] == "config" and names["-t"] == "timeout"   # alias kept as a kind hint


def test_discover_from_help_when_the_binary_usage_is_terse():
    """The modern-GNU-tool case: usage says only '[options]', the flags live in --help."""
    import re
    found = invocation.discover(["Usage: svc [options]"], help_text=(
        "Options:\n  -s <NNN-NNN-NNN-NNN>  id\n  -c, --config FILE  cfg\n  -t N  secs\n"))
    assert found["confidence"] == "high" and "help" in found["sources"]
    bf = {f["flag"]: f for f in found["flags"]}
    assert re.fullmatch(r"\d{3}-\d{3}-\d{3}-\d{3}", bf["-s"]["default"])
    assert bf["-c"]["default"] == "@@" and bf["-t"]["kind"] == "number"


def test_mine_shape_values_recovers_a_structured_value_from_strings():
    """No --help and no usage shape, but the binary PRINTS the format it wants in an error
    string: recover a usable value from it so a strict validator is satisfied."""
    vals = invocation.mine_shape_values(
        ["bad session id (want NNN-NNN-NNN-NNN)", "e.g. 111-222-333-444",
         "/lib/x.so", "version 4.0.3", "gcc 16.2.0-1", "ld-linux-x86-64.so.2"])
    assert "111-111-111-111" in vals          # the TEMPLATE is rendered to a concrete value
    # literal digit-strings (a version, an soname, a path) are NOT shapes anyone asked for and
    # must never be mined as a flag value -- that injected garbage into real binaries' flags
    assert all("4.0.3" not in v and ".so" not in v and "16.2.0" not in v for v in vals)
    assert "111-222-333-444" not in vals      # a bare literal example is not mined (templates only)
    # end to end: optstring gives the flags, the error string's TEMPLATE gives -s its shape
    found = invocation.discover(["t:s:c:", "bad session id (want NNN-NNN-NNN-NNN)"])
    sflag = next(f for f in found["flags"] if f["flag"] == "-s")
    assert sflag["default"] != "x" and "-" in sflag["default"]
    assert "strings" in found["sources"]


def test_input_behind_an_optional_read_flag_is_used():
    """A reader whose only input path is an OPTIONAL flag (`tcpdump -r <pcap>`, `openssl -in
    <file>`) still gets fuzzed: when no REQUIRED flag carries the input, the input goes on an
    optional READ flag -- never an output one, or we would overwrite the fuzzed path."""
    found = invocation.discover(["usage: prog [ -r file ] [ -w file ] [ -v ]"])
    argv = invocation.propose_argv(found)
    assert argv == ["-r", "@@"], argv          # read flag chosen, write flag avoided
    # a required file flag still wins over an optional one
    found2 = invocation.discover(["usage: prog -c <config> [ -r file ]"])
    argv2 = invocation.propose_argv(found2)
    assert argv2[argv2.index("-c") + 1] == "@@" and "@@" not in argv2[argv2.index("-c") + 2:]


def test_write_only_optional_flag_is_not_fed_the_input():
    """No read flag at all -> we do NOT put @@ on a write/output flag (that would clobber it)."""
    found = invocation.discover(["usage: prog [ -o outfile ] [ -v ]"])
    argv = invocation.propose_argv(found)
    assert "@@" not in argv                     # nothing safe to carry the input


def test_getopt_only_input_flag_becomes_the_optional_input_slot():
    """A reader (tcpdump) hides its input behind `-r`, which is in the getopt OPTSTRING but not the
    terse usage line. The optstring flag is added as an optional candidate, and the input-slot
    fallback puts @@ on it -- the READ flag `-r`, never a non-input optstring flag. Derived purely
    from the binary (no man page); the fuzz stage then verifies the invocation against the target."""
    # usage names only -v; the optstring adds -r (value) and -w (value, a WRITE flag)
    found = invocation.discover(["vr:w:", "usage: prog [-v]"])
    argv = invocation.propose_argv(found)
    assert argv == ["-r", "@@"], argv              # -r chosen; -w (write) never fed the input
    # a usage that already names the input flag is unchanged (no spurious optstring slot)
    found2 = invocation.discover(["c:v", "usage: prog -c <config>"])
    argv2 = invocation.propose_argv(found2)
    assert argv2 == ["-c", "@@"], argv2


def test_converter_usage_proposes_input_and_output_positionals():
    """A converter (`tool [opts] input output`) is driven by its two positionals; propose just
    them -- input at @@, a scratch output at the OUTPUT placeholder -- not its optional flags."""
    found = invocation.discover(["usage: conv [options] input output", "c:f:v"])
    assert found["output_positional"] is True
    assert invocation.propose_argv(found) == [invocation.INPUT_PLACEHOLDER,
                                              invocation.OUTPUT_PLACEHOLDER]
    # a non-converter (no output positional) is unchanged
    assert invocation.discover(["usage: tool -c <config>"])["output_positional"] is False


def test_verify_accepts_content_error_but_rejects_file_error():
    """A converter handed a bad input exits non-zero with a CONTENT error (it got past args); that
    is accepted. A wrong proposal that names a file it cannot find is rejected."""
    def run_content(argv):           # bad input -> parser engaged, content error
        return _R(2, b"tiffcp: Sanity check on directory count failed\n") if argv \
            else _R(255, b"usage: tiffcp [options] input... output\n")
    assert invocation.verify(run_content, "c", ["@@", "lykos.out"], "/s")["accepted"]
    def run_filerr(argv):            # wrong proposal -> file not found
        return _R(9, b"conv: cannot open nope: No such file\n") if argv \
            else _R(2, b"usage: conv in out\n")
    assert not invocation.verify(run_filerr, "c", ["-x", "nope", "@@"], "/s")["accepted"]


# ---- subcommand-dispatched tools (tool <command> INPUT): mutool, git, busybox ----------------
def test_subcommand_dispatch_picks_an_input_reading_command():
    from lykos.analyze import invocation as inv
    mutool = ("usage: mutool <command> [options]\n\tclean\t-- rewrite pdf file\n"
              "\tdraw\t-- convert document\n\tinfo\t-- show information\n\tcreate\t-- create pdf")
    best, allc = inv.from_subcommands(mutool)
    assert best == "draw" and "create" in allc            # a reader, not the create command
    found = inv.discover([], help_text=mutool)
    assert found["subcommand"] == "draw"
    assert inv.propose_argv(found) == ["draw", "@@"]       # subcommand first, input after it


def test_subcommand_dispatch_handles_git_and_busybox_styles():
    from lykos.analyze import invocation as inv
    git = ("usage: git [--version] <command> [<args>]\n   clone     Clone a repository\n"
           "   log       Show commit logs\n   show      Show objects")
    assert inv.from_subcommands(git)[0] in ("show", "log")   # a read-only inspector, not clone
    bb = ("Usage: busybox [function]\nCommands:\n   cat   concatenate files\n"
          "   ls    list directory\n   tar   archive")
    assert inv.from_subcommands(bb)[0] == "cat"


def test_a_non_dispatch_tool_is_not_given_a_subcommand():
    from lykos.analyze import invocation as inv
    # a viewer that takes a file directly (mupdf) must NOT be handed a spurious subcommand
    assert inv.from_subcommands("usage: mupdf [options] file.pdf [page]")[0] is None
    assert inv.discover([], help_text="usage: tool [-v] [-o OUT] file").get("subcommand") is None


def test_verify_accepts_a_content_format_error_as_engaged():
    """A parser that opened the input and rejected its FORMAT (mutool's 'cannot find document
    handler') engaged past the argument gate -- it must not be read as a file-open refusal."""
    from lykos.analyze import invocation as inv

    class _R:
        def __init__(s, out, rc): s.stdout, s.stderr, s.exit_code, s.crashed = out, b"", rc, False
    def run(a):
        if not a:
            return _R(b"usage: mutool <command> [options]", 1)      # bare -> usage (rejected)
        return _R(b"error: cannot find document handler for file: /x/sample", 1)  # engaged
    v = inv.verify(run, "mutool", ["draw", "@@"], "/x/sample")
    assert v["accepted"] and v["bare_rejected"]
