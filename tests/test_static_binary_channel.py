"""A statically linked binary has no import table, and that is not evidence that it reads nothing.

Measured on `zigzag`, a static-pie stripped HTB binary that reads a command menu from stdin. The
channel ranking is built on the input functions a binary imports; a static binary resolves
`read`/`fopen` inside itself, so there are no dynamic imports at all, and stripped there are no
names either. Every channel came out without evidence, the no-evidence default ranked `arg`
first, the orchestrator pinned it, and the input never reached the program. Each execution then
blocked until its 10-second timeout, so all three engines managed NINE executions between them
and two of them errored outright.

The gate row for that target: `EXECS 9, RATE 0.1, ERR 3`. Nothing about it said "we fuzzed the
wrong channel" -- it looked like a target that resists fuzzing.
"""
import pytest
from lykos.analyze.poc.capture import MODES, modes_for, no_import_evidence


class _T:
    def __init__(self, linking="dynamic", file_type="elf"):
        self.linking, self.file_type = linking, file_type


def test_a_static_binary_is_recognised_as_having_no_import_evidence():
    assert no_import_evidence(_T("static-pie"))
    assert no_import_evidence(_T("static"))
    # A dynamically linked STRIPPED binary is not this case: .dynsym still names its imports,
    # which is why /usr/bin/readelf (stripped, dynamic) ranked correctly in the same run.
    assert not no_import_evidence(_T("dynamic"))
    assert not no_import_evidence(_T(""))
    assert not no_import_evidence(_T(None))


def test_argv_does_not_lead_on_silence_from_a_static_binary():
    """The no-evidence default stays `arg` where the import table WAS read and named no input
    function -- that reasoning is sound and separately tested. It is unsound when there is no
    table to read."""
    assert modes_for([], None)[0] == "arg"
    assert modes_for([], None, no_imports=True)[0] == "stdin"
    # every channel is still attempted either way
    assert set(modes_for([], None, no_imports=True)) == set(MODES)


def test_evidence_still_outranks_the_static_default():
    """`no_imports` must not override a signal that exists: a static binary with recovered
    symbols naming `fopen`/`fread` is a file parser and must rank as one."""
    class _E:
        def __init__(self, n):
            self.dst_name = n
    assert modes_for([_E("fopen"), _E("fread")], no_imports=True)[0] == "file"
    assert modes_for([], symbols=["fgets", "main"], file_type="elf", no_imports=True)[0] == "stdin"


def test_the_autopilot_does_not_pin_a_channel_it_has_no_evidence_for():
    """The `fuzz` stage splits its budget across every channel it is handed, and passing one
    collapses that sweep to a single guess. On a target with nothing to rank by, the sweep is
    worth more than the guess."""
    import pathlib

    import lykos.analyze as analyze_pkg
    src = pathlib.Path(analyze_pkg.__path__[0], "orchestrate.py").read_text()
    body = src.split("def run_case_autopilot", 1)[1]
    assert "_no_imports(t)" in body, "the pass no longer asks whether it has channel evidence"
    assert body.count('"fuzz", status, stop, fz') == 2, \
        "a fuzz call site still pins the orchestrator's channel guess unconditionally"
    # the channel-specific engines keep a single mode -- AFL takes one -t and one channel
    assert '"coverage_fuzz", status, stop, dyn' in body
    assert '"directed_fuzz", status, stop, dyn' in body


@pytest.mark.parametrize("linking", ["static", "static-pie"])
def test_the_ranking_reaches_the_engines_for_a_static_target(linking):
    """End of the chain: `modes_for` is the one ranking, and both the stage and the pass derive
    `no_imports` from the same recorded column, so they cannot disagree about the channel."""
    import pathlib

    import lykos.analyze as analyze_pkg
    for mod in ("fuzz/stage.py", "poc/capture.py", "orchestrate.py"):
        src = pathlib.Path(analyze_pkg.__path__[0], mod).read_text()
        assert "no_import_evidence" in src, f"{mod} does not consult the recorded linking"
    assert no_import_evidence(_T(linking))
