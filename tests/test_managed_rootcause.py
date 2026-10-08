"""Re-parsing a managed crash must not make the fault vanish.

`RunResult.exit_code` is deliberately None when the run CRASHED -- every substrate in the
sandbox does that. But the managed parsers use the exit code as their ONE discriminator between
a program that printed an exception trace and handled it correctly, and one the runtime killed:
`traceback.print_exc()` and `Console.Error.Write(ex)` produce byte-identical output to an
uncaught exception, so without that check a target which merely ECHOES its input would "crash"
on any mutation containing the words, and a mutator rewarded for crashes learns to emit them.

So the guard is right and must stay. The bug was that `root_cause` re-parsed a STORED result
whose exit code had already been blanked by that convention: the fault vanished, and the stage
went on to file `uncaught None` / CWE-248 at state `confirmed`. That outranks the crash finding
which named the defect correctly, so a reproduced IndexOutOfRangeException (CWE-129) was
reported as a generic missing catch. It broke dotnet_oob_index and was latent on the JVM and
CPython paths, where the conformance gate happened to early-stop on the fuzzer's finding first.
"""
import pytest
from lykos.analyze.debug.stage import _managed_runtime, _reparse_rc
from lykos.analyze.dynamic.sandbox import RunResult

_TRACES = {
    "jvm": (b"Exception in thread \"main\" java.lang.ArrayIndexOutOfBoundsException: "
            b"Index 9 out of bounds for length 4\n\tat Idx.main(Idx.java:5)\n",
            "ArrayIndexOutOfBoundsException"),
    "cpython": (b"Traceback (most recent call last):\n"
                b'  File "/t/o.py", line 4, in <module>\n    print(t[len(s)])\n'
                b"IndexError: list index out of range\n",
                "IndexError"),
    "clr": (b"Unhandled exception. System.IndexOutOfRangeException: Index was outside the "
            b"bounds of the array.\n   at Program.Main(String[] a) in /t/Program.cs:line 6\n",
            "IndexOutOfRangeException"),
}


def _crashed(trace, name):
    """A RunResult shaped exactly as the sandbox stores a managed crash."""
    return RunResult(isolation="bwrap+netns+x", crashed=True, exit_code=None,
                     signal_name=name, stderr=trace)


@pytest.mark.parametrize("kind", sorted(_TRACES))
def test_a_stored_managed_crash_still_parses_when_re_read(kind):
    trace, name = _TRACES[kind]
    rt = _managed_runtime(kind)
    got, detail, _frames = rt["parse"](_crashed(trace, name))
    assert got == name, f"{kind}: the fault vanished on re-parse (got {got!r})"
    assert detail


@pytest.mark.parametrize("kind", sorted(_TRACES))
def test_the_frames_survive_the_re_parse_too(kind):
    """The frames are the whole reason root_cause re-parses rather than trusting signal_name:
    a managed fault is blamed on its deepest APPLICATION frame."""
    trace, name = _TRACES[kind]
    rt = _managed_runtime(kind)
    _got, _detail, frames = rt["parse"](_crashed(trace, name))
    if kind == "jvm":
        assert frames, "the JVM trace carries the frames root_cause blames on"
    else:
        assert frames


def test_a_crash_gets_a_truthful_nonzero_code_and_a_clean_run_does_not():
    assert _reparse_rc(RunResult(isolation="x", crashed=True, exit_code=None)) == 1
    assert _reparse_rc(RunResult(isolation="x", crashed=False, exit_code=0)) == 0
    # A real code is never overridden -- 134 is SIGABRT through the CLR, and the parsers read it.
    assert _reparse_rc(RunResult(isolation="x", crashed=True, exit_code=134)) == 134
    assert _reparse_rc(RunResult(isolation="x", crashed=False, exit_code=None)) == 0


@pytest.mark.parametrize("kind", ["cpython", "clr"])
def test_the_echo_guard_still_holds_where_the_exit_code_is_the_only_discriminator(kind):
    """The fix must not weaken what the exit code is FOR.

    Under CPython and the CLR there is no marker that distinguishes the runtime's own default
    handler from the program printing a formatted exception itself: `traceback.print_exc()` and
    `Console.Error.Write(ex)` are byte-identical to the real thing. So a trace with exit 0 is a
    program handling its errors, and must not read as a crash.
    """
    trace, name = _TRACES[kind]
    clean = RunResult(isolation="bwrap+netns+x", crashed=False, exit_code=0, stderr=trace)
    assert _managed_runtime(kind)["parse"](clean)[0] in (None, ""), \
        f"{kind}: an exit-0 trace read as a crash"


def test_the_jvm_needs_no_exit_code_because_the_prefix_is_the_proof():
    """The JVM is deliberately different and it is not an inconsistency.

    `Exception in thread "main" ...` is emitted ONLY by the JVM's default handler --
    `printStackTrace()` does not produce it -- and it is read from stderr alone, where a target
    cannot place it by echoing its input (an echo goes to stdout). The prefix is therefore
    self-authenticating, and the exit code is reserved for the two cases that are read from
    stdout as well: the VM's own termination line and a fatal VM crash.
    """
    trace, name = _TRACES["jvm"]
    rt = _managed_runtime("jvm")
    assert rt["parse"](RunResult(isolation="x", crashed=False, exit_code=0,
                                 stderr=trace))[0] == name
    # ...but the same text arriving on STDOUT, which a target can echo, proves nothing.
    assert rt["parse"](RunResult(isolation="x", crashed=False, exit_code=0,
                                 stdout=trace))[0] is None
