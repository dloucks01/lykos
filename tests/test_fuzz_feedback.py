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


def test_echoed_input_is_not_new_behaviour():
    """A parser handed its input as a filename prints that filename back, so every distinct
    payload looked like a distinct path -- 40% of inputs counted as new behaviour in argv mode.
    A program repeating what it was given has told us nothing about which branch it took."""
    a = behaviour_of(_R(err=b"Error : cannot open 'AAAABBBB'"), b"AAAABBBB")
    b = behaviour_of(_R(err=b"Error : cannot open 'CCCCDDDD'"), b"CCCCDDDD")
    assert a == b


def test_a_real_difference_still_registers_when_the_input_is_echoed():
    a = behaviour_of(_R(err=b"Error : cannot open 'AAAA'"), b"AAAA")
    b = behaviour_of(_R(err=b"Illegal subdirectory link 'AAAA'"), b"AAAA")
    assert a != b


def test_an_option_travels_with_the_input_it_crashed(tmp_path):
    """A crash found under an option only means something WITH that option, so the re-run that
    checks it reproduces has to use the same prefix."""
    from lykos.analyze.fuzz.runner import run_input
    seen = {}

    class _Sandbox:
        @staticmethod
        def run(exe, argv=(), stdin=b"", **kw):
            seen["argv"] = list(argv)

            class R:
                crashed = False
                signal_name = None
            return R()
    import lykos.analyze.fuzz.runner as runner
    real, runner.sandbox = runner.sandbox, _Sandbox()
    try:
        wf = tmp_path / "in.bin"
        run_input(tmp_path / "t", "file", wf, 1.0, "x86-64", b"data",
                  base_argv=["-exonly", "-v"])
        assert seen["argv"][:2] == ["-exonly", "-v"], seen["argv"]
        assert seen["argv"][-1] == str(wf), "the carrier still comes last"
        run_input(tmp_path / "t", "file", wf, 1.0, "x86-64", b"data")
        assert seen["argv"] == [str(wf)], "and no prefix when none was given"
    finally:
        runner.sandbox = real


def test_a_crash_that_does_not_happen_again_is_not_filed():
    """Some targets REWRITE their input -- jhead's `-dc` and `-zt` edit the file in place --
    so the program faults on bytes it produced itself while the input we hold runs clean. On
    one jhead campaign 36 of 137 crashes were like that: a quarter of everything downstream
    was chasing a crash nobody could reproduce, and the release gate failed with "PoC not
    reproduced"."""
    from lykos.analyze.fuzz.stage import _reproduces

    class _T:
        arch, endianness, bits = "x86-64", "little", 64

    calls = []

    def _fake(exe, mode, wf, timeout, arch, data, **kw):
        calls.append(kw.get("base_argv"))

        class R:
            crashed = False
        return [], R()
    import lykos.analyze.fuzz.stage as st
    real, st.run_input = st.run_input, _fake
    try:
        assert _reproduces(st.run_input, "exe", "file", None, 1.0, _T(), b"x",
                           ["-dc"]) is False
        assert calls == [["-dc"]], "re-run under the same options it was found with"
    finally:
        st.run_input = real


def test_the_input_goes_where_the_target_wants_it(tmp_path):
    """A service that takes `-c <config>` cannot be fuzzed by appending the input to argv: with
    any other flag present you get `-c -v <path>` and the flag eats the file. `@@` marks the
    position, the convention the eval harness already used."""
    from lykos.analyze.fuzz.runner import invocation
    wf = tmp_path / "in.bin"
    argv, stdin = invocation("file", wf, b"name=x", ["-c", "@@"])
    assert argv == ["-c", str(wf)] and stdin == b""
    argv, _ = invocation("file", wf, b"name=x", ["-c", "@@", "-v"])
    assert argv == ["-c", str(wf), "-v"], "position is preserved, not appended"
    # no placeholder: appended, which is what every existing caller expects
    argv, _ = invocation("file", wf, b"x", ["-v"])
    assert argv == ["-v", str(wf)]
    argv, _ = invocation("file", wf, b"x")
    assert argv == [str(wf)]
    # stdin carries no carrier at all, so argv passes through untouched
    argv, stdin = invocation("stdin", wf, b"payload", ["-q"])
    assert argv == ["-q"] and stdin == b"payload"


def test_the_fuzz_stage_honours_the_operator_argv():
    """It read `params.argv` nowhere: a target requiring a flag was run as `daemon <workfile>`,
    printed its usage and exited -- 8,000 executions, `behaviours: 1`, reported as a clean
    campaign that found nothing. The mined flags are exploration and go in front; the
    operator's argv is the contract."""
    import inspect

    from lykos.analyze.fuzz import stage as fz
    src = inspect.getsource(fz.fuzz_stage)
    assert 'p.get("argv")' in src, "the stage has to read it"
    assert "base_argv=base_argv" in src, "...and pass it to the campaign"
    camp = inspect.getsource(fz.fuzz_campaign)
    assert "run_argv = prefix + base_argv" in camp
    for used in ("base_argv=run_argv", 'kw["base_argv"] = run_argv',
                 "argv = list(run_argv)"):
        assert used in camp, used


def test_coverage_novelty_falls_back_when_blocks_are_armed_but_never_reported():
    """If blocks were recovered and armed but the runner reports no coverage for any input
    (ptrace refused in this sandbox, a runner that cannot answer), block-only novelty is dead
    and the corpus would freeze forever. The campaign latches whether coverage ever answered
    and falls back to behaviour novelty when it never did -- and says so, rather than reporting
    a silently frozen 'no crashes' campaign."""
    import inspect

    from lykos.analyze.fuzz import stage as fz
    camp = inspect.getsource(fz.fuzz_campaign)
    assert "cover_reported" in camp, "must latch whether coverage ever answered"
    assert "if all_blocks and cover_reported:" in camp, "trust blocks only once they answer"
    assert "novel = b not in seen_behaviour" in camp, "otherwise fall back to behaviour novelty"
    assert "coverage_unavailable" in camp, "armed-but-silent coverage must be surfaced"
    assert '"coverage":' in camp, "stats distinguish live / unavailable / none"


def test_minimize_reproduces_under_the_same_invocation_it_was_found_with():
    """A crash behind an option (jhead's `-cmd`) does not reproduce without it. The confirm
    step already re-ran with the flag prefix, but the minimizer predicate did not -- so a
    flag-triggered crash minimized against an invocation that never crashes, reducing nothing
    or, worse, to a non-crashing input. The predicate now carries the same run_argv."""
    import inspect

    from lykos.analyze.fuzz import stage as fz
    camp = inspect.getsource(fz.fuzz_campaign)
    assert "def _same(d, _sig=sig, _prefix=run_argv):" in camp
    assert 'kw["base_argv"] = _prefix' in camp


def test_starved_means_never_entered_not_merely_slow():
    """`starved` must catch the campaign that ran plenty but never got past the gate -- 8,000
    executions, one behaviour -- and the one whose coverage was armed and reached nothing, not
    only the one that barely ran. Reaching any block, more than one behaviour, or a crash all
    clear it, so a slow-but-productive campaign is never falsely flagged."""
    import inspect

    from lykos.analyze.fuzz import stage as fz
    camp = inspect.getsource(fz.fuzz_campaign)
    # the original slow-but-not-starved guard is preserved
    assert "did_work = crashes > 0 or len(seen_behaviour) > 1" in camp
    assert "execs < 200 and rate < 20 and not did_work" in camp
    # ...and the new not-entered triggers are added
    assert "entered = did_work or len(seen_blocks) > 0" in camp
    assert "execs >= 200 and not entered" in camp
    assert "coverage_dead and not did_work" in camp


def test_only_reproducible_crashes_count_and_stop_the_channel_sweep():
    """A target that rewrites its own input produces crashes that never reproduce. Counting
    those in the headline and letting them halt the channel sweep reported `crashes > 0,
    unique: 0` and stopped probing the channel that actually carries the bug. The reproducible
    count is tracked separately and drives both the report and the early break."""
    import inspect

    from lykos.analyze.fuzz import stage as fz
    camp = inspect.getsource(fz.fuzz_campaign)
    assert "crashes_reproducible += 1" in camp
    assert '"crashes_reproducible": crashes_reproducible' in camp
    stg = inspect.getsource(fz.fuzz_stage)
    assert 'if st.get("crashes_reproducible"):' in stg, "early break gates on reproducible"
