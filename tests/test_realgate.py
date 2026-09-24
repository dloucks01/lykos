"""The gate that covers the join the other gates leave open.

`test` never runs a program, `eval-gate` stops at detect, and `arch-gate` -- which IS end to
end -- never runs detect or root_cause, hands every stage an explicit `input_mode="stdin"`,
and never runs a produced bundle. Six confident-but-wrong results shipped through that gap in
one session. These tests cover the gate's decision logic; the chain itself runs under
`make real-gate`, and is mutation-tested against each of those six bugs.
"""
from lykos.eval import realgate


def _rep(results, skipped=()):
    return {"results": list(results), "skipped": list(skipped)}


def _ok(label="a", **detail):
    return {"label": label, "ok": True, "missing": [], "detail": detail, "note": ""}


def test_a_clean_run_passes():
    passed, verdict, reason = realgate.gate(_rep([_ok(), _ok("b")]))
    assert passed and verdict == "PASS" and "2 real-chain cases" in reason


def test_a_case_that_did_not_build_is_a_FAILURE_not_a_skip():
    """A silent opt-out is the same failure mode this gate exists to catch: something looks
    green because it never ran."""
    passed, verdict, reason = realgate.gate(
        _rep([_ok()], [{"label": "argv_ip_control", "why": "did not compile"}]))
    assert not passed and "did not build" in reason and "argv_ip_control" in reason


def test_a_failure_names_what_was_missing():
    bad = {"label": "argv_ip_control", "ok": False,
           "missing": ["L2", "bundle_reproduces"], "detail": {}, "note": ""}
    passed, _v, reason = realgate.gate(_rep([bad]))
    assert not passed and "L2" in reason and "bundle_reproduces" in reason


def test_the_gate_returns_the_shape_the_cli_expects():
    """archgate's command unpacks three values; realgate shares it."""
    assert len(realgate.gate(_rep([_ok()]))) == 3


# ---------------------------------------------------------------- the matrix's invariants
def test_a_substrate_that_is_not_machine_code_is_covered():
    """Java has its own triage, executor, crash oracle, CWE mapping and bundle runner, and
    none of it was covered by a gate -- including a bundle that ran `./target.bin` on a zip.
    A gate over native ELF only cannot see any of that."""
    jvm = [c for c in realgate.MATRIX if c.lang == "java"]
    assert jvm, "the real gate has to cover the JVM path"
    c = jvm[0]
    assert c.fuzz, "found from the jar alone, like the other real cases"
    # the assertion that the ladder's ceiling is stated honestly: no L2 is claimed for a
    # runtime that owns the instruction pointer
    assert "L2" not in c.expect and "L3" not in c.expect
    assert c.expect["not_memory_corruption"] is True


def test_both_delivery_channels_are_covered():
    """arg and file are exactly the channels no other gate exercises -- arch-gate is
    stdin-only, which is why three stages could default to stdin undetected."""
    assert {c.channel for c in realgate.MATRIX} == {"arg", "file"}


def test_each_case_is_reachable_through_exactly_one_channel():
    """The sweep is load-bearing: if a case crashed under several modes, a stage that guessed
    wrong would still pass and the regression would hide again.

    What matters is that each case has ONE channel and that every channel is covered -- not
    that the cases have distinct channels from each other, which only held while there were
    exactly as many cases as channels."""
    assert all(c.channel in ("arg", "file", "stdin") for c in realgate.MATRIX)
    assert {c.channel for c in realgate.MATRIX} >= {"arg", "file"}
    # Each case names exactly one channel. Cases used to be required to have channels DISTINCT
    # from each other, which the docstring above already flagged as an accident of there being
    # as many cases as channels -- and it expired the moment a second file-driven case existed
    # (the Java service, whose input is a config path behind `-c`). Single-channel-ness is a
    # property of the fixture's source, not of the matrix, so it cannot be asserted here; what
    # can be is that no case hedges by naming more than one.
    assert all(isinstance(c.channel, str) and c.channel for c in realgate.MATRIX)


def test_the_expectations_cover_the_defects_this_gate_exists_for():
    expects = set().union(*(c.expect for c in realgate.MATRIX))
    # the PoC ladder, the deliverable, and the detect<->root_cause join
    assert {"L1", "L2", "bundle_reproduces", "attributed", "poc_backed"} <= expects
    assert {"cwe120", "cwe121"} <= expects, "detect must be asserted, not just the ladder"


def test_the_fixtures_are_built_without_a_canary():
    """A canary blocks the return-address overwrite outright, so L2 could never confirm."""
    assert "-fno-stack-protector" in realgate._CFLAGS


def test_the_fixtures_stay_position_independent():
    """PIE is the point: symbolisation has to rebase runtime addresses into the decompiler's
    image, and it silently resolved nothing before that was fixed."""
    assert not any(f in realgate._CFLAGS for f in ("-no-pie", "-fno-pie"))


def test_the_table_reports_what_is_missing():
    bad = {"label": "x", "ok": False, "missing": ["L2"], "detail": {"mode": "arg"}, "note": ""}
    out = realgate.table(_rep([bad], [{"label": "y", "why": "did not compile"}]))
    assert "FAIL" in out and "L2" in out and "mode=arg" in out and "SKIP" in out


def test_the_recorded_argv_is_a_prefix_not_the_whole_invocation():
    """`dyn_result.argv` is the FLAG PREFIX, never the thing carrying the input. The carrier is
    a scratch path that no longer exists by the time anything replays the crash, and every
    replay appends its own. Recording the whole invocation made the replay

        jhead /tmp/<gone>/input.bin /tmp/new/input.bin

    and jhead stops at the missing first file without ever reaching the crashing one, so a real
    crash was filed as "did not reproduce" -- the confident-wrong-answer shape this gate exists
    for. Every stage that records a crash has to honour the convention, so this pins the two
    that build an argv by appending."""
    import inspect

    from lykos.analyze.dynamic import stage as dyn
    src = inspect.getsource(dyn.dynamic_stage)
    assert "argv=prefix" in src, "dynamic_run must record the prefix it started from"
    assert "prefix = list(argv)" in src, "captured before the carrier is appended"

    from lykos.analyze.fuzz import stage as fz
    src = inspect.getsource(fz.fuzz_campaign)
    assert "argv = list(run_argv)" in src, "fuzz must record the argv it ran under"
    assert "invocation(mode, workfile, data)[0]" not in src, \
        "recording the invocation puts a dead scratch path in front of the real input"


def test_a_real_binary_usually_has_no_shell_to_jump_to():
    """L3 is "redirect to a chosen function and prove arrival", and the target has to be one
    the program would NOT have reached. Real code rarely offers one: ncompress has a reachable
    stack overflow and confirmed instruction-pointer control but imports nothing that spawns a
    shell and has no function called `win`, so L3 is honestly unavailable there.

    Relaxing this to "any named function" does produce an L3 -- it picks `Usage` -- but
    redirecting into a function the program calls anyway is a far weaker claim than the badge
    implies, so the strict rule stands."""
    from lykos.analyze.poc.exploit import find_win
    funcs = {"main": 0x1000, "Usage": 0x2000, "_start": 0x3000, "comprexx": 0x4000}
    assert find_win(funcs) == (None, None)
    assert find_win({"win": 0x5000, **funcs})[0] == "win", "a real win target is still found"


def test_an_unreached_hijack_says_why_it_was_unreached():
    """"alignment/mitigations?" sent me reading exploit code when the answer was in the bytes:
    a non-PIE x86-64 win address like 0x4019f5 is f5 19 40 00 00 00 00 00, so the first NUL
    sits THREE BYTES INTO the eight-byte slot and an argv-delivered strcpy stops there."""
    from lykos.analyze.poc.exploit import ret2win_input
    from lykos.analyze.poc.exploit_stage import _nul_cuts_the_slot
    payload = ret2win_input(1048, 0x4019F5, 2096)
    assert _nul_cuts_the_slot(payload, 1048, 8)
    # a NUL-free address is delivered whole
    assert not _nul_cuts_the_slot(ret2win_input(1048, 0x1337C0DE1337, 2096), 1048, 6)


def test_last_done_field_reads_a_terminal_event_past_the_window(tmp_path):
    """A `no_crash` verdict is credited only when the fuzzer actually ran, read from the fuzz
    stage's TERMINAL summary. That event sits past _done_field's small window (fuzz emits a
    progress event every 250 execs), so realgate scans to the end for it."""
    from lykos.casestore import CaseStore

    store = CaseStore.open(tmp_path / "case")
    try:
        c = store.cases.create("x")
        run = store.runs.create(c.id, "fuzz", status="done")
        for i in range(200):                      # bury the terminal event past the window
            store.events.append("fuzz.progress", case_id=c.id, run_id=run.id,
                                payload={"execs": i})
        store.events.append("fuzz.channels", case_id=c.id, run_id=run.id,
                            payload={"execs": 12345})
        # the small-window reader cannot see the terminal summary ...
        assert realgate._done_field(store, c.id, "fuzz", "fuzz.channels", "execs") is None
        # ... the paginating reader finds it, so a real campaign is distinguishable from none
        assert realgate._last_done_field(
            store, c.id, "fuzz", "fuzz.channels", "execs") == 12345
    finally:
        store.close()
