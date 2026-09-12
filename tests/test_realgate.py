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
    # the synthetic cases are single-channel BY CONSTRUCTION: stdin is ignored and the other
    # channel cannot carry enough bytes to reach the bug
    synthetic = [c for c in realgate.MATRIX if not c.prebuilt]
    assert len({c.channel for c in synthetic}) == len(synthetic)


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
    """The dynamic run records the argv it crashed with, and that argv ENDS with the thing
    carrying the input -- the workfile path for a file target, the payload for an argv one.
    Handing the whole thing back as a prefix made the replay

        jhead /tmp/<gone>/input.bin /tmp/new/input.bin

    and jhead stops at the missing first file without ever reaching the crashing one. A real
    crash was filed as "did not reproduce", which is the confident-wrong-answer shape this
    gate exists to catch."""
    from lykos.analyze.poc.capture import how_to_feed

    class _Row:
        def __init__(self, mode, argv):
            self.input_sha, self.input_mode, self.argv = "s" * 64, mode, argv

    class _Conn:
        pass

    class _Target:
        id = 1

    import lykos.analyze.poc.capture as cap
    rows = []

    class _DAO:
        def __init__(self, _conn):
            pass

        def list_by_target(self, _tid):
            return rows
    old = cap.DynResultDAO if hasattr(cap, "DynResultDAO") else None
    import lykos.db.dao as dao
    real = dao.DynResultDAO
    dao.DynResultDAO = _DAO
    try:
        rows[:] = [_Row("file", ["-autorot", "/tmp/old/input.bin"])]
        mode, argv, why = how_to_feed(_Conn(), _Target(), "s" * 64, {})
        assert mode == "file" and argv == ["-autorot"], argv

        rows[:] = [_Row("arg", ["-x", "AAAAPAYLOAD"])]
        _m, argv, _w = how_to_feed(_Conn(), _Target(), "s" * 64, {})
        assert argv == ["-x"], "the payload is not part of the setup"

        rows[:] = [_Row("stdin", ["-q", "-v"])]
        _m, argv, _w = how_to_feed(_Conn(), _Target(), "s" * 64, {})
        assert argv == ["-q", "-v"], "stdin carries no argv, so all of it is flags"
    finally:
        dao.DynResultDAO = real
        assert old is None or True
