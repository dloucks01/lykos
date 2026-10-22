"""A target that does not terminate is a target, not a failure.

Measured on `zigzag`, a static-pie stripped HTB binary that prints a banner and then blocks
forever on every input, on every channel (verified directly: rc=124 under `timeout 25` with empty
stdin, with 4 bytes, and with 256 random bytes). Two separate things went wrong with it:

  * `coverage_fuzz` RAISED. Its seed screening drops seeds that time out, because afl-fuzz aborts
    its dry run on one -- but when EVERY seed was dropped the code substituted the built-in
    default seeds, which time out too, so AFL aborted on those instead and the stage errored.
  * the blind campaign got ONE execution out of a 47-second slice, because every execution waits
    out the full per-execution timeout. Nothing in that row said "this target never returns"; it
    read like a target that resists fuzzing.
"""
import pathlib

import lykos.analyze as analyze_pkg
from lykos.analyze.orchestrate import _NONTERM_EXEC_TIMEOUT, _baseline_timed_out


class _Row:
    def __init__(self, mode, timed_out):
        self.input_mode, self.timed_out = mode, timed_out


class _Store:
    def __init__(self, rows):
        self._rows = rows
        self.conn = None


def _patched(monkeypatch, rows):
    import lykos.db.dao as dao

    class _DAO:
        def __init__(self, _conn):
            pass

        def list_by_target(self, _tid):
            return rows
    monkeypatch.setattr(dao, "DynResultDAO", _DAO)
    return _Store(rows)


def test_a_baseline_that_never_returns_is_recognised(monkeypatch):
    st = _patched(monkeypatch, [_Row("none", True)])
    assert _baseline_timed_out(st, "t1")


def test_a_baseline_that_returns_is_not(monkeypatch):
    st = _patched(monkeypatch, [_Row("none", False)])
    assert not _baseline_timed_out(st, "t1")


def test_a_timeout_on_a_FUZZED_input_is_not_the_baseline(monkeypatch):
    """Individual inputs time out all the time -- that is ordinary. The question is whether the
    program terminates when it is simply run, which is the baseline's own row."""
    st = _patched(monkeypatch, [_Row("none", False), _Row("stdin", True), _Row("file", True)])
    assert not _baseline_timed_out(st, "t1")


def test_no_baseline_at_all_is_not_a_claim(monkeypatch):
    st = _patched(monkeypatch, [])
    assert not _baseline_timed_out(st, "t1")


def test_the_campaigns_get_a_short_timeout_for_such_a_target():
    """A program that blocks after consuming its input reaches the same code at 1s as at 10s, so
    the only thing the longer wait buys is fewer executions."""
    assert 0 < _NONTERM_EXEC_TIMEOUT <= 2.0
    src = pathlib.Path(analyze_pkg.__path__[0], "orchestrate.py").read_text()
    body = src.split("def run_case_autopilot", 1)[1]
    assert "_baseline_timed_out(store, tid)" in body, \
        "the pass never asks whether the target terminates"
    assert "exec_timeout=_NONTERM_EXEC_TIMEOUT" in body


def test_afl_declines_a_target_it_cannot_dry_run():
    """Its own seed screening defeated itself: with every seed dropped as a timeout, it fell back
    to the DEFAULT seeds -- which time out on this target too."""
    src = pathlib.Path(analyze_pkg.__path__[0], "fuzz", "coverage.py").read_text()
    i = src.index("slow = _drop_timeout_seeds")
    j = src.index("seeds = seeds or list(_DEFAULT_SEEDS)")
    between = src[i:j]
    assert "if slow and not seeds:" in between, \
        "all-seeds-dropped still falls through to the default seeds, which time out too"
    # The decline now covers both causes afl's dry run rejects (a seed that hangs OR crashes), so
    # it names what is true of the target rather than assuming non-termination.
    assert "timed out or crashed" in between, "the decline does not say what is true of the target"
    assert '"supported": False' in between, "AFL's inability here must be a decline, not an error"
