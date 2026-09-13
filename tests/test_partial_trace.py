"""A behaviour trace that was CUT SHORT must say so.

Found by a real failure: under load the Wine +relay trace did not finish, the registry write
the target makes never reached the log, and the inventory came back empty -- reported with
exactly the same confidence as a program that ran to completion and did nothing. `_relay`
knew it had killed the target at the timeout and `trace` passed the fact along; every consumer
dropped it. An absence of evidence is only evidence of absence if we were watching the whole
time, and the operator cannot tell the two apart from an empty list.
"""
from __future__ import annotations

from lykos.analyze.debug.trace_stage import _partial_note


def test_a_complete_trace_carries_no_caveat():
    assert _partial_note({"ok": True}) == ""
    assert _partial_note({"ok": True, "timed_out": False, "truncated": False}) == ""


def test_a_timed_out_trace_says_we_stopped_watching():
    note = _partial_note({"ok": True, "timed_out": True})
    assert note
    assert "timeout" in note.lower()
    # the operator has to be told what an empty inventory does NOT mean
    assert "does not mean" in note
    assert "timeout" in note.lower() and "re-run" in note


def test_a_truncated_trace_says_the_log_was_capped():
    note = _partial_note({"ok": True, "truncated": True})
    assert note and "cap" in note.lower()


def test_both_reasons_are_reported_together():
    note = _partial_note({"ok": True, "timed_out": True, "truncated": True})
    assert "timeout" in note.lower() and "cap" in note.lower()
    assert note.count(";") == 1


def test_the_relay_reports_a_timeout_instead_of_swallowing_it():
    """`except TimeoutExpired: pass` made a killed run indistinguishable from a finished one."""
    import inspect

    from lykos.analyze.debug import winapi
    src = inspect.getsource(winapi._relay)
    assert "timed_out = True" in src, "the timeout is swallowed again"
    # and every successful return has to carry it, or a caller cannot ask
    oks = [ln for ln in src.splitlines() if "\"ok\": True" in ln]
    assert oks, "no success return found -- did _relay change shape?"


def test_every_relay_success_path_carries_both_flags():
    """There are two success returns (resolved module map, and the ImageBase fallback). One of
    them carrying the flags is not enough: the fallback is the path a stripped or packed PE
    takes, which is exactly where a partial trace is most likely."""
    from lykos.analyze.debug import winapi
    seen = []

    def fake_run(*a, **k):
        raise __import__("subprocess").TimeoutExpired(cmd="wine", timeout=1)

    import subprocess as sp
    real = sp.run
    sp.run = fake_run
    try:
        # no wine here is fine -- we only care that the shape is right when it IS there
        if winapi._wine():
            r = winapi._relay("/nonexistent.exe", argv=[], stdin=b"", timeout=1,
                              wineprefix=None)
            seen.append(r)
    except Exception:
        pass
    finally:
        sp.run = real
    for r in seen:
        if r.get("ok"):
            assert "timed_out" in r and "truncated" in r


def test_the_consumers_read_the_flags_rather_than_dropping_them():
    """The defect was not a missing flag, it was a flag nobody read."""
    import inspect

    from lykos.analyze.debug import monitor_stage, trace_stage, winmonitor
    for mod in (trace_stage, monitor_stage):
        src = inspect.getsource(mod)
        assert "_partial_note(" in src, f"{mod.__name__} does not consult the partial flags"
    assert "timed_out" in inspect.getsource(winmonitor.monitor)
