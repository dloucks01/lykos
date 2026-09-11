"""Whose calls are we looking at?

The runtime monitor breakpoints the dangerous sinks a binary imports. The dynamic loader
resolves symbols through those same libc entry points long before `main` runs, so an
unfiltered log is mostly ld.so startup: on ncompress **11 of 13** recorded calls came from
`_dl_new_object` and friends, burying the two the program actually made (`read` from
`compress`). `winmonitor` already attributes this way -- only calls whose caller is inside the
exe's own mapping -- and the Linux path did not.
"""
from lykos.analyze.debug.monitor_stage import program_calls


def _h(func, in_target=None, caller=None):
    h = {"func": func, "caller_name": caller}
    if in_target is not None:
        h["in_target"] = in_target
    return h


def test_loader_calls_are_separated_from_the_programs():
    mine, loader = program_calls([
        _h("read", True, "compress"),
        _h("strcmp", False, "_dl_new_object"),
        _h("memcpy", False, "dl_main"),
    ])
    assert [h["caller_name"] for h in mine] == ["compress"]
    assert len(loader) == 2


def test_an_unattributed_call_is_kept():
    """Absence of attribution is not evidence the program did not make the call -- a stripped
    or unreadable frame must not silently drop a real sink hit."""
    mine, loader = program_calls([_h("strcpy")])
    assert len(mine) == 1 and not loader


def test_nothing_observed_stays_nothing():
    assert program_calls([]) == ([], [])


def test_the_excluded_count_is_reported_not_discarded():
    """The caller reports how many were excluded, so a log of 2 is not mistaken for a monitor
    that barely ran."""
    mine, loader = program_calls([_h("a", False)] * 11 + [_h("b", True)] * 2)
    assert (len(mine), len(loader)) == (2, 11)
