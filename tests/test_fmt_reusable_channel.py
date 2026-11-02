"""fmt-on-PIE reusable-channel detection (the "fgets/read-loop leak channel" the TTP names).

The two-stage format-string leak->write needs the vulnerable printf(user) sink reached at least
TWICE in one process (iteration 1 leaks the PIE base, iteration 2 plants the %hhn write). The old
gate used only `x64frame.in_loop(sink)` -- a back-edge inside the sink's OWN function -- and so
withheld the two-stage plan from the common menu/dispatch shape: a `main` loop that re-reads input
and calls a handler which prints the user string exactly once. `fmt_recipe.sink_reached_repeatedly`
closes that by proving a caller invokes the sink's function from inside a loop, over the EXACT
recovered call site. Soundly: a real back-edge is required, not "a loop somewhere".
"""
from __future__ import annotations

import types

from lykos.analyze.poc import fmt_recipe


def _ir(instrs):
    return {"blocks": [{"instructions": [{"addr": a, "text": t} for a, t in instrs]}]}


# a `main` that loops: read a choice, call the handler at 0x2000, branch back over the call.
_CALLER_LOOP = _ir([
    (0x1000, "endbr64"),
    (0x1004, "call 0x1500"),            # read the menu choice
    (0x1100, "call 0x2000"),            # <- the call site to the sink's function (CallEdge.site_addr)
    (0x1108, "test eax, eax"),
    (0x110c, "jne 0x1000"),             # back-edge OVER the call site -> the handler runs each pass
    (0x1110, "ret"),
])
# a `main` that calls the handler exactly once (no back-edge over the call site).
_CALLER_ONCE = _ir([
    (0x1000, "endbr64"),
    (0x1100, "call 0x2000"),
    (0x1108, "ret"),
])

_LEAD = types.SimpleNamespace(function_addr=0x2000)         # the sink's FUNCTION
_EDGE = types.SimpleNamespace(src_addr=0x1000, site_addr=0x1100, dst_addr=0x2000)


def _with_caller_ir(monkeypatch, ir):
    monkeypatch.setattr(fmt_recipe, "_function_ir",
                        lambda conn, tid, faddr: ir if int(faddr) == 0x1000 else None)


def test_a_caller_loop_makes_the_channel_reusable(monkeypatch):
    _with_caller_ir(monkeypatch, _CALLER_LOOP)
    assert fmt_recipe.sink_reached_repeatedly(object(), 1, _LEAD, [_EDGE]) is True


def test_a_single_call_is_not_a_reusable_channel(monkeypatch):
    _with_caller_ir(monkeypatch, _CALLER_ONCE)
    assert fmt_recipe.sink_reached_repeatedly(object(), 1, _LEAD, [_EDGE]) is False


def test_no_edges_or_no_function_addr_is_false(monkeypatch):
    _with_caller_ir(monkeypatch, _CALLER_LOOP)
    assert fmt_recipe.sink_reached_repeatedly(object(), 1, _LEAD, []) is False
    nolead = types.SimpleNamespace(function_addr=None)
    assert fmt_recipe.sink_reached_repeatedly(object(), 1, nolead, [_EDGE]) is False


def test_an_edge_to_a_different_function_is_ignored(monkeypatch):
    _with_caller_ir(monkeypatch, _CALLER_LOOP)
    other = types.SimpleNamespace(src_addr=0x1000, site_addr=0x1100, dst_addr=0x9999)
    assert fmt_recipe.sink_reached_repeatedly(object(), 1, _LEAD, [other]) is False
