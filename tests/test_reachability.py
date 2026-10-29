"""Source-reachability path over the call graph: the shared helper behind the report figure, the
report's structured field, and the GUI's clickable source->sink chain."""
from __future__ import annotations

from types import SimpleNamespace

from lykos.analyze.reachability import bare_sym, reachability_steps


def _e(src, dst, name=None):
    return SimpleNamespace(src_addr=src, dst_addr=dst, dst_name=name)


def test_bare_sym_strips_decoration():
    assert bare_sym("sym.imp.recv") == "recv"
    assert bare_sym("_read") == "read"
    assert bare_sym("recv@plt") == "recv"


def test_reachability_steps_finds_path_with_addresses():
    # entry() reads recv() (an input source) and calls parse() (the finding's function)
    edges = [_e("0x1000", "0x1100", "recv"), _e("0x1000", "0x1200", "parse")]
    steps = reachability_steps(edges, {"function_addr": "0x1200"})
    assert steps, "a reachable path should be found"
    assert steps[0]["tone"] == "source" and steps[-1]["tone"] == "sink"
    assert [s["addr"] for s in steps] == ["0x1000", "0x1200"]   # addr on every hop (for graph focus)
    assert steps[-1]["label"] == "parse"


def test_reachability_steps_never_fabricates():
    # no function on the finding
    assert reachability_steps([_e("0x1000", "0x1200", "parse")], {}) is None
    # no input source among the edges -> no source caller -> no path
    assert reachability_steps([_e("0x1000", "0x1200", "parse")],
                              {"function_addr": "0x1200"}) is None
    # no edges at all
    assert reachability_steps([], {"function_addr": "0x1200"}) is None
