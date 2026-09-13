"""Whole-system scenario construction: which component is the entry, which are services, and
which channel joins them.

The stage detonates a multi-component system and blames the component that crashed for an
input delivered somewhere else. Getting the scenario wrong is not a crash, it is a silently
wrong experiment: send into the wrong end and nothing happens, which reads exactly like a
system with no bug in it.
"""
from __future__ import annotations

import pytest
from lykos.analyze.link import whole_system as ws


class _T:
    def __init__(self, tid, filename="c"):
        self.id, self.filename = tid, filename
        self.sha256 = "0" * 64
        self.arch = "x86-64"


class _TDao:
    def __init__(self, by_id):
        self._by = by_id

    def get(self, tid):
        return self._by.get(tid)


class _Edge:
    def __init__(self, kind, src, dst, symbol, detail):
        self.kind, self.src_target, self.dst_target = kind, src, dst
        self.symbol, self.detail = symbol, detail


class _Ctx:
    def __init__(self, targets, edges=(), case_id="case1", target_id=None):
        self.case_id, self.target_id = case_id, target_id
        self._edges = list(edges)
        self.conn = self
        self.targets = targets


@pytest.fixture
def two():
    return {"a": _T("a", "producer"), "b": _T("b", "consumer")}


# ---- explicit scenarios ------------------------------------------------------------------

def test_an_explicit_scenario_is_used_as_given(two):
    ctx = _Ctx(two)
    entry, services, channel = ws._scenario_from_params(
        ctx, _TDao(two), {"entry_target": "a", "services": ["b"],
                          "channel": {"family": "socket", "key": "/tmp/q"}})
    assert entry.id == "a"
    assert [s.id for s in services] == ["b"]
    assert channel == {"family": "socket", "key": "/tmp/q"}


def test_the_stages_own_target_is_the_default_entry(two):
    """The operator selected a target and pressed the button; that is the entry unless they
    said otherwise."""
    ctx = _Ctx(two, target_id="a")
    entry, services, _c = ws._scenario_from_params(ctx, _TDao(two), {"services": ["b"]})
    assert entry.id == "a" and [s.id for s in services] == ["b"]


def test_a_service_id_that_does_not_resolve_is_dropped_not_carried_as_none(two):
    """A None in the component list would be materialised and crash the stage; dropping it
    leaves a scenario that is still runnable with the components that do exist."""
    ctx = _Ctx(two)
    _e, services, _c = ws._scenario_from_params(
        ctx, _TDao(two), {"entry_target": "a", "services": ["b", "ghost"]})
    assert [s.id for s in services] == ["b"]
    assert all(s is not None for s in services)


def test_no_entry_and_no_services_yields_an_empty_scenario(two):
    ctx = _Ctx(two)
    entry, services, _c = ws._scenario_from_params(ctx, _TDao(two), {})
    assert entry is None and services == []


# ---- auto-derivation from the IPC graph --------------------------------------------------

def _auto(targets, edges):
    ctx = _Ctx(targets, edges)

    class _CE:
        def __init__(self, es):
            self._es = es

        def list_by_case(self, _cid):
            return self._es

    orig = ws.ComponentEdgeDAO
    ws.ComponentEdgeDAO = lambda _conn: _CE(edges)
    try:
        return ws._scenario_from_ipc(ctx, _TDao(targets))
    finally:
        ws.ComponentEdgeDAO = orig


def test_an_ipc_edge_makes_the_producer_the_entry_and_the_consumer_the_service(two):
    """Direction is the whole point: the entry is the end that RECEIVES untrusted input, and
    the service is the one that consumes it across the channel. Reversed, the payload goes to
    the component that was already trusted and the experiment proves nothing."""
    edges = [_Edge("ipc", "a", "b", "/tmp/q", "socket:/tmp/q")]
    entry, services, channel = _auto(two, edges)
    assert entry.id == "a", "the producer is the entry"
    assert [s.id for s in services] == ["b"], "the consumer is the service under test"
    assert channel == {"family": "socket", "key": "/tmp/q"}


def test_the_channel_family_is_taken_from_the_edge_detail(two):
    edges = [_Edge("ipc", "a", "b", "/run/f", "fifo:/run/f")]
    _e, _s, channel = _auto(two, edges)
    assert channel["family"] == "fifo" and channel["key"] == "/run/f"


def test_an_edge_with_no_detail_still_yields_a_scenario(two):
    """An edge recorded without a family is not a reason to refuse the whole run."""
    edges = [_Edge("ipc", "a", "b", "/tmp/q", None)]
    entry, services, channel = _auto(two, edges)
    assert entry.id == "a" and services and channel["key"] == "/tmp/q"
    assert channel["family"] == ""


def test_a_non_ipc_edge_is_not_a_scenario(two):
    """Dynamic-link and taint edges join components too, and neither is a channel a payload
    can be delivered over."""
    for kind in ("dynamic", "taint", "static"):
        entry, services, channel = _auto(two, [_Edge(kind, "a", "b", "sym", "x:y")])
        assert entry is None and services == [] and channel is None, kind


def test_no_edges_at_all_yields_no_scenario(two):
    assert _auto(two, []) == (None, [], None)


def test_an_edge_naming_a_component_that_is_gone_is_skipped(two):
    """A target deleted from the case leaves its edges behind; building a scenario on a None
    component would crash the stage instead of moving to the next edge."""
    edges = [_Edge("ipc", "a", "ghost", "/tmp/q", "socket:/tmp/q"),
             _Edge("ipc", "a", "b", "/tmp/r", "socket:/tmp/r")]
    entry, services, channel = _auto(two, edges)
    assert entry.id == "a" and [s.id for s in services] == ["b"]
    assert channel["key"] == "/tmp/r"


# ---- the component list handed to the runner ---------------------------------------------

def test_services_start_before_the_entry(tmp_path):
    """A listener has to be running before anything is sent to it. The entry last is not
    cosmetic: reversed, every payload is delivered to a process that does not exist yet."""
    class _C:
        def __init__(self, d):
            self.d = d

        def scratch(self):
            return self.d

        class content:
            @staticmethod
            def path(_sha):
                class _P:
                    @staticmethod
                    def read_bytes():
                        return b"\x7fELF" + b"\x00" * 64
                return _P
    ctx = _C(tmp_path)
    comps = ws._components(ctx, _T("entry", "e"), [_T("svc1", "s1"), _T("svc2", "s2")])
    assert [c["role"] for c in comps] == ["service", "service", "entry"]
    assert comps[-1]["target_id"] == "entry"


def test_the_seed_corpus_covers_the_shapes_that_break_a_service():
    """An empty datagram, an oversized one, and a format string: the three that most often
    take down a receiver, and none of them is reachable by mutating the others by accident."""
    assert b"" in ws._SEEDS, "no empty input -- a receiver that assumes a non-empty read"
    assert any(len(s) >= 64 for s in ws._SEEDS), "nothing long enough to overflow"
    assert any(b"%n" in s or b"%s" in s for s in ws._SEEDS), "no format-string seed"
    assert any(b"\xff" in s for s in ws._SEEDS), "nothing non-ASCII"
