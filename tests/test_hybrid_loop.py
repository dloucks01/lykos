"""The iterative concolic<->fuzz hybrid loop (doc 6): it repeats the concolic->refuzz handoff while
each round keeps paying off and stops the instant a round stalls, the budget runs low, or stop is
requested -- and it never does LESS than the prior one-shot handoff (the first round is unconditional).

Driven with the module-level stage runner and progress probe monkeypatched, so the control flow is
tested deterministically without running angr or a fuzzer."""
from __future__ import annotations

from lykos.analyze import orchestrate as orch


class _Events:
    def __init__(self):
        self.rows = []

    def append(self, kind, *, case_id, payload):
        self.rows.append((kind, payload))

    def of(self, kind):
        return [p for k, p in self.rows if k == kind]


class _Store:
    def __init__(self):
        self.events = _Events()


class _Budget:
    def __init__(self, avail):
        self._avail = avail
        self.pause = None
        self.skip_stages = ()
        self.overrides = None

    def available(self):
        return self._avail


class _Stop:
    def __init__(self, val=False):
        self.val = val

    def is_set(self):
        return self.val


class _Target:
    case_id = "case-1"
    id = "tgt-1"


def _install(monkeypatch, progress_seq):
    """Drive `_hybrid_progress` from a fixed sequence (first value is the pre-loop baseline, then one
    per completed round) and record every `_staged` call. `_distinct_crashes` returns a list whose
    length matches the latest progress crash-count, which is what the loop returns."""
    calls = []
    state = {"i": 0, "last": progress_seq[0]}

    def fake_staged(bud, store, target, stage, status, stop, params=None, *, want=None, **kw):
        calls.append((stage, want, dict(params or {})))

    def fake_progress(store, target_id):
        # baseline is index 0; each call after a round advances through the sequence
        i = min(state["i"], len(progress_seq) - 1)
        state["last"] = progress_seq[i]
        state["i"] += 1
        return progress_seq[i]

    def fake_distinct(store, target_id):
        return [object()] * int(state["last"][0])

    monkeypatch.setattr(orch, "_staged", fake_staged)
    monkeypatch.setattr(orch, "_hybrid_progress", fake_progress)
    monkeypatch.setattr(orch, "_distinct_crashes", fake_distinct)
    return calls


def test_advanced_detects_any_component():
    assert orch._hybrid_advanced((0, 10.0, 5), (1, 10.0, 5))     # a new crash
    assert orch._hybrid_advanced((0, 10.0, 5), (0, 20.0, 5))     # more coverage
    assert orch._hybrid_advanced((0, 10.0, 5), (0, 10.0, 6))     # a new corpus input
    assert not orch._hybrid_advanced((0, 10.0, 5), (0, 10.0, 5))  # nothing moved


def test_runs_every_round_while_it_keeps_advancing(monkeypatch):
    # baseline, then three rounds that each raise coverage -> the loop runs the full cap.
    seq = [(0, 10.0, 5), (0, 20.0, 8), (0, 30.0, 11), (0, 40.0, 14)]
    calls = _install(monkeypatch, seq)
    store = _Store()
    out = orch._hybrid_coverage_loop(_Budget(600.0), store, _Target(), "tgt-1", {"input_mode": "stdin"},
                                     {}, _Stop(), size_mb=1.0)
    rounds = store.events.of("autopilot.hybrid_round")
    loop = store.events.of("autopilot.hybrid_loop")[0]
    assert len(rounds) == orch._MAX_HYBRID_ROUNDS == 3
    assert loop["ended"] == "max_rounds" and loop["rounds"] == 3
    # concolic + directed_fuzz per round, each with a distinct refuzz seed
    assert [c[0] for c in calls] == ["concolic", "directed_fuzz"] * 3
    seeds = [c[2].get("seed") for c in calls if c[0] == "directed_fuzz"]
    assert seeds == [4242, 4243, 4244]
    assert isinstance(out, list)


def test_stops_on_stall(monkeypatch):
    # round 1 moves nothing -> stall after exactly one round (the one-shot's worth of work).
    seq = [(0, 10.0, 5), (0, 10.0, 5)]
    calls = _install(monkeypatch, seq)
    store = _Store()
    orch._hybrid_coverage_loop(_Budget(600.0), store, _Target(), "tgt-1", {}, {}, _Stop(), size_mb=1.0)
    loop = store.events.of("autopilot.hybrid_loop")[0]
    assert loop["ended"] == "stall" and loop["rounds"] == 1
    assert [c[0] for c in calls] == ["concolic", "directed_fuzz"]


def test_first_round_runs_even_under_tight_budget(monkeypatch):
    # available() below the follow-on floor must NOT skip the first round: never less than one-shot.
    seq = [(0, 10.0, 5), (0, 10.0, 5)]
    calls = _install(monkeypatch, seq)
    store = _Store()
    orch._hybrid_coverage_loop(_Budget(0.0), store, _Target(), "tgt-1", {}, {}, _Stop(), size_mb=1.0)
    assert [c[0] for c in calls] == ["concolic", "directed_fuzz"]   # the first round ran
    assert store.events.of("autopilot.hybrid_loop")[0]["rounds"] == 1


def test_budget_stops_followon_round(monkeypatch):
    # round 1 advances, but the search phase is below the floor, so round 2 never starts.
    seq = [(0, 10.0, 5), (0, 20.0, 8), (0, 30.0, 11)]
    calls = _install(monkeypatch, seq)
    store = _Store()
    orch._hybrid_coverage_loop(_Budget(10.0), store, _Target(), "tgt-1", {}, {}, _Stop(), size_mb=1.0)
    loop = store.events.of("autopilot.hybrid_loop")[0]
    assert loop["ended"] == "budget" and loop["rounds"] == 1
    assert [c[0] for c in calls] == ["concolic", "directed_fuzz"]   # only the first round's stages


def test_stop_requested_before_any_round(monkeypatch):
    seq = [(0, 10.0, 5)]
    calls = _install(monkeypatch, seq)
    store = _Store()
    orch._hybrid_coverage_loop(_Budget(600.0), store, _Target(), "tgt-1", {}, {}, _Stop(True), size_mb=1.0)
    loop = store.events.of("autopilot.hybrid_loop")[0]
    assert loop["ended"] == "stopped" and loop["rounds"] == 0
    assert calls == []
