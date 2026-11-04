"""Concolic seeds pin only a gate-byte PREFIX (the rest stays symbolic), and the directed-confirm
ladder actually passes a harness's seeds through to concolic_confirm / the angr spec.

A seed hard-constrained in full (`byte == v` for every byte) makes the state fully concrete over the
seed length -- angr just replays the seed and solves nothing -- so the driver pins a prefix only."""
import base64
import importlib.util
from pathlib import Path

from lykos.analyze.symbolic import directed_confirm as DC

_DRIVER = Path(__file__).resolve().parents[1] / "core/lykos/analyze/symbolic/angr_driver.py"


def _driver():
    spec = importlib.util.spec_from_file_location("lykos_angr_driver_seedt", _DRIVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_seed_prefix_plan_pins_prefixes_not_whole_seed():
    d = _driver()
    seed = bytes(range(100))
    plan = d.seed_prefix_plan([seed], size=256)
    assert [len(p) for _i, p in plan] == [50, 16]           # len//2 and the 16-byte gate prefix
    assert all(seed.startswith(p) for _i, p in plan)
    assert all(len(p) < len(seed) for _i, p in plan)         # never the whole seed for a long seed


def test_seed_prefix_plan_clips_to_symbolic_size_and_dedups():
    d = _driver()
    plan = d.seed_prefix_plan([b"A" * 1000], size=8)
    assert [len(p) for _i, p in plan] == [8]                 # min(n,16)==min(n,len//2)==8 -> one state
    assert d.seed_prefix_plan([b"", b"Z"], size=64) == [(1, b"Z")]   # empty seed/prefix dropped


def test_seed_prefix_plan_bounded():
    d = _driver()
    plan = d.seed_prefix_plan([bytes([i]) * 64 for i in range(20)], size=256)
    assert len(plan) == 8 and len(plan) <= d._MAX_SEEDED_STATES


def test_rung_concolic_threads_seeds_into_spec(monkeypatch, tmp_path):
    seen = {}

    def fake_run_explore(py, spec, ctx=None, timeout=None):
        seen["spec"] = spec
        return {"generated": []}

    monkeypatch.setattr(DC._concolic, "locate_angr_python", lambda: "/usr/bin/false")
    monkeypatch.setattr(DC._concolic, "run_explore", fake_run_explore)
    exe = tmp_path / "h"
    exe.write_bytes(b"\x7fELF")
    seeds = [b"MAGIC\x00\x01" + b"x" * 40, b"HDR"]
    r = DC._rung_concolic({"explore_binary": str(exe), "seeds": seeds}, timeout=5, ctx=None)
    assert r["confirmed"] is False                            # no inputs generated -> honest decline
    assert [base64.b64decode(s) for s in seen["spec"]["seeds"]] == seeds
