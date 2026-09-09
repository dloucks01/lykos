"""Crash minimization (ddmin-style)."""
from lykos.analyze.dynamic.minimize import minimize


def test_reduces_to_trigger():
    out, execs = minimize(lambda d: b"A" in d, b"XXAXXAXX")
    assert b"A" in out and len(out) < 8 and execs > 0


def test_single_trigger_byte():
    out, _ = minimize(lambda d: b"A" in d, b"AAAA")
    assert out == b"A"


def test_noop_on_single_byte():
    out, execs = minimize(lambda d: True, b"A")
    assert out == b"A" and execs == 0


def test_respects_cap():
    n = {"c": 0}

    def crashes(d):
        n["c"] += 1
        return b"A" in d
    out, execs = minimize(crashes, b"A" * 200, cap=10)
    assert execs <= 10 and n["c"] <= 10
