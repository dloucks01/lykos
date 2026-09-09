"""Crash-input minimization (ddmin-style chunk removal), deterministic and budget-bounded.

`run_crashes(bytes) -> bool` returns True when the input still reproduces the same crash.
The minimizer removes progressively finer chunks, keeping any shorter input that still
crashes, until only single-byte removals remain. Bounded by `cap` executions.
"""
from __future__ import annotations

from typing import Callable, Tuple


def minimize(run_crashes: Callable[[bytes], bool], data: bytes,
             cap: int = 300) -> Tuple[bytes, int]:
    best = bytes(data)
    execs = 0
    if len(best) <= 1:
        return best, execs
    n = 2
    while len(best) > 1 and execs < cap:
        chunk = max(1, len(best) // n)
        i = 0
        reduced = False
        while i < len(best) and execs < cap:
            cand = best[:i] + best[i + chunk:]
            execs += 1
            if cand and run_crashes(cand):
                best = cand
                reduced = True          # list shrank; retry at same offset/granularity
            else:
                i += chunk
        if not reduced:
            if chunk == 1:
                break
            n = min(len(best), n * 2)    # finer granularity
    return best, execs
