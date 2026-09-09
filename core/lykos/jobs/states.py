"""JE-01 — Run status state machine.

Terminal states: done, cancelled. `error` may be requeued for retry. `running` may go back
to `queued` (reaper reclaim / retry).
"""
from __future__ import annotations

QUEUED, RUNNING, DONE, ERROR, CANCELLED = "queued", "running", "done", "error", "cancelled"
TERMINAL = frozenset({DONE, CANCELLED})

_VALID: dict[str, set[str]] = {
    QUEUED: {RUNNING, CANCELLED},
    RUNNING: {DONE, ERROR, CANCELLED, QUEUED},
    ERROR: {QUEUED},         # retry
    DONE: set(),
    CANCELLED: set(),
}


def can_transition(src: str, dst: str) -> bool:
    return dst in _VALID.get(src, set())


def check_transition(src: str, dst: str) -> None:
    if not can_transition(src, dst):
        raise ValueError(f"illegal status transition {src!r} -> {dst!r}")
