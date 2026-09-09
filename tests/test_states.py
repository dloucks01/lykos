"""JE-01 — status state machine."""
import pytest
from lykos.jobs.states import can_transition, check_transition


def test_valid_transitions():
    assert can_transition("queued", "running")
    assert can_transition("running", "done")
    assert can_transition("running", "queued")   # reaper/retry
    assert can_transition("error", "queued")     # retry
    assert can_transition("queued", "cancelled")


def test_invalid_transitions():
    assert not can_transition("done", "running")     # terminal
    assert not can_transition("cancelled", "queued")  # terminal
    assert not can_transition("queued", "done")       # must run first
    with pytest.raises(ValueError):
        check_transition("done", "running")
