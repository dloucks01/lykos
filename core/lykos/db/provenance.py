"""Ambient provenance: the pipeline stage currently executing (doc 49, Themes 1a/2b).

The job worker sets this around each ``fn(ctx)`` call to the running run's stage name; ``FindingDAO``
reads it so a finding records WHICH stage discovered it -- without threading an argument through the
~150 sites that build and upsert a candidate.

A :class:`contextvars.ContextVar` is per-thread, so the pool's concurrent workers never
cross-contaminate one another's stage, and it is simply ``None`` when a finding is written outside a
stage (for example in a unit test, or during ingest before a worker claims the run). That is the
point: provenance we know is recorded; provenance we do not know is left blank, never guessed.
"""
from __future__ import annotations

import contextvars
from typing import Optional

_current_stage: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "lykos_current_stage", default=None)


def current_stage() -> Optional[str]:
    """The stage whose ``fn(ctx)`` is executing on this thread, or None."""
    return _current_stage.get()


def set_current_stage(name: Optional[str]):
    """Set the ambient stage for this thread; returns a token for :func:`reset_current_stage`."""
    return _current_stage.set(name)


def reset_current_stage(token) -> None:
    """Restore the ambient stage to what it was before the matching :func:`set_current_stage`."""
    try:
        _current_stage.reset(token)
    except (ValueError, LookupError):
        # Token from another context (e.g. the stage spawned a thread that reset it): leave as-is.
        pass
