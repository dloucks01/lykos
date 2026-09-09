"""Symbolic / concolic execution (Phase 6). Importing registers the `concolic` stage.

Concolic execution is provided by angr, an optional bundled tool that runs in its own
interpreter via a standalone driver (the core stays stdlib-only). When angr is absent the
stage fails clearly and the fuzzing stages remain the deterministic fallback.
"""
from .stage import CONCOLIC_STAGE, enqueue_concolic  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
