"""Sandboxed dynamic analysis (Phase 4). Importing registers the `dynamic_run` stage."""
from .sandbox import RunResult, run  # noqa: F401
from .stage import DYNAMIC_STAGE, enqueue_dynamic  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
