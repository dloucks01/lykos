"""Debugger-driven root-cause slicing (Phase 6). Importing registers the `root_cause` stage.

GDB is an optional backend; the pure-stdlib ptrace helper is the fallback, so root-cause works
with no external tool installed.
"""
from .multidebug import MULTI_DEBUG_STAGE, enqueue_multi_debug  # noqa: F401
from .multidebug import register as _register_multi
from .stage import ROOT_CAUSE_STAGE, enqueue_root_cause  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
    _register_multi()
