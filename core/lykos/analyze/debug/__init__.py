"""Debugger-driven root-cause slicing (Phase 6). Importing registers the `root_cause` stage.

GDB is an optional backend; the pure-stdlib ptrace helper is the fallback, so root-cause works
with no external tool installed.
"""
from .extract_stage import EXTRACT_STAGE, enqueue_extract  # noqa: F401
from .extract_stage import register as _register_extract
from .monitor_stage import MONITOR_STAGE, enqueue_monitor  # noqa: F401
from .monitor_stage import register as _register_monitor
from .multidebug import MULTI_DEBUG_STAGE, enqueue_multi_debug  # noqa: F401
from .multidebug import register as _register_multi
from .stage import ROOT_CAUSE_STAGE, enqueue_root_cause  # noqa: F401
from .stage import register as _register
from .taint_stage import TAINT_STAGE, enqueue_taint  # noqa: F401
from .taint_stage import register as _register_taint
from .trace_stage import TRACE_STAGE, enqueue_behavior_trace  # noqa: F401
from .trace_stage import register as _register_trace


def register() -> None:
    _register()
    _register_multi()
    _register_monitor()
    _register_extract()
    _register_trace()
    _register_taint()
