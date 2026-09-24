"""Sandboxed dynamic analysis (Phase 4). Importing registers the `dynamic_run`, `heap_check`,
`heap_trace` and `oob_index` stages."""
from .heap_discover import HEAP_TRACE_STAGE, enqueue_heap_trace  # noqa: F401
from .heap_discover import register as _register_heaptrace
from .heap_stage import HEAP_STAGE, enqueue_heap_check  # noqa: F401
from .heap_stage import register as _register_heap
from .oob_index import OOB_INDEX_STAGE, enqueue_oob_index  # noqa: F401
from .oob_index import register as _register_oob
from .sandbox import RunResult, run  # noqa: F401
from .stage import DYNAMIC_STAGE, enqueue_dynamic  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
    _register_heap()
    _register_heaptrace()
    _register_oob()
