"""Phase 8 (doc 17.1/17.2) — the component graph: cross-binary linking.

Resolves each component's imports against every other component's exports to build ONE
merged system graph spanning the case's binaries (Karonte's Binary Dependency Graph
pattern, deterministic, zero-AI). Importing registers the `link_case` stage.
"""
from .crosstaint import cross_taint_case  # noqa: F401
from .ipc import model_ipc_case  # noqa: F401
from .resolve import resolve_case, symbol_resolution  # noqa: F401
from .stage import (  # noqa: F401
    CROSS_TAINT_STAGE,
    IPC_STAGE,
    LINK_STAGE,
    enqueue_cross_taint,
    enqueue_ipc,
    enqueue_link,
    link_case_stage,
)
from .stage import register as _register
from .stage import register_cross_taint as _register_ct
from .stage import register_ipc as _register_ipc


def register() -> None:
    _register()
    _register_ct()
    _register_ipc()
