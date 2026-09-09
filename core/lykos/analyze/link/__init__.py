"""Phase 8 (doc 17.1/17.2) — the component graph: cross-binary linking.

Resolves each component's imports against every other component's exports to build ONE
merged system graph spanning the case's binaries (Karonte's Binary Dependency Graph
pattern, deterministic, zero-AI). Importing registers the `link_case` stage.
"""
from .resolve import resolve_case, symbol_resolution  # noqa: F401
from .stage import LINK_STAGE, enqueue_link, link_case_stage  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
