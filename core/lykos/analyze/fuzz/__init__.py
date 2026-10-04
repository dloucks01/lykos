"""Fuzzing (Phase 5). Importing registers three stages:
  - `fuzz`          black-box mutational fuzzing (zero dependencies)
  - `coverage_fuzz` coverage-guided via AFL++ qemu-mode (optional bundled tool)
  - `directed_fuzz` distance-directed at statically-flagged sinks (zero dependencies)
"""
from .coverage import COVERAGE_STAGE, enqueue_coverage_fuzz  # noqa: F401
from .coverage import register as _register_cov
from .directed import DIRECTED_STAGE, enqueue_directed_fuzz  # noqa: F401
from .directed import register as _register_dir
from .env_stage import ENV_FUZZ_STAGE, enqueue_env_fuzz  # noqa: F401
from .env_stage import register as _register_env
from .net_stage import NET_FUZZ_STAGE, enqueue_net_fuzz  # noqa: F401
from .net_stage import register as _register_net
from .stage import FUZZ_STAGE, enqueue_fuzz  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
    _register_cov()
    _register_dir()
    _register_net()
    _register_env()
