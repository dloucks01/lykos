"""PoC bundle generation + verification (Phase 6/9). Importing registers the stages:
  - `build_poc`      L1: verify a crashing input, bundle it, promote to poc-backed
  - `poc_primitive`  L2: prove instruction-pointer control (cyclic pattern + ptrace capture)
  - `build_exploit`  L3: assisted ret2win template exploit synthesis (control-flow hijack)
"""
from .exploit_stage import EXPLOIT_STAGE, enqueue_exploit  # noqa: F401
from .exploit_stage import register as _register_exploit
from .inject_stage import INJECT_STAGE, enqueue_inject  # noqa: F401
from .inject_stage import register as _register_inject
from .primitive_stage import PRIMITIVE_STAGE, enqueue_primitive  # noqa: F401
from .primitive_stage import register as _register_prim
from .secret_stage import SECRET_STAGE, enqueue_secret  # noqa: F401
from .secret_stage import register as _register_secret
from .stage import BUILD_POC_STAGE, enqueue_build_poc  # noqa: F401
from .stage import register as _register
from .synthesize_stage import SYNTH_STAGE, enqueue_synthesize  # noqa: F401
from .synthesize_stage import register as _register_synth


def register() -> None:
    _register()
    _register_prim()
    _register_exploit()
    _register_synth()
    _register_inject()
    _register_secret()
