"""PoC bundle generation + verification (Phase 6/9). Importing registers the stages:
  - `build_poc`      L1: verify a crashing input, bundle it, promote to poc-backed
  - `poc_primitive`  L2: prove instruction-pointer control (cyclic pattern + ptrace capture)
  - `build_exploit`  L3: assisted ret2win template exploit synthesis (control-flow hijack)
"""
from .chain_primitive import CHAIN_STAGE, enqueue_chain  # noqa: F401
from .chain_primitive import register as _register_chain
from .cve_poc_stage import CVE_POC_STAGE, enqueue_cve_poc  # noqa: F401
from .cve_poc_stage import register as _register_cve_poc
from .poc_diff import POC_DIFF_STAGE, enqueue_poc_diff  # noqa: F401
from .poc_diff import register as _register_poc_diff
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
    _register_chain()
    _register_poc_diff()
    _register_synth()
    _register_inject()
    _register_secret()
    _register_cve_poc()
