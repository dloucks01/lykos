"""Deterministic analysis stages (zero-AI).

Phase 0: ingest/triage (pure-stdlib ELF parsing; LIEF deferred for PE/Mach-O).
Phase 1: `disassemble` via Ghidra headless (bundled in the full offline package; the
locator falls back to config/env/PATH, and the stage fails clearly if Ghidra is absent).

Importing this package registers both stages with the job engine.
"""
from .debug import register as _register_debug
from .detect import register as _register_detect
from .disassemble import DISASSEMBLE_STAGE  # noqa: F401
from .disassemble import register as _register_disasm
from .dynamic import register as _register_dynamic
from .firmware import register as _register_firmware
from .fuzz import register as _register_fuzz
from .ingest import INGEST_TRIAGE_STAGE, ingest  # noqa: F401
from .ingest import register as _register_ingest
from .link import register as _register_link
from .poc import register as _register_poc
from .symbolic import register as _register_symbolic


def register() -> None:
    _register_ingest()
    _register_disasm()
    _register_detect()
    _register_dynamic()
    _register_fuzz()
    _register_poc()
    _register_symbolic()
    _register_debug()
    _register_link()
    _register_firmware()


register()
