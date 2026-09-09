"""Phase 8 (doc 17.5) — firmware / embedded image decomposition.

Deterministic, air-gapped, zero-dependency: carve a firmware image into its embedded
components (signature scan, binwalk-style), extract embedded ELFs (and gzip/xz/bzip2-wrapped
ELFs) as new case targets so the whole multi-binary pipeline (component graph, cross-binary
taint, IPC) applies, and for a bare-metal blob with no container, identify the CPU
architecture, endianness, load/base address and entry point (headerless loader, doc 04.6) --
notably ARM Cortex-M via its reset vector table.

Out of scope here (needs bundled emulator infra + real images, doc 17.5): peripheral/MMIO
modelling (Fuzzware/ES-Fuzz), DMA rehosting (GDMA), modelled interrupts/timers, and executing
the rehosted firmware under Unicorn/QEMU. This increment delivers the *decomposition + loader*
that those would consume.
"""
from .carve import extract_components, scan_signatures  # noqa: F401
from .headerless import analyze_blob  # noqa: F401
from .rehost import locate_unicorn_python  # noqa: F401
from .rehost_stage import REHOST_STAGE, enqueue_rehost, firmware_rehost_stage  # noqa: F401
from .rehost_stage import register as _register_rehost
from .stage import FIRMWARE_STAGE, enqueue_firmware, firmware_carve_stage  # noqa: F401
from .stage import register as _register


def register() -> None:
    _register()
    _register_rehost()
