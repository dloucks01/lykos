"""Offline third-party-component CVE fingerprinting (Phase 3). Importing registers `cve_scan`."""
from .stage import (  # noqa: F401
    CVE_STAGE,
    enqueue_cve_scan,
    register,  # noqa: F401
)
