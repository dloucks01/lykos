"""Offline third-party-component CVE fingerprinting (Phase 3).

Importing and calling `register()` installs two stages: `cve_scan` (version banners in a binary)
and `source_cve_scan` (dependency manifests + vendored headers in a built-from-source project).
"""
from .source_scan import SOURCE_CVE_STAGE, enqueue_source_cve_scan  # noqa: F401
from .source_scan import register as _register_source
from .stage import CVE_STAGE, enqueue_cve_scan  # noqa: F401
from .stage import register as _register_cve


def register() -> None:
    _register_cve()
    _register_source()
