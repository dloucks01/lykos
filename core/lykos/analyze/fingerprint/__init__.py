"""Offline third-party-component CVE fingerprinting (Phase 3).

Importing and calling `register()` installs two stages: `cve_scan` (version banners in a binary)
and `source_cve_scan` (dependency manifests + vendored headers in a built-from-source project).
"""
from .corroborate import CORROBORATE_STAGE, enqueue_cve_corroborate  # noqa: F401
from .corroborate import register as _register_corroborate
from .embedded_config import EMBEDDED_AUDIT_STAGE, enqueue_embedded_audit  # noqa: F401
from .embedded_config import register as _register_embedded
from .int_overflow import INT_OVERFLOW_STAGE, enqueue_int_overflow_scan  # noqa: F401
from .int_overflow import register as _register_intovf
from .source_scan import SOURCE_CVE_STAGE, enqueue_source_cve_scan  # noqa: F401
from .source_scan import register as _register_source
from .stage import CVE_STAGE, enqueue_cve_scan  # noqa: F401
from .stage import register as _register_cve


def register() -> None:
    _register_cve()
    _register_source()
    _register_embedded()
    _register_intovf()
    _register_corroborate()
