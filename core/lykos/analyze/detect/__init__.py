"""Deterministic CWE detection engine (Phase 3). Importing registers the built-in
detectors and the `detect_cwe` stage."""
from .detectors import DETECTORS, DetectContext, correlate  # noqa: F401
from .stage import DETECT_STAGE, detect_stage, enqueue_detect  # noqa: F401
from .stage import register as _register_stage


def register() -> None:
    _register_stage()
