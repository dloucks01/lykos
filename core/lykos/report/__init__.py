"""Phase 7 — Reporting & export.

Turns a case's findings/evidence/PoCs into shareable, reproducible deliverables:
a self-contained **HTML** report (print-optimized), a genuine **PDF** (pure-stdlib
writer, no external deps -- air-gap clean), a **SARIF 2.1.0** export for tool interop,
and a machine-readable **case JSON** for archival/transfer. All generators consume one
`build_report(...)` model so the four formats never drift.
"""
from __future__ import annotations

from .casejson import to_case_json
from .html import to_html
from .model import DEFAULT_MIN_STATE, build_report
from .pdf import to_pdf
from .sarif import to_sarif

__all__ = [
    "build_report", "to_html", "to_pdf", "to_sarif", "to_case_json",
    "DEFAULT_MIN_STATE",
]
