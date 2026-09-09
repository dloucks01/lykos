"""Machine-readable case export (doc 08 §8.5) — the full findings/evidence/PoC model
as JSON, for archival, transfer, or downstream tooling. This is the *data* export;
`CaseStore.export()` is the *whole-case* (rows + artifact blobs) archive.
"""
from __future__ import annotations

import json
from typing import Any


def to_case_json(report: dict[str, Any]) -> dict[str, Any]:
    out = dict(report)
    out["schema"] = "lykos.case-export/1"
    return out


def to_case_json_bytes(report: dict[str, Any]) -> bytes:
    return json.dumps(to_case_json(report), indent=2, sort_keys=False).encode("utf-8")
