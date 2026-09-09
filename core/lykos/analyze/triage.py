"""IT-00, IT-16..IT-18, IT-20 — triage record schema, builder, validator.

Deterministic: the record carries NO timestamps or absolute paths, so identical input +
tool_version yields byte-identical JSON and the result cache (JE-16) hits on re-run.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from . import elf as elfmod
from . import filetype

SCHEMA_VERSION = 1
TOOL = "elf-stdlib"
TOOL_VERSION = "triage-2"          # bump to invalidate the cache when parsing changes
MITIGATION_ENUM = {"on", "off", "partial", "unknown"}
_FILE_TYPES = {filetype.ELF, filetype.PE, filetype.MACHO, filetype.RAW, filetype.OTHER}
_PACK_ENTROPY = 7.2


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in freq if c), 3)


def _packer_heuristic(overall: float, sections: list[dict]) -> dict:
    reasons, packer = [], None
    if overall >= _PACK_ENTROPY:
        reasons.append(f"high overall entropy {overall}")
    names = " ".join(s.get("name", "") for s in sections).lower()
    if "upx" in names:
        reasons.append("UPX section names")
        packer = "upx"
    return {"overall": overall, "packed_hint": bool(reasons), "packer": packer,
            "reasons": reasons}


def build_triage(path: str | Path, hashes: dict[str, Any], filename: str) -> dict:
    """Produce a schema-v1 triage record. Best-effort; never raises on bad input."""
    parse_errors: list[str] = []
    rec: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sha256": hashes.get("sha256"), "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"), "size": hashes.get("size"),
        "file_type": filetype.RAW, "detected": None,
        "arch": None, "bits": None, "endianness": None, "linking": None,
        "stripped": None, "entry_point": None, "interpreter": None,
        "sections": [], "imports": {"libraries": [], "functions_count": 0, "symbols": []},
        "exports_count": 0, "exports": {"count": 0, "symbols": []},
        "toolchain_hint": "unknown", "mitigations": {},
        "entropy": {"overall": 0.0, "packed_hint": False, "packer": None, "reasons": []},
        "format_details": {}, "parse_errors": parse_errors,
        "tool": TOOL, "tool_version": TOOL_VERSION,
    }
    try:
        data = Path(path).read_bytes()
    except Exception as e:
        parse_errors.append(f"read: {e!r}")
        return rec

    rec["file_type"] = filetype.detect(data[:64])
    rec["entropy"] = _packer_heuristic(_shannon(data), [])

    if rec["file_type"] == filetype.ELF:
        info = elfmod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "linking": info.linking, "stripped": info.stripped,
            "entry_point": (f"0x{info.entry:x}" if info.entry is not None else None),
            "interpreter": info.interpreter, "sections": info.sections,
            "imports": info.imports, "exports_count": info.exports_count,
            "exports": {"count": info.exports_count, "symbols": info.exported_symbols},
            "toolchain_hint": info.toolchain_hint, "mitigations": info.mitigations,
            "format_details": elfmod.to_format_details(info),
        })
        rec["entropy"] = _packer_heuristic(rec["entropy"]["overall"], info.sections)
        rec["detected"] = _describe(rec)
    elif rec["file_type"] in (filetype.PE, filetype.MACHO):
        parse_errors.append(f"{rec['file_type']} parsing pending LIEF backend (detected only)")
        rec["detected"] = rec["file_type"].upper()
    else:
        rec["detected"] = rec["file_type"]
    return rec


def _describe(rec: dict) -> str:
    parts = ["ELF"]
    if rec["bits"]:
        parts.append(f"{rec['bits']}-bit")
    if rec["endianness"]:
        parts.append(rec["endianness"])
    if rec["arch"]:
        parts.append(rec["arch"])
    if rec["linking"]:
        parts.append("dynamically linked" if rec["linking"] == "dynamic"
                     else "statically linked")
    if rec["stripped"]:
        parts.append("stripped")
    return ", ".join(parts)


def validate(rec: dict) -> list[str]:
    """Return a list of schema violations (empty = valid)."""
    errs = []
    if rec.get("schema_version") != SCHEMA_VERSION:
        errs.append("bad schema_version")
    for k in ("sha256", "file_type", "mitigations", "entropy", "parse_errors",
              "tool_version"):
        if k not in rec:
            errs.append(f"missing key {k}")
    if rec.get("file_type") not in _FILE_TYPES:
        errs.append(f"bad file_type {rec.get('file_type')!r}")
    if rec.get("bits") not in (None, 32, 64):
        errs.append(f"bad bits {rec.get('bits')!r}")
    for mk, mv in (rec.get("mitigations") or {}).items():
        if mv not in MITIGATION_ENUM:
            errs.append(f"bad mitigation {mk}={mv!r}")
    return errs
