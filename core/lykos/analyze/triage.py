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
from . import pe as pemod

SCHEMA_VERSION = 1
TOOL = "elf-stdlib"
TOOL_VERSION = "triage-4"          # bump to invalidate the cache when parsing changes
#   triage-4: static-pie linking classification (PT_DYNAMIC no longer implies dynamic)
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


# leading-byte signatures for common non-executable container/text formats, so a mistaken
# upload is described helpfully rather than dismissed as "unknown data".
_CONTENT_MAGIC = [
    (b"PK\x03\x04", "ZIP archive (or ZIP-based document)"),
    (b"PK\x05\x06", "empty ZIP archive"),
    (b"\x1f\x8b", "gzip-compressed data"),
    (b"BZh", "bzip2-compressed data"),
    (b"\xfd7zXZ\x00", "xz-compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"!<arch>\n", "ar/deb archive"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"<?xml", "XML document"),
    (b"{\n", "JSON/text data"),
]

# interpreter basename -> friendly language name (for shebang scripts)
_SCRIPT_LANG = {
    "sh": "shell", "bash": "Bourne-Again shell", "dash": "shell", "zsh": "Z shell",
    "ksh": "Korn shell", "python": "Python", "python2": "Python", "python3": "Python",
    "perl": "Perl", "ruby": "Ruby", "node": "Node.js", "php": "PHP", "lua": "Lua",
    "awk": "AWK", "tclsh": "Tcl", "Rscript": "R", "pwsh": "PowerShell",
}


def _classify_content(data: bytes) -> str:
    """Human description of a non-binary blob (script / archive / text / data)."""
    if not data:
        return "empty file"
    if data[:2] == b"#!":
        line = data[:256].split(b"\n", 1)[0].decode("latin-1", "ignore")
        toks = line[2:].strip().split()
        interp = ""
        for t in toks:                                # skip `/usr/bin/env`
            base = t.rsplit("/", 1)[-1]
            if base and base != "env" and not base.startswith("-"):
                interp = base
                break
        lang = _SCRIPT_LANG.get(interp, interp or "script")
        return f"{lang} script" if lang != "script" else "shell/interpreter script"
    for magic, desc in _CONTENT_MAGIC:
        if data[:len(magic)] == magic:
            return desc
    sample = data[:4096]
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    if printable / len(sample) >= 0.95:
        return "plain-text / source file"
    return "unrecognized data (not a known binary format)"


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
        "analyzable": False, "advisory": None,
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
    rec["_data_head"] = data[:4096]                     # transient: for non-binary classify
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
        rec["analyzable"] = True                       # ELF is the fully-supported format
        rec["advisory"] = None
    elif rec["file_type"] == filetype.PE:
        info = pemod.parse(data)
        parse_errors.extend(info.errors)
        rec.update({
            "arch": info.arch, "bits": info.bits, "endianness": info.endianness,
            "linking": info.linking, "stripped": info.stripped,
            "entry_point": (f"0x{info.entry:x}" if info.entry is not None else None),
            "sections": info.sections, "imports": info.imports,
            "exports_count": info.exports_count,
            "exports": {"count": info.exports_count, "symbols": info.exported_symbols},
            "toolchain_hint": info.toolchain_hint, "mitigations": info.mitigations,
            "format_details": pemod.to_format_details(info),
        })
        rec["entropy"] = _packer_heuristic(rec["entropy"]["overall"], info.sections)
        rec["detected"] = _describe(rec)
        # The old advisory said disassembly, CWE detection and the dynamic stages were "not
        # yet available for this format" -- while the platform was disassembling 282 functions
        # out of this very binary, producing findings from it and running it under Wine. What
        # is actually missing is narrower, so say that instead.
        rec["analyzable"] = True
        rec["advisory"] = (
            "PE analysed: headers, disassembly, CWE detection and execution under Wine all "
            "work. Not available for PE: the LD_PRELOAD heap checker and P-Code dynamic "
            "taint (both Linux/ELF), and fuzzing runs at Wine speed (~1 execution/second) "
            "with no coverage feedback, so it is not a practical campaign.")
    elif rec["file_type"] == filetype.MACHO:
        parse_errors.append("mach-o parsing pending (detected only)")
        rec["detected"] = "MACHO (detected only)"
        rec["analyzable"] = False
        rec["advisory"] = ("Mach-O binary detected, but this build parses ELF and PE headers "
                           "only. Format and hashes were recorded.")
    else:
        desc = _classify_content(rec["_data_head"])
        rec["detected"] = f"Not a binary — {desc}"
        rec["analyzable"] = False
        rec["advisory"] = (f"This file is not a supported executable binary ({desc}). It was "
                           "imported and hashed, but there is no machine code to analyze: "
                           "disassembly, CWE detection, and the dynamic/fuzzing/PoC stages do "
                           "not apply. Import an ELF executable or shared object to analyze.")
    rec.pop("_data_head", None)
    return rec


def _describe(rec: dict) -> str:
    # was hardcoded "ELF", which described a Windows PE as an ELF the moment PE triage
    # started filling these fields in
    parts = [{"pe": "PE", "macho": "Mach-O"}.get(rec.get("file_type"), "ELF")]
    if rec["bits"]:
        parts.append(f"{rec['bits']}-bit")
    if rec["endianness"]:
        parts.append(rec["endianness"])
    if rec["arch"]:
        parts.append(rec["arch"])
    if rec["linking"]:
        parts.append({"dynamic": "dynamically linked", "static-pie": "statically linked (PIE)",
                      "static": "statically linked"}.get(rec["linking"], "statically linked"))
    if rec["stripped"]:
        parts.append("stripped")
    sub = (rec.get("format_details") or {}).get("subsystem")
    if sub:
        parts.append(sub)
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
