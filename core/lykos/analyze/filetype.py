"""IT-04 — magic-based file-type detection (before any format-specific parse)."""
from __future__ import annotations

ELF = "elf"
PE = "pe"
MACHO = "macho"
RAW = "raw"
OTHER = "other"

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat / universal
}


def detect(head: bytes) -> str:
    """Classify by leading bytes. `head` should be the first >= 64 bytes."""
    if head[:4] == b"\x7fELF":
        return ELF
    if head[:2] == b"MZ":
        return PE          # DOS/PE stub; full PE-header check happens in a PE parser
    if head[:4] in _MACHO_MAGICS:
        return MACHO
    if not head:
        return RAW
    return OTHER
