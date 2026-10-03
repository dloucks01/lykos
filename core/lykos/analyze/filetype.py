"""IT-04 — magic-based file-type detection (before any format-specific parse)."""
from __future__ import annotations

ELF = "elf"
PE = "pe"
MACHO = "macho"
JAR = "jar"
CLASS = "class"
WASM = "wasm"
PYC = "pyc"
FIRMWARE = "firmware"
RAW = "raw"
OTHER = "other"

# Container formats that identify a file as a FIRMWARE IMAGE at offset 0. Not the whole of
# `firmware.carve.SIGNATURES`, which also scans for things embedded at any offset (a gzip
# member, a certificate, a PNG) -- those say "this file contains one", not "this file IS one".
#
# Without this a firmware image was `other`, and `advise` told the operator "this file is not a
# recognised executable, library or firmware image, so there is nothing to run or decompile"
# about an image the carve stage then pulled two executables and an RSA private key out of.
# A test binds this list to carve.SIGNATURES so the two cannot drift.
FIRMWARE_MAGICS = (
    (b"\x27\x05\x19\x56", "U-Boot uImage"),
    (b"hsqs", "SquashFS (little-endian)"),
    (b"sqsh", "SquashFS (big-endian)"),
    (b"\x45\x3d\xcd\x28", "CramFS"),
    (b"\xd0\x0d\xfe\xed", "Flattened Device Tree"),
    (b"UBI#", "UBI image"),
)

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
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        # CAFEBABE is BOTH the Java class-file magic and Mach-O's universal-binary magic --
        # chosen independently, and identical. Whichever check runs first claims every file of
        # the other kind. The next four bytes separate them: Java writes minor then MAJOR
        # version (45 = Java 1.0 .. 65 = Java 21), Mach-O writes a 32-bit count of
        # architectures, which is a handful. Nothing has 45 architectures.
        major = (head[6] << 8) | head[7]
        if 45 <= major <= 90:
            return CLASS
        return MACHO
    if head[:4] in _MACHO_MAGICS:
        return MACHO
    if head[:4] == b"\x00asm":
        # WebAssembly: "\0asm" then a 4-byte LE version (1 for the MVP). The magic alone is
        # distinctive enough; the version is checked in the parser.
        return WASM
    if len(head) >= 16 and head[2:4] == b"\r\n":
        # CPython bytecode: a 2-byte LE version magic that increments every release, always followed
        # by 0x0d 0x0a. Rather than enumerate every release's magic, accept the ranges CPython has
        # ever used (3.x is ~3000-4000; 2.x ~20000-65000), with the \r\n and a 16-byte header guard
        # against a chance collision. The parser maps the exact magic to a Python version or rejects.
        v = head[0] | (head[1] << 8)
        if 3000 <= v <= 4000 or 20000 <= v <= 65000:
            return PYC
    for magic, _desc in FIRMWARE_MAGICS:
        if head[:len(magic)] == magic:
            return FIRMWARE
    if head[:4] == b"PK\x03\x04":
        # A zip. Whether it is a JAR is decided by looking inside it, which needs the whole
        # file; the caller confirms with jvm.is_jar and falls back if it is an ordinary
        # archive.
        return JAR
    if not head:
        return RAW
    return OTHER


def firmware_kind(head: bytes):
    """Human name of the firmware container, or None."""
    for magic, desc in FIRMWARE_MAGICS:
        if head[:len(magic)] == magic:
            return desc
    return None
