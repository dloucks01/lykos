"""Signature-based firmware carving (binwalk-style, pure stdlib).

Scans a firmware image for embedded artifacts by magic number, bounds embedded ELFs by
parsing their headers, and transparently decompresses gzip/xz/bzip2 streams (extracting an
ELF payload when the decompressed data is itself an ELF -- the common compressed-kernel case).
"""
from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from typing import Optional

# magic bytes -> (type, description). Kept to low-false-positive, meaningful firmware markers.
SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x7fELF", "elf", "ELF executable/object"),
    (b"\x1f\x8b\x08", "gzip", "gzip-compressed data"),
    (b"\xfd7zXZ\x00", "xz", "XZ-compressed data"),
    (b"BZh", "bzip2", "bzip2-compressed data"),
    (b"hsqs", "squashfs", "SquashFS filesystem (little-endian)"),
    (b"sqsh", "squashfs", "SquashFS filesystem (big-endian)"),
    (b"\x45\x3d\xcd\x28", "cramfs", "CramFS filesystem"),
    (b"\x27\x05\x19\x56", "uimage", "U-Boot uImage header"),
    (b"\xd0\x0d\xfe\xed", "dtb", "Flattened Device Tree (DTB) blob"),
    (b"UBI#", "ubi", "UBI image"),
    (b"\x85\x19", "jffs2", "JFFS2 node (little-endian)"),
    (b"\x19\x85", "jffs2", "JFFS2 node (big-endian)"),
    (b"070701", "cpio", "cpio archive (newc)"),
    (b"070702", "cpio", "cpio archive (newc-crc)"),
    (b"-----BEGIN CERTIFICATE-----", "cert", "PEM certificate"),
    (b"-----BEGIN RSA PRIVATE KEY-----", "privkey", "PEM RSA private key"),
    (b"-----BEGIN PRIVATE KEY-----", "privkey", "PEM private key"),
    (b"-----BEGIN EC PRIVATE KEY-----", "privkey", "PEM EC private key"),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", "privkey", "OpenSSH private key"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
]
_MAX_HITS = 4000
_MIN_GAP = 4          # collapse dense duplicate magics (e.g. many jffs2 nodes)


def _elf_extent(data: bytes, o: int) -> Optional[int]:
    """Size of the ELF starting at offset o (max of section-header end and PT_LOAD extent)."""
    if len(data) - o < 64 or data[o:o + 4] != b"\x7fELF":
        return None
    try:
        ei_class, ei_data = data[o + 4], data[o + 5]
        is64 = ei_class == 2
        endc = "<" if ei_data == 1 else ">"
        if is64:
            (_t, _m, _v, _entry, e_phoff, e_shoff, _fl, _eh, e_phentsize, e_phnum,
             e_shentsize, e_shnum, _si) = struct.unpack_from(endc + "HHIQQQIHHHHHH", data, o + 16)
        else:
            (_t, _m, _v, _entry, e_phoff, e_shoff, _fl, _eh, e_phentsize, e_phnum,
             e_shentsize, e_shnum, _si) = struct.unpack_from(endc + "HHIIIIIHHHHHH", data, o + 16)
        end = 0
        if e_shoff and e_shnum:
            end = max(end, e_shoff + e_shnum * e_shentsize)
        # program headers: p_offset (+ p_filesz)
        for i in range(min(e_phnum, 128)):
            po = o + e_phoff + i * e_phentsize
            if po + e_phentsize > len(data):
                break
            if is64:
                p_offset = struct.unpack_from(endc + "Q", data, po + 8)[0]
                p_filesz = struct.unpack_from(endc + "Q", data, po + 32)[0]
            else:
                p_offset = struct.unpack_from(endc + "I", data, po + 4)[0]
                p_filesz = struct.unpack_from(endc + "I", data, po + 16)[0]
            end = max(end, p_offset + p_filesz)
        if 0 < end <= len(data) - o:
            return end
    except Exception:
        return None
    return None


def scan_signatures(data: bytes) -> list[dict]:
    """All magic hits in the image: [{offset, type, description, size?}] (offset-sorted)."""
    hits: list[dict] = []
    last_by_type: dict[str, int] = {}
    for magic, typ, desc in SIGNATURES:
        start = 0
        while len(hits) < _MAX_HITS:
            o = data.find(magic, start)
            if o < 0:
                break
            start = o + 1
            # collapse dense repeats of the same type (filesystem node spam)
            if typ in last_by_type and o - last_by_type[typ] < _MIN_GAP:
                continue
            last_by_type[typ] = o
            hit = {"offset": o, "type": typ, "description": desc}
            if typ == "elf":
                sz = _elf_extent(data, o)
                if sz:
                    hit["size"] = sz
            hits.append(hit)
    hits.sort(key=lambda h: h["offset"])
    return hits


def _decompress(typ: str, blob: bytes) -> Optional[bytes]:
    try:
        if typ == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob, 64 << 20)
        if typ == "xz":
            return lzma.decompress(blob)
        if typ == "bzip2":
            return bz2.decompress(blob)
    except Exception:
        return None
    return None


def extract_components(data: bytes, *, max_components: int = 64) -> list[dict]:
    """Embeddable components to register as sub-targets: embedded ELFs and ELF payloads of
    gzip/xz/bzip2 streams. Each: {offset, kind, filename, bytes, note}."""
    hits = scan_signatures(data)
    out: list[dict] = []
    seen_ranges: list[tuple[int, int]] = []

    def _overlaps(o, sz):
        return any(o < e and o + sz > s for s, e in seen_ranges)

    for h in hits:
        if len(out) >= max_components:
            break
        o, typ = h["offset"], h["type"]
        if typ == "elf" and h.get("size"):
            sz = h["size"]
            if o == 0 and sz >= len(data) - 16:
                continue                      # the whole image IS this ELF, not embedded
            if _overlaps(o, sz):
                continue
            seen_ranges.append((o, o + sz))
            out.append({"offset": o, "kind": "elf", "filename": f"carved_0x{o:x}.elf",
                        "bytes": data[o:o + sz], "note": f"embedded ELF ({sz} bytes)"})
        elif typ in ("gzip", "xz", "bzip2"):
            dec = _decompress(typ, data[o:])
            if dec and dec[:4] == b"\x7fELF":
                esz = _elf_extent(dec, 0) or len(dec)
                out.append({"offset": o, "kind": "elf",
                            "filename": f"carved_0x{o:x}_{typ}.elf",
                            "bytes": dec[:esz],
                            "note": f"{typ}-compressed ELF ({esz} bytes decompressed)"})
    return out
