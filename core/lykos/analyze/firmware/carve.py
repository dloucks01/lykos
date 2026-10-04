"""Signature-based firmware carving (binwalk-style, pure stdlib).

Scans a firmware image for embedded artifacts by magic number, bounds embedded ELFs by
parsing their headers, and transparently decompresses gzip/xz/bzip2 streams (extracting an
ELF payload when the decompressed data is itself an ELF -- the common compressed-kernel case).
"""
from __future__ import annotations

import bz2
import logging
import lzma
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from typing import Optional

_log = logging.getLogger(__name__)

# Zstandard: stdlib `compression.zstd` from Python 3.14, else the third-party `zstandard` if present,
# else None (zstd streams are then IDENTIFIED but not extracted). Resolved once, at import.
try:
    from compression import zstd as _zstd_mod          # Python 3.14+ stdlib

    def _zstd_decompress(blob, cap):
        d = _zstd_mod.ZstdDecompressor()
        return _bounded(d, blob, cap)
except Exception:                                       # noqa: BLE001
    try:
        import zstandard as _zstandard

        def _zstd_decompress(blob, cap):
            return _zstandard.ZstdDecompressor().decompress(blob, max_output_size=cap)
    except Exception:                                   # noqa: BLE001
        _zstd_decompress = None

# magic bytes -> (type, description). Kept to low-false-positive, meaningful firmware markers.
SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x7fELF", "elf", "ELF executable/object"),
    (b"\x1f\x8b\x08", "gzip", "gzip-compressed data"),
    (b"\xfd7zXZ\x00", "xz", "XZ-compressed data"),
    (b"BZh", "bzip2", "bzip2-compressed data"),
    (b"hsqs", "squashfs", "SquashFS filesystem (little-endian)"),
    (b"sqsh", "squashfs", "SquashFS filesystem (big-endian)"),
    (b"\x45\x3d\xcd\x28", "cramfs", "CramFS filesystem"),
    (b"-rom1fs-", "romfs", "ROMFS filesystem"),
    (b"\x27\x05\x19\x56", "uimage", "U-Boot uImage header"),
    (b"HDR0", "trx", "Broadcom TRX firmware header"),
    (b"ANDROID!", "androidboot", "Android boot image"),
    (b"\xd0\x0d\xfe\xed", "dtb", "Flattened Device Tree (DTB) blob"),
    (b"UBI#", "ubi", "UBI image"),
    (b"\x28\xb5\x2f\xfd", "zstd", "Zstandard-compressed data"),
    (b"\x04\x22\x4d\x18", "lz4", "LZ4-frame-compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7zip", "7-zip archive"),
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
_MAX_DECOMPRESS = 64 << 20    # hard ceiling on decompressed output (matches the gzip cap):
                              # a crafted xz/bz2 member must not expand to GB into RAM-backed tmpfs


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
        _log.debug("_elf_extent: parsing ELF headers at offset %d failed", o, exc_info=True)
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


def _bounded(dec, blob: bytes, cap: int = _MAX_DECOMPRESS) -> bytes:
    """Stream `blob` through an incremental decompressor, stopping once output reaches `cap`.
    Returns at most `cap` bytes (truncated like the gzip path), so a decompression bomb can
    never expand past the ceiling into RAM. Input is fed on the first call and buffered inside
    the decompressor; b"" then drains its remaining output up to the cap."""
    out = bytearray()
    data_in = blob
    while len(out) < cap:
        out += dec.decompress(data_in, cap - len(out))
        data_in = b""
        if dec.eof or dec.needs_input:
            break
    return bytes(out)


def _decompress(typ: str, blob: bytes) -> Optional[bytes]:
    try:
        if typ == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob, _MAX_DECOMPRESS)
        if typ == "xz":
            return _bounded(lzma.LZMADecompressor(), blob)
        if typ == "lzma":                               # raw .lzma (LZMA_ALONE), ubiquitous in OpenWRT
            return _bounded(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE), blob)
        if typ == "bzip2":
            return _bounded(bz2.BZ2Decompressor(), blob)
        if typ == "zstd" and _zstd_decompress is not None:
            return _zstd_decompress(blob, _MAX_DECOMPRESS)
    except Exception:
        _log.debug("_decompress: %s stream decompression failed", typ, exc_info=True)
        return None
    return None


def extract_components(data: bytes, *, max_components: int = 64, _depth: int = 0) -> list[dict]:
    """Embeddable components to register as sub-targets: embedded ELFs and ELF payloads of
    gzip/xz/bzip2/zstd/raw-LZMA streams. Each: {offset, kind, filename, bytes, note}.

    Recursive (bounded to _MAX_CARVE_DEPTH): a compressed stream whose content is NOT a bare ELF
    is itself re-scanned, so the common firmware shapes -- gzip of a padded ELF, xz/gzip of a
    cpio/initramfs full of ELFs, or nested compression -- are reached, not dropped at the first layer."""
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
        elif typ in ("gzip", "xz", "bzip2", "zstd"):
            dec = _decompress(typ, data[o:])
            if not dec:
                continue
            if dec[:4] == b"\x7fELF":
                esz = _elf_extent(dec, 0) or len(dec)
                out.append({"offset": o, "kind": "elf",
                            "filename": f"carved_0x{o:x}_{typ}.elf",
                            "bytes": dec[:esz],
                            "note": f"{typ}-compressed ELF ({esz} bytes decompressed)"})
            elif _depth < _MAX_CARVE_DEPTH:
                # Not a bare ELF: the decompressed stream may be a padded ELF, a cpio/initramfs or
                # tar of ELFs, or another compression layer. Re-scan it -- the embedded ELFs are not
                # visible as contiguous magic in the ORIGINAL (compressed) image.
                for sub in extract_components(dec, max_components=max_components - len(out),
                                              _depth=_depth + 1):
                    sub["note"] = f"{typ} stream @ 0x{o:x} -> " + sub["note"]
                    sub["filename"] = f"carved_0x{o:x}_{typ}_" + sub["filename"]
                    out.append(sub)
                    if len(out) >= max_components:
                        break
    # Raw LZMA (.lzma / LZMA_ALONE) has no reliable magic, so it is NOT a SIGNATURE (a bare 0x5d
    # byte is far too common to report). Instead scan for its header shape and VALIDATE each
    # candidate by trial-decompression -- an embedded LZMA-compressed ELF is kept, noise is not.
    for o, dec in _scan_raw_lzma(data):
        if len(out) >= max_components or _overlaps(o, 1):
            continue
        esz = _elf_extent(dec, 0) or len(dec)
        out.append({"offset": o, "kind": "elf", "filename": f"carved_0x{o:x}_lzma.elf",
                    "bytes": dec[:esz],
                    "note": f"raw-LZMA-compressed ELF ({esz} bytes decompressed)"})
    return out


# The .lzma (LZMA_ALONE) header: properties byte (0x5D is the lc3/lp0/pb2 default used by every
# common packer), a 4-byte LE dictionary size that is a power of two, then an 8-byte LE uncompressed
# size. 0x5D alone is a common data byte, so a candidate is only trusted once it actually
# decompresses to an ELF -- validation, not a magic guess.
_LZMA_DICT_SIZES = {1 << k for k in range(16, 28)}      # 64 KiB .. 128 MiB, the realistic range
_LZMA_MAX_TRIALS = 256


def _scan_raw_lzma(data: bytes):
    """Yield (offset, decompressed_bytes) for every embedded raw-LZMA stream whose content is an
    ELF. Bounded: at most _LZMA_MAX_TRIALS validations, each on a capped window."""
    trials = 0
    start = 0
    while trials < _LZMA_MAX_TRIALS:
        o = data.find(b"\x5d", start)
        if o < 0 or o + 13 > len(data):
            break
        start = o + 1
        dict_sz = int.from_bytes(data[o + 1:o + 5], "little")
        if dict_sz not in _LZMA_DICT_SIZES:
            continue
        trials += 1
        try:
            dec = _bounded(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE), data[o:])
        except Exception:                               # noqa: BLE001
            continue
        if dec and dec[:4] == b"\x7fELF":
            yield o, dec


# ---------------------------------------------------------------- embedded filesystem unpack
# Real firmware keeps its binaries inside a root FILESYSTEM (SquashFS almost always, sometimes
# cpio/CramFS), which is compressed block-by-block -- so the embedded ELFs are NOT visible as
# contiguous ELF or gzip magic in the raw image and extract_components() finds nothing. Unpacking
# the filesystem is the only way to reach them. We shell out to the standard extractor when it is
# on PATH (unsquashfs / cpio): optional tools, degrading to [] when absent -- never a hard dep.
_MAX_CARVE_DEPTH = 2           # how deep extract_components recurses into nested compression layers
_MAX_FS_FILES = 1024
_MAX_FS_FILE = 32 << 20        # skip any single extracted file larger than this
_MAX_FS_TOTAL = 256 << 20      # stop walking once this many bytes have been read out


def _squashfs_size(data: bytes, o: int) -> Optional[int]:
    """Total on-disk size of the SquashFS at offset o, read from its v4 superblock (bytes_used
    at +40). 'hsqs' is little-endian, 'sqsh' big-endian."""
    magic = data[o:o + 4]
    endc = "<" if magic == b"hsqs" else (">" if magic == b"sqsh" else None)
    if endc is None or len(data) - o < 48:
        return None
    try:
        bytes_used = struct.unpack_from(endc + "Q", data, o + 40)[0]
    except struct.error:
        return None
    if 96 <= bytes_used <= len(data) - o:
        return bytes_used
    return None


def _walk_tree(root: str) -> list[dict]:
    """Every regular file under `root`: [{path, bytes, kind}] (path relative to root). kind is
    'elf' when the file begins with the ELF magic, else 'file'. Symlinks are skipped."""
    files: list[dict] = []
    total = 0
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            if len(files) >= _MAX_FS_FILES or total >= _MAX_FS_TOTAL:
                return files
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            try:
                if os.path.getsize(full) > _MAX_FS_FILE:
                    continue
                blob = open(full, "rb").read()
            except OSError:
                continue
            total += len(blob)
            rel = os.path.relpath(full, root)
            kind = "elf" if blob[:4] == b"\x7fELF" else "file"
            files.append({"path": rel, "bytes": blob, "kind": kind})
    return files


def _unpack_squashfs(fs: bytes) -> list[dict]:
    exe = shutil.which("unsquashfs")
    if not exe:
        _log.debug("unsquashfs not on PATH; cannot unpack SquashFS root filesystem")
        return []
    with tempfile.TemporaryDirectory(prefix="lykos-fw-") as td:
        img = os.path.join(td, "fs.sqsh")
        dest = os.path.join(td, "root")        # must NOT pre-exist: unsquashfs creates it
        with open(img, "wb") as fh:
            fh.write(fs)
        try:
            subprocess.run([exe, "-no-progress", "-force", "-dest", dest, img],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired):
            _log.debug("unsquashfs failed on carved SquashFS region", exc_info=True)
            return []
        if not os.path.isdir(dest):
            return []
        return _walk_tree(dest)


_CPIO_NEWC = (b"070701", b"070702")        # newc, and newc with a CRC
_S_IFREG = 0o100000


def _cpio_newc_files(data: bytes, start: int = 0) -> list[dict]:
    """Parse a newc cpio archive in pure Python -- no external tool. Each entry is a 110-byte ASCII
    header (6-byte magic + 13 eight-hex fields) then the NUL-terminated name and the file body, the
    header+name and the body each padded to a 4-byte boundary measured from the archive origin.
    'TRAILER!!!' ends it. Returns regular files only: [{path, bytes, kind}]. Every read is
    bounds-checked (untrusted firmware) and the file/byte totals are capped."""
    files: list[dict] = []
    pos, total = start, 0
    while pos + 110 <= len(data) and len(files) < _MAX_FS_FILES and total < _MAX_FS_TOTAL:
        if data[pos:pos + 6] not in _CPIO_NEWC:
            break
        try:
            f = [int(data[pos + 6 + i * 8:pos + 6 + (i + 1) * 8], 16) for i in range(13)]
        except ValueError:
            break
        mode, filesize, namesize = f[1], f[6], f[11]
        if namesize > 4096 or filesize > (1 << 31):       # absurd -> corrupt/not really newc
            break
        name = data[pos + 110:pos + 110 + namesize].split(b"\x00", 1)[0]
        nm = name.decode("utf-8", "replace").lstrip("./")
        body_off = pos + 110 + namesize
        body_off += (start - body_off) % 4                # pad header+name to 4 from the origin
        if nm == "TRAILER!!!":
            break
        body = data[body_off:body_off + filesize] if filesize <= _MAX_FS_FILE else b""
        nxt = body_off + filesize
        nxt += (start - nxt) % 4                           # pad body to 4 from the origin
        if nxt <= pos:                                     # no forward progress -> stop
            break
        pos = nxt
        if (mode & 0o170000) == _S_IFREG and body and nm:
            total += len(body)
            files.append({"path": nm, "bytes": body,
                          "kind": "elf" if body[:4] == b"\x7fELF" else "file"})
    return files


def _unpack_cpio(fs: bytes) -> list[dict]:
    # Pure-Python newc parse first -- no dependency, and it works where `cpio` is not installed
    # (the common case for an analysis host). Fall back to the system tool only if that finds
    # nothing (e.g. an old binary/odc cpio variant the pure parser does not implement).
    files = _cpio_newc_files(fs, 0)
    if files:
        return files
    exe = shutil.which("cpio")
    if not exe:
        return []
    with tempfile.TemporaryDirectory(prefix="lykos-fw-") as td:
        dest = os.path.join(td, "root")
        os.makedirs(dest, exist_ok=True)
        try:
            subprocess.run([exe, "-idm", "--no-absolute-filenames", "--quiet"],
                           input=fs, cwd=dest, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired):
            _log.debug("cpio extraction failed", exc_info=True)
            return []
        return _walk_tree(dest)


def extract_filesystems(data: bytes, *, max_filesystems: int = 8) -> list[dict]:
    """Unpack embedded root filesystems (SquashFS, cpio) with the matching system extractor and
    return every regular file inside them: [{offset, fs, path, bytes, kind}] where `offset` is
    where the filesystem starts in the image, `fs` its type, `path` the file's path within it,
    and `kind` 'elf' for an ELF file else 'file'. Returns [] when no filesystem is present or no
    extractor is installed -- the raw-ELF carve (extract_components) is unaffected either way."""
    out: list[dict] = []
    seen: set[int] = set()
    hits = scan_signatures(data)
    n_fs = 0
    for h in hits:
        if n_fs >= max_filesystems:
            break
        o, typ = h["offset"], h["type"]
        if typ == "squashfs":
            sz = _squashfs_size(data, o)
            if sz is None or o in seen:
                continue
            seen.add(o)
            files = _unpack_squashfs(data[o:o + sz])
        elif typ == "cpio":
            if o in seen:
                continue
            seen.add(o)
            files = _unpack_cpio(data[o:])
        elif typ in ("gzip", "xz", "bzip2", "zstd"):
            # A compressed cpio is the standard Linux initramfs root filesystem. Decompress and, if
            # the result is a cpio, recover its whole file tree -- the raw-ELF carve only pulls the
            # contiguous ELFs out and loses every path and non-ELF file (configs, keys).
            if o in seen:
                continue
            seen.add(o)
            dec = _decompress(typ, data[o:])
            if not (dec and dec[:6] in _CPIO_NEWC):
                continue
            typ = f"{typ}+cpio"
            files = _cpio_newc_files(dec, 0)
        else:
            continue
        if not files:
            continue
        n_fs += 1
        for f in files:
            out.append({"offset": o, "fs": typ, "path": f["path"],
                        "bytes": f["bytes"], "kind": f["kind"]})
    return out
