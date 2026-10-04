""".NET managed-PE parsing -- a PE that is CIL bytecode, not native machine code.

A .NET assembly is a Windows PE, so magic-based detection calls it `pe` and the native PE path
disassembles it as x86 -- decoding CIL (a stack bytecode) as x86 yields pure garbage, the same
mis-decode trap as feeding RISC-V to an x86 backend. The managed truth is in the CLI header (PE
optional-header data directory 14) and the `BSJB` metadata root it points at: the CLR version, the
TypeDef/MethodDef tables, and -- like a Java constant pool -- every type/method NAME in the
`#Strings` heap and every literal in the `#US` user-string heap, all in the clear.

So the right move mirrors the JVM front-end: recognise the format, inventory what it plainly gives
up (names, strings, counts, runtime version) for the string-based detectors and invocation
discovery, and stop the PoC ladder honestly -- the CLR checks every array access and owns every
pointer, so there is no native instruction pointer to take. Pure stdlib struct parsing; every read
is bounds-checked because the input is untrusted.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

_META_SIG = 0x424A5342          # 'BSJB', the metadata-root signature
_DIR_COM = 14                   # data directory index of the CLI (COM descriptor) header
# #~ table ids we surface a row count for (ECMA-335 II.22): the two that say "how much code".
_TBL_TYPEDEF = 0x02
_TBL_METHODDEF = 0x06


@dataclass
class DotNetInfo:
    is_dotnet: bool = False
    clr_version: Optional[str] = None       # e.g. "v4.0.30319"
    runtime_flags: int = 0
    type_count: int = 0
    method_count: int = 0
    streams: list = field(default_factory=list)      # stream names present (#~, #Strings, #US, ...)
    names: list = field(default_factory=list)        # #Strings heap: type/method/field names
    user_strings: list = field(default_factory=list)  # #US heap: literal strings in the code
    bits: Optional[int] = None
    errors: list = field(default_factory=list)


def _opt_header(data: bytes):
    """(opt_offset, is64, dir_off, n_dirs, section_table_offset, nsections) for a PE, or None."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    (pe_off,) = struct.unpack_from("<I", data, 0x3C)
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
        return None
    coff = pe_off + 4
    nsections, opt_size = struct.unpack_from("<H", data, coff + 2)[0], \
        struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if opt + 2 > len(data):
        return None
    (magic,) = struct.unpack_from("<H", data, opt)
    is64 = magic == 0x20B
    n_dirs_off = (opt + 108) if is64 else (opt + 92)
    dir_off = (opt + 112) if is64 else (opt + 96)
    if n_dirs_off + 4 > len(data):
        return None
    (n_dirs,) = struct.unpack_from("<I", data, n_dirs_off)
    return opt, is64, dir_off, n_dirs, opt + opt_size, nsections


def _sections(data: bytes, sh: int, nsections: int):
    """[(vaddr, vsize, roff, rsize)] from the section table -- for RVA -> file-offset mapping."""
    secs = []
    for i in range(min(nsections, 96)):
        o = sh + i * 40
        if o + 40 > len(data):
            break
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        secs.append((vaddr, vsize, roff, rsize))
    return secs


def _rva_to_off(rva: int, secs) -> Optional[int]:
    for vaddr, vsize, roff, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return roff + (rva - vaddr)
    return None


def _cstr(blob: bytes, start: int) -> bytes:
    end = blob.find(b"\0", start)
    return blob[start:end if end >= 0 else len(blob)]


def _compressed_uint(blob: bytes, i: int):
    """ECMA-335 II.23.2 compressed unsigned int (1/2/4 bytes by top-bit prefix). (value, next_i)."""
    if i >= len(blob):
        return None, i
    b0 = blob[i]
    if b0 & 0x80 == 0:
        return b0, i + 1
    if b0 & 0xC0 == 0x80 and i + 2 <= len(blob):
        return ((b0 & 0x3F) << 8) | blob[i + 1], i + 2
    if b0 & 0xE0 == 0xC0 and i + 4 <= len(blob):
        return (((b0 & 0x1F) << 24) | (blob[i + 1] << 16) | (blob[i + 2] << 8) | blob[i + 3]), i + 4
    return None, i + 1


def _parse_us(heap: bytes, cap: int = 2000) -> list:
    """The #US user-string heap: each entry is a compressed length then that many bytes of UTF-16LE
    plus one trailing flag byte. Entry 0 is the empty string. Returns the decoded literals."""
    out, i = [], 1                      # skip the mandatory empty entry at offset 0
    while i < len(heap) and len(out) < cap:
        n, j = _compressed_uint(heap, i)
        if n is None or n == 0:
            break
        body = heap[j:j + n - 1] if n >= 1 else b""     # last byte is the UTF-16 flag, not data
        try:
            s = body.decode("utf-16-le", "replace")
        except Exception:                               # noqa: BLE001
            s = ""
        if s.strip("\x00"):
            out.append(s)
        i = j + n
    return out


def _parse_tilde_counts(stream: bytes):
    """From the #~ metadata-table stream header, return (typedef_rows, methoddef_rows). The header
    is: reserved u32, major u8, minor u8, heapsizes u8, reserved u8, Valid u64 (bitmask of present
    tables), Sorted u64, then a u32 row count for each set bit in Valid (low->high)."""
    if len(stream) < 24:
        return 0, 0
    valid = struct.unpack_from("<Q", stream, 8)[0]
    present = [t for t in range(64) if valid & (1 << t)]
    rows, off = {}, 24
    for t in present:
        if off + 4 > len(stream):
            break
        rows[t] = struct.unpack_from("<I", stream, off)[0]
        off += 4
    return rows.get(_TBL_TYPEDEF, 0), rows.get(_TBL_METHODDEF, 0)


def is_dotnet(data: bytes) -> bool:
    """A managed (.NET) PE: a PE whose CLI (COM descriptor) data directory is non-empty."""
    hdr = _opt_header(data)
    if not hdr:
        return False
    _opt, _is64, dir_off, n_dirs, _sh, _ns = hdr
    if n_dirs <= _DIR_COM:
        return False
    eo = dir_off + _DIR_COM * 8
    if eo + 8 > len(data):
        return False
    com_rva, com_size = struct.unpack_from("<II", data, eo)
    return bool(com_rva and com_size)


def parse(data: bytes) -> DotNetInfo:
    info = DotNetInfo()
    hdr = _opt_header(data)
    if not hdr:
        info.errors.append("not a PE")
        return info
    opt, is64, dir_off, n_dirs, sh, nsections = hdr
    info.bits = 64 if is64 else 32
    if n_dirs <= _DIR_COM:
        return info
    com_rva, com_size = struct.unpack_from("<II", data, dir_off + _DIR_COM * 8)
    if not (com_rva and com_size):
        return info
    info.is_dotnet = True
    secs = _sections(data, sh, nsections)
    try:
        com_off = _rva_to_off(com_rva, secs)
        if com_off is None or com_off + 72 > len(data):
            info.errors.append("CLI header not in any section")
            return info
        # IMAGE_COR20_HEADER: cb u32, major/minor u16, MetaData(rva u32,size u32), Flags u32, ...
        info.runtime_flags = struct.unpack_from("<I", data, com_off + 16)[0]
        meta_rva, meta_size = struct.unpack_from("<II", data, com_off + 8)
        meta_off = _rva_to_off(meta_rva, secs)
        if meta_off is None or meta_off + 20 > len(data):
            info.errors.append("metadata root not in any section")
            return info
        if struct.unpack_from("<I", data, meta_off)[0] != _META_SIG:
            info.errors.append("metadata root signature is not BSJB")
            return info
        (ver_len,) = struct.unpack_from("<I", data, meta_off + 12)
        ver_len = max(0, min(ver_len, 255))
        info.clr_version = _cstr(data[meta_off + 16:meta_off + 16 + ver_len], 0).decode(
            "utf-8", "replace") or None
        # stream headers follow the 4-byte-aligned version, past flags u16 + stream count u16
        p = meta_off + 16 + ((ver_len + 3) & ~3)
        (nstreams,) = struct.unpack_from("<H", data, p + 2)
        p += 4
        heaps = {}
        for _ in range(min(nstreams, 32)):
            if p + 8 > len(data):
                break
            s_off, s_size = struct.unpack_from("<II", data, p)
            name_start = p + 8
            name = _cstr(data, name_start).decode("ascii", "replace")
            info.streams.append(name)
            base = meta_off + s_off
            heaps[name] = data[base:base + s_size] if base + s_size <= len(data) else b""
            # stream name is null-terminated and padded to a 4-byte boundary
            p = name_start + ((len(name) + 1 + 3) & ~3)
        if "#Strings" in heaps:
            info.names = [s.decode("utf-8", "replace")
                          for s in heaps["#Strings"].split(b"\0") if s][:4000]
        if "#US" in heaps:
            info.user_strings = _parse_us(heaps["#US"])
        if "#~" in heaps:
            info.type_count, info.method_count = _parse_tilde_counts(heaps["#~"])
        elif "#-" in heaps:                              # uncompressed table stream variant
            info.type_count, info.method_count = _parse_tilde_counts(heaps["#-"])
    except Exception as e:                               # noqa: BLE001 -- untrusted input
        info.errors.append(f"metadata parse: {e!r}")
    return info


def to_format_details(info: DotNetInfo) -> dict:
    return {
        "format": "dotnet",
        "clr_version": info.clr_version,
        "types": info.type_count,
        "methods": info.method_count,
        "streams": info.streams,
        "il_only": bool(info.runtime_flags & 0x1),       # COMIMAGE_FLAGS_ILONLY
        "names_sample": info.names[:32],
        "user_strings_sample": info.user_strings[:32],
    }
