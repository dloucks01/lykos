"""PE/COFF header parsing (pure stdlib, never raises).

`filetype.detect` has always recognised a PE and said "full PE-header check happens in a PE
parser" -- there was none, so triage recorded the format and nothing else: arch, bits,
linking, stripped and mitigations all came back null for every Windows binary, and the panel
that shows them was blank. Meanwhile disassembly, CWE detection and the Wine dynamic path all
work on PE, so the gap was in what we could SAY about the file, not what we could do with it.

Mitigations matter more here than the rest: on Windows they live in one DllCharacteristics
word, and ASLR/DEP/CFG being off is the difference between a crash and a straightforward
exploit. Same shape as the ELF parser: every sub-parse is guarded and failures are collected
in `errors` rather than raised.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

_log = logging.getLogger(__name__)

# IMAGE_FILE_MACHINE_*
_MACHINE = {
    0x014C: ("x86", 32), 0x8664: ("x86-64", 64), 0x01C0: ("arm", 32),
    0x01C4: ("arm", 32), 0xAA64: ("aarch64", 64), 0x0200: ("ia64", 64),
    0x0166: ("mips", 32), 0x01F0: ("ppc", 32), 0x5032: ("riscv", 32),
    0x5064: ("riscv64", 64), 0x5128: ("riscv64", 64),
}
# IMAGE_DLLCHARACTERISTICS_*
_DLLCHAR = {
    0x0020: "high_entropy_va", 0x0040: "dynamic_base", 0x0080: "force_integrity",
    0x0100: "nx_compat", 0x0200: "no_isolation", 0x0400: "no_seh",
    0x0800: "no_bind", 0x1000: "appcontainer", 0x2000: "wdm_driver",
    0x4000: "guard_cf", 0x8000: "terminal_server_aware",
}
_FILE_DEBUG_STRIPPED = 0x0200
_SUBSYSTEM = {1: "native", 2: "windows-gui", 3: "windows-cui", 9: "wince-gui",
              10: "efi-application", 16: "boot-application"}


@dataclass
class PeInfo:
    ok: bool = False
    arch: Optional[str] = None
    bits: Optional[int] = None
    endianness: str = "little"          # PE is little-endian on every machine we decode
    entry: Optional[int] = None
    image_base: Optional[int] = None
    subsystem: Optional[str] = None
    linking: Optional[str] = None
    stripped: Optional[bool] = None
    sections: list = field(default_factory=list)
    imports: dict = field(default_factory=dict)
    exports_count: int = 0
    exported_symbols: list = field(default_factory=list)
    export_dll_name: Optional[str] = None     # the DLL's own name per its export directory
    export_forwarders: dict = field(default_factory=dict)   # name -> "OTHERDLL.Func"
    tls_callbacks: list = field(default_factory=list)       # VAs run BEFORE the entry point
    mitigations: dict = field(default_factory=dict)
    toolchain_hint: str = "unknown"
    errors: list = field(default_factory=list)


def parse(data: bytes) -> PeInfo:
    info = PeInfo()
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            info.errors.append("not a PE: no MZ stub")
            return info
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            info.errors.append("not a PE: no PE signature at e_lfanew")
            return info
    except Exception as e:
        info.errors.append(f"dos header: {e!r}")
        return info

    coff = e_lfanew + 4
    try:
        machine, nsections, _ts, sym_ptr, nsyms, opt_size, characteristics = \
            struct.unpack_from("<HHIIIHH", data, coff)
        info.arch, info.bits = _MACHINE.get(machine, (None, None))
        if info.arch is None:
            info.errors.append(f"unknown machine 0x{machine:04x}")
        # A PE keeps no COFF symbol table in practice; DEBUG_STRIPPED is the real signal, and
        # a build with neither is "stripped" for the purpose the UI uses it for.
        info.stripped = bool(characteristics & _FILE_DEBUG_STRIPPED) or not (sym_ptr and nsyms)
    except Exception as e:
        info.errors.append(f"coff header: {e!r}")
        return info

    opt = coff + 20
    magic = 0
    dir_off = None          # data-directory offset; stays None if the optional header is short
    dirs_base = None        # offset of data directory [0]
    n_dirs = 0
    try:
        (magic,) = struct.unpack_from("<H", data, opt)
        is64 = magic == 0x20B
        if info.bits is None:
            info.bits = 64 if is64 else 32
        (entry_rva,) = struct.unpack_from("<I", data, opt + 16)
        if is64:
            (info.image_base,) = struct.unpack_from("<Q", data, opt + 24)
            # data directories start here; entry [0] is EXPORT and [1] is IMPORT, and
            # reading the first one found no imports at all on a binary with an .idata section
            sub_off, dll_off, dirs_base = opt + 68, opt + 70, opt + 112
        else:
            (info.image_base,) = struct.unpack_from("<I", data, opt + 28)
            sub_off, dll_off, dirs_base = opt + 68, opt + 70, opt + 96
        dir_off = dirs_base + 8
        # NumberOfRvaAndSizes: how many data directories the optional header actually holds. The
        # IMPORT directory is entry [1], so with < 2 entries dir_off points past the directories
        # into the section table -- reading it yields garbage imports and a wrong `linking`. Skip.
        n_dirs_off = (opt + 108) if is64 else (opt + 92)
        (n_dirs,) = struct.unpack_from("<I", data, n_dirs_off)
        if n_dirs < 2:
            dir_off = None
        # the directories must also fit inside the declared optional header
        n_dirs = max(0, min(n_dirs, 16, (opt_size - (dirs_base - opt)) // 8))
        (subsystem,) = struct.unpack_from("<H", data, sub_off)
        info.subsystem = _SUBSYSTEM.get(subsystem, f"0x{subsystem:x}")
        (dllchar,) = struct.unpack_from("<H", data, dll_off)
        info.entry = (info.image_base or 0) + entry_rva if entry_rva else None
        info.mitigations = _mitigations(dllchar, magic)
    except Exception as e:
        info.errors.append(f"optional header: {e!r}")

    sh = opt + opt_size
    try:
        for i in range(min(nsections, 96)):
            o = sh + i * 40
            if o + 40 > len(data):
                break
            raw = data[o:o + 8]
            name = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
            (flags,) = struct.unpack_from("<I", data, o + 36)
            body = data[roff:roff + min(rsize, 2 << 20)] if rsize else b""
            info.sections.append({
                "name": name, "size": rsize, "vaddr": vaddr, "vsize": vsize,
                "perms": ("r" if flags & 0x40000000 else "-")
                         + ("w" if flags & 0x80000000 else "-")
                         + ("x" if flags & 0x20000000 else "-"),
                "entropy": _entropy(body) if body else None})
    except Exception as e:
        info.errors.append(f"sections: {e!r}")

    try:
        info.imports = _imports(data, info, dir_off)
        info.linking = "dynamic" if info.imports.get("libraries") else "static"
        info.toolchain_hint = _toolchain(info.imports.get("libraries") or [], data)
    except Exception as e:
        info.errors.append(f"imports: {e!r}")

    try:
        _exports(data, info, _data_dir(data, dirs_base, n_dirs, 0))
    except Exception as e:
        info.errors.append(f"exports: {e!r}")
    try:
        _tls_callbacks(data, info, _data_dir(data, dirs_base, n_dirs, 9))
    except Exception as e:
        info.errors.append(f"tls: {e!r}")

    info.ok = info.arch is not None or bool(info.sections)
    return info


def _mitigations(dllchar: int, magic: int) -> dict:
    """The Windows equivalents of the ELF hardening set, named the way a reader expects."""
    on = {name: bool(dllchar & bit) for bit, name in _DLLCHAR.items()}
    return {
        "aslr": "on" if on["dynamic_base"] else "off",
        "high_entropy_va": "on" if on["high_entropy_va"] else "off",
        "dep": "on" if on["nx_compat"] else "off",
        "seh": "off" if on["no_seh"] else "on",
        "cfg": "on" if on["guard_cf"] else "off",
        "force_integrity": "on" if on["force_integrity"] else "off",
        "pe_format": "PE32+" if magic == 0x20B else "PE32",
    }


def _imports(data: bytes, info: PeInfo, dir_off: Optional[int]) -> dict:
    """{libraries: [...], symbols: [...]} from the import directory."""
    out: dict = {"libraries": [], "symbols": []}
    if dir_off is None or dir_off + 8 > len(data):
        return out
    imp_rva, imp_size = struct.unpack_from("<II", data, dir_off)
    if not imp_rva or not imp_size:
        return out
    off_of = _rva_mapper(data, info)
    base = off_of(imp_rva)
    if base is None:
        return out
    for n in range(256):                                # a descriptor is 20 bytes, 0-terminated
        o = base + n * 20
        if o + 20 > len(data):
            break
        ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", data, o)
        if not (ilt or name_rva or iat):
            break
        no = off_of(name_rva) if name_rva else None
        if no is not None and no < len(data):
            end = data.find(b"\0", no)
            if end < 0:                                 # unterminated: run to the end of file
                end = len(data)
            lib = data[no:end].decode("utf-8", "replace")
            if lib:
                out["libraries"].append(lib)
        thunk = off_of(ilt or iat)
        if thunk is None:
            continue
        step = 8 if info.bits == 64 else 4
        fmt = "<Q" if step == 8 else "<I"
        ordinal_flag = (1 << 63) if step == 8 else (1 << 31)
        for k in range(4096):
            t = thunk + k * step
            if t + step > len(data):
                break
            (val,) = struct.unpack_from(fmt, data, t)
            if not val:
                break
            if val & ordinal_flag:
                continue                                # imported by ordinal: no name to record
            ho = off_of(val & 0x7FFFFFFF)
            if ho is None or ho + 2 >= len(data):
                continue
            end = data.find(b"\0", ho + 2)
            if end < 0:                                 # unterminated: run to the end of file
                end = len(data)
            sym = data[ho + 2:end].decode("utf-8", "replace")
            if sym:
                out["symbols"].append(sym)
    return out


def _data_dir(data: bytes, dirs_base: Optional[int], n_dirs: int, idx: int):
    """(rva, size) of data directory `idx`, or None when the header does not carry it."""
    if dirs_base is None or idx >= n_dirs:
        return None
    o = dirs_base + idx * 8
    if o + 8 > len(data):
        return None
    rva, size = struct.unpack_from("<II", data, o)
    return (rva, size) if rva and size else None


def _rva_mapper(data: bytes, info: PeInfo):
    """RVA -> file offset, or None. Only bytes actually PRESENT in the file map: an RVA in a
    section's zero-filled tail (past SizeOfRawData) has no file bytes, and returning
    `raw + delta` there read the NEXT section's bytes as if they were this one's -- garbage
    names attributed to the wrong directory."""
    raw_offsets = _section_raw_offsets(data, info)
    secs = [(s.get("vaddr") or 0, s.get("vsize") or 0, s.get("size") or 0,
             raw_offsets[i] if i < len(raw_offsets) else 0)
            for i, s in enumerate(info.sections)]
    first_vaddr = min((v for v, _vs, _rs, _r in secs if v), default=None)

    def off_of(rva):
        if rva is None or rva < 0:
            return None
        for vaddr, vsize, rsize, raw in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                delta = rva - vaddr
                if delta >= rsize or raw + delta >= len(data):
                    return None
                return raw + delta
        # the headers are mapped 1:1 below the first section
        if first_vaddr is not None and rva < first_vaddr and rva < len(data):
            return rva
        return None
    return off_of


def _cstr(data: bytes, off: Optional[int], limit: int = 512) -> str:
    if off is None or off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off, off + limit)
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("utf-8", "replace")


_MAX_EXPORTS = 65536


def _exports(data: bytes, info: PeInfo, ddir) -> None:
    """Export directory -> names, ordinal-only count, and forwarders. Every count and pointer in
    the directory is attacker-controlled: each is bounded by the file and a hard cap, so a
    NumberOfNames of 0xFFFFFFFF is a short loop, not a hang."""
    if not ddir:
        return
    exp_rva, exp_size = ddir
    off_of = _rva_mapper(data, info)
    base = off_of(exp_rva)
    if base is None or base + 40 > len(data):
        info.errors.append("exports: directory RVA not backed by file data")
        return
    (_ch, _ts, _maj, _min, name_rva, _ord_base, n_funcs, n_names,
     funcs_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", data, base)
    if name_rva:
        info.export_dll_name = _cstr(data, off_of(name_rva)) or None
    n_funcs = min(n_funcs, _MAX_EXPORTS)
    n_names = min(n_names, _MAX_EXPORTS)
    funcs_off = off_of(funcs_rva) if funcs_rva else None
    names_off = off_of(names_rva) if names_rva else None
    ords_off = off_of(ords_rva) if ords_rva else None
    func_rvas: list = []
    if funcs_off is not None:
        n_funcs = min(n_funcs, max(0, (len(data) - funcs_off) // 4))
        func_rvas = list(struct.unpack_from(f"<{n_funcs}I", data, funcs_off)) if n_funcs else []
    named_idx: set = set()
    names: list = []
    if names_off is not None and ords_off is not None:
        n_names = min(n_names, max(0, (len(data) - names_off) // 4),
                      max(0, (len(data) - ords_off) // 2))
        name_rvas = struct.unpack_from(f"<{n_names}I", data, names_off) if n_names else ()
        ordinals = struct.unpack_from(f"<{n_names}H", data, ords_off) if n_names else ()
        for nrva, idx in zip(name_rvas, ordinals):
            nm = _cstr(data, off_of(nrva))
            if not nm:
                continue
            names.append(nm)
            named_idx.add(idx)
            if idx < len(func_rvas):
                frva = func_rvas[idx]
                # an RVA INSIDE the export directory is a forwarder string, not code
                if exp_rva <= frva < exp_rva + exp_size and len(info.export_forwarders) < 4096:
                    fwd = _cstr(data, off_of(frva))
                    if fwd:
                        info.export_forwarders[nm] = fwd
    # ordinal-only exports (no name) are real entry points, so they count -- but
    # `exported_symbols` stays a NAME list because the cross-binary linker (link/resolve.py)
    # matches it against imported names.
    ordinal_only = sum(1 for i, r in enumerate(func_rvas) if r and i not in named_idx)
    info.exported_symbols = sorted(set(names))[:8000]
    info.exports_count = len(set(names)) + ordinal_only


def _tls_callbacks(data: bytes, info: PeInfo, ddir) -> None:
    """IMAGE_TLS_DIRECTORY.AddressOfCallBacks: code the loader runs BEFORE the entry point (a
    classic anti-debug / unpacking hook, and a reachable surface a fuzzer of `main` never sees)."""
    if not ddir or info.image_base is None:
        return
    off_of = _rva_mapper(data, info)
    base = off_of(ddir[0])
    if base is None:
        return
    step, fmt = (8, "<Q") if info.bits == 64 else (4, "<I")
    if base + 4 * step > len(data):
        return
    (cb_va,) = struct.unpack_from(fmt, data, base + 3 * step)
    if not cb_va or cb_va < info.image_base:
        return
    arr = off_of(cb_va - info.image_base)
    for k in range(64):
        if arr is None or arr + (k + 1) * step > len(data):
            break
        (va,) = struct.unpack_from(fmt, data, arr + k * step)
        if not va:
            break
        info.tls_callbacks.append(va)


def _section_raw_offsets(data: bytes, info: PeInfo) -> list:
    """PointerToRawData per section, in section order (parsed alongside `sections`)."""
    offs = []
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        coff = e_lfanew + 4
        nsections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        sh = coff + 20 + opt_size
        for i in range(min(nsections, 96)):
            o = sh + i * 40
            offs.append(struct.unpack_from("<I", data, o + 20)[0] if o + 40 <= len(data) else 0)
    except Exception:
        _log.debug("PE section raw offsets parse failed", exc_info=True)
        pass
    return offs or [0] * len(info.sections)


def _toolchain(libs: list, data: bytes) -> str:
    low = " ".join(libs).lower()
    if "ucrtbase" in low or "api-ms-win-crt" in low:
        return "mingw/ucrt" if b"GCC: (" in data[:1 << 20] else "msvc/ucrt"
    if "msvcrt" in low:
        return "mingw/msvcrt" if b"GCC: (" in data[:1 << 20] else "msvc"
    return "unknown"


def _entropy(blob: bytes) -> float:
    import math
    if not blob:
        return 0.0
    counts = [0] * 256
    for b in blob:
        counts[b] += 1
    n = len(blob)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def to_format_details(info: PeInfo) -> dict[str, Any]:
    return {"format": "pe", "subsystem": info.subsystem,
            "image_base": (f"0x{info.image_base:x}" if info.image_base else None),
            "sections": len(info.sections),
            "libraries": info.imports.get("libraries", []),
            "export_name": info.export_dll_name,
            "export_forwarders": dict(list(info.export_forwarders.items())[:256]),
            "tls_callbacks": [f"0x{v:x}" for v in info.tls_callbacks]}
