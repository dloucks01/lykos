"""Mach-O header parser (macOS / iOS executables, dylibs, bundles), the third native object format
beside ELF and PE. Extracts arch/bits/endianness, file type, entry point, linked dylibs (imports),
exported/imported symbols, and the security mitigations the header advertises (PIE, stack execution,
encryption, code signature, stack-canary use), for thin and fat (universal) binaries, on any host.

Best-effort and defensive like `elf.parse`: a truncated or hostile file yields a partial record and
an `errors` list, never an exception. Mach-O carries no machine-code analysis here -- that is
Ghidra's job downstream -- but a parsed header turns a Mach-O from "detected only" into a target the
string, symbol and invocation detectors can work on."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional

# magic (raw leading 4 bytes) -> (endianness, bits, is_fat)
_MAGICS = {
    b"\xfe\xed\xfa\xce": ("big", 32, False),     # MH_MAGIC
    b"\xce\xfa\xed\xfe": ("little", 32, False),  # MH_CIGAM
    b"\xfe\xed\xfa\xcf": ("big", 64, False),     # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe": ("little", 64, False),  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe": ("big", None, True),    # FAT_MAGIC (universal; slices follow, big-endian)
    b"\xbe\xba\xfe\xca": ("little", None, True),  # FAT_CIGAM
    b"\xca\xfe\xba\xbf": ("big", None, True),    # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca": ("little", None, True),  # FAT_CIGAM_64
}
_CPU_ABI64 = 0x01000000
_CPU_ABI64_32 = 0x02000000                       # arm64_32 (ILP32 on a 64-bit ISA)
# cputype (with the ABI bits masked off) -> base arch name
_CPUS = {7: "x86", 12: "arm", 18: "ppc", 6: "m68k", 10: "mc98000", 14: "sparc"}
_FILETYPES = {1: "object", 2: "executable", 3: "fvmlib", 4: "core", 5: "preload",
              6: "dylib", 7: "dylinker", 8: "bundle", 9: "dylib-stub", 10: "dsym",
              11: "kext-bundle", 12: "fileset"}
# header flags we surface
MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL = 0x1, 0x4, 0x80
MH_PIE, MH_ALLOW_STACK_EXECUTION, MH_NO_HEAP_EXECUTION = 0x200000, 0x20000, 0x1000000
# load commands
LC_REQ_DYLD = 0x80000000
LC_SEGMENT, LC_SYMTAB, LC_UNIXTHREAD, LC_SEGMENT_64 = 0x1, 0x2, 0x5, 0x19
LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_DYLINKER = 0xC, 0xD, 0xE
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
LC_CODE_SIGNATURE, LC_MAIN = 0x1D, (0x28 | LC_REQ_DYLD)
_MAX_CMDS = 20000                                # a hostile ncmds is a u32; bound the loop


@dataclass
class MachoInfo:
    arch: Optional[str] = None
    bits: Optional[int] = None
    endianness: Optional[str] = None
    macho_type: Optional[str] = None             # "executable" / "dylib" / ...
    fat: bool = False
    fat_arches: list[str] = field(default_factory=list)
    entry: Optional[int] = None
    linking: Optional[str] = None
    stripped: Optional[bool] = None
    interpreter: Optional[str] = None            # the dynamic linker (LC_LOAD_DYLINKER)
    sections: list[dict] = field(default_factory=list)
    imports: dict = field(default_factory=lambda: {"libraries": [], "functions_count": 0})
    exports_count: int = 0
    imported_symbols: list = field(default_factory=list)
    exported_symbols: list = field(default_factory=list)
    toolchain_hint: str = "unknown"
    mitigations: dict = field(default_factory=dict)
    signed: bool = False
    encrypted: bool = False
    errors: list[str] = field(default_factory=list)


def _arch_name(cputype: int, bits: Optional[int]) -> tuple[str, int]:
    """(arch, bits) from a Mach-O cputype, honouring the 64-bit ABI bit (which can disagree with the
    slice's declared word size, e.g. arm64_32)."""
    base = _CPUS.get(cputype & ~(_CPU_ABI64 | _CPU_ABI64_32), f"cputype-{cputype & 0xffffff}")
    is64 = bool(cputype & _CPU_ABI64) or bits == 64
    if base == "x86":
        return ("x86-64" if is64 else "x86"), (64 if is64 else 32)
    if base == "arm":
        return ("aarch64" if is64 else "arm"), (64 if is64 else 32)
    if base == "ppc":
        return ("ppc64" if is64 else "ppc"), (64 if is64 else 32)
    return base, (64 if is64 else 32)


def _cstr(data: bytes, off: int, limit: int = 4096) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("utf-8", "replace")


def parse(data: bytes) -> MachoInfo:
    info = MachoInfo()
    if len(data) < 8 or data[:4] not in _MAGICS:
        info.errors.append("not a Mach-O (bad magic)")
        return info
    endian, bits, is_fat = _MAGICS[data[:4]]
    info.endianness = endian
    if is_fat:
        return _parse_fat(data, endian, data[:4] in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"), info)
    return _parse_thin(data, 0, endian, bits, info)


def _parse_fat(data: bytes, endian: str, fat64: bool, info: MachoInfo) -> MachoInfo:
    """Universal binary: a fat header lists (cputype, offset, size) per slice. Report every slice's
    arch, then parse the FIRST slice in full so the record has concrete header fields."""
    info.fat = True
    e = ">" if endian == "big" else "<"
    try:
        (nfat,) = struct.unpack_from(e + "I", data, 4)
    except struct.error:
        info.errors.append("truncated fat header")
        return info
    nfat = min(nfat, 64)
    # fat_arch: cputype, cpusubtype, offset, size, align  (32-bit offsets; fat_arch_64 uses 64-bit)
    rec_sz = 8 + (8 + 8 + 4 + 4) if fat64 else 8 + (4 + 4 + 4)
    off_fmt = e + ("iiQQI" if fat64 else "iiIII")
    first = None
    for i in range(nfat):
        base = 8 + i * rec_sz
        try:
            cputype, _sub, soff, ssize = struct.unpack_from(off_fmt, data, base)[:4]
        except struct.error:
            info.errors.append("truncated fat_arch table")
            break
        aname, _ = _arch_name(cputype, None)
        info.fat_arches.append(aname)
        if first is None and 0 < soff < len(data):
            first = (soff, ssize)
    if first is not None:
        soff = first[0]
        if data[soff:soff + 4] in _MAGICS:
            sl_endian, sl_bits, _ = _MAGICS[data[soff:soff + 4]]
            _parse_thin(data, soff, sl_endian, sl_bits, info)
    info.linking = info.linking or "dynamic"
    return info


def _parse_thin(data: bytes, base: int, endian: str, bits: int, info: MachoInfo) -> MachoInfo:
    e = ">" if endian == "big" else "<"
    hdr_sz = 32 if bits == 64 else 28
    if base + hdr_sz > len(data):
        info.errors.append("truncated Mach-O header")
        return info
    # mach_header[_64]: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, [reserved]
    try:
        _magic, cputype, _sub, ftype, ncmds, _szcmds, flags = struct.unpack_from(e + "IiiIIII", data, base)
    except struct.error:
        info.errors.append("unpackable Mach-O header")
        return info
    info.endianness, info.bits = endian, bits
    info.arch, info.bits = _arch_name(cputype, bits)
    info.macho_type = _FILETYPES.get(ftype, f"type-{ftype}")
    libs: list[str] = []
    has_dyld = False
    off = base + hdr_sz
    for _ in range(min(ncmds, _MAX_CMDS)):
        if off + 8 > len(data):
            info.errors.append("load commands truncated")
            break
        try:
            cmd, cmdsize = struct.unpack_from(e + "II", data, off)
        except struct.error:
            break
        if cmdsize < 8 or off + cmdsize > len(data):
            info.errors.append("bad load-command size")
            break
        _parse_lc(data, off, cmd, cmdsize, e, bits, info, libs)
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_ID_DYLIB):
            has_dyld = True
        off += cmdsize
    info.imports = {"libraries": sorted(set(libs))[:64], "functions_count": len(info.imported_symbols),
                    "symbols": info.imported_symbols[:512]}
    info.exports_count = len(info.exported_symbols)
    info.linking = "dynamic" if (has_dyld or flags & MH_DYLDLINK) else "static"
    info.mitigations = _mitigations(flags, info)
    info.toolchain_hint = "clang/ld64 (Mach-O)"
    return info


def _parse_lc(data, off, cmd, cmdsize, e, bits, info, libs):
    """Dispatch one load command into the record. Each reader is bounds-checked and best-effort."""
    try:
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_ID_DYLIB):
            (name_off,) = struct.unpack_from(e + "I", data, off + 8)
            if 8 <= name_off < cmdsize:
                lib = _cstr(data, off + name_off, cmdsize)
                if cmd != LC_ID_DYLIB and lib:
                    libs.append(lib.rsplit("/", 1)[-1])          # the install-name's leaf
        elif cmd == LC_LOAD_DYLINKER:
            (name_off,) = struct.unpack_from(e + "I", data, off + 8)
            if 8 <= name_off < cmdsize:
                info.interpreter = _cstr(data, off + name_off, cmdsize)
        elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
            _parse_segment(data, off, cmd, e, info)
        elif cmd == LC_SYMTAB:
            _parse_symtab(data, off, e, bits, info)
        elif cmd == LC_MAIN and cmdsize >= 16:                        # entryoff+stacksize = 16 bytes
            (entryoff,) = struct.unpack_from(e + "Q", data, off + 8)   # file offset of entry
            info.entry = entryoff
        elif cmd == LC_UNIXTHREAD and info.entry is None:
            info.entry = info.entry                                   # pc is in the thread state;
            # left unparsed (ISA-specific register layout); LC_MAIN covers modern binaries.
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            cryptid = struct.unpack_from(e + "I", data, off + 16)[0]
            info.encrypted = bool(cryptid)
        elif cmd == LC_CODE_SIGNATURE:
            info.signed = True
    except struct.error:
        info.errors.append(f"load command 0x{cmd:x} truncated")


def _parse_segment(data, off, cmd, e, info):
    is64 = cmd == LC_SEGMENT_64
    # segment_command[_64]: cmd, cmdsize, segname[16], vmaddr, vmsize, fileoff, filesize,
    #                       maxprot, initprot, nsects, flags
    segname = _cstr(data, off + 8, 16)
    ptr = e + ("QQQQ" if is64 else "IIII")
    sz = 8 if is64 else 4
    try:
        vmaddr, vmsize, _fileoff, _filesz = struct.unpack_from(ptr, data, off + 24)
        maxprot, initprot, nsects, _flags = struct.unpack_from(e + "iiII", data, off + 24 + 4 * sz)
    except struct.error:
        return
    info.sections.append({"name": segname, "vaddr": vmaddr, "size": vmsize,
                          "exec": bool(initprot & 0x4), "write": bool(initprot & 0x2)})
    # section records follow the segment command; collect their names (seg,sect) + sizes
    sect_sz = 80 if is64 else 68
    sbase = off + (72 if is64 else 56)
    for i in range(min(nsects, 256)):
        s = sbase + i * sect_sz
        if s + 32 > len(data):
            break
        sect = _cstr(data, s, 16)
        info.sections.append({"name": f"{segname.strip()},{sect.strip()}", "size": None})


def _parse_symtab(data, off, e, bits, info):
    try:
        symoff, nsyms, stroff, strsize = struct.unpack_from(e + "IIII", data, off + 8)
    except struct.error:
        return
    imported, exported = [], []
    nl_sz = 16 if bits == 64 else 12               # nlist_64 / nlist
    nsyms = min(nsyms, 200000)
    for i in range(nsyms):
        b = symoff + i * nl_sz
        if b + nl_sz > len(data):
            break
        try:
            n_strx, n_type, _n_sect, _n_desc = struct.unpack_from(e + "IBBH", data, b)
            n_value = struct.unpack_from(e + ("Q" if bits == 64 else "I"), data, b + 8)[0]
        except struct.error:
            break
        if n_type & 0xe0:                          # N_STAB: debug symbol, not a real import/export
            continue
        name = _cstr(data, stroff + n_strx, 1024) if n_strx and (stroff + n_strx) < len(data) else ""
        if not name:
            continue
        n_type_field = n_type & 0x0e                # N_TYPE
        if (n_type & 0x01) and n_type_field == 0x00:   # N_EXT and N_UNDF -> undefined external = import
            imported.append(name.lstrip("_"))
        elif (n_type & 0x01) and n_value:               # N_EXT defined -> export
            exported.append(name.lstrip("_"))
    info.imported_symbols = imported[:2048]
    info.exported_symbols = exported[:2048]
    # a Mach-O with no non-stab, non-dynamic local symbols is effectively stripped
    info.stripped = len(exported) == 0 and len(imported) == 0


def _mitigations(flags: int, info: MachoInfo) -> dict:
    """Map the header flags + symbol evidence to the mitigation keys the rest of lykos reads. nx/pie
    use the same vocabulary as the ELF parser so the shared exploit/report code needs no special
    case; the Mach-O-specific facts (code signature, encryption) ride alongside."""
    stack_exec = bool(flags & MH_ALLOW_STACK_EXECUTION)
    canary = any(s in ("__stack_chk_fail", "__stack_chk_guard", "stack_chk_fail", "stack_chk_guard")
                 for s in info.imported_symbols + info.exported_symbols)
    return {
        "nx": "off" if stack_exec else "on",
        "pie": "on" if flags & MH_PIE else "off",
        "canary": "on" if canary else "off",
        "code_signature": "on" if info.signed else "off",
        "encrypted": "on" if info.encrypted else "off",
        "no_heap_exec": "on" if flags & MH_NO_HEAP_EXECUTION else "off",
    }


def to_format_details(info: MachoInfo) -> dict[str, Any]:
    return {"macho": {"type": info.macho_type, "entry": info.entry, "fat": info.fat,
                      "fat_arches": info.fat_arches, "interpreter": info.interpreter,
                      "linking": info.linking, "signed": info.signed, "encrypted": info.encrypted,
                      "sections": len(info.sections)}}
