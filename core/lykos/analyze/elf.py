"""IT-06..IT-12 — pure-stdlib ELF parser.

Extracts arch/bits/endianness/type, sections, imports, linking, stripped, toolchain hint,
and security mitigations, for any ELF regardless of host architecture. Best-effort and
robust: every sub-parse is guarded; failures are appended to `errors` and never raise.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

# e_machine -> normalized arch name (extend freely)
_MACHINES = {
    0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "ppc", 0x15: "ppc64",
    0x16: "s390", 0x28: "arm", 0x2A: "sh", 0x04: "m68k", 0x2B: "sparcv9",
    0x3E: "x86-64", 0xB7: "aarch64", 0xF3: "riscv", 0x102: "loongarch",
    0x12: "sparc",          # EM_SPARC32PLUS (v8plus) -- same ISA family as EM_SPARC
}
_ETYPES = {0: "none", 1: "rel", 2: "exec", 3: "dyn", 4: "core"}

# program header types
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
# section header types
SHT_PROGBITS, SHT_SYMTAB, SHT_DYNSYM, SHT_DYNAMIC = 1, 2, 11, 6
# dynamic tags
DT_NEEDED, DT_STRTAB, DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 1, 5, 24, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x08, 0x00000001, 0x08000000
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 0x1, 0x2, 0x4
STT_FUNC = 2


@dataclass
class ElfInfo:
    arch: Optional[str] = None
    bits: Optional[int] = None
    endianness: Optional[str] = None
    elf_type: Optional[str] = None
    entry: Optional[int] = None
    interpreter: Optional[str] = None
    linking: Optional[str] = None
    stripped: Optional[bool] = None
    sections: list[dict] = field(default_factory=list)
    imports: dict = field(default_factory=lambda: {"libraries": [], "functions_count": 0})
    exports_count: int = 0
    # Phase 8 (doc 17.1/17.2): dynamic-symbol NAMES for cross-binary import/export resolution.
    imported_symbols: list = field(default_factory=list)  # undefined dynsym (needs)
    exported_symbols: list = field(default_factory=list)   # defined STT_FUNC (provides)
    toolchain_hint: str = "unknown"
    mitigations: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return round(h, 3)


def parse(data: bytes) -> ElfInfo:
    info = ElfInfo()
    try:
        if len(data) < 20 or data[:4] != b"\x7fELF":
            info.errors.append("not an ELF or too short")
            return info
        ei_class, ei_data = data[4], data[5]
        info.bits = {1: 32, 2: 64}.get(ei_class)
        info.endianness = {1: "little", 2: "big"}.get(ei_data)
        endc = "<" if ei_data == 1 else ">"
        is64 = ei_class == 2
    except Exception as e:  # pragma: no cover - defensive
        info.errors.append(f"ident: {e!r}")
        return info

    try:
        if is64:
            (e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _fl, _eh,
             e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
                endc + "HHIQQQIHHHHHH", data, 16)
        else:
            (e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _fl, _eh,
             e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
                endc + "HHIIIIIHHHHHH", data, 16)
        info.elf_type = _ETYPES.get(e_type, f"0x{e_type:x}")
        info.arch = _MACHINES.get(e_machine, f"em-{e_machine}")
        info.entry = e_entry
    except Exception as e:
        info.errors.append(f"header: {e!r}")
        return info

    has_interp = has_dynamic = False
    df1 = dt_flags = 0
    dyn_offsets: list[tuple[int, int]] = []  # (offset, size) of PT_DYNAMIC
    gnu_stack = None  # None=absent, True=exec, False=noexec
    gnu_relro = False

    # --- program headers (mitigations: NX/RELRO, interp) ---
    try:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if is64:
                p_type, p_flags, p_offset, _va, _pa, p_filesz = struct.unpack_from(
                    endc + "IIQQQQ", data, off)[:6]
            else:
                p_type, p_offset, _va, _pa, p_filesz, _memsz, p_flags = struct.unpack_from(
                    endc + "IIIIIII", data, off)[:7]
            if p_type == PT_GNU_STACK:
                gnu_stack = bool(p_flags & 0x1)  # X flag => executable stack
            elif p_type == PT_GNU_RELRO:
                gnu_relro = True
            elif p_type == PT_INTERP:
                has_interp = True
                info.interpreter = data[p_offset:p_offset + p_filesz].split(b"\x00")[0].decode(
                    "utf-8", "replace") or None
            elif p_type == PT_DYNAMIC:
                has_dynamic = True
                dyn_offsets.append((p_offset, p_filesz))
    except Exception as e:
        info.errors.append(f"phdrs: {e!r}")

    # --- section headers (names, symtab/stripped, comment, dynsym, dynamic) ---
    sh = []
    shstr = b""
    try:
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is64:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
                 sh_info, _al, sh_entsize) = struct.unpack_from(endc + "IIQQQQIIQQ", data, off)
            else:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
                 sh_info, _al, sh_entsize) = struct.unpack_from(endc + "IIIIIIIIII", data, off)
            sh.append(dict(name_off=sh_name, type=sh_type, flags=sh_flags, addr=sh_addr,
                           offset=sh_offset, size=sh_size, link=sh_link, info=sh_info,
                           entsize=sh_entsize))
        if e_shnum and e_shstrndx < len(sh):
            s = sh[e_shstrndx]
            shstr = data[s["offset"]:s["offset"] + s["size"]]
    except Exception as e:
        info.errors.append(f"shdrs: {e!r}")

    def _name(off: int) -> str:
        end = shstr.find(b"\x00", off)
        return shstr[off:end].decode("utf-8", "replace") if off < len(shstr) else ""

    by_name: dict[str, dict] = {}
    try:
        for s in sh:
            nm = _name(s["name_off"])
            s["name"] = nm
            by_name[nm] = s
            perms = "".join([("r" if s["flags"] & SHF_ALLOC else "-"),
                             ("w" if s["flags"] & SHF_WRITE else "-"),
                             ("x" if s["flags"] & SHF_EXEC else "-")])
            ent = None
            if s["type"] == SHT_PROGBITS and s["size"]:
                blob = data[s["offset"]:s["offset"] + min(s["size"], 2 << 20)]
                ent = _entropy(blob)
            info.sections.append({"name": nm, "size": s["size"], "perms": perms,
                                  "entropy": ent})
    except Exception as e:
        info.errors.append(f"sections: {e!r}")

    # stripped: no .symtab section
    if sh:
        info.stripped = ".symtab" not in by_name

    # toolchain hint
    try:
        if ".gopclntab" in by_name or ".note.go.buildid" in by_name:
            info.toolchain_hint = "go"
        elif ".comment" in by_name:
            c = data[by_name[".comment"]["offset"]:
                     by_name[".comment"]["offset"] + by_name[".comment"]["size"]]
            low = c.lower()
            if b"clang" in low:
                info.toolchain_hint = "clang"
            elif b"gcc" in low:
                info.toolchain_hint = "gcc"
            elif b"rust" in low:
                info.toolchain_hint = "rust"
    except Exception as e:
        info.errors.append(f"toolchain: {e!r}")

    # --- dynamic section: needed libs, bind-now, PIE flag ---
    needed_offs: list[int] = []
    try:
        dyn = by_name.get(".dynamic")
        dyn_off = dyn["offset"] if dyn else (dyn_offsets[0][0] if dyn_offsets else None)
        dyn_sz = dyn["size"] if dyn else (dyn_offsets[0][1] if dyn_offsets else 0)
        if dyn_off is not None:
            step = 16 if is64 else 8
            fmt = endc + ("qQ" if is64 else "iI")
            for o in range(dyn_off, dyn_off + dyn_sz, step):
                d_tag, d_val = struct.unpack_from(fmt, data, o)
                if d_tag == 0:  # DT_NULL
                    break
                if d_tag == DT_NEEDED:
                    needed_offs.append(d_val)
                elif d_tag == DT_BIND_NOW:
                    dt_flags |= DF_BIND_NOW
                elif d_tag == DT_FLAGS:
                    dt_flags |= d_val
                elif d_tag == DT_FLAGS_1:
                    df1 |= d_val
    except Exception as e:
        info.errors.append(f"dynamic: {e!r}")

    # resolve needed names via the .dynstr section (file-offset addressable)
    try:
        ds = by_name.get(".dynstr")
        if ds and needed_offs:
            blob = data[ds["offset"]:ds["offset"] + ds["size"]]
            libs = []
            for no in needed_offs:
                end = blob.find(b"\x00", no)
                if 0 <= no < len(blob):
                    libs.append(blob[no:end].decode("utf-8", "replace"))
            info.imports["libraries"] = libs
    except Exception as e:
        info.errors.append(f"needed: {e!r}")

    # --- dynamic symbols: imports count, canary, fortify, exports ---
    canary = fortify = False
    try:
        dsym = by_name.get(".dynsym")
        dstr = by_name.get(".dynstr")
        if dsym and dstr and dsym["entsize"]:
            strblob = data[dstr["offset"]:dstr["offset"] + dstr["size"]]
            count = dsym["size"] // dsym["entsize"]
            imported = 0
            imp_names: set[str] = set()
            exp_names: set[str] = set()
            for i in range(count):
                o = dsym["offset"] + i * dsym["entsize"]
                if is64:
                    st_name, st_info, _o, st_shndx, _val, _sz = struct.unpack_from(
                        endc + "IBBHQQ", data, o)
                else:
                    st_name, _val, _sz, st_info, _o, st_shndx = struct.unpack_from(
                        endc + "IIIBBH", data, o)
                end = strblob.find(b"\x00", st_name)
                nm = (strblob[st_name:end].decode("utf-8", "replace")
                      if st_name < len(strblob) else "")
                sttype = st_info & 0xF
                st_bind = st_info >> 4
                if st_shndx == 0 and nm:              # undefined => imported
                    imported += 1
                    imp_names.add(nm)
                    if nm == "__stack_chk_fail":
                        canary = True
                    if nm.endswith("_chk"):
                        fortify = True
                elif sttype == STT_FUNC and st_shndx != 0:
                    info.exports_count += 1
                    # GLOBAL(1)/WEAK(2) defined functions are what other components can bind to
                    if nm and st_bind in (1, 2):
                        exp_names.add(nm)
            info.imports["functions_count"] = imported
            info.imports["symbols"] = sorted(imp_names)[:8000]
            info.imported_symbols = sorted(imp_names)[:8000]
            info.exported_symbols = sorted(exp_names)[:8000]
    except Exception as e:
        info.errors.append(f"dynsym: {e!r}")

    # --- linking ---
    # PT_DYNAMIC alone does NOT mean dynamically linked: every PIE (static-pie included) carries
    # it for self-relocation. Dynamic linking is signalled by an interpreter (PT_INTERP) or
    # needed external libraries (DT_NEEDED). A PIE with PT_DYNAMIC but neither is static-pie.
    if has_interp or info.imports["libraries"]:
        info.linking = "dynamic"
    elif has_dynamic and info.elf_type == "dyn":
        info.linking = "static-pie"
    elif sh:
        info.linking = "static"

    # --- mitigations ---
    nx = "unknown" if gnu_stack is None else ("off" if gnu_stack else "on")
    pie = ("on" if (info.elf_type == "dyn" and (has_interp or (df1 & DF_1_PIE)))
           else ("off" if info.elf_type == "exec" else "unknown"))
    bind_now = bool(dt_flags & DF_BIND_NOW) or bool(df1 & DF_1_NOW)
    relro = "on" if (gnu_relro and bind_now) else ("partial" if gnu_relro else "off")
    info.mitigations = {"nx": nx, "pie": pie, "relro": relro,
                        "canary": "on" if canary else "off",
                        "fortify": "on" if fortify else "off"}
    return info


def to_format_details(info: ElfInfo) -> dict[str, Any]:
    return {"elf": {"type": info.elf_type, "entry": info.entry,
                    "interpreter": info.interpreter, "linking": info.linking,
                    "sections": len(info.sections)}}
