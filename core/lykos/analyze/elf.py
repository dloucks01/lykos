"""IT-06..IT-12 — pure-stdlib ELF parser.

Extracts arch/bits/endianness/type, sections, imports, linking, stripped, toolchain hint,
and security mitigations, for any ELF regardless of host architecture. Best-effort and
robust: every sub-parse is guarded; failures are appended to `errors` and never raise.
"""
from __future__ import annotations

import bisect
import logging
import math
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

_log = logging.getLogger(__name__)

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

# Per-section entropy is a pure-Python byte loop, and e_shnum is attacker-controlled (u16, up
# to 65535). A crafted ELF whose sections all point at one 2 MiB high-entropy region would
# otherwise run that loop tens of thousands of times -- ~137 GB of work from a ~6 MiB file.
# Cap both the number of sections scanned (mirroring the PE parser's 96) and the cumulative
# bytes hashed. Real ELFs have a few dozen sections and never approach either bound.
_MAX_ENTROPY_SECTIONS = 96
_MAX_ENTROPY_BYTES = 64 << 20


def _fits(data: bytes, base: int, entsize: int, claimed: int) -> int:
    """How many `entsize`-byte records starting at `base` the file can actually hold, capped
    to what the header claims. Bounds a hostile e_phnum/e_shnum to reality so a struct error
    mid-loop cannot discard the records that DID parse."""
    if entsize <= 0 or base < 0 or base >= len(data):
        return 0
    return min(claimed, max(0, (len(data) - base) // entsize))


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
        # A valid ELF ident says 32/64-bit (EI_CLASS 1/2) and little/big-endian (EI_DATA 1/2).
        # Anything else means we do not know the layout: defaulting to 32-bit little/big and
        # reading e_machine anyway hands downstream a guessed arch dressed as fact. Stop, and
        # let the null bits/endianness plus the error speak for themselves.
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            info.errors.append(
                f"invalid ELF ident: EI_CLASS={ei_class}, EI_DATA={ei_data}")
            return info
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
    n_ph = _fits(data, e_phoff, e_phentsize, e_phnum)
    if n_ph < e_phnum:
        info.errors.append(f"e_phnum={e_phnum} exceeds file; parsing {n_ph}")
    try:
        for i in range(n_ph):
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
    n_sh = _fits(data, e_shoff, e_shentsize, e_shnum)
    if n_sh < e_shnum:
        info.errors.append(f"e_shnum={e_shnum} exceeds file; parsing {n_sh}")
    try:
        for i in range(n_sh):
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
        # SHN_XINDEX: when the real string-table index does not fit in 16 bits, e_shstrndx is
        # 0xFFFF (>= SHN_LORESERVE) and the true index lives in section header 0's sh_link.
        strndx = e_shstrndx
        if e_shstrndx >= 0xFF00 and sh:
            strndx = sh[0].get("link", 0)
        if e_shnum and 0 <= strndx < len(sh):
            s = sh[strndx]
            shstr = data[s["offset"]:s["offset"] + s["size"]]
    except Exception as e:
        info.errors.append(f"shdrs: {e!r}")

    def _name(off: int) -> str:
        if not 0 <= off < len(shstr):
            return ""
        end = shstr.find(b"\x00", off)
        if end < 0:                              # unterminated: run to the end, don't drop a byte
            end = len(shstr)
        return shstr[off:end].decode("utf-8", "replace")

    by_name: dict[str, dict] = {}
    ent_scanned = 0
    ent_budget = _MAX_ENTROPY_BYTES
    try:
        for s in sh:
            nm = _name(s["name_off"])
            s["name"] = nm
            by_name[nm] = s
            perms = "".join([("r" if s["flags"] & SHF_ALLOC else "-"),
                             ("w" if s["flags"] & SHF_WRITE else "-"),
                             ("x" if s["flags"] & SHF_EXEC else "-")])
            ent = None
            if (s["type"] == SHT_PROGBITS and s["size"]
                    and ent_scanned < _MAX_ENTROPY_SECTIONS and ent_budget > 0):
                take = min(s["size"], 2 << 20, ent_budget)
                blob = data[s["offset"]:s["offset"] + take]
                ent = _entropy(blob)
                ent_scanned += 1
                ent_budget -= len(blob)
            info.sections.append({"name": nm, "size": s["size"], "perms": perms,
                                  "entropy": ent})
    except Exception as e:
        info.errors.append(f"sections: {e!r}")

    # stripped: no .symtab section
    if sh:
        info.stripped = ".symtab" not in by_name

    # toolchain / source language. Sections are the strongest signal (Go embeds .gopclntab); Rust
    # and C++ are LLVM/GCC underneath so .comment says clang/gcc -- identify them by their runtime
    # symbols/strings instead. A real deployment runs on all of these, and the language decides what
    # analysis applies (memory-safety detectors mean little on a bounds-checked Go/Rust binary).
    try:
        if ".gopclntab" in by_name or ".note.go.buildid" in by_name or b"\xfb\xff\xff\xff\x00\x00" in data[:1 << 20]:
            info.toolchain_hint = "go"
        elif b"/rustc/" in data or b"rust_begin_unwind" in data or b"__rust_alloc" in data \
                or b"rust_eh_personality" in data:
            info.toolchain_hint = "rust"
        elif b"libstdc++" in data or b"libc++.so" in data or b"__cxa_throw" in data \
                or b"_ZSt" in data or b"_ZNSt" in data:
            info.toolchain_hint = "c++"
        elif ".comment" in by_name:
            low = data[by_name[".comment"]["offset"]:
                       by_name[".comment"]["offset"] + by_name[".comment"]["size"]].lower()
            info.toolchain_hint = ("clang" if b"clang" in low else
                                   "gcc" if b"gcc" in low else "unknown")
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
                if 0 <= no < len(blob):
                    end = blob.find(b"\x00", no)
                    if end < 0:                  # unterminated: take the whole remaining span
                        end = len(blob)
                    libs.append(blob[no:end].decode("utf-8", "replace"))
            info.imports["libraries"] = libs
    except Exception as e:
        info.errors.append(f"needed: {e!r}")

    # --- dynamic symbols: imports count, canary, fortify, exports ---
    canary = fortify = False
    try:
        dsym = by_name.get(".dynsym")
        dstr = by_name.get(".dynstr")
        _symsize = 24 if is64 else 16            # sizeof(Elf64_Sym) / sizeof(Elf32_Sym)
        if dsym and dstr and dsym["entsize"] >= _symsize:
            strblob = data[dstr["offset"]:dstr["offset"] + dstr["size"]]
            count = dsym["size"] // dsym["entsize"]
            # A hostile header can claim a huge sh_size with a tiny entsize, turning this into
            # an O(file) loop that scans the whole string blob each pass. Cap to what the file
            # can actually hold, so the work is bounded by the real bytes present.
            fits = max(0, (len(data) - dsym["offset"]) // dsym["entsize"])
            if count > fits:
                info.errors.append(
                    f".dynsym claims {count} symbols; file holds at most {fits}")
                count = fits
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
                if st_name < len(strblob):
                    end = strblob.find(b"\x00", st_name)
                    if end < 0:                  # unterminated: take the whole remaining span
                        end = len(strblob)
                    nm = strblob[st_name:end].decode("utf-8", "replace")
                else:
                    nm = ""
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


STT_OBJECT, STT_FUNC, STT_FILE, STT_GNU_IFUNC = 1, 2, 4, 10
_LIB_FILE = "crtstuff.c"          # the compiler's own glue, linked into every program


def program_ranges(data: bytes) -> list:
    """Address ranges that belong to the program's OWN source, not to code linked in with it.

    A statically linked binary carries its libc, so the decompiler recovers every block of it:
    jhead is 1,887 blocks dynamically linked and 38,418 statically, of which 36,000 are library
    code the fuzzer will never meaningfully explore. Counting those as coverage understates the
    program by more than an order of magnitude, and worse, an input that wanders into a new
    printf path scores as "novel" and earns a place in the corpus.

    ELF says who owns what. A symbol table groups local symbols under an STT_FILE symbol naming
    the object they came from -- `exif.c` for the program, `iofclose.o` for a libc archive
    member -- so every function is attributed to the nearest preceding local symbol's file.
    Measured against the dynamically linked build's own symbols, across all twelve
    architectures jhead is built for: 56 of 56 program functions found, five adjacent crt glue
    symbols over-claimed, nothing from libc.

    Returns [(start, end)] sorted, or [] when the binary cannot say -- stripped, no local
    symbols, or a result too degenerate to trust -- in which case the caller must fall back to
    using everything rather than pretending the program is tiny.
    """
    try:
        if any(sec.get("name") == ".opd" for sec in parse(data).sections):
            # PowerPC64 ELFv1: a function symbol's value is the address of its OPD descriptor,
            # not of its code, so every range this derived would be in the wrong address space.
            return []
        marks, funcs, end = _symbol_owners(data)
    except Exception:
        _log.debug("program_ranges symbol parse failed", exc_info=True)
        return []
    if not marks or not funcs:
        return []
    addrs = [a for a, _ in marks]
    owned, total = [], 0
    for addr, size in funcs:
        total += 1
        i = bisect.bisect_right(addrs, addr) - 1
        if i < 0:
            continue
        owner = marks[i][1]
        if owner.endswith(".c") and owner != _LIB_FILE:
            owned.append((addr, addr + (size or 1)))
    # A small program really is a handful of functions -- a single .c file with one static
    # anchors three -- so there is no ratio to test here. The failure this has to catch is
    # attributing NOTHING, which would hide the whole program from coverage.
    if not owned or total < 2:
        return []
    owned.sort()
    merged = [list(owned[0])]
    for lo, hi in owned[1:]:
        if lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, min(hi, end) if end else hi) for lo, hi in merged]


def _symbol_owners(data: bytes):
    """(local-symbol -> owning file marks, function (addr, size) list, end of text)."""
    info = parse(data)
    is64 = info.bits == 64
    endc = "<" if info.endianness == "little" else ">"
    # ARM tags a Thumb function by setting bit 0 of its symbol value; the address the code
    # actually lives at is even. Left in, every range started one byte late and lost whichever
    # function sat exactly on its edge.
    mask = ~1 if (info.arch or "").startswith("arm") else ~0
    e_shoff, e_shentsize, e_shnum = _section_header_table(data, is64, endc)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        fmt = endc + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
        (_nm, typ, _fl, _ad, s_off, s_sz, link, _inf, _al, ent) = struct.unpack_from(fmt, data, off)
        sections.append((typ, s_off, s_sz, link, ent))
    sym = next((s for s in sections if s[0] == SHT_SYMTAB), None)
    if sym is None:
        return [], [], 0
    _t, s_off, s_sz, link, ent = sym
    if link >= len(sections):
        return [], [], 0
    str_off, str_sz = sections[link][1], sections[link][2]
    strtab = data[str_off:str_off + str_sz]

    def name_at(o):
        e = strtab.find(b"\x00", o)
        return strtab[o:e].decode("utf-8", "replace") if 0 <= o < len(strtab) else ""

    ent = ent or (24 if is64 else 16)
    marks, funcs, cur, end = [], [], None, 0
    for off in range(s_off, min(s_off + s_sz, len(data)) - ent + 1, ent):
        if is64:
            nm, info_b, _oth, shndx, val, size = struct.unpack_from(endc + "IBBHQQ", data, off)
        else:
            nm, val, size, info_b, _oth, shndx = struct.unpack_from(endc + "IIIBBH", data, off)
        typ, bind = info_b & 0xF, info_b >> 4
        if typ == STT_FILE:
            cur = name_at(nm)
            continue
        if not shndx or not val:                       # undefined, or absolute with no address
            continue
        val &= mask
        if typ in (STT_FUNC, STT_GNU_IFUNC):
            funcs.append((val, size))
            end = max(end, val + (size or 1))
        if bind == 0 and cur and typ in (STT_FUNC, STT_GNU_IFUNC, STT_OBJECT):   # STB_LOCAL
            marks.append((val, cur))
    marks.sort()
    return marks, funcs, end


def _section_header_table(data: bytes, is64: bool, endc: str):
    if is64:
        (e_shoff,) = struct.unpack_from(endc + "Q", data, 0x28)
        (e_shentsize, e_shnum) = struct.unpack_from(endc + "HH", data, 0x3A)
    else:
        (e_shoff,) = struct.unpack_from(endc + "I", data, 0x20)
        (e_shentsize, e_shnum) = struct.unpack_from(endc + "HH", data, 0x2E)
    return e_shoff, e_shentsize, e_shnum


def to_format_details(info: ElfInfo) -> dict[str, Any]:
    return {"elf": {"type": info.elf_type, "entry": info.entry,
                    "interpreter": info.interpreter, "linking": info.linking,
                    "sections": len(info.sections)}}
