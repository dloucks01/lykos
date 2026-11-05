"""IFUNC resolution for x86-64 and aarch64 ELF images: what the loader (or a static binary's
startup) does with IRELATIVE relocations, done once, offline, so an emulator or a symbolic
executor sees the GOT the real process would see.

In a statically linked glibc binary every string/memory routine (memcpy, strlen, strchr, ...)
is an IFUNC: callers jump through a `.plt` slot whose GOT entry the startup fills by CALLING a
resolver that picks an implementation for the CPU. Nothing in lykos ran those resolvers, so every
such call jumped to whatever the slot held on disk -- usually 0. Measured: static jhead-3.04 sent
113,738 angr states to 0x0, and the emulated harness "faulted" on the first memcpy.

`resolve` runs each resolver under unicorn with the CPU-feature block zeroed, which makes glibc
pick its baseline (SSE2) implementation -- a correct implementation of the routine, just not the
fastest one. `ifunc_names` recovers the routine NAME behind each resolver from the symbol table,
so a consumer that models libc by name (the harness's libc stubs, a SimProcedure) can use that
instead of executing the implementation.

All addresses are LINK-TIME virtual addresses (0-based for a PIE).
"""
from __future__ import annotations

import struct
from collections import OrderedDict
from typing import Optional

_R_IRELATIVE = {"x86-64": 37, "aarch64": 1032}
_EM = {62: "x86-64", 183: "aarch64"}
_SHT_SYMTAB, _SHT_RELA = 2, 4
_STT_GNU_IFUNC = 10
_PAGE = 0x1000
_PIE_BASE = 0x555555554000            # where a PIE is mapped while its resolvers run
_STACK_TOP = 0x7FF000000000
_STACK_SZ = 0x40000
_TLS = 0x7FE000000000
_SENTINEL = 0x7FD000000000
_MAX_INSNS = 200_000                  # a glibc resolver is a few dozen instructions
_CACHE: "OrderedDict" = OrderedDict()


def _machine(data: bytes):
    """'x86-64' / 'aarch64' for a little-endian ELF64 image, else None."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return None
    return _EM.get(struct.unpack_from("<H", data, 18)[0])


def _is_x86_64_elf(data: bytes) -> bool:
    """A supported image (the name predates aarch64 support)."""
    return _machine(data) is not None


def _sections(data: bytes) -> list:
    """[(sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize)] -- [] without headers."""
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    if not shoff or shentsize < 64 or shoff + shnum * shentsize > len(data):
        return []
    out = []
    for i in range(min(shnum, 4096)):
        o = shoff + i * shentsize
        _nm, typ, _fl, addr, off, size, link, _info, _al, ent = struct.unpack_from(
            "<IIQQQQIIQQ", data, o)
        out.append((typ, addr, off, size, link, ent))
    return out


def _loads(data: bytes) -> list:
    """[(p_vaddr, p_offset, p_filesz, p_memsz, p_flags)] for every PT_LOAD."""
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(min(phnum, 256)):
        o = phoff + i * phentsize
        if o + 56 > len(data):
            break
        p_type, p_flags = struct.unpack_from("<II", data, o)
        if p_type == 1:
            off, va, _pa, fs, ms = struct.unpack_from("<QQQQQ", data, o + 8)
            out.append((va, off, fs, ms, p_flags))
    return out


def irelative_relocs(data: bytes) -> list:
    """[(slot_va, resolver_va)] for every R_X86_64_IRELATIVE relocation, from the RELA sections
    (a static binary has no PT_DYNAMIC: its `.rela.plt` is found through the section headers),
    falling back to the dynamic tables when the section headers are gone."""
    machine = _machine(data)
    if machine is None:
        return []
    irel = _R_IRELATIVE[machine]
    found: dict = {}

    def scan(off: int, size: int) -> None:
        for k in range(0, max(0, min(size, len(data) - off)) - 23, 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", data, off + k)
            if r_info & 0xFFFFFFFF == irel and r_add > 0:
                found.setdefault(r_off, r_add)

    secs = _sections(data)
    for typ, _addr, off, size, _link, ent in secs:
        if typ == _SHT_RELA and ent == 24:
            scan(off, size)
    if not secs:
        loads = _loads(data)
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
        for i in range(min(phnum, 256)):
            o = phoff + i * phentsize
            if struct.unpack_from("<I", data, o)[0] != 2:          # PT_DYNAMIC
                continue
            doff, _va, _pa, dsz = struct.unpack_from("<QQQQ", data, o + 8)
            tags: dict = {}
            for k in range(0, max(0, min(dsz, len(data) - doff) - 15), 16):
                t, v = struct.unpack_from("<qQ", data, doff + k)
                if t == 0:
                    break
                tags.setdefault(t, v)
            for va_tag, sz_tag in ((7, 8), (23, 2)):               # DT_RELA, DT_JMPREL
                va, sz = tags.get(va_tag), tags.get(sz_tag, 0)
                fo = next((fo + (va - v) for v, fo, fs, _m, _f in loads
                           if va is not None and v <= va < v + fs), None)
                if fo is not None:
                    scan(fo, sz)
    return sorted(found.items())


def ifunc_names(data: bytes) -> dict:
    """{resolver_va: routine name} from the static symbol table's STT_GNU_IFUNC symbols. Several
    aliases share a resolver (memcpy / __memcpy / memmove ...); the public name -- fewest leading
    underscores, then shortest -- wins. {} for a stripped image."""
    if not _is_x86_64_elf(data):
        return {}
    secs = _sections(data)
    best: dict = {}
    for typ, _addr, off, size, link, ent in secs:
        if typ != _SHT_SYMTAB or ent != 24 or link >= len(secs):
            continue
        stroff = secs[link][2]
        for k in range(0, min(size, len(data) - off) - 23, 24):
            st_name, st_info = struct.unpack_from("<IB", data, off + k)
            value = struct.unpack_from("<Q", data, off + k + 8)[0]
            if st_info & 0xF != _STT_GNU_IFUNC or not value or not st_name:
                continue
            a = stroff + st_name
            nm = data[a:data.find(b"\x00", a)].decode("latin-1", "ignore")
            if not nm:
                continue
            key = (len(nm) - len(nm.lstrip("_")), len(nm), nm)
            cur = best.get(value)
            if cur is None or key < cur[0]:
                best[value] = (key, nm)
    return {v: k[1] for v, k in best.items()}


def resolve(data: bytes) -> dict:
    """{slot_va: implementation_va}: run every IRELATIVE resolver once under unicorn (CPU-feature
    block zeroed -> glibc's baseline implementation) and keep each result that lands in an
    executable segment. A resolver that faults or runs away is simply left out. Cached per image."""
    key = id(data)
    hit = _CACHE.get(key)
    if hit is not None and hit[0] is data:
        return hit[1]
    out = _resolve(data)
    _CACHE[key] = (data, out)
    while len(_CACHE) > 8:
        _CACHE.popitem(last=False)
    return out


def _resolve(data: bytes) -> dict:
    relocs = irelative_relocs(data)
    if not relocs:
        return {}
    machine = _machine(data)
    try:
        from unicorn import UC_PROT_ALL, Uc, UcError
        if machine == "x86-64":
            from unicorn import UC_ARCH_X86, UC_MODE_64
            from unicorn import x86_const as c
            uc_args = (UC_ARCH_X86, UC_MODE_64)
            SP, RET, ARGS = c.UC_X86_REG_RSP, c.UC_X86_REG_RAX, (c.UC_X86_REG_RDI, c.UC_X86_REG_RSI)
            TLS_REG, LR = c.UC_X86_REG_FS_BASE, None
        else:
            from unicorn import UC_ARCH_ARM64, UC_MODE_ARM
            from unicorn import arm64_const as c
            uc_args = (UC_ARCH_ARM64, UC_MODE_ARM)
            SP, RET, ARGS = c.UC_ARM64_REG_SP, c.UC_ARM64_REG_X0, (c.UC_ARM64_REG_X0,
                                                                c.UC_ARM64_REG_X1)
            TLS_REG, LR = c.UC_ARM64_REG_TPIDR_EL0, c.UC_ARM64_REG_X30
    except Exception:                                      # noqa: BLE001 -- no unicorn: nothing resolved
        return {}
    e_type = struct.unpack_from("<H", data, 0x10)[0]
    base = _PIE_BASE if e_type == 3 else 0
    loads = _loads(data)
    exec_spans = [(v, v + ms) for v, _o, _fs, ms, fl in loads if fl & 1]
    uc = Uc(*uc_args)
    try:
        if machine == "aarch64":
            try:
                uc.reg_write(c.UC_ARM64_REG_CPACR_EL1, 0x300000)
            except Exception:                              # noqa: BLE001
                pass
        mapped: list = []
        for v, off, fs, ms, _fl in loads:
            lo = (base + v) & ~(_PAGE - 1)
            hi = (base + v + max(ms, fs) + _PAGE - 1) & ~(_PAGE - 1)
            for a_, b_ in mapped:                           # never double-map a shared page
                if lo < b_ and hi > a_:
                    lo = max(lo, b_) if lo >= a_ else lo
                    hi = min(hi, a_) if hi <= b_ else hi
            if hi > lo:
                uc.mem_map(lo, hi - lo, UC_PROT_ALL)
                mapped.append((lo, hi))
            if fs:
                uc.mem_write(base + v, data[off:off + fs])
        uc.mem_map(_STACK_TOP - _STACK_SZ, _STACK_SZ, UC_PROT_ALL)
        uc.mem_map(_TLS - _PAGE, 2 * _PAGE, UC_PROT_ALL)
        uc.mem_map(_SENTINEL, _PAGE, UC_PROT_ALL)
        uc.reg_write(TLS_REG, _TLS)
        out: dict = {}
        for slot, res in relocs:
            sp = _STACK_TOP - 0x1000
            if LR is None:
                uc.mem_write(sp, struct.pack("<Q", _SENTINEL))
            else:
                uc.reg_write(LR, _SENTINEL)
            uc.reg_write(SP, sp)
            uc.reg_write(RET, 0)
            for r in ARGS:                                  # hwcap / cpu-feature arguments: none
                uc.reg_write(r, 0)
            try:
                uc.emu_start(base + res, _SENTINEL, count=_MAX_INSNS)
            except UcError:
                continue
            impl = (uc.reg_read(RET) - base) & 0xFFFFFFFFFFFFFFFF
            if any(lo <= impl < hi for lo, hi in exec_spans):
                out[slot] = impl
        return out
    except Exception:                                      # noqa: BLE001 -- best-effort, never fatal
        return {}
    finally:
        try:
            uc.emu_stop()
        except Exception:                                  # noqa: BLE001
            pass
        del uc


def slot_names(data: bytes) -> dict:
    """{slot_va: routine name} for the slots whose resolver the symbol table names."""
    names = ifunc_names(data)
    return {slot: names[res] for slot, res in irelative_relocs(data) if res in names}


def is_static(data: bytes) -> bool:
    """No PT_INTERP: nothing loads a libc beside it (static, or static-PIE)."""
    if not _is_x86_64_elf(data):
        return False
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(min(phnum, 256)):
        o = phoff + i * phentsize
        if o + 4 <= len(data) and struct.unpack_from("<I", data, o)[0] == 3:
            return False
    return True


def func_symbols(data: bytes, wanted) -> dict:
    """{va: name} for FUNC symbols in .symtab whose name is in `wanted` (a static binary's own
    malloc/free/... the harness models by name)."""
    if not _is_x86_64_elf(data):
        return {}
    secs = _sections(data)
    out: dict = {}
    for typ, _addr, off, size, link, ent in secs:
        if typ != _SHT_SYMTAB or ent != 24 or link >= len(secs):
            continue
        stroff = secs[link][2]
        for k in range(0, min(size, len(data) - off) - 23, 24):
            st_name, st_info = struct.unpack_from("<IB", data, off + k)
            shndx = struct.unpack_from("<H", data, off + k + 6)[0]
            value = struct.unpack_from("<Q", data, off + k + 8)[0]
            if st_info & 0xF != 2 or not value or not shndx or not st_name:
                continue
            a = stroff + st_name
            nm = data[a:data.find(b"\x00", a)].decode("latin-1", "ignore")
            if nm in wanted:
                out.setdefault(value, nm)
    return out


def summary(data: bytes) -> Optional[dict]:
    """Counts for an operator note: slots, resolved, named. None when the image has no IFUNCs."""
    relocs = irelative_relocs(data)
    if not relocs:
        return None
    return {"slots": len(relocs), "resolved": len(resolve(data)), "named": len(slot_names(data))}
