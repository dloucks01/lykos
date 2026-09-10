"""Minimal ELF symbol reader for cross-arch breakpoint resolution (pure stdlib).

Returns STT_FUNC symbols (name -> vaddr) from .symtab, the entry point, and whether the file is
PIE (ET_DYN). Breakpoints are then placed at `sym_vaddr + (runtime_entry - e_entry)`, where
runtime_entry comes from the qemu gdbstub -- both live in the same ELF vaddr space, so the delta
is consistent regardless of the emulator's load base. Handles ELF32/64 and both byte orders.
"""
from __future__ import annotations

import struct


def read(path) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        return {"symbols": {}, "entry": None, "pie": False}
    is64 = data[4] == 2
    le = data[5] == 1
    en = "<" if le else ">"

    if is64:
        e_type, _mach, _v, e_entry, _ph, e_shoff = struct.unpack_from(en + "HHIQQQ", data, 16)
        _fl, _ehs, _phes, _phn, shentsize, shnum, shstrndx = \
            struct.unpack_from(en + "IHHHHHH", data, 16 + 2 + 2 + 4 + 8 + 8 + 8)
    else:
        e_type, _mach, _v, e_entry, _ph, e_shoff = struct.unpack_from(en + "HHIIII", data, 16)
        _fl, _ehs, _phes, _phn, shentsize, shnum, shstrndx = \
            struct.unpack_from(en + "IHHHHHH", data, 16 + 2 + 2 + 4 + 4 + 4 + 4)

    def sh(i):
        off = e_shoff + i * shentsize
        if is64:
            name, typ, _fl, _ad, offset, size, link, _inf, _al, entsz = \
                struct.unpack_from(en + "IIQQQQIIQQ", data, off)
        else:
            name, typ, _fl, _ad, offset, size, link, _inf, _al, entsz = \
                struct.unpack_from(en + "IIIIIIIIII", data, off)
        return {"name": name, "type": typ, "offset": offset, "size": size,
                "link": link, "entsize": entsz}

    secs = [sh(i) for i in range(shnum)] if e_shoff and shnum else []
    symtab = next((s for s in secs if s["type"] == 2), None)          # SHT_SYMTAB
    symbols = {}
    if symtab and symtab["entsize"]:
        strt = secs[symtab["link"]] if symtab["link"] < len(secs) else None
        stroff = strt["offset"] if strt else 0

        def name_at(idx):
            end = data.find(b"\x00", stroff + idx)
            return data[stroff + idx:end].decode("latin-1", "ignore")

        n = symtab["size"] // symtab["entsize"]
        for i in range(n):
            off = symtab["offset"] + i * symtab["entsize"]
            if is64:
                st_name, st_info, _o, _shndx, st_value, _sz = \
                    struct.unpack_from(en + "IBBHQQ", data, off)
            else:
                st_name, st_value, _sz, st_info, _o, _shndx = \
                    struct.unpack_from(en + "IIIBBH", data, off)
            if (st_info & 0xF) == 2 and st_value:                     # STT_FUNC, defined
                nm = name_at(st_name)
                if nm and nm not in symbols:
                    symbols[nm] = st_value
    return {"symbols": symbols, "entry": e_entry, "pie": e_type == 3}   # ET_DYN == 3
