"""Small, pure ELF facts the non-executed recipes need and the existing helpers do not expose:
section VADDRs, PIE-ness, the PLT stub address of an import (without objdump), and a C string at a
virtual address. Stdlib-only, best-effort: every function returns an empty/None answer on a
malformed image rather than raising."""
from __future__ import annotations

import functools
import struct


@functools.lru_cache(maxsize=32)
def sections(data: bytes) -> dict:
    """{name: {"addr", "offset", "size", "flags"}}; {} when the header table is absent/malformed."""
    try:
        if data[:4] != b"\x7fELF":
            return {}
        is64 = data[4] == 2
        endc = "<" if data[5] == 1 else ">"
        if is64:
            e_shoff = struct.unpack_from(endc + "Q", data, 0x28)[0]
            she, shn, shx = struct.unpack_from(endc + "HHH", data, 0x3A)
            fmt = endc + "IIQQQQIIQQ"
        else:
            e_shoff = struct.unpack_from(endc + "I", data, 0x20)[0]
            she, shn, shx = struct.unpack_from(endc + "HHH", data, 0x2E)
            fmt = endc + "IIIIIIIIII"
        if not e_shoff or not shn:
            return {}
        shs = [struct.unpack_from(fmt, data, e_shoff + i * she) for i in range(shn)]
        so = shs[shx][4]
        out = {}
        for sh in shs:
            end = data.find(b"\x00", so + sh[0])
            name = data[so + sh[0]:end].decode("latin-1", "replace")
            if name and name not in out:
                out[name] = {"addr": sh[3], "offset": sh[4], "size": sh[5], "flags": sh[2]}
        return out
    except Exception:                                    # noqa: BLE001 -- best-effort facts
        return {}


def is_pie(data: bytes) -> bool:
    """ET_DYN with an interpreter / a zero-based image: a position-independent executable (or a
    shared object). Addresses read from the image are then OFFSETS from a runtime base."""
    try:
        endc = "<" if data[5] == 1 else ">"
        return struct.unpack_from(endc + "H", data, 0x10)[0] == 3
    except Exception:                                    # noqa: BLE001
        return False


def vaddr_to_offset(data: bytes, vaddr: int):
    for s in sections(data).values():
        if s["addr"] and s["addr"] <= vaddr < s["addr"] + s["size"]:
            return s["offset"] + (vaddr - s["addr"])
    return None


def cstring_at(data: bytes, vaddr: int, limit: int = 512):
    """The NUL-terminated bytes at `vaddr` (without the NUL), or None."""
    off = vaddr_to_offset(data, vaddr)
    if off is None or off >= len(data):
        return None
    end = data.find(b"\x00", off, off + limit)
    return data[off:end] if end != -1 else None


@functools.lru_cache(maxsize=32)
def plt_stubs(data: bytes) -> dict:
    """{import name: PLT stub vaddr} for x86-64 / i386, read from the stub BYTES: every
    `jmp qword [rip+disp32]` (ff 25) in .plt.sec / .plt / .plt.got whose computed target is a GOT
    slot named by .rela.plt. The stub's entry is the 16-byte-aligned start of its slot (an IBT
    `endbr64` / `bnd` prefix sits before the jmp). No objdump needed -- an air-gapped bundle
    without binutils still gets the address of `system@plt`."""
    from . import rop
    try:
        got = {v: k for k, v in rop.got_entries(data).items()}
    except Exception:                                    # noqa: BLE001
        got = {}
    if not got:
        return {}
    is64 = data[4] == 2
    endc = "<" if data[5] == 1 else ">"
    secs = sections(data)
    out: dict = {}
    for sname in (".plt.sec", ".plt", ".plt.got"):
        s = secs.get(sname)
        if not s or not s["size"]:
            continue
        blob = data[s["offset"]:s["offset"] + s["size"]]
        i = 0
        while True:
            i = blob.find(b"\xff\x25", i)
            if i < 0 or i + 6 > len(blob):
                break
            disp = struct.unpack_from(endc + "i", blob, i + 2)[0]
            insn = s["addr"] + i
            # x86-64: rip-relative (next insn + disp); i386 non-PIC: absolute disp32
            slot = (insn + 6 + disp) if is64 else (disp & 0xFFFFFFFF)
            name = got.get(slot)
            if name and name not in out:
                out[name] = insn & ~0xF
            i += 2
    return out


def plt_callees(data: bytes, func_vaddr: int, *, window: int = 0x400) -> set:
    """Import names the function at `func_vaddr` calls via the PLT, read from its bytes: every
    `call rel32` (e8) in a bounded window whose target is a known PLT stub. Used to avoid aiming a
    GOT overwrite at a slot the chosen WIN itself calls -- that would make the win recurse through
    the hijacked pointer instead of running. Best-effort ({} knowledge -> empty set)."""
    import struct as _s
    stubs = {a: n for n, a in plt_stubs(data).items()}
    foff = vaddr_to_offset(data, func_vaddr)
    if foff is None or not stubs:
        return set()
    # Bound the scan at the next function symbol (a tiny win that ends in a `call _exit` has no
    # `ret`, so an unbounded scan would collect its NEIGHBOURS' callees and over-exclude).
    try:
        from . import exploit
        nxt = min((a for a in exploit.elf_functions(data).values() if a > func_vaddr),
                  default=func_vaddr + window)
        window = min(window, max(5, nxt - func_vaddr))
    except Exception:                                    # noqa: BLE001 -- the ret/window bound still applies
        pass
    out, i, end = set(), foff, min(len(data) - 5, foff + window)
    while i <= end:
        if data[i] == 0xE8:
            rel = _s.unpack_from("<i", data, i + 1)[0]
            tgt = (func_vaddr + (i - foff) + 5 + rel) & 0xFFFFFFFFFFFFFFFF
            if tgt in stubs:
                out.add(stubs[tgt])
            i += 5
            continue
        if data[i] == 0xC3:                               # ret -- end of the function (bounded)
            break
        i += 1
    return out
