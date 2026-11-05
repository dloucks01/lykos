"""Name libc functions in a STRIPPED STATIC binary by WHAT THEY DO, not what their bytes look like.

FLIRT (flirt.py) matches a stripped static binary's code against the host's libc.a. That works
when the target was linked against the same glibc build; across versions the bodies differ and
nothing matches. Measured on jhead-3.04 stripped (Debian gcc 16.2.0-1 / its glibc): of 786
functions FLIRT named one (sprintf), so `system`, `execve`, `open` and `read` stayed `fcn.*`. The
injection stage then had no command sink to probe, channel discovery saw no file API and fell back
to stdin, and a CVE the symbolized build exploits to L3 was missed entirely.

Two version-independent facts recover the names that matter:

  * a libc SYSCALL WRAPPER loads a fixed syscall number into eax and executes `syscall`. The
    number is the kernel ABI (x86-64: read=0, openat=257, execve=59, ...), identical in every
    glibc. A function whose every `syscall` uses one number in the table is that wrapper.
  * `system(NULL)` is defined to return whether a shell exists, and glibc implements it as
    `do_system("exit 0") == 0`, so `system` is the function that references the literal
    "exit 0" and calls the function that references "/bin/sh".

Names a function whose current name is generic (fcn./sub_/blank) -- or, on a binary with no
symbol table, any disassembler-guessed name that contradicts the evidence. Never overrides a real
symbol. x86-64 static ELF only.
The caller propagates names onto call edges exactly as flirt.relabel does. Deterministic, pure.
"""
from __future__ import annotations

import struct
from typing import Optional

#: x86-64 syscall number -> the libc API name its wrapper implements (security-relevant subset:
#: input sources, command/exec sinks, file and socket APIs the detectors and channel logic key on)
_X86_64 = {0: "read", 1: "write", 2: "open", 257: "open", 17: "pread", 19: "readv",
           20: "writev", 59: "execve", 322: "execveat", 45: "recvfrom", 47: "recvmsg",
           43: "accept", 288: "accept4", 49: "bind", 50: "listen", 41: "socket", 42: "connect",
           87: "unlink", 263: "unlinkat", 82: "rename", 264: "renameat", 316: "renameat2",
           90: "chmod", 268: "fchmodat", 92: "chown", 260: "fchownat", 105: "setuid",
           106: "setgid", 113: "setreuid", 114: "setregid", 117: "setresuid", 119: "setresgid",
           21: "access", 269: "faccessat", 4: "stat", 6: "lstat", 262: "fstatat",
           83: "mkdir", 258: "mkdirat", 88: "symlink", 266: "symlinkat", 86: "link",
           265: "linkat", 32: "dup", 33: "dup2", 292: "dup3", 22: "pipe", 293: "pipe2",
           57: "fork", 58: "vfork", 62: "kill", 161: "chroot", 80: "chdir"}

_GENERIC = ("fcn.", "sub_", "FUN_", "func_", "loc_")


def _is_generic(name) -> bool:
    return not name or str(name).startswith(_GENERIC)


def _int(a) -> Optional[int]:
    try:
        return int(str(a), 16) if str(a).lower().startswith("0x") else int(a)
    except (TypeError, ValueError):
        return None


class _Image:
    def __init__(self, data: bytes):
        self.data = data
        self.segs = []
        (phoff,) = struct.unpack_from("<Q", data, 32)
        (phentsize,) = struct.unpack_from("<H", data, 54)
        (phnum,) = struct.unpack_from("<H", data, 56)
        self.static = True
        self.has_symtab = self._has_symtab()
        for i in range(min(phnum, 256)):
            b = phoff + i * phentsize
            if b + 56 > len(data):
                break
            p_type = struct.unpack_from("<I", data, b)[0]
            if p_type == 3:                              # PT_INTERP -> dynamically linked
                self.static = False
            if p_type == 1:
                off, va = struct.unpack_from("<QQ", data, b + 8)
                filesz = struct.unpack_from("<Q", data, b + 32)[0]
                self.segs.append((va, off, filesz))

    def _has_symtab(self) -> bool:
        """A .symtab section (SHT_SYMTAB=2) means real names; without one every name is a guess."""
        d = self.data
        try:
            (shoff,) = struct.unpack_from("<Q", d, 40)
            (shentsize,) = struct.unpack_from("<H", d, 58)
            (shnum,) = struct.unpack_from("<H", d, 60)
            for i in range(min(shnum, 4096)):
                b = shoff + i * shentsize
                if b + 8 > len(d):
                    break
                if struct.unpack_from("<I", d, b + 4)[0] == 2:
                    return True
        except struct.error:
            pass
        return False

    def bytes_at(self, va: int, n: int) -> bytes:
        for sva, off, sz in self.segs:
            if sva <= va < sva + sz:
                o = off + (va - sva)
                return self.data[o:o + min(n, sva + sz - va)]
        return b""

    def va_of(self, needle: bytes) -> list:
        """Every VA where `needle` occurs as a NUL-terminated string."""
        out, start = [], 0
        while True:
            i = self.data.find(needle + b"\x00", start)
            if i < 0:
                return out
            if i == 0 or self.data[i - 1] == 0:          # starts a string, not a suffix of one
                for sva, off, sz in self.segs:
                    if off <= i < off + sz:
                        out.append(sva + (i - off))
            start = i + 1


def identify(target_bytes: bytes, funcs: list) -> dict:
    """{hex_va: name} for the generic-named functions of a stripped static x86-64 ELF that are a
    syscall wrapper in the table, plus `system`. {} for anything else (dynamic, other arch)."""
    data = target_bytes
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or \
            struct.unpack_from("<H", data, 18)[0] != 0x3E:
        return {}
    img = _Image(data)
    if not img.static:
        return {}
    try:
        import capstone as cs
    except Exception:                                    # noqa: BLE001
        return {}
    md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    md.detail = True
    eax_like = {"eax", "rax"}
    stripped = not img.has_symtab

    def renamable(cur, want) -> bool:
        """A generic name, or -- on a binary with NO symbol table, where every name is the
        disassembler's guess (rizin named execve 'readlink_15', measured) -- any name other than
        `want` itself. Never overrides a real symbol."""
        if _is_generic(cur):
            return True
        # with no symbol table, CANONICALISE even a near-miss guess: rizin's 'libc_system' is not
        # a name the sink catalog maps to `system`, so the call stayed invisible to the probes
        return stripped and str(cur) != want
    # A recovered size can run past the function into the next one (rizin gave `system` 1,245
    # bytes, swallowing the `rename` wrapper after it): clip every body at the next function start.
    starts = sorted(a for a in (_int(x.get("addr")) for x in funcs) if a is not None)
    nxt = {a: b for a, b in zip(starts, starts[1:])}
    named: dict = {}
    pushed: dict = {}                                    # func va -> (pushed imm, callee) if wrapper-shaped
    refs: dict = {}                                      # func va -> set(referenced VAs)
    calls: dict = {}                                     # func va -> set(callee VAs)
    for f in funcs:
        va = _int(f.get("addr"))
        size = f.get("size") or 0
        if va is None or not size or size > 4096:
            continue
        full = int(size)
        if va in nxt:                                    # syscall attribution: the clipped body
            size = min(full, nxt[va] - va)
        code = img.bytes_at(va, int(size))
        nums, last_eax, rset, cset = set(), None, set(), set()
        last_push = None
        push_calls = []
        for ins in md.disasm(code, va):
            m = ins.mnemonic
            if m == "push" and ins.operands and ins.operands[0].type == cs.CS_OP_IMM:
                last_push = ins.operands[0].imm
            elif m == "call" and ins.operands and ins.operands[0].type == cs.CS_OP_IMM \
                    and last_push is not None:
                push_calls.append((last_push, ins.operands[0].imm))
                last_push = None
            if m == "syscall":
                nums.add(last_eax)
            elif m in ("mov", "movl") and len(ins.operands) == 2:
                d, s = ins.operands
                if d.type == cs.CS_OP_REG and ins.reg_name(d.reg) in eax_like:
                    last_eax = s.imm if s.type == cs.CS_OP_IMM else None
            elif m == "xor" and len(ins.operands) == 2 and \
                    all(o.type == cs.CS_OP_REG and ins.reg_name(o.reg) in eax_like
                        for o in ins.operands):
                last_eax = 0
        # references and calls over the disassembler's FULL extent: a split at a branch target
        # (rizin started a "function" at system's `je` target) must not hide the string load
        for ins in md.disasm(img.bytes_at(va, full), va):
            m = ins.mnemonic
            if m in ("call", "jmp") and ins.operands and ins.operands[0].type == cs.CS_OP_IMM:
                cset.add(ins.operands[0].imm)
            if m == "lea" and len(ins.operands) == 2 and ins.operands[1].type == cs.CS_OP_MEM:
                mem = ins.operands[1].mem
                if ins.reg_name(mem.base) == "rip":
                    rset.add(ins.address + ins.size + mem.disp)
            elif m == "mov" and len(ins.operands) == 2 and ins.operands[1].type == cs.CS_OP_IMM:
                rset.add(ins.operands[1].imm)            # mov $string_va (non-PIE)
        refs[va], calls[va] = rset, cset
        if size <= 96 and len(push_calls) == 1 and not nums:
            pushed[va] = push_calls[0]
        if not nums or None in nums or len(nums) != 1:
            continue
        name = _X86_64.get(next(iter(nums)))
        if name and renamable(f.get("name"), name):
            named[hex(va)] = name
    # CANCELLABLE wrappers (glibc >= 2.41): `push $NR; call __syscall_cancel` -- the number is the
    # pushed 7th argument. The shared callee is recognised as the one >=3 small wrappers call with
    # DISTINCT pushed numbers, so an ordinary `push imm; call f` is not mistaken for a wrapper.
    by_callee: dict = {}
    for va, (imm, callee) in pushed.items():
        by_callee.setdefault(callee, {})[va] = imm
    fname = {_int(x.get("addr")): x.get("name") for x in funcs}
    for callee, wrappers in by_callee.items():
        if len(set(wrappers.values())) < 3:
            continue
        for va, imm in wrappers.items():
            name = _X86_64.get(imm)
            if name and renamable(fname.get(va), name):
                named[hex(va)] = name
    # system: references "exit 0" and calls the function that references "/bin/sh"
    exit0 = set(img.va_of(b"exit 0"))
    binsh = set(img.va_of(b"/bin/sh"))
    if exit0 and binsh:
        shellers = {va for va, r in refs.items() if r & binsh}

        def _refs_binsh(target_va) -> bool:
            """A callee the disassembler never isolated as a function (glibc's static do_system):
            read its code directly for the "/bin/sh" reference."""
            # scan to the next known function start (an early `ret` is not the end of a body)
            import bisect
            j = bisect.bisect_right(starts, target_va)
            span = min(4096, (starts[j] - target_va) if j < len(starts) else 4096)
            for ins in md.disasm(img.bytes_at(target_va, span), target_va):
                for op in ins.operands:
                    if op.type == cs.CS_OP_MEM and ins.reg_name(op.mem.base) == "rip" and \
                            ins.address + ins.size + op.mem.disp in binsh:
                        return True
                    if op.type == cs.CS_OP_IMM and op.imm in binsh:
                        return True
            return False
        for va, r in refs.items():
            cl = calls.get(va, set())
            if r & exit0 and (cl & shellers or va in shellers
                              or any(_refs_binsh(c) for c in cl if c not in refs)):
                f = next((x for x in funcs if _int(x.get("addr")) == va), None)
                if f is not None and renamable(f.get("name"), "system"):
                    named[hex(va)] = "system"
    return named


def relabel(target_bytes: bytes, funcs: list) -> int:
    """Apply `identify` to `funcs` (in place) and to their call edges' dst_name. Returns how many
    names were applied. Never overwrites a non-generic name (FLIRT's or a real symbol)."""
    named = identify(target_bytes, funcs)               # already applies the override rule
    if not named:
        return 0
    applied = 0
    for f in funcs:
        hx = hex(_int(f.get("addr"))) if _int(f.get("addr")) is not None else None
        if hx in named and f.get("name") != named[hx]:
            f["name"] = named[hx]
            applied += 1
        for c in f.get("calls", []) or []:
            d = _int(c.get("dst_addr"))
            if d is not None and hex(d) in named and c.get("dst_name") != named[hex(d)]:
                c["dst_name"] = named[hex(d)]
                applied += 1
    return applied
