"""One-gadget search: locate libc addresses that execve("/bin/sh", ...) in a single jump, found by
byte pattern (lea rdi -> "/bin/sh" followed by an execve call/syscall) without the external
one_gadget tool. Used as a fallback redirect in the leak-based ret2libc when a clean
pop-rdi+system pairing is unavailable, and on older glibc where one-gadgets are common."""
from __future__ import annotations

import struct

from lykos.analyze.poc import rop


def _seg_with_gadget(base_va=0x1000, binsh_at=32, zero_regs=True):
    """A synthetic executable segment: `lea rdi,[rip->/bin/sh]` (+ optional xor esi/edx) + an
    execve syscall (mov eax,0x3b; syscall), and "/bin/sh\\0" at `binsh_at`."""
    disp = binsh_at - 7                                   # lea is 7 bytes; rip points past it
    code = b"\x48\x8d\x3d" + struct.pack("<i", disp)      # lea rdi, [rip+disp]
    if zero_regs:
        code += b"\x31\xf6\x31\xd2"                        # xor esi,esi ; xor edx,edx
    code += b"\xb8\x3b\x00\x00\x00\x0f\x05"               # mov eax,0x3b ; syscall
    seg = bytearray(b"\x90" * max(binsh_at, len(code)) + b"/bin/sh\x00")
    seg[:len(code)] = code
    seg[binsh_at:binsh_at + 8] = b"/bin/sh\x00"
    return bytes(seg), base_va


def _run_finder(monkeypatch, seg, base_va):
    monkeypatch.setattr(rop, "_loads", lambda data: [(0, len(seg), base_va, 1)])
    return rop.find_one_gadgets(seg)


def test_finds_execve_syscall_gadget_no_constraint(monkeypatch):
    seg, base = _seg_with_gadget(zero_regs=True)
    gs = _run_finder(monkeypatch, seg, base)
    assert len(gs) == 1
    assert gs[0]["offset"] == base                        # the lea itself is the one-gadget entry
    assert gs[0]["constraint"] == "none (rsi/rdx zeroed inline)"


def test_records_constraint_when_regs_not_zeroed(monkeypatch):
    seg, base = _seg_with_gadget(zero_regs=False)
    gs = _run_finder(monkeypatch, seg, base)
    assert len(gs) == 1 and gs[0]["constraint"] == "rsi==NULL && rdx==NULL"


def test_no_gadget_when_lea_does_not_reach_binsh(monkeypatch):
    # a lea that points somewhere other than "/bin/sh" must not be reported
    seg = bytearray(b"\x48\x8d\x3d\x00\x00\x00\x00" + b"\xb8\x3b\x00\x00\x00\x0f\x05"
                    + b"\x90" * 16 + b"/bin/sh\x00")
    monkeypatch.setattr(rop, "_loads", lambda data: [(0, len(seg), 0x1000, 1)])
    assert rop.find_one_gadgets(bytes(seg)) == []


def test_no_gadget_without_execve_follow(monkeypatch):
    # lea rdi -> /bin/sh but no execve call/syscall in the window -> not a one-gadget
    disp = 32 - 7
    seg = bytearray(b"\x90" * 40 + b"/bin/sh\x00")
    seg[:7] = b"\x48\x8d\x3d" + struct.pack("<i", disp)
    seg[32:40] = b"/bin/sh\x00"
    monkeypatch.setattr(rop, "_loads", lambda data: [(0, len(seg), 0x1000, 1)])
    assert rop.find_one_gadgets(bytes(seg)) == []
