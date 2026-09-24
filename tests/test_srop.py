"""SROP (sigreturn-oriented programming) synthesis primitives for static/no-PIE x86-64."""
import struct

from lykos.analyze.poc import rop


def test_sigreturn_frame_amd64_layout():
    f = rop.sigreturn_frame(rip=0xdeadbeef, rax=59, rdi=0x1234, rsi=0, rdx=0, rsp=0x7fff)
    assert len(f) == 248
    at = lambda o: struct.unpack_from("<Q", f, o)[0]
    assert at(0x68) == 0x1234       # rdi
    assert at(0x90) == 59           # rax
    assert at(0xA0) == 0x7fff       # rsp
    assert at(0xA8) == 0xdeadbeef   # rip
    assert at(0xB8) == 0x33         # csgsfs (cs=0x33 for 64-bit user)


def test_build_srop_execve_structure():
    # cyclic(offset) then pop_rax, 15, syscall, then the 248-byte frame.
    payload = rop.build_srop_execve(40, syscall=0x401014, binsh=0x404000, length=512,
                                    pop_rax=0x401234, rsp=0x404200)
    assert len(payload) >= 40 + 24 + 248
    at = lambda o: struct.unpack_from("<Q", payload, o)[0]
    assert at(40) == 0x401234       # pop rax ; ret
    assert at(48) == 15             # rt_sigreturn number
    assert at(56) == 0x401014       # syscall gadget
    frame = payload[64:64 + 248]
    assert struct.unpack_from("<Q", frame, 0x90)[0] == 59        # rax=execve
    assert struct.unpack_from("<Q", frame, 0x68)[0] == 0x404000  # rdi=&"/bin/sh"


def test_srop_feasible_reports_pieces():
    # a syscall;ret gadget with no pop-rax / writable / binsh -> feasible shape, missing pieces
    blob = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
    feo = rop.srop_feasible(blob)
    assert set(feo) == {"syscall", "pop_rax", "writable", "binsh"}
