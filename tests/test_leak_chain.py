"""Leak->corruption chain primitives (canary-preserving overflow)."""
import struct

from lykos.analyze.poc import exploit


def test_build_canary_overflow_writes_canary_back_then_redirects():
    canary = 0x1122334455667700          # low byte 00 as real canaries have
    p = exploit.build_canary_overflow(40, canary, 0x401234, 512)
    # filler(40) then the canary verbatim, then saved rbp(word), then the return target
    assert struct.unpack_from("<Q", p, 40)[0] == canary
    assert struct.unpack_from("<Q", p, 56)[0] == 0x401234   # 40 + 8(canary) + 8(rbp) = 56
    assert len(p) == 512


def test_build_canary_overflow_custom_ret_gap():
    p = exploit.build_canary_overflow(24, 0xdeadbeefcafe0000, 0x400abc, 256, ret_gap=24)
    assert struct.unpack_from("<Q", p, 24)[0] == 0xdeadbeefcafe0000
    # 24 filler + 8 canary + 24 gap = 56 -> return target
    assert struct.unpack_from("<Q", p, 56)[0] == 0x400abc
