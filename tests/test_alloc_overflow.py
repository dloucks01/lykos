"""Allocation-size integer-overflow detector (CWE-190 -> CWE-787): a wire-derived product/sum used
as an alloc/copy size with no overflow guard. Precision-first -- must stay silent on guarded math."""
from lykos.analyze.alloc_overflow import find_alloc_overflows


def test_fires_on_unguarded_wire_product():
    src = ("int f(wStream* s){ UINT32 w,h; Stream_Read_UINT32(s,w); Stream_Read_UINT32(s,h);"
           " char* p = malloc(w * h); return 0; }")
    hits = find_alloc_overflows(src)
    assert any(h["kind"] == "malloc" for h in hits)


def test_silent_on_division_guard():
    src = ("int f(wStream* s){ UINT32 w,h; Stream_Read_UINT32(s,w); Stream_Read_UINT32(s,h);"
           " if (w > UINT32_MAX / h) return -1; char* p = malloc(w * h); return 0; }")
    assert find_alloc_overflows(src) == []


def test_silent_on_64bit_widening():
    src = ("int f(wStream* s){ UINT32 w,h; Stream_Read_UINT32(s,w); Stream_Read_UINT32(s,h);"
           " char* p = malloc(1ull * w * h); return 0; }")
    assert find_alloc_overflows(src) == []


def test_silent_on_calloc():
    # calloc is overflow-checked by the runtime -> never flagged (it's not in the alloc set).
    src = ("int f(wStream* s){ UINT32 w,h; Stream_Read_UINT32(s,w); Stream_Read_UINT32(s,h);"
           " char* p = calloc(w, h); return 0; }")
    assert find_alloc_overflows(src) == []


def test_silent_on_single_var_size():
    # a single read value (no product/sum) is guard_gap's job, not this one.
    src = ("int f(wStream* s){ UINT32 n; Stream_Read_UINT32(s,n); char* p = malloc(n); return 0; }")
    assert find_alloc_overflows(src) == []


def test_silent_on_16bit_product_that_cannot_wrap_32_bits():
    # 0xFFFF * 0xFFFF = 0xFFFE0001 < 2^32: two UINT16 wire values cannot wrap a 32-bit product.
    src = ("int f(wStream* s){ UINT16 w,h; Stream_Read_UINT16(s,w); Stream_Read_UINT16(s,h);"
           " char* p = malloc(w * h); return 0; }")
    assert find_alloc_overflows(src) == []


def test_fires_when_16bit_product_is_scaled_past_32_bits():
    # 0xFFFF * 0xFFFF * 4 ~ 2^34: CAN wrap.
    src = ("int f(wStream* s){ UINT16 w,h; Stream_Read_UINT16(s,w); Stream_Read_UINT16(s,h);"
           " char* p = malloc(w * h * 4); return 0; }")
    assert any(h["kind"] == "malloc" for h in find_alloc_overflows(src))
    src2 = src.replace("w * h * 4", "w * h * sizeof(UINT32)")
    assert any(h["kind"] == "malloc" for h in find_alloc_overflows(src2))
    src3 = src.replace("w * h * 4", "w * h * bpp")          # unknown operand: full-width assumption
    assert any(h["kind"] == "malloc" for h in find_alloc_overflows(src3))


def test_silent_on_small_widths_sum():
    src = ("int f(wStream* s){ UINT8 a; UINT16 b; Stream_Read_UINT8(s,a); Stream_Read_UINT16(s,b);"
           " char* p = malloc(a * b + 16); return 0; }")
    assert find_alloc_overflows(src) == []


def test_reads_after_the_allocation_do_not_count():
    # w/h are read AFTER the malloc -> they cannot be its size; the size math is not wire-derived.
    src = ("int f(wStream* s, UINT32 w, UINT32 h){ char* p = malloc(w * h);"
           " Stream_Read_UINT32(s,w); Stream_Read_UINT32(s,h); return 0; }")
    assert find_alloc_overflows(src) == []


def test_mixed_width_uses_the_widest_preceding_read():
    src = ("int f(wStream* s){ UINT32 w; UINT16 h; Stream_Read_UINT32(s,w); Stream_Read_UINT16(s,h);"
           " char* p = malloc(w * h); return 0; }")
    assert any(h["kind"] == "malloc" for h in find_alloc_overflows(src))
