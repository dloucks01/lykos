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
