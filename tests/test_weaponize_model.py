"""Weaponization feasibility model (analyze/weaponize_model.py) — capability #6.

Encodes the engagement's hard-won lessons: an mmap-resident buffer is not heap-groomable, and a
linear memset-style overflow is a weak RCE primitive. Lets the weaponizer triage up front.
"""
from __future__ import annotations
from lykos.analyze import weaponize_model as W


def test_large_buffer_is_mmap_and_not_groomable():
    p = W.allocator_placement(8 * 1024 * 1024)       # ~ClearCodec TempBuffer
    assert p.region == "mmap" and p.groomable is False


def test_small_default_aligned_buffer_is_heap_and_groomable():
    p = W.allocator_placement(96, alignment=16)      # audin SoundFormats-sized
    assert p.region == "heap" and p.groomable is True


def test_over_aligned_large_buffer_is_not_groomable():
    p = W.allocator_placement(64 * 1024, alignment=32)   # winpr_aligned_recalloc shape
    assert p.region == "mmap" and p.groomable is False


def test_clearcodec_primitive_is_downgraded_on_mmap():
    # controlled-value linear overflow, but the buffer is mmap-resident (the real ClearCodec case)
    v = W.primitive_quality("linear-overflow-controlled-value", buffer_size=8 * 1024 * 1024,
                            alignment=32)
    assert v.region == "mmap"
    assert v.l3_reachable is False
    assert "mmap" in v.needs and ("leak" in v.needs or "heap-resident" in v.needs)


def test_write_what_where_is_top_rated():
    v = W.primitive_quality("write-what-where", buffer_size=128)
    assert v.l3_reachable is True and v.score >= 0.8


def test_dos_is_zero_and_oob_read_is_an_enabler():
    assert W.primitive_quality("dos").l3_reachable is False
    assert "leak" in W.primitive_quality("oob-read").needs.lower()


def test_same_linear_primitive_on_heap_keeps_its_strength():
    v = W.primitive_quality("linear-overflow-controlled-value", buffer_size=96, alignment=16)
    assert v.region == "heap" and v.l3_reachable is True   # groomable -> not downgraded
