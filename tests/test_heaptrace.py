"""Custom-allocator heap-primitive discovery: allocator identification + op-sequence synthesis."""
from lykos.analyze.dynamic import heaptrace


def test_identify_allocator_picks_custom_pair_skips_libc():
    fns = {"ta_alloc": 0x1000, "ta_free": 0x2000, "malloc": 0x3000, "free": 0x4000, "main": 0x5000}
    a = heaptrace.identify_allocator(fns)
    assert a["alloc_name"] == "ta_alloc" and a["free_name"] == "ta_free"
    assert a["alloc"] == 0x1000 and a["free"] == 0x2000


def test_identify_allocator_none_when_only_libc():
    assert heaptrace.identify_allocator({"malloc": 1, "free": 2, "main": 3}) is None


def test_identify_allocator_prefers_shared_stem():
    fns = {"pool_alloc": 0x10, "pool_free": 0x20, "scratch_new": 0x30, "widget_delete": 0x40}
    a = heaptrace.identify_allocator(fns)
    assert a["alloc_name"] == "pool_alloc" and a["free_name"] == "pool_free"


def test_ret_offsets_finds_rets():
    # ... 0xC3 (ret) at offset 3 and 6
    assert heaptrace.ret_offsets(b"\x55\x48\x89\xc3\x90\x90\xc3") == [3, 6]


def test_heap_op_sequences_creates_then_double_acts():
    seqs = heaptrace.heap_op_sequences(["1", "2", "3", "4"])
    assert seqs
    # a create (option 1) followed by the same act option twice appears (double-free shape)
    assert any(s.count(b"\n") >= 4 and s.startswith(b"1\n") for s in seqs)


def test_heap_op_sequences_empty_without_menu():
    assert heaptrace.heap_op_sequences([]) == []
    assert heaptrace.heap_op_sequences(["1"]) == []


def test_heap_op_sequences_include_uaf_cross_option():
    seqs = heaptrace.heap_op_sequences(["1", "2", "3", "4"])
    # a create then a FREE-op then a different USE-op (use-after-free shape) exists
    assert any(s.startswith(b"1\n") and s.count(b"\n") >= 4
               and len({b for b in s.split(b"\n") if b in {b"2", b"3", b"4"}}) >= 2
               for s in seqs)


def test_allocator_ranges_covers_family_and_transitive_callees():
    from types import SimpleNamespace as NS
    from lykos.analyze.dynamic import heap_discover
    # ta_alloc calls memclear; ta_free calls compact; both + same-stem must be ignored ranges
    fns = {"ta_alloc": 0x1000, "ta_free": 0x1100, "ta_safe": 0x1200, "compact": 0x1300,
           "memclear": 0x1400, "main": 0x1500}
    edges = [NS(src_addr=0x1000, dst_name="memclear"), NS(src_addr=0x1100, dst_name="compact")]
    alloc = {"alloc_name": "ta_alloc", "alloc": 0x1000, "free_name": "ta_free", "free": 0x1100}
    rngs = heap_discover._allocator_ranges(fns, edges, alloc)
    starts = {a for a, _ in rngs}
    assert {0x1000, 0x1100, 0x1200, 0x1300, 0x1400} <= starts   # family + callees
    assert 0x1500 not in starts                                  # main is NOT the allocator
