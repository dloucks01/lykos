"""Static input-to-state dictionary from P-Code comparison operands (cmpdict)."""
from lykos.analyze.fuzz import cmpdict


def _ops(*ops):
    return {0x1000: {"blocks": [{"instructions": [{"pcode": list(ops)}]}]}}


def test_four_byte_magic_is_mined_both_byte_orders():
    toks = cmpdict.cmp_tokens(["INT_EQUAL const:0x47464923:4 reg:eax:4 -> unique:0x1:1"])
    # LE bytes spell the on-disk magic '#IFG'; BE is the numeric form.
    assert b"#IFG" in toks
    assert bytes.fromhex("47464923") in toks


def test_length_gate_and_delimiter_and_tag():
    toks = cmpdict.cmp_tokens([
        "INT_SLESS reg:ecx:4 const:0x400:4 -> unique:0x1:1",     # size gate 1024
        "INT_EQUAL const:0xa:1 reg:dl:1 -> unique:0x2:1",         # newline delimiter
        "INT_NOTEQUAL const:0x8950:2 reg:ax:2 -> unique:0x3:1",   # 2-byte tag
    ])
    assert (0x400).to_bytes(4, "little") in toks and (0x400).to_bytes(2, "little") in toks
    assert b"\n" in toks
    assert bytes.fromhex("5089") in toks and bytes.fromhex("8950") in toks


def test_trivial_constants_are_dropped():
    toks = cmpdict.cmp_tokens([
        "INT_EQUAL const:0x0:4 reg:esi:4 -> unique:0x1:1",       # null check
        "INT_EQUAL const:0x1:4 reg:esi:4 -> unique:0x2:1",       # +1
        "INT_EQUAL const:0xffffffff:4 reg:esi:4 -> unique:0x3:1",# -1 sentinel
    ])
    assert b"\x00\x00\x00\x00" not in toks
    assert b"\xff\xff\xff\xff" not in toks


def test_non_comparison_ops_are_ignored():
    assert cmpdict.cmp_tokens(["COPY reg:eax:4 -> reg:ebx:4",
                               "LOAD const:0x1234:8 reg:rax:8 -> reg:rbx:8"]) == set()


def test_int_sub_immediate_is_treated_as_a_compared_value():
    # `sub reg, K` is how several ISAs lower a compare-against-K.
    toks = cmpdict.cmp_tokens(["INT_SUB reg:edi:4 const:0x2a:4 -> reg:edi:4"])
    assert b"\x2a" in toks


def test_dictionary_orders_longest_first_and_caps():
    firs = _ops(
        "INT_EQUAL const:0x47464923:4 reg:eax:4 -> unique:0x1:1",
        "INT_EQUAL const:0xa:1 reg:dl:1 -> unique:0x2:1",
    )
    d = cmpdict.mine_cmp_dictionary(firs, limit=50)
    assert d, "expected tokens"
    assert len(d[0]) >= len(d[-1])                       # longest-first
    assert all(1 <= len(t) <= 32 for t in d)


def test_address_like_constants_are_droppable():
    # a pointer comparison (0x401080) must not leak its bytes as an input token when a range
    # predicate says it is code/data.
    firs = _ops("INT_EQUAL const:0x401080:8 reg:rax:8 -> unique:0x1:1",
                "INT_EQUAL const:0xcafebabe:4 reg:eax:4 -> unique:0x2:1")
    d = cmpdict.mine_cmp_dictionary(firs, is_addr=lambda v: 0x400000 <= v < 0x402000)
    assert (0x401080).to_bytes(8, "little") not in d
    assert bytes.fromhex("bebafeca") in d                # the real magic survives
