from lykos.analyze.wire_flow import find_wire_flows

def test_divisor_flagged():
    src='int f(wStream* s){UINT16 nb; Stream_Read_UINT16(s,nb); int x = 100/nb; return x;}'
    f=find_wire_flows(src); assert any(w.use=="divisor" and w.cwe=="CWE-369" for w in f)

def test_unguarded_seek_flagged():
    src='int f(wStream* s){UINT32 L; Stream_Read_UINT32(s,L); Stream_Seek(s,L); return 0;}'
    assert any(w.use=="seek" for w in find_wire_flows(src))

def test_guarded_seek_suppressed():
    src=('int f(wStream* s){UINT32 L; Stream_Read_UINT32(s,L);'
         ' if(!Stream_CheckAndLogRequiredLength(T,s,L)) return 1; Stream_Seek(s,L); return 0;}')
    assert not any(w.use=="seek" for w in find_wire_flows(src))

def test_range_checked_divisor_suppressed():
    src='int f(wStream* s){UINT16 nb; Stream_Read_UINT16(s,nb); if(nb==0) return 1; return 100/nb;}'
    assert not any(w.use=="divisor" for w in find_wire_flows(src))

def test_index_flagged():
    src='int f(wStream* s){UINT8 i; Stream_Read_UINT8(s,i); arr[i]=1; return 0;}'
    assert any(w.use=="index" for w in find_wire_flows(src))


def test_value_range_suppresses_provably_nonzero_divisor():
    """Integration (gap 1): a wire-read divisor the interval engine proves is never zero is
    suppressed, while a divisor that CAN be zero is still reported."""
    from lykos.analyze.wire_flow import find_wire_flows
    # d = raw + 1, raw in 0..255 -> d in 1..256, never zero -> no CWE-369
    safe = """
    void a(wStream* s) {
        UINT8 raw; Stream_Read_UINT8(s, raw);
        int d = raw + 1;
        int q = 1000 % d;
    }
    """
    assert not [f for f in find_wire_flows(safe) if f.use == "divisor"]
    # d = raw, raw in 0..255 -> includes zero -> reported
    bad = """
    void b(wStream* s) {
        UINT8 raw; Stream_Read_UINT8(s, raw);
        int d = raw;
        int q = 1000 % d;
    }
    """
    assert [f for f in find_wire_flows(bad) if f.use == "divisor"]
