"""Guard-gap detector (CWE-125/787): an attacker-controlled stream length used as a size/seek bound
with no bounds guard. Precision-first -- the whole point is to NOT fire where the code guards."""
from lykos.analyze.guard_gap import (discover_guards, find_guard_gaps, variant_confirmed, _base)


def _guards(src):
    return discover_guards({"x.c": src})


def test_fires_on_unguarded_seek():
    src = """
    static int recv_pdu(void* cb, wStream* s) {
        if (!Stream_CheckAndLogRequiredLength("T", s, 13)) return -1;
        Stream_Read_UINT32(s, pdu.bitmapDataLength);
        pdu.bitmapData = Stream_Pointer(s);
        Stream_Seek(s, pdu.bitmapDataLength);     /* no check on bitmapDataLength */
        return 0;
    }
    """
    hits = find_guard_gaps(src, _guards(src))
    assert any(h["base"] == "bitmapDataLength" and h["kind"] == "seek" for h in hits)


def test_suppressed_when_primitive_guards_the_value():
    src = """
    static int recv_ok(void* cb, wStream* s) {
        Stream_Read_UINT32(s, len);
        if (!Stream_CheckAndLogRequiredLength("T", s, len)) return -1;
        Stream_Seek(s, len);
        return 0;
    }
    """
    assert find_guard_gaps(src, _guards(src)) == []


def test_suppressed_when_guard_call_wraps_across_lines():
    # the dominant false positive: the guard call spans physical lines before the value.
    src = """
    static int recv_wrap(void* cb, wStream* s) {
        Stream_Read_UINT32(s, ticket->ServiceTicketLength);
        if (!Stream_CheckAndLogRequiredLength(
                "T", s, 16ull + ticket->ServiceTicketLength))
            return FALSE;
        Stream_Seek(s, ticket->ServiceTicketLength);
        return 0;
    }
    """
    assert find_guard_gaps(src, _guards(src)) == []


def test_suppressed_by_discovered_project_guard_wrapper():
    src = """
    static int my_check(wLog* log, wStream* s, size_t n) {
        if (!Stream_GetRemainingLength(s)) return FALSE;
        if (Stream_GetRemainingLength(s) < n) return FALSE;
        return TRUE;
    }
    static int recv_wrapped(void* cb, wStream* s) {
        Stream_Read_UINT32(s, cbScope);
        if (!my_check(log, s, cbScope)) return -1;
        Stream_Seek(s, cbScope);
        return 0;
    }
    """
    guards = _guards(src)
    assert "my_check" in guards
    assert find_guard_gaps(src, guards) == []


def test_suppressed_by_plain_branch_clamp():
    src = """
    static int recv_clamped(void* cb, wStream* s) {
        Stream_Read_UINT16(s, n);
        if (n > 1024) return -1;            /* branch clamp */
        Stream_Seek(s, n);
        return 0;
    }
    """
    assert find_guard_gaps(src, _guards(src)) == []


def test_variant_confirmed_cross_check():
    src = """
    static int recv_1_pdu(void* cb, wStream* s) {
        Stream_Read_UINT32(s, pdu.bitmapDataLength);
        if (!Stream_CheckAndLogRequiredLength("T", s, pdu.bitmapDataLength)) return -1;
        Stream_Seek(s, pdu.bitmapDataLength);
        return 0;
    }
    static int recv_2_pdu(void* cb, wStream* s) {
        Stream_Read_UINT32(s, pdu.bitmapDataLength);
        Stream_Seek(s, pdu.bitmapDataLength);     /* sibling guards it; this one does not */
        return 0;
    }
    """
    guards = _guards(src)
    gaps = find_guard_gaps(src, guards)
    gap2 = next(g for g in gaps if g["fn"] == "recv_2_pdu")
    assert variant_confirmed(src, gap2, guards)


def test_base_identifier():
    assert _base("pdu.bitmapDataLength") == "bitmapDataLength"
    assert _base("ticket->ServiceTicketLength") == "ServiceTicketLength"
