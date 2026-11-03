"""Reachable-DoS enumerator: the unguarded-wire-seek class, modelled on FreeRDP rdpgfx."""
from lykos.analyze.reachable_dos import find_unguarded_seeks, DosSite


# the real rdpgfx_recv_wire_to_surface_2_pdu shape: read a length, seek by it, NO guard between.
VULN = """
static UINT rdpgfx_recv_wire_to_surface_2_pdu(GENERIC_CHANNEL_CALLBACK* callback, wStream* s)
{
    RDPGFX_WIRE_TO_SURFACE_PDU_2 pdu = { 0 };
    WINPR_ASSERT(callback);
    if (!Stream_CheckAndLogRequiredLength(TAG, s, RDPGFX_WIRE_TO_SURFACE_PDU_2_SIZE))
        return ERROR_INVALID_DATA;
    Stream_Read_UINT16(s, pdu.surfaceId);
    Stream_Read_UINT32(s, pdu.bitmapDataLength);
    Stream_Seek(s, pdu.bitmapDataLength);
    return CHANNEL_RC_OK;
}
"""

# the guarded sibling: identical but checks bitmapDataLength BEFORE the seek -> NOT a site.
SAFE = """
static UINT rdpgfx_recv_wire_to_surface_1_pdu(GENERIC_CHANNEL_CALLBACK* callback, wStream* s)
{
    RDPGFX_WIRE_TO_SURFACE_PDU_1 pdu = { 0 };
    if (!Stream_CheckAndLogRequiredLength(TAG, s, RDPGFX_WIRE_TO_SURFACE_PDU_1_SIZE))
        return ERROR_INVALID_DATA;
    Stream_Read_UINT16(s, pdu.surfaceId);
    Stream_Read_UINT32(s, pdu.bitmapDataLength);
    if (!Stream_CheckAndLogRequiredLength(TAG, s, pdu.bitmapDataLength))
        return ERROR_INVALID_DATA;
    Stream_Seek(s, pdu.bitmapDataLength);
    return CHANNEL_RC_OK;
}
"""

# a constant seek: always bounded by the fixed-size guard -> NOT this class.
CONST = """
static UINT rdpgfx_recv_header(wStream* s)
{
    if (!Stream_CheckAndLogRequiredLength(TAG, s, 8))
        return ERROR_INVALID_DATA;
    Stream_Read_UINT16(s, cmdId);
    Stream_Seek(s, 4);
    return CHANNEL_RC_OK;
}
"""


def test_detects_unguarded_wire_seek():
    sites = find_unguarded_seeks(VULN)
    assert len(sites) == 1
    assert sites[0].function == "rdpgfx_recv_wire_to_surface_2_pdu"
    assert sites[0].trigger_field == "pdu.bitmapDataLength"
    assert sites[0].cwe == "CWE-617"


def test_guarded_sibling_not_reported():
    assert find_unguarded_seeks(SAFE) == []


def test_constant_seek_not_reported():
    assert find_unguarded_seeks(CONST) == []


def test_only_the_vuln_in_a_mixed_tu():
    sites = find_unguarded_seeks(VULN + SAFE + CONST)
    assert [s.function for s in sites] == ["rdpgfx_recv_wire_to_surface_2_pdu"]
