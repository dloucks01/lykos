"""DoS harvest driver: enumerate sites -> targeted trigger -> confirm via the 0-FP DoS lane."""
from lykos.analyze.dos_harvest import (resolve_constants, case_subparser_map,
                                       build_dos_trigger, harvest_dos, RDPGFX_HEADER)

HEADER_DEFS = """
#define RDPGFX_CMDID_WIRETOSURFACE_1 0x0001
#define RDPGFX_CMDID_WIRETOSURFACE_2 0x0002
"""

DISPATCH = """
static UINT rdpgfx_recv_pdu(GENERIC_CHANNEL_CALLBACK* cb, wStream* s)
{
    Stream_Read_UINT16(s, header.cmdId);
    switch (header.cmdId)
    {
        case RDPGFX_CMDID_WIRETOSURFACE_1:
            rdpgfx_recv_wire_to_surface_1_pdu(cb, s);
            break;
        case RDPGFX_CMDID_WIRETOSURFACE_2:
            rdpgfx_recv_wire_to_surface_2_pdu(cb, s);
            break;
    }
    return 0;
}
static UINT rdpgfx_recv_wire_to_surface_1_pdu(GENERIC_CHANNEL_CALLBACK* cb, wStream* s)
{
    if (!Stream_CheckAndLogRequiredLength(TAG, s, 7)) return 1;
    Stream_Read_UINT16(s, pdu.surfaceId);
    Stream_Read_UINT32(s, pdu.bitmapDataLength);
    if (!Stream_CheckAndLogRequiredLength(TAG, s, pdu.bitmapDataLength)) return 1;
    Stream_Seek(s, pdu.bitmapDataLength);
    return 0;
}
static UINT rdpgfx_recv_wire_to_surface_2_pdu(GENERIC_CHANNEL_CALLBACK* cb, wStream* s)
{
    if (!Stream_CheckAndLogRequiredLength(TAG, s, 7)) return 1;
    Stream_Read_UINT16(s, pdu.surfaceId);
    Stream_Read_UINT32(s, pdu.bitmapDataLength);
    Stream_Seek(s, pdu.bitmapDataLength);
    return 0;
}
"""


def test_resolve_and_casemap():
    consts = resolve_constants(HEADER_DEFS)
    assert consts["RDPGFX_CMDID_WIRETOSURFACE_2"] == 2
    cm = case_subparser_map(DISPATCH)
    assert cm["rdpgfx_recv_wire_to_surface_2_pdu"] == "RDPGFX_CMDID_WIRETOSURFACE_2"


def test_trigger_routes_and_oversizes():
    import struct
    from lykos.analyze.dispatcher_harness import _functions
    body = {n: b for n, _s, _p, b in _functions(DISPATCH)}["rdpgfx_recv_wire_to_surface_2_pdu"]
    trig = build_dos_trigger(body, "pdu.bitmapDataLength", 2)
    assert trig[0:2] == b"\x02\x00"                 # cmdId routes to wire_to_surface_2
    assert b"\xff\xff\xff\xff" in trig              # oversized seek amount
    assert struct.unpack_from("<I", trig, 4)[0] == len(trig) - 8   # pduLength == body length


def test_harvest_confirms_only_the_unguarded_site():
    # oracle: the oversized trigger for wire_to_surface_2 aborts; everything else is clean.
    def replay(data: bytes) -> str:
        if not data:
            return ""                                # negative control: no fault
        # the unguarded site's trigger routes to cmdId 2 and seeks past end -> assert
        if data[0:2] == b"\x02\x00" and b"\xff\xff\xff\xff" in data:
            return "WINPR_ASSERT failed: Stream_GetRemainingCapacity(s) >= size\nSIGABRT"
        return ""
    out = harvest_dos(DISPATCH, resolve_constants(HEADER_DEFS), replay)
    confirmed = [f for f in out if f.confirmed]
    assert len(confirmed) == 1
    assert confirmed[0].function == "rdpgfx_recv_wire_to_surface_2_pdu"
    assert confirmed[0].cwe == "CWE-617"


def test_negative_control_gate_rejects_flaky_oracle():
    # if the empty input ALSO faults, nothing confirms (0-FP gate).
    def replay(data: bytes) -> str:
        return "WINPR_ASSERT failed\nSIGABRT"        # faults on everything, incl. empty
    out = harvest_dos(DISPATCH, resolve_constants(HEADER_DEFS), replay)
    assert [f for f in out if f.confirmed] == []
