"""Dispatcher-aware internal-parser harnessing (analyze/dispatcher_harness.py) — capability #2.

Detect the switch-on-wire-tag dispatcher, expose a static function for export, and emit a driver
that reaches it — the three manual steps used to fuzz FreeRDP's rdpgfx_recv_pdu.
"""
from __future__ import annotations
from lykos.analyze import dispatcher_harness as D

RDPGFX = """
static UINT rdpgfx_recv_pdu(GENERIC_CHANNEL_CALLBACK* callback, wStream* s)
{
    RDPGFX_HEADER header = { 0 };
    UINT error = rdpgfx_read_header(s, &header);
    switch (header.cmdId)
    {
        case RDPGFX_CMDID_WIRETOSURFACE_1:
            error = rdpgfx_recv_wire_to_surface_1_pdu(callback, s);
            break;
        case RDPGFX_CMDID_SOLIDFILL:
            error = rdpgfx_recv_solid_fill_pdu(callback, s);
            break;
        case RDPGFX_CMDID_SURFACETOCACHE:
            error = rdpgfx_recv_surface_to_cache_pdu(callback, s);
            break;
        case RDPGFX_CMDID_CACHETOSURFACE:
            error = rdpgfx_recv_cache_to_surface_pdu(callback, s);
            break;
    }
    return error;
}
"""


def test_detects_the_dispatcher_tag_and_subparsers():
    ds = D.find_dispatchers(RDPGFX)
    assert len(ds) == 1
    d = ds[0]
    assert d.name == "rdpgfx_recv_pdu"
    assert d.tag == "header.cmdId"
    assert d.is_static is True
    assert "rdpgfx_recv_wire_to_surface_1_pdu" in d.subparsers
    assert "rdpgfx_recv_solid_fill_pdu" in d.subparsers
    assert len(d.subparsers) == 4


def test_a_non_dispatcher_function_is_ignored():
    src = "static int add(int a, int b) { switch(a){ case 1: return b; } return 0; }"
    assert D.find_dispatchers(src) == []     # one case, no sub-parser calls -> not a dispatcher


def test_expose_static_adds_default_visibility():
    out = D.expose_static(RDPGFX, "rdpgfx_recv_pdu")
    assert '__attribute__((visibility("default"))) UINT rdpgfx_recv_pdu(' in out
    assert "static UINT rdpgfx_recv_pdu(" not in out
    # idempotent
    assert D.expose_static(out, "rdpgfx_recv_pdu") == out


def test_synth_dispatcher_harness_builds_a_stream_and_calls_the_dispatcher():
    r = D.ContextRecipe(
        includes=['"rdpgfx_main.h"'],
        setup_c="static GENERIC_CHANNEL_CALLBACK cb; /* ...context setup... */",
        call_expr="rdpgfx_recv_pdu(&cb, s)")
    src = D.synth_dispatcher_harness(r)
    assert "#include <winpr/stream.h>" in src
    assert '#include "rdpgfx_main.h"' in src
    assert "Stream_New(NULL, size)" in src and "Stream_Write(s, data, size)" in src
    assert "rdpgfx_recv_pdu(&cb, s);" in src
    assert "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)" in src
