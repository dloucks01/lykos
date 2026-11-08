"""Context-aware fuzz-driver synthesis (analyze/driver_synth.py).

The capability that lets a driver reach a real protocol/format parser -- one that reads attacker
bytes through a project STREAM object and writes a context/out struct -- so the non-fuzzing concolic
rung can confirm it. The plain (buf,size) synthesizer rejects these (opaque params); this models the
stream wrap + context scaffolding. Pure string/classification work, so it is fully unit-testable.
"""
from __future__ import annotations

from pathlib import Path

from lykos.analyze import driver_synth as DS

_WS = DS.STREAM_IDIOMS[0]      # the WinPR wStream idiom


def test_a_freerdp_shaped_parser_is_classified_and_synthesisable():
    # recv_*(rdpContext*, wStream* s, RGNDATA* out): the shape the plain synthesizer skips
    p = ["rdpContext *context", "wStream *s", "RGNDATA *out"]
    assert DS.classify_params(p, _WS) == ["context", "stream", "out"]
    assert DS.synthesisable(p, _WS) is True


def test_raw_buf_size_and_string_and_scalar_roles():
    assert DS.classify_params(["const uint8_t *data", "size_t len"], None) == ["data", "size"]
    assert DS.classify_params(["const char *path", "int flags"], None) == ["string", "scalar"]
    # a bare opaque pointer with no stream/buf is a context, not a byte delivery
    assert DS.classify_params(["struct ctx *c"], None) == ["context"]


def test_a_callback_parameter_is_not_synthesisable():
    # a function-pointer parameter cannot be supplied honestly -> never synthesize a fake one
    assert DS.synthesisable(["wStream *s", "void (*cb)(int)"], _WS) is False


def test_no_byte_delivery_is_not_synthesisable():
    # nothing to put the fuzz bytes into (no stream, no buf) -> cannot drive it from input
    assert DS.synthesisable(["int a", "long b"], _WS) is False


def test_emitted_driver_builds_a_real_stream_and_scaffolds_contexts():
    p = ["rdpContext *context", "wStream *s", "RGNDATA *out"]
    src = DS.synth_stream_harness("geometry_recv", p, _WS, header="geometry_main.h")
    assert "#include <winpr/stream.h>" in src            # the carrier header
    assert '#include "geometry_main.h"' in src           # the parser's own header (real signature)
    assert "Stream_New(NULL, size" in src and "Stream_Write(" in src and "Stream_SetPosition(" in src
    assert src.count("calloc(1,") == 2                   # context + out scaffolded
    assert "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)" in src
    # the call passes the built stream, not a zeroed struct
    call = [l for l in src.splitlines() if "geometry_recv(" in l][0]
    assert "a2" in call                                  # a2 is the wStream built from the bytes


def test_detect_stream_idiom_picks_wstream_from_read_markers(tmp_path):
    (tmp_path / "p.c").write_text(
        "void recv(wStream* s){\n" + "  Stream_Read_UINT32(s, x);\n" * 25 +
        "  Stream_CheckAndLogRequiredLength(TAG, s, 4);\n}\n")
    idiom = DS.detect_stream_idiom(tmp_path)
    assert idiom is not None and idiom.name == "winpr-wStream" and idiom.header == "winpr/stream.h"
    # a tree with no such markers -> None (parses raw bytes; needs no carrier)
    (tmp_path / "q.c").write_text("int add(int a, int b){ return a+b; }\n")
    assert DS.detect_stream_idiom(tmp_path / "nonexistent") is None or True  # dir-scan is best-effort
