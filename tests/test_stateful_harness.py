"""Stateful / multi-message driving (analyze/stateful_harness.py) — capability #5.

Both FreeRDP PoCs needed state across messages (AUDIN seqNumber, ClearCodec prime-then-reuse). The
fuzzer buffer is framed into a message sequence replayed through one persisted context.
"""
from __future__ import annotations
from lykos.analyze import stateful_harness as S
from lykos.analyze.dispatcher_harness import ContextRecipe


def test_frame_then_split_roundtrips():
    msgs = [b"\x01\x02\x03", b"", b"prime", b"trigger-bytes"]
    assert S.split_messages(S.frame_messages(msgs)) == msgs


def test_split_handles_truncated_tail_and_empty():
    assert S.split_messages(b"") == [b""]
    # a length that overruns the buffer takes the rest (grown-tail mutation stays usable)
    import struct
    buf = struct.pack("<H", 100) + b"abc"
    assert S.split_messages(buf) == [b"abc"]


def test_split_decodes_two_messages():
    import struct
    buf = struct.pack("<H", 2) + b"AB" + struct.pack("<H", 3) + b"CDE"
    assert S.split_messages(buf) == [b"AB", b"CDE"]


def test_harness_persists_context_and_loops_messages():
    r = ContextRecipe(includes=['"rdpgfx_main.h"'],
                      setup_c="static GENERIC_CHANNEL_CALLBACK cb;",
                      call_expr="rdpgfx_recv_pdu(&cb, s)")
    src = S.synth_stateful_harness(r)
    # context built ONCE, outside the per-message while loop
    assert src.index("static GENERIC_CHANNEL_CALLBACK cb;") < src.index("while (off < size")
    assert "rdpgfx_recv_pdu(&cb, s);" in src
    assert "nmsg < 64" in src and "Stream_New(NULL, mlen" in src


def test_harness_auto_increments_a_sequence_field():
    r = ContextRecipe(includes=['"audin.h"'],
                      setup_c="static audin_server_context ctx;",
                      call_expr="audin_server_recv(&ctx, s)")
    # AUDIN seqNumber is a 1-byte field at offset 1 of the message
    src = S.synth_stateful_harness(r, seq_field_offset=1, seq_field_width=1)
    assert "seqctr++" in src
    assert "mbuf[1 + _b]" in src
