"""Multi-message / stateful driving -- capability #5.

A single message often cannot reach a bug: the parser bails at a sequence/version check, or the bug
only appears across messages that share state. Both FreeRDP PoCs needed this -- AUDIN rejects a
SNDIN_FORMATS whose `seqNumber` is not the expected next value, and the ClearCodec OOB needed a
FIRST message to size `clear->TempBuffer` and a SECOND to overflow the reused buffer. A one-shot
harness never gets there.

This models a fuzzer input as a SEQUENCE of messages replayed through ONE persisted context, so
state carries across them (the dispatcher's own `switch` selects the sub-parser per message). The
framing is length-prefixed so a coverage-guided fuzzer can grow/shrink the sequence. An optional
auto-sequenced field is rewritten per message so handshake/sequence gates pass without the fuzzer
having to rediscover the counter each time (mirrors SOTA stateful fuzzers AFLNet/StateAFL, but
message-framed on top of the synthesized dispatcher harness rather than a live socket).

Pure byte/string work (framing + emitted C); the consuming stage builds and fuzzes it.
"""
from __future__ import annotations

import struct


def split_messages(data: bytes, *, max_messages: int = 64) -> list:
    """Decode a fuzzer buffer into a message sequence. Framing: each message is a 2-byte
    little-endian length then that many bytes. A truncated trailing frame takes the rest of the
    buffer (so a mutator that grows the tail still yields a usable last message). An empty buffer is
    one empty message, so the harness always makes at least one call."""
    msgs: list = []
    i, n = 0, len(data)
    while i < n and len(msgs) < max_messages:
        if i + 2 > n:
            msgs.append(data[i:]); break
        ln = struct.unpack_from("<H", data, i)[0]
        i += 2
        if ln == 0:
            msgs.append(b""); continue
        chunk = data[i:i + ln]
        msgs.append(chunk)
        i += ln
        if len(chunk) < ln:                              # truncated final frame
            break
    return msgs or [b""]


def frame_messages(messages: list) -> bytes:
    """Encode a message list into the length-prefixed wire form `split_messages` decodes -- used to
    build seed corpora (e.g. the prime message then the trigger message)."""
    out = bytearray()
    for m in messages:
        out += struct.pack("<H", len(m) & 0xFFFF)
        out += m
    return bytes(out)


def synth_stateful_harness(recipe, *, seq_field_offset: "int | None" = None,
                           seq_field_width: int = 1) -> str:
    """A libFuzzer driver that decodes the fuzz buffer into a message sequence and replays each
    message through ONE persisted context (built once via `recipe.setup_c`), so state carries across
    messages. `recipe.call_expr` must call the dispatcher with a `wStream* s` built from the current
    message (named `s`). When `seq_field_offset` is set, the byte(s) at that offset of each message
    are overwritten with an incrementing counter before the call, so a sequence/handshake gate
    (AUDIN's seqNumber) passes without the fuzzer rediscovering the counter.

    `recipe` is a dispatcher_harness.ContextRecipe. The context is constructed ONCE outside the
    per-message loop (persistence is the whole point), unlike the one-shot dispatcher harness."""
    inc = "\n".join(f"#include {h}" for h in recipe.includes)
    seq_c = ""
    if seq_field_offset is not None:
        seq_c = (f"        if (mlen > {seq_field_offset + seq_field_width - 1}) {{\n"
                 f"            uint64_t _sq = seqctr++;\n"
                 f"            for (int _b = 0; _b < {seq_field_width}; _b++)\n"
                 f"                mbuf[{seq_field_offset} + _b] = (uint8_t)(_sq >> (8*_b));\n"
                 f"        }}\n")
    return (f"""#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <winpr/stream.h>
{inc}

{recipe.setup_c}

/* length-prefixed framing: [u16 len][len bytes] per message, replayed through one context */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    size_t off = 0; uint64_t seqctr = 0; int nmsg = 0;
    while (off < size && nmsg < 64) {{
        size_t mlen; const uint8_t* msrc;
        if (off + 2 > size) {{ mlen = size - off; msrc = data + off; off = size; }}
        else {{ mlen = (size_t)(data[off] | (data[off+1] << 8)); off += 2;
                if (mlen > size - off) mlen = size - off;
                msrc = data + off; off += mlen; }}
        nmsg++;
        uint8_t* mbuf = (uint8_t*)malloc(mlen ? mlen : 1);
        if (!mbuf) break;
        memcpy(mbuf, msrc, mlen);
{seq_c}        wStream* s = Stream_New(NULL, mlen ? mlen : 1);
        if (s) {{ Stream_Write(s, mbuf, mlen); Stream_SealLength(s); Stream_SetPosition(s, 0);
                  {recipe.call_expr}; Stream_Free(s, TRUE); }}
        free(mbuf);
    }}
    return 0;
}}
""")
