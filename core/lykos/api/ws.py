"""Minimal server-side WebSocket (RFC 6455): handshake accept + unmasked text frames.

Send-only is enough for the event stream; we also detect client close by an empty read.
"""
from __future__ import annotations

import base64
import hashlib
import struct

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(sec_websocket_key: str) -> str:
    digest = hashlib.sha1((sec_websocket_key + _GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def text_frame(payload: str) -> bytes:
    data = payload.encode("utf-8")
    n = len(data)
    b0 = 0x81  # FIN + opcode 0x1 (text)
    if n < 126:
        header = bytes([b0, n])
    elif n < 65536:
        header = bytes([b0, 126]) + struct.pack("!H", n)
    else:
        header = bytes([b0, 127]) + struct.pack("!Q", n)
    return header + data


def close_frame() -> bytes:
    return bytes([0x88, 0x00])  # opcode 0x8 close, no payload
