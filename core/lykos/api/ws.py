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


def pong_frame(payload: bytes = b"") -> bytes:
    return bytes([0x8A, len(payload) & 0x7f]) + payload


def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return b""                    # EOF / partial -> treat as closed
        buf += c
    return buf


def read_frame(sock):
    """Read one client->server frame (always masked per RFC 6455). Returns (opcode, payload),
    or (None, b'') on EOF. Assumes unfragmented frames (what browsers send for small messages)."""
    h = _recvn(sock, 2)
    if len(h) < 2:
        return None, b""
    opcode = h[0] & 0x0F
    masked = h[1] & 0x80
    ln = h[1] & 0x7F
    if ln == 126:
        ext = _recvn(sock, 2)
        if len(ext) < 2:
            return None, b""
        ln = struct.unpack("!H", ext)[0]
    elif ln == 127:
        ext = _recvn(sock, 8)
        if len(ext) < 8:
            return None, b""
        ln = struct.unpack("!Q", ext)[0]
    mask = _recvn(sock, 4) if masked else b"\x00\x00\x00\x00"
    if masked and len(mask) < 4:
        return None, b""
    data = _recvn(sock, ln) if ln else b""
    if ln and len(data) < ln:
        return None, b""
    if masked:
        data = bytes(data[i] ^ mask[i & 3] for i in range(len(data)))
    return opcode, data
