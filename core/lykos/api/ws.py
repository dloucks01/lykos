"""Minimal server-side WebSocket (RFC 6455): handshake accept + unmasked text frames.

Send-only is enough for the event stream; we also detect client close by an empty read.
"""
from __future__ import annotations

import base64
import hashlib
import struct

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# A client-declared frame length is honoured up to 2**64; without a ceiling a single frame
# header can make _recvn accumulate an unbounded buffer (memory DoS). No interactive console or
# seed payload is anywhere near this, so a frame larger than the cap is a hostile client.
MAX_FRAME = 8 * 1024 * 1024  # 8 MiB


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


def _read_one(sock):
    """Read one raw frame off the wire. Returns (fin, opcode, payload), or (None, None, b'') on
    EOF / oversize / short read. Applies the client mask if present (RFC 6455 requires masking
    for client->server frames)."""
    h = _recvn(sock, 2)
    if len(h) < 2:
        return None, None, b""
    fin = h[0] & 0x80
    opcode = h[0] & 0x0F
    masked = h[1] & 0x80
    ln = h[1] & 0x7F
    if ln == 126:
        ext = _recvn(sock, 2)
        if len(ext) < 2:
            return None, None, b""
        ln = struct.unpack("!H", ext)[0]
    elif ln == 127:
        ext = _recvn(sock, 8)
        if len(ext) < 8:
            return None, None, b""
        ln = struct.unpack("!Q", ext)[0]
    if ln > MAX_FRAME:
        return None, None, b""             # oversize frame: refuse rather than buffer it
    mask = _recvn(sock, 4) if masked else b"\x00\x00\x00\x00"
    if masked and len(mask) < 4:
        return None, None, b""
    data = _recvn(sock, ln) if ln else b""
    if ln and len(data) < ln:
        return None, None, b""
    if masked:
        data = bytes(data[i] ^ mask[i & 3] for i in range(len(data)))
    return fin, opcode, data


def read_frame(sock):
    """Read one logical client->server message. Returns (opcode, payload), or (None, b'') on
    EOF / protocol error / oversize.

    Reassembles a fragmented data message (an initial text/binary frame with FIN=0 followed by
    continuation frames, opcode 0x0, until FIN). Control frames (close 0x8, ping 0x9, pong 0xA)
    are never fragmented per RFC 6455 and are returned immediately so the caller can answer a
    ping or honour a close even mid-stream; the accumulated total is capped at MAX_FRAME."""
    payload = b""
    msg_opcode = None
    while True:
        fin, opcode, data = _read_one(sock)
        if opcode is None:
            return None, b""
        if opcode >= 0x8:                  # control frame: complete in itself
            return opcode, data
        if opcode == 0x0:                  # continuation
            if msg_opcode is None:
                return None, b""           # continuation with nothing to continue
        else:                              # 0x1 text / 0x2 binary: start of a message
            msg_opcode = opcode
        payload += data
        if len(payload) > MAX_FRAME:
            return None, b""               # reassembled message too large
        if fin:
            return msg_opcode, payload
