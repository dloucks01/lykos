"""Interactive detonation console: WebSocket frame decode + live PTY proxying of a target."""
import base64
import json
import os
import shutil
import socket
import struct
import threading

import pytest
from lykos.api import console, ws


def test_ws_read_frame_unmasks_client_data():
    payload = b'{"t":"in","s":"hi"}'
    mask = b"\x01\x02\x03\x04"
    masked = bytes(payload[i] ^ mask[i & 3] for i in range(len(payload)))
    frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
    a, b = socket.socketpair()
    a.sendall(frame)
    op, data = ws.read_frame(b)
    assert op == 0x1 and data == payload
    a.close(); b.close()


def _client_send(sock, obj):
    d = json.dumps(obj).encode(); m = os.urandom(4)
    mk = bytes(d[i] ^ m[i & 3] for i in range(len(d)))
    n = len(d)
    ln = bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
    sock.sendall(bytes([0x81]) + ln + m + mk)


def _client_recv(sock, t=2.0):
    sock.settimeout(t); out = []
    try:
        while True:
            h = sock.recv(2)
            if len(h) < 2:
                break
            ln = h[1] & 0x7f
            if ln == 126:
                ln = struct.unpack("!H", sock.recv(2))[0]
            data = b""
            while len(data) < ln:
                data += sock.recv(ln - len(data))
            if (h[0] & 0xf) == 1:
                out.append(json.loads(data))
            elif (h[0] & 0xf) == 8:
                break
    except socket.timeout:
        pass
    return out


@pytest.mark.skipif(not shutil.which("cat"), reason="needs /bin/cat")
def test_console_proxies_pty_io_and_saves_seed():
    srv, cli = socket.socketpair()
    saved = {}
    th = threading.Thread(target=console.serve, kwargs=dict(
        sock=srv, exe=shutil.which("cat"), timeout=8,
        put_seed=lambda d: saved.setdefault("data", d) and "sha"), daemon=True)
    th.start()
    _client_recv(cli, 1.0)                       # started info
    _client_send(cli, {"t": "in", "b64": base64.b64encode(b"ping\n").decode()})
    outs = _client_recv(cli, 1.5)
    echoed = b"".join(base64.b64decode(m["b64"]) for m in outs if m["t"] == "out")
    assert b"ping" in echoed                     # cat echoed our input back over the PTY
    _client_send(cli, {"t": "save"})
    _client_recv(cli, 1.0)
    _client_send(cli, {"t": "signal", "sig": "KILL"})
    cli.close(); th.join(timeout=5)
    assert saved.get("data") == b"ping\n"        # sent bytes captured as a seed
