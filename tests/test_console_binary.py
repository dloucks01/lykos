"""Interactive console: binary-protocol driving (the GUI's hex / escape input modes).

  * `stdin_mode="pipe"`: every byte reaches the target exactly (NUL, 0xff, ^C, ^D, CR are data,
    not line-discipline keys), the output comes back exactly (raw PTY: no LF -> CRLF), and "eof"
    really closes stdin -- `cat` then exits 0;
  * a BINARY WebSocket frame is input bytes (backward-compatible with the JSON {"t":"in"} form);
  * terminal mode "eof" with a partial line pending still ends input (^D twice);
  * "save as seed" stores exactly the bytes sent, in order.
"""
import base64
import json
import os
import shutil
import socket
import struct
import threading
import time

import pytest
from lykos.api import console

pytestmark = pytest.mark.skipif(not shutil.which("cat"), reason="needs /bin/cat")


def _frame(op, d):
    m = os.urandom(4)
    mk = bytes(d[i] ^ m[i & 3] for i in range(len(d)))
    n = len(d)
    ln = bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
    return bytes([0x80 | op]) + ln + m + mk


def _send(sock, obj):
    sock.sendall(_frame(0x1, json.dumps(obj).encode()))


def _recv_until(sock, pred, t=5.0):
    """Collect server messages until pred(messages) or the deadline."""
    sock.settimeout(0.2)
    out, end = [], time.time() + t
    while time.time() < end and not pred(out):
        try:
            h = sock.recv(2)
        except socket.timeout:
            continue
        if len(h) < 2:
            break
        ln = h[1] & 0x7f
        if ln == 126:
            ln = struct.unpack("!H", sock.recv(2))[0]
        data = b""
        sock.settimeout(2.0)
        while len(data) < ln:
            data += sock.recv(ln - len(data))
        sock.settimeout(0.2)
        if (h[0] & 0xf) == 1:
            out.append(json.loads(data))
        elif (h[0] & 0xf) == 8:
            break
    return out


def _out_bytes(msgs):
    return b"".join(base64.b64decode(m["b64"]) for m in msgs if m["t"] == "out")


def _start(stdin_mode, saved):
    srv, cli = socket.socketpair()
    th = threading.Thread(target=console.serve, kwargs=dict(
        sock=srv, exe=shutil.which("cat"), timeout=10, stdin_mode=stdin_mode,
        put_seed=lambda d: saved.setdefault("data", d) and "sha"), daemon=True)
    th.start()
    first = _recv_until(cli, lambda o: any(m["t"] == "info" for m in o), 3.0)
    return cli, th, first


PAYLOAD = b"\x00\xff\x03\x04\r\nAB\x7f\x15"


def test_pipe_mode_delivers_exact_bytes_and_a_real_eof():
    saved = {}
    cli, th, first = _start("pipe", saved)
    assert any(m.get("stdin") == "pipe" for m in first)
    _send(cli, {"t": "in", "b64": base64.b64encode(PAYLOAD).decode()})
    got = _recv_until(cli, lambda o: len(_out_bytes(o)) >= len(PAYLOAD))
    assert _out_bytes(got) == PAYLOAD               # byte-exact both ways (no echo, no CRLF)
    _send(cli, {"t": "eof"})
    done = _recv_until(cli, lambda o: any(m["t"] == "exit" for m in o))
    assert any(m["t"] == "eof" and m["closed"] for m in done)
    ex = [m for m in done if m["t"] == "exit"]
    assert ex and ex[0]["code"] == 0                # cat saw end-of-file and exited cleanly
    _send(cli, {"t": "save"})
    _recv_until(cli, lambda o: any(m["t"] == "saved" for m in o), 2.0)
    cli.close(); th.join(timeout=5)
    assert saved.get("data") == PAYLOAD             # the seed is exactly what was sent


def test_a_binary_frame_is_raw_input():
    saved = {}
    cli, th, _ = _start("pipe", saved)
    cli.sendall(_frame(0x2, b"\x01\x02\x00\xfe"))
    got = _recv_until(cli, lambda o: len(_out_bytes(o)) >= 4)
    assert _out_bytes(got) == b"\x01\x02\x00\xfe"
    _send(cli, {"t": "signal", "sig": "KILL"})
    cli.close(); th.join(timeout=5)


def test_terminal_mode_eof_ends_input_even_with_a_partial_line():
    saved = {}
    cli, th, first = _start("pty", saved)
    assert any(m.get("stdin") == "pty" for m in first)
    _send(cli, {"t": "in", "b64": base64.b64encode(b"abc").decode()})   # no newline
    _send(cli, {"t": "eof"})
    done = _recv_until(cli, lambda o: any(m["t"] == "exit" for m in o))
    ex = [m for m in done if m["t"] == "exit"]
    assert ex and ex[0]["code"] == 0                # ^D^D: line delivered, then EOF
    assert b"abc" in _out_bytes(done)
    _send(cli, {"t": "save"})
    _recv_until(cli, lambda o: any(m["t"] == "saved" for m in o), 2.0)
    cli.close(); th.join(timeout=5)
    assert saved.get("data") == b"abc"              # no ^D in the seed


def test_an_unknown_stdin_mode_falls_back_to_the_terminal():
    cli, th, first = _start("bogus", {})
    assert any(m.get("stdin") == "pty" for m in first)
    _send(cli, {"t": "signal", "sig": "KILL"})
    cli.close(); th.join(timeout=5)
