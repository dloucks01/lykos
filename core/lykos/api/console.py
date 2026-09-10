"""Interactive detonation console: run a target in the sandbox behind a PTY and proxy its
stdin/stdout live over a WebSocket, so an analyst can drive menus / protocol handshakes that
the one-shot dynamic stages can't reach -- and save the bytes they sent as a reusable seed.

Isolation reuses the Phase-4 sandbox (bwrap+netns when available, else rlimits-only; qemu-user
for cross-arch). The PTY makes interactive programs line-buffer and see a tty. Protocol is JSON
text frames both ways:
  server->client : {"t":"info",...} {"t":"out","b64":...} {"t":"exit","code"/"signal":...}
                   {"t":"saved","sha":...}
  client->server : {"t":"in","b64"|"s":...} {"t":"eof"} {"t":"signal","sig":"INT"} {"t":"save"}
"""
from __future__ import annotations

import base64
import json
import os
import pty
import select
import signal as _signal
import subprocess
import time
from pathlib import Path

from ..analyze.dynamic import sandbox
from . import ws

_HARD_CAP = 600.0        # overall wall-clock ceiling for one console session


def _build_cmd(exe, argv, arch, endianness, bits):
    host = sandbox.host_arch()
    emu = sandbox._qemu_for(arch, endianness, bits) if arch and arch != host else None
    inner = ([emu] if emu else []) + [str(exe)] + [str(a) for a in argv]
    if sandbox._bwrap_usable():
        exedir = str(Path(exe).resolve().parent)     # bind the exe dir ro past the /tmp tmpfs
        cmd = ["bwrap"] + sandbox._BWRAP_ARGS[:-1] + ["--ro-bind", exedir, exedir] + ["--"] + inner
        iso = "bwrap+netns" + ("+qemu" if emu else "")
    else:
        cmd, iso = inner, "rlimits-only" + ("+qemu" if emu else "")
    return cmd, iso, emu


def serve(sock, exe, *, argv=(), arch=None, endianness=None, bits=None, cwd=None,
          timeout=_HARD_CAP, put_seed=None):
    """Run `exe` under a PTY and proxy it over the (already-upgraded) WebSocket `sock`."""
    cmd, iso, emu = _build_cmd(exe, argv, arch, endianness, bits)
    rl = sandbox._rlimits(2048, int(min(timeout, _HARD_CAP)) + 5, set_as=(emu is None),
                          nproc=sandbox._nproc_cap(emu is not None))

    def _preexec():
        os.setsid()
        rl()

    mfd, sfd = pty.openpty()
    try:
        proc = subprocess.Popen(cmd, stdin=sfd, stdout=sfd, stderr=sfd, close_fds=True,
                                cwd=cwd, preexec_fn=_preexec)
    except OSError as e:
        _send(sock, {"t": "info", "msg": f"failed to start: {e}"})
        os.close(mfd); os.close(sfd)
        return
    os.close(sfd)
    _send(sock, {"t": "info", "msg": f"started [{iso}] pid {proc.pid} -- interactive"})

    sent = bytearray()
    deadline = time.time() + min(timeout, _HARD_CAP)
    exited_at = None                                   # set on process exit -> short save grace
    try:
        while True:
            if time.time() > deadline:
                _send(sock, {"t": "info", "msg": "wall-clock cap reached; terminating"})
                break
            if exited_at is not None and time.time() - exited_at > 3.0:
                break                                  # grace elapsed after exit
            waitfds = [sock] if exited_at is not None else [mfd, sock]
            r, _, _ = select.select(waitfds, [], [], 0.2)
            if mfd in r:
                try:
                    chunk = os.read(mfd, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    _send(sock, {"t": "out", "b64": base64.b64encode(chunk).decode()})
                elif proc.poll() is not None:
                    pass
            if sock in r:
                op, data = ws.read_frame(sock)
                if op is None or op == 0x8:            # EOF / client close
                    break
                if op == 0x9:                          # ping -> pong
                    try:
                        sock.sendall(ws.pong_frame(data))
                    except OSError:
                        break
                    continue
                msg = _parse(data)
                if msg is None:
                    continue
                t = msg.get("t")
                if t == "in":
                    b = base64.b64decode(msg["b64"]) if msg.get("b64") is not None \
                        else str(msg.get("s", "")).encode("utf-8", "ignore")
                    sent += b
                    try:
                        os.write(mfd, b)
                    except OSError:
                        break
                elif t == "eof":
                    try:
                        os.write(mfd, b"\x04")         # EOT -> EOF for a canonical-mode reader
                    except OSError:
                        pass
                elif t == "signal":
                    sig = {"INT": _signal.SIGINT, "TERM": _signal.SIGTERM,
                           "KILL": _signal.SIGKILL}.get(msg.get("sig"), _signal.SIGINT)
                    _killpg(proc, sig)
                elif t == "save" and put_seed:
                    try:
                        sha = put_seed(bytes(sent))
                        _send(sock, {"t": "saved", "sha": sha, "bytes": len(sent)})
                    except Exception as e:             # noqa: BLE001 - report to the client
                        _send(sock, {"t": "info", "msg": f"save failed: {e}"})
            if exited_at is None and proc.poll() is not None:
                _drain(sock, mfd)
                rc = proc.returncode
                _send(sock, {"t": "exit", "code": rc if rc is not None and rc >= 0 else None,
                             "signal": (-rc) if rc is not None and rc < 0 else None})
                _send(sock, {"t": "info", "msg": "process ended -- 'save as seed' still available"})
                exited_at = time.time()               # keep the socket briefly for a trailing save
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        _killpg(proc, _signal.SIGKILL)
        try:
            os.close(mfd)
        except OSError:
            pass
        try:
            sock.sendall(ws.close_frame())
        except OSError:
            pass


def _drain(sock, mfd):
    for _ in range(64):
        r, _, _ = select.select([mfd], [], [], 0)
        if mfd not in r:
            return
        try:
            chunk = os.read(mfd, 65536)
        except OSError:
            return
        if not chunk:
            return
        _send(sock, {"t": "out", "b64": base64.b64encode(chunk).decode()})


def _send(sock, obj):
    try:
        sock.sendall(ws.text_frame(json.dumps(obj)))
    except OSError:
        pass


def _parse(data):
    try:
        return json.loads(data.decode("utf-8", "ignore"))
    except ValueError:
        return None


def _killpg(proc, sig):
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
