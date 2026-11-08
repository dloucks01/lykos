"""Interactive detonation console: run a target in the sandbox behind a PTY and proxy its
stdin/stdout live over a WebSocket, so an analyst can drive menus / protocol handshakes that
the one-shot dynamic stages can't reach -- and save the bytes they sent as a reusable seed.

Isolation reuses the Phase-4 sandbox (bwrap+netns when available, else rlimits-only; qemu-user
for cross-arch). The PTY makes interactive programs line-buffer and see a tty. Protocol is JSON
text frames both ways:
  server->client : {"t":"info",...} {"t":"out","b64":...} {"t":"exit","code"/"signal":...}
                   {"t":"saved","sha":...} {"t":"eof","closed":bool}
  client->server : {"t":"in","b64"|"s":...} {"t":"eof"} {"t":"signal","sig":"INT"} {"t":"save"}
                   or a BINARY frame (opcode 0x2): its payload is input bytes, sent as-is.

Two stdin channels, picked per session (`stdin=` on the /console URL):
  "pty"  (default) stdin, stdout and stderr are the terminal: line editing, echo, Ctrl-C/Ctrl-D
         keys. The line discipline interprets some bytes (^C ^D ^U DEL, CR->NL), so it is for
         menus and text protocols. "eof" sends ^D (twice when a partial line is pending, so the
         line is delivered and THEN the reader sees end-of-file).
  "pipe" stdin is a pipe: every byte reaches the target exactly (a binary protocol), and "eof"
         really closes it. stdout/stderr stay on the PTY (so stdio still line-buffers) in raw mode
         -- no CR/LF rewriting -- so the output bytes are exact too.
In both, "save as seed" stores exactly the bytes delivered as input, in order (no ^D, no echo).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import pty
import select
import signal as _signal
import subprocess
import termios
import time
import tty
from pathlib import Path

from .. import observe
from ..analyze.dynamic import sandbox
from . import ws

_log = logging.getLogger(__name__)

_HARD_CAP = 600.0        # overall wall-clock ceiling for one console session
_SEED_CAP = 4 << 20      # bytes of operator input kept for "save as seed" (bounded memory)
_SAVE_GRACE = 60.0       # seconds the socket stays open after the target exits, for "save as seed"
_PENDING_CAP = 8 << 20   # input queued for a target that is not reading (never block the proxy)
STDIN_MODES = ("pty", "pipe")


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
          timeout=_HARD_CAP, put_seed=None, stdin_mode="pty"):
    """Run `exe` under a PTY and proxy it over the (already-upgraded) WebSocket `sock`.
    `stdin_mode` is "pty" (the terminal) or "pipe" (exact bytes + a real EOF); see the module doc."""
    stdin_mode = stdin_mode if stdin_mode in STDIN_MODES else "pty"
    cmd, iso, emu = _build_cmd(exe, argv, arch, endianness, bits)
    rl = sandbox._rlimits(2048, int(min(timeout, _HARD_CAP)) + 5, set_as=(emu is None),
                          nproc=sandbox._nproc_cap(emu is not None))

    def _preexec():
        os.setsid()
        rl()

    mfd, sfd = pty.openpty()
    pin_r = pin_w = None
    if stdin_mode == "pipe":
        pin_r, pin_w = os.pipe()
        try:
            tty.setraw(sfd)                            # output bytes exact: no ONLCR, no echo
        except termios.error:
            observe.absorbed(_log, "pty raw mode unavailable; output may carry CR/LF rewriting")
    try:
        proc = subprocess.Popen(cmd, stdin=(pin_r if pin_r is not None else sfd), stdout=sfd,
                                stderr=sfd, close_fds=True, cwd=cwd, preexec_fn=_preexec)
    except OSError as e:
        _send(sock, {"t": "info", "msg": f"failed to start: {e}"})
        for fd in (mfd, sfd, pin_r, pin_w):
            if fd is not None:
                os.close(fd)
        return
    os.close(sfd)
    if pin_r is not None:
        os.close(pin_r)
    wfd = pin_w if pin_w is not None else mfd          # where operator input is written
    os.set_blocking(wfd, False)
    _send(sock, {"t": "info", "stdin": stdin_mode,
                 "msg": f"started [{iso}] pid {proc.pid} -- interactive, stdin "
                        + ("pipe (exact bytes, EOF closes it)" if pin_w is not None
                           else "terminal")})

    sent = bytearray()
    pending = bytearray()                              # input not yet accepted by the target
    close_after = False                                # pipe EOF requested behind pending input
    last_in = b"\n"                                    # last input byte: is a line pending?
    deadline = time.time() + min(timeout, _HARD_CAP)
    exited_at = None                                   # set on process exit -> short save grace

    def _queue(b: bytes) -> bool:
        nonlocal last_in
        if wfd is None:
            _send(sock, {"t": "info", "msg": "ignored input: stdin is closed"})
            return False
        if len(pending) + len(b) > _PENDING_CAP:
            _send(sock, {"t": "info", "msg": "ignored input: the target is not reading stdin"})
            return False
        if len(sent) < _SEED_CAP:                      # the seed is bounded; the target is not
            sent.extend(b[:_SEED_CAP - len(sent)])
        pending.extend(b)
        if b:
            last_in = b[-1:]
        return True

    def _close_stdin():
        nonlocal wfd, pin_w
        if pin_w is not None:
            try:
                os.close(pin_w)
            except OSError:
                pass
            pin_w = None
        wfd = None
        _send(sock, {"t": "eof", "closed": True})

    try:
        while True:
            if time.time() > deadline:
                _send(sock, {"t": "info", "msg": "wall-clock cap reached; terminating"})
                break
            if exited_at is not None and time.time() - exited_at > _SAVE_GRACE:
                break                                  # grace elapsed after exit
            waitfds = [sock] if exited_at is not None else [mfd, sock]
            wwait = [wfd] if (pending and wfd is not None and exited_at is None) else []
            r, w, _ = select.select(waitfds, wwait, [], 0.2)
            if w:
                try:
                    n = os.write(wfd, bytes(pending[:65536]))
                    del pending[:n]
                except BlockingIOError:
                    pass
                except OSError:                        # target closed its stdin (EPIPE)
                    pending.clear()
                    if pin_w is not None:
                        _close_stdin()
                if close_after and not pending and pin_w is not None:
                    close_after = False
                    _close_stdin()
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
                if op == 0x2:                          # binary frame: raw input bytes
                    if data and exited_at is None:
                        _queue(bytes(data))
                    continue
                msg = _parse(data)
                if msg is None:
                    continue
                t = msg.get("t")
                if t == "in":
                    try:
                        b = base64.b64decode(msg["b64"], validate=True) \
                            if msg.get("b64") is not None \
                            else str(msg.get("s", "")).encode("utf-8", "ignore")
                    except (ValueError, TypeError):
                        # bad base64 raised out of the loop and killed the session (and then
                        # the handler wrote an HTTP 500 into the upgraded socket)
                        _send(sock, {"t": "info", "msg": "ignored input: invalid base64"})
                        continue
                    if b and exited_at is None:
                        _queue(b)
                elif t == "eof":
                    if wfd is None:
                        _send(sock, {"t": "eof", "closed": True})
                    elif pin_w is not None:            # pipe: really close stdin (after pending)
                        if pending:
                            close_after = True
                        else:
                            _close_stdin()
                    else:
                        # terminal: ^D ends input for a canonical-mode reader -- but with a
                        # partial line pending the first ^D only delivers that line, so send two.
                        try:
                            canon = bool(termios.tcgetattr(mfd)[3] & termios.ICANON)
                        except termios.error:
                            canon = True
                        pending.extend(b"\x04\x04" if canon and last_in != b"\n" else b"\x04")
                        last_in = b"\n"
                        _send(sock, {"t": "eof", "closed": False})
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
        for fd in (mfd, pin_w):
            if fd is None:
                continue
            try:
                os.close(fd)
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
    """A client message, or None. Only a JSON OBJECT is a message: `[]`/`3`/`"x"` used to reach
    `msg.get(...)` and raise out of the proxy loop."""
    try:
        msg = json.loads(data.decode("utf-8", "ignore"))
    except ValueError:
        return None
    return msg if isinstance(msg, dict) else None


def _killpg(proc, sig):
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except Exception:
        observe.absorbed(_log, "falling back")
        try:
            proc.kill()
        except Exception:
            observe.absorbed(_log, "continuing")
