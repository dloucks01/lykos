"""Data-flow taint over Ghidra low-P-Code (deterministic).

Intra-procedural: flow-sensitive CFG fixpoint, def-use with kill-on-redefine, per-arch ABI
registers. Inter-procedural: a summary-based fixpoint over the call graph that (a) pushes
tainted call arguments into callees' entry parameters, and (b) pulls tainted return values
back to callers. So a source in a caller reaching a sink deep in a callee, and source-wrapper
functions, are handled.

Taint origins are (a) calls to catalog.SOURCES (read/fgets/getenv/...) and (b) the entry
point's own parameters -- argv/envp, which the loader hands to main with no call site to
observe (see catalog.ENTRY_PARAM_SOURCES).

Honest limits: register-granularity (no precise memory/points-to model, so buffer taint via
pointer args is not tracked) and raw low-P-Code (call args inferred from ABI registers).
Path-insensitive: a flow guarded by a correct bounds check still reports as a flow, because
the analysis models where attacker bytes GO, not whether the destination is large enough.
"""
from __future__ import annotations

from collections import defaultdict, deque

from .catalog import (
    DANGEROUS,
    OUT_PARAM_SOURCES,
    SINK_TAINT_ARGS,
    SOURCES,
    normalize,
)

# Per-arch calling convention (register NAMES, upper-cased; families cover sub-registers).
# Per-arch calling convention. "frame" lists the registers that legitimately serve as a
# stack/frame base, so [BASE + const] spill slots can be tracked (see _frame_slot). It is
# per-arch on purpose: R1 is the stack pointer on PowerPC but an ARGUMENT register on ARM, so
# a shared list would invent slots keyed on a register that changes on every call.
ARCH_ABI = {
    "x86-64": {"ret": {"RAX", "EAX"},
               "args": [{"RDI", "EDI"}, {"RSI", "ESI"}, {"RDX", "EDX"},
                        {"RCX", "ECX"}, {"R8", "R8D"}, {"R9", "R9D"}],
               "frame": {"RBP", "RSP"}},
    # cdecl passes everything on the stack, so "args" is empty and the two "stack_*" keys
    # carry the convention instead (see _arg_taints / _push_taint):
    #   stack_params -- the callee sees its own parameters at [EBP + 8 + 4i] once the standard
    #                   prologue has run, which the frame-slot tracker already resolves.
    #   stack_call   -- the caller PUSHes arguments right-to-left, so at the CALL the most
    #                   recent push is argument 0.
    "x86":    {"ret": {"EAX"}, "args": [],
               "frame": {"EBP", "ESP"},
               "stack_params": {"base": "EBP", "offset0": 8, "stride": 4},
               "stack_call": {"base": "ESP", "stride": 4}},
    "aarch64": {"ret": {"X0", "W0"},
                "args": [{"X%d" % i, "W%d" % i} for i in range(8)],
                "frame": {"X29", "SP"}},
    # R7 is the Thumb frame pointer. Measured on a gcc -O0 Thumb build of the guard fixture:
    # every local is addressed [r7,#n] and r11 never appears, so without R7 no stack argument
    # on this ISA resolves at all.
    "arm":    {"ret": {"R0"}, "args": [{"R0"}, {"R1"}, {"R2"}, {"R3"}],
               "frame": {"R11", "FP", "R7", "SP"}},
    "mips":   {"ret": {"V0"}, "args": [{"A0"}, {"A1"}, {"A2"}, {"A3"}],
               "frame": {"FP", "S8", "SP"}},
    "ppc":    {"ret": {"R3"}, "args": [{"R%d" % i} for i in range(3, 11)],
               "frame": {"R1", "R31"}},
    "ppc64":  {"ret": {"R3"}, "args": [{"R%d" % i} for i in range(3, 11)],
               "frame": {"R1", "R31"}},
    # RV32/RV64 share register names (verified against Ghidra: lowercase a0..a7, s0 = frame
    # pointer), so one row covers both -- the ELF machine id does not distinguish them either.
    "riscv":  {"ret": {"A0"}, "args": [{"A%d" % i} for i in range(8)],
               "frame": {"S0", "SP"}},
    # Verified against Ghidra's lp64d.cspec and real P-Code: integer args a0-a7 (the cspec
    # lists fa0-fa7 ahead of them, but those are the FLOAT pentries), fp/sp as frame bases.
    "loongarch": {"ret": {"A0"}, "args": [{"A%d" % i} for i in range(8)],
                  "frame": {"FP", "SP"}},
    # m68k has no argument registers at all (68000.cspec declares none) -- SysV m68k passes
    # everything on the stack, exactly like cdecl. `link A6` establishes the frame, so the
    # callee reads parameters from [A6 + 8 + 4i], and calls push onto SP.
    "m68k":   {"ret": {"D0"}, "args": [],
               "frame": {"A6", "SP"},
               "stack_params": {"base": "A6", "offset0": 8, "stride": 4},
               "stack_call": {"base": "SP", "stride": 4}},
    # SPARC register windows: the CALLER writes arguments to o0-o5, then `save` rotates the
    # window and the CALLEE reads the very same values as i0-i5. "args" is the caller side
    # (what a call site stages) and "param_regs" the callee side (what an entry point
    # receives) -- without the split, seeding main's argv would mark the wrong register file.
    # Verified against real P-Code: `mov i0,g1` / `stx i1,[fp+0x887]` in main's prologue.
    "sparc":  {"ret": {"O0"}, "args": [{"O%d" % i} for i in range(6)],
               "param_regs": [{"I%d" % i} for i in range(6)],
               "frame": {"FP", "SP"}},
    "sparcv9": {"ret": {"O0"}, "args": [{"O%d" % i} for i in range(6)],
                "param_regs": [{"I%d" % i} for i in range(6)],
                "frame": {"FP", "SP"}},
    # SuperH: verified against superh.cspec and real P-Code -- integer args r4-r7 (the cspec
    # lists fr4-fr11/dr4-dr10 first, which are the FLOAT pentries), r0 return, r14 frame
    # pointer / r15 stack pointer.
    "sh":     {"ret": {"R0"}, "args": [{"R%d" % i} for i in range(4, 8)],
               "frame": {"R14", "R15"}},
}
# Sub-register aliasing. The ABI table groups a parameter's register with its narrower
# alias ({"RSI", "ESI"}), and a seed marks the whole group -- but a later write names only
# one of them, so killing just that name would leave the alias tainted for the rest of the
# function and every downstream sink would inherit it. Writing either name defines the other
# (a 32-bit write zero-extends), so define and kill operate on the whole family.
_REG_FAMILY = {}
for _abi in ARCH_ABI.values():
    for _grp in list(_abi["args"]) + [_abi["ret"]]:
        for _r in _grp:
            _REG_FAMILY.setdefault(_r, set()).update(_grp)

# x86/x86-64 SUB-REGISTER aliases. The ABI groups above only relate the 64- and 32-bit forms
# (RAX<->EAX), so tainting RAX did NOT taint AL/AX -- and `movzx eax, al` (read the low byte of a
# tainted register) then read a "clean" AL and CLEARED the whole chain, so a value assembled from a
# tainted buffer's bytes (a length field, `buf[0]`) lost its taint before reaching the sink. Relate
# every register to its 32/16/8-bit sub-registers so a byte read of a tainted register stays tainted.
# Over-approximate (whole family), the safe direction for a bug-finding taint that a second channel
# still has to corroborate.
_X86_SUBREGS = [
    ("RAX", "EAX", "AX", "AL", "AH"), ("RBX", "EBX", "BX", "BL", "BH"),
    ("RCX", "ECX", "CX", "CL", "CH"), ("RDX", "EDX", "DX", "DL", "DH"),
    ("RSI", "ESI", "SI", "SIL"), ("RDI", "EDI", "DI", "DIL"),
    ("RBP", "EBP", "BP", "BPL"), ("RSP", "ESP", "SP", "SPL"),
    *[(f"R{_n}", f"R{_n}D", f"R{_n}W", f"R{_n}B") for _n in range(8, 16)],
]
for _grp in _X86_SUBREGS:
    for _r in _grp:
        _REG_FAMILY.setdefault(_r, set()).update(_grp)

_MAX_BLOCKS = 3000
_MAX_FUNCS = 6000


def _arch_key(arch):
    a = (arch or "").lower()
    if a in ARCH_ABI:
        return a
    return "ppc" if a.startswith("ppc") else None


def _key(tok):
    parts = tok.split(":")
    if len(parts) >= 3 and parts[0] == "reg":
        return ("reg", parts[1].upper())
    if len(parts) >= 3:
        return None if parts[0] == "const" else (parts[0], parts[1])
    return None


def _parse(pc):
    if " -> " in pc:
        left, out = pc.split(" -> ", 1)
        outk = _key(out.strip())
    else:
        left, outk = pc, None
    toks = left.split()
    if not toks:
        return None, [], None, []
    ins = [k for k in (_key(t) for t in toks[1:]) if k is not None]
    return toks[0], ins, outk, toks


# --------------------------------------------------------------- frame-slot (spill) tracking
# At -O0 a function's parameters are spilled to the stack in its prologue and reloaded on
# every use, so register-only taint dies at the first spill: `main`'s argv lands in
# [RBP-0x10] and every later read comes from memory the analysis does not model. That makes
# the entry-param seed useless for anything in main itself.
#
# The tractable subset of a memory model is a CONSTANT-OFFSET FRAME SLOT. Ghidra emits the
# address arithmetic as p-code in the SAME instruction as the access:
#
#     INT_ADD reg:RBP const:0xfffffffffffffff0 -> unique:0x8f00
#     STORE   const:0x1b1 unique:0x8f00 unique:0xd500     (spill)
#     ...
#     INT_ADD reg:RBP const:0xfffffffffffffff0 -> unique:0x8f00
#     LOAD    const:0x1b1 unique:0x8f00 -> unique:0x23e00  (reload)
#
# so recognising `[BASE + const]` needs no cross-instruction state: the map is rebuilt per
# instruction and the taint itself lives in the caller's set, keyed ("stack", BASE, offset).
# Anything more general (aliasing, computed indices, heap) stays out of scope by design.
def _const_val(tok, consts):
    """The literal value of an operand: a `const:` token, or a unique holding one.

    Only x86 puts the displacement straight into the INT_ADD. RISC-V (and other RISC
    encodings) materialise it first -- `COPY const:-0x20 -> unique:U` then
    `INT_ADD reg:s0 unique:U` -- so resolving through single-instruction uniques is what
    makes frame-slot tracking work off x86 at all.
    """
    parts = tok.split(":")
    if len(parts) >= 2 and parts[0] == "const":
        try:
            return int(parts[1], 0)
        except ValueError:
            return None
    return consts.get(_key(tok))


def _base_of(k, bases, aliases):
    """Resolve a varnode to (frame base, offset), directly or through a derived alias."""
    if k is None or k[0] != "reg":
        return None
    if k[1] in bases:
        return (k[1], 0)
    return aliases.get(k)


def _frame_slot(toks, consts, bases, aliases):
    """Recognise `INT_ADD <frame base or alias> <displacement>` -> slot key, else None."""
    if len(toks) < 3:
        return None
    a, b = _key(toks[1]), _key(toks[2])
    for reg_tok, disp_tok in ((a, toks[2]), (b, toks[1])):    # either operand order
        base = _base_of(reg_tok, bases, aliases)
        if base is None:
            continue
        off = _const_val(disp_tok, consts)
        if off is not None:
            return ("stack", base[0], base[1] + off)
    return None


def _track_alias(outk, mnem, toks, consts, bases, aliases, slots=None):
    """Maintain `register -> (frame base, offset)` for DERIVED frame bases.

    SuperH (and others) stage a scratch pointer instead of addressing the frame register
    directly:  `mov r14,r1` ; `add #-0x38,r1` ; `mov.l r4,@(0x3c,r1)`. Without following r1
    the spill is invisible and the whole architecture yields no data flow. Resolving it to an
    R14-relative offset keeps the slot key stable (which a raw ("stack","R1",0x3c) key would
    not be, since r1 is a scratch register).

    Any define that is not a recognised base/alias propagation clears the alias, so a
    reused scratch register cannot keep a stale frame identity.
    """
    if outk is None or outk[0] != "reg":
        return
    if mnem == "COPY" and len(toks) >= 2:
        src = _base_of(_key(toks[1]), bases, aliases)
        if src is None and slots is not None:
            # The address was computed into a UNIQUE earlier in this same instruction:
            #   INT_ADD RBP,-0x210 -> unique ; COPY unique -> RAX
            # `slots` holds that fact, but this function only consulted `aliases`, and
            # `aliases` is never written for a unique (it returns early unless the output is a
            # register). So the chain unique -> RAX -> RDI never started, and no register ever
            # became a known pointer into the frame -- which is why a buffer's address could
            # not be recognised at a call site.
            sl = slots.get(_key(toks[1]))
            if sl is not None:
                src = (sl[1], sl[2])
        if src is not None:
            aliases[outk] = src
            return
    elif mnem == "INT_ADD" and len(toks) >= 3:
        slot = _frame_slot(toks, consts, bases, aliases)
        if slot is not None:
            aliases[outk] = (slot[1], slot[2])
            return
    aliases.pop(outk, None)


def _define(taint, key, tainted):
    """Define `key` (and its sub-register aliases) as tainted or clean."""
    keys = [key]
    if key[0] == "reg":
        keys = [("reg", r) for r in _REG_FAMILY.get(key[1], (key[1],))]
    for k in keys:
        taint.add(k) if tainted else taint.discard(k)


def _region_slots(addr_tok, via, heap_regions):
    """The `("hmem", base, off)` region tokens the pointer `addr_tok` may name (P1.2).

    For every stack-slot origin of the address that is a KNOWN heap-pointer slot (a slot that
    holds a single-writer allocation, from `bounds._heap_capacities`), produce its region token.
    `_origins` spans blocks (P1.1), so the slot the pointer was loaded from is still visible even
    when that load and this access are in different basic blocks. Region-granular on purpose: the
    index is not modelled, so one token covers the whole allocation -- conservative, to recover a
    downstream read of attacker-written heap memory without over-tainting arbitrary pointers.
    """
    if not heap_regions:
        return ()
    out = []
    for org in _origins(_key(addr_tok), via):
        if isinstance(org, tuple) and len(org) == 3 and org[0] == "stack":
            base, off = org[1], org[2]
            soff = off
            for b in (64, 32):                       # the slot table carries signed displacements
                if off >= (1 << (b - 1)):
                    soff = off - (1 << b)
                    break
            if (base, soff) in heap_regions or (base, off) in heap_regions:
                out.append(("hmem", base, off))
    return out


def _apply(taint, ops, bases=(), aliases=None, mem_out=None, via=None, heap_regions=None):
    slots = {}                       # varnode key -> frame-slot key (this instruction only)
    consts = {}                      # varnode key -> literal value  (this instruction only)
    # What each computed value was built FROM. A dominating guard compares the INDEX, not the
    # finished pointer, and at -O0 the index reaches its dereference as
    # slot -> unique -> register -> unique, so this is per BLOCK, like aliases.
    via = {} if via is None else via
    aliases = {} if aliases is None else aliases         # reg -> (base, off), per BLOCK
    for pc in ops:
        try:
            mnem, ins, outk, toks = _parse(pc)
        except Exception:
            continue

        if outk is not None and mnem == "COPY" and len(toks) >= 2:
            cv = _const_val(toks[1], consts)             # const materialised into a unique
            if cv is not None:
                consts[outk] = cv

        if mnem == "INT_ADD" and outk is not None:
            slot = _frame_slot(toks, consts, bases, aliases)
            if slot is not None:
                slots[outk] = slot

        _track_alias(outk, mnem, toks, consts, bases, aliases, slots)

        if mnem == "STORE":
            # STORE space, addr, value -- spill a value into a frame slot (kill on overwrite)
            if len(toks) >= 4:
                dst = slots.get(_key(toks[2]))
                if dst is not None:
                    val = _key(toks[3])
                    _define(taint, dst, val is not None and val in taint)
                else:
                    # P1.2: a tainted store through a pointer loaded from a heap slot taints that
                    # slot's heap region, so a later read of the same allocation is tainted too.
                    if heap_regions and _key(toks[3]) in taint:
                        for tok in _region_slots(toks[2], via, heap_regions):
                            taint.add(tok)
                    if mem_out is not None:
                        _note_access(mem_out, "store", toks[2], taint, slots, via)
            continue

        if outk is None:
            continue

        if mnem == "LOAD" and len(toks) >= 3:
            # LOAD space, addr -> out. A known frame slot answers definitively; any other
            # address falls through to the generic rule, which keeps "load through a tainted
            # pointer yields tainted data" (that is how argv[1] stays tainted).
            src = slots.get(_key(toks[2]))
            if src is not None:
                via[outk] = [src]        # this value IS that frame slot, as a guard sees it
                _define(taint, outk, src in taint)
                continue
            region = bool(heap_regions) and any(
                tok in taint for tok in _region_slots(toks[2], via, heap_regions))
            if mem_out is not None:
                _note_access(mem_out, "load", toks[2], taint, slots, via)
            if region:
                # P1.2: reading from a heap region a tainted store reached -> tainted data
                via.pop(outk, None)
                _define(taint, outk, True)
                continue

        if outk is not None and mnem in _ADDR_ARITH:
            ins_keys = [k for k in ins if k is not None]
            # Snapshot each input's origins BEFORE overwriting via[outk]. An in-place op --
            # `add rdx, rax -> rdx`, the normal -O0 shape for `base + index` -- otherwise loses
            # outk's own pre-op origin (the base pointer), because via[outk] is replaced and the
            # self-reference dead-ends in _origins. Folding the resolved origins in keeps both the
            # base-pointer slot and the index slot reachable (P1.1/P1.2).
            resolved = []
            for k in ins_keys:
                resolved.extend(_origins(k, via))
            via[outk] = list(dict.fromkeys(ins_keys + resolved))
        elif outk is not None:
            # A definition we do NOT track as an address computation (a non-slot LOAD, an
            # arithmetic/logical op outside _ADDR_ARITH) kills any origin this key carried in from
            # a predecessor block (seeded `via`, P1.1). Within a single block the key starts
            # unbound, so popping it is a no-op for the intra-block callers.
            via.pop(outk, None)
        _define(taint, outk, any(k in taint for k in ins))

        # The ADDRESS of tainted memory is itself a tainted pointer -- and this has to come
        # AFTER the generic rule, which otherwise clears it: `RBP + const` has no tainted
        # input, so the frame base looks clean even when the slot it names holds attacker
        # bytes, and `_define(..., False)` discards the fact on the same instruction that
        # established it.
        #
        # Without this the out-parameter seeding above is unreachable in practice.
        # `strcpy(dst, line)` passes the ADDRESS of `line`; the argument register holds a
        # pointer, not the bytes, so the sink check -- which asks whether an argument register
        # is tainted -- never sees it. This is the rule that already makes argv work, applied
        # to a buffer the program filled itself.
        if outk is not None and slots.get(outk) in taint:
            _define(taint, outk, True)


# Operations that build an address out of a base and something else.
_ADDR_ARITH = {"INT_ADD", "INT_SUB", "INT_MULT", "INT_LEFT", "PTRADD", "PTRSUB", "COPY",
               "INT_ZEXT", "INT_SEXT", "SUBPIECE", "MULTIEQUAL"}


def _note_access(mem_out, kind, addr_tok, taint, slots, via=None):
    """Record a memory access whose address is attacker-influenced.

    A recovered frame slot is excluded by the caller: its address is a fixed displacement,
    not something an input can move. What is left is a dereference through a pointer the
    input had a hand in computing, which is the shape of every out-of-bounds read and write
    -- and the shape the rule channel cannot see at all, because it is not a CALL.
    """
    ak = _key(addr_tok)
    if ak is not None and ak in taint:
        mem_out.append({"kind": kind, "addr_key": ak, "via": _origins(ak, via)})


def _origins(key, via, depth=8):
    """Every value this address was computed from, followed back through the block.

    Transitively: one hop is not enough, and the frame slot the guard compares sits at the far
    end of the chain.
    """
    seen, order, frontier = {key}, [key], [key]
    for _ in range(depth):
        nxt = []
        for k in frontier:
            for src in (via or {}).get(k, ()):
                if src is not None and src not in seen:
                    seen.add(src)
                    order.append(src)
                    nxt.append(src)
        if not nxt:
            break
        frontier = nxt
    return order


def _carry_origins(via):
    """The part of a block's exit `via` that is STABLE across a block boundary (P1.1).

    `via` keys are register, stack-slot or `unique` p-code temporaries. Uniques are block-local
    (the next block's p-code reuses the numbers for unrelated values), so only register- and
    stack-keyed values are carried; each is resolved to the frame-slot origin(s) a guard compares,
    so the successor block sees the origin in one hop.
    """
    out = {}
    for k in list(via):
        if isinstance(k, tuple) and k and k[0] in ("reg", "stack"):
            origins = [o for o in _origins(k, via)
                       if o != k and isinstance(o, tuple) and o[0] == "stack"]
            if origins:
                out[k] = origins
    return out


def _merge_origins(maps):
    """Merge predecessor origin maps at a block entry. A binding is carried only when EVERY
    predecessor agrees on it (same key, same origin set) -- the intersection. This is what keeps
    it sound: if the paths into a block disagree about where a value came from, no slot is claimed,
    so a guard on one path cannot be fabricated onto the merged value."""
    maps = [m for m in maps if m]
    if not maps:
        return {}
    common = set(maps[0])
    for m in maps[1:]:
        common &= set(m)
    out = {}
    for k in common:
        vals = [tuple(m[k]) for m in maps]
        if all(v == vals[0] for v in vals):
            out[k] = list(vals[0])
    return out


def _has_abi(abi):
    """A usable calling convention: argument registers, or a stack convention."""
    return bool(_arg_regs(abi) or abi.get("stack_call"))


def _arg_regs(abi):
    regs = set()
    for a in abi["args"]:
        regs |= a
    return regs


_MAX_STACK_ARGS = 8


def _arg_taints(taint, argregs_list, pushes):
    """Taint of each argument position, as a list of bools.

    Register ABIs read the argument registers directly. Stack ABIs (cdecl) read the pending
    push list: arguments go right-to-left, so the most recent push is argument 0.
    """
    if argregs_list:
        return [any(("reg", r) in taint for r in grp) for grp in argregs_list]
    return [pushes[-1 - i] for i in range(min(len(pushes), _MAX_STACK_ARGS))]


def _sink_tainted(argt, sink):
    """Is the argument that MAKES this sink a bug tainted?

    Falls back to "any argument" for sinks with no declared position (see
    catalog.SINK_TAINT_ARGS), so an unlisted sink keeps the old conservative behaviour.
    """
    idx = SINK_TAINT_ARGS.get(sink)
    if idx is None:
        return any(argt)
    return any(argt[i] for i in idx if i < len(argt))


def _push_taint(ops, taint, base):
    """If this instruction is a `PUSH <value>` onto `base`, return that value's taint.

    The cdecl idiom is a stack-pointer decrement plus a store through it, in one instruction:

        COPY    reg:EAX:4 -> unique:0x41500:4
        INT_SUB reg:ESP:4 const:0x4:4 -> reg:ESP:4
        STORE   const:0x1a1:8 reg:ESP:4 unique:0x41500:4

    Read AFTER _apply, so the COPY has already propagated taint into the unique. Returns None
    when the instruction is not a push. ESP-relative slot KEYS are deliberately not used:
    the stack pointer moves, so ("stack","ESP",0) names different memory at different points.
    """
    dec = False
    val = None
    for pc in ops:
        try:
            mnem, _, outk, toks = _parse(pc)
        except Exception:
            continue
        if mnem == "INT_SUB" and outk == ("reg", base) and len(toks) >= 2 \
                and _key(toks[1]) == ("reg", base):
            dec = True
        elif mnem == "STORE" and len(toks) >= 4 and _key(toks[2]) == ("reg", base):
            val = _key(toks[3])
    if not dec:
        return None
    return val is not None and val in taint


def build_callmap(call_edges):
    return {e.site_addr: normalize(e.dst_name) for e in call_edges if e.site_addr}


def _run(ir, abi, callmap, dstmap, func_addrs, entry_params, ret_tainted, *, oversized=None,
         seed_sources=True, extmap=None, ext_out=None, mem_out=None, heap_regions=None):
    """Analyze one function. Returns (flagged_sink_sites, return_is_tainted, callee_contribs).

    Cross-binary hooks (Phase 8, doc 17.2):
      * seed_sources=False disables SOURCES seeding so taint originates only from the
        seeded entry params -- used to summarise a callee export (does tainting its
        parameter reach a sink?).
      * extmap {site: imported_symbol} + ext_out set: record imported symbols called with
        tainted arguments -- used to summarise a caller (which imports does it taint?).
      * heap_regions {(base, offset)}: this function's heap-pointer slots (P1.2) -- a tainted
        store through one taints its region; a load from it reads tainted (disabled with the
        LYKOS_REGION_TAINT flag).
    """
    import os as _osr
    if _osr.environ.get("LYKOS_REGION_TAINT", "1") == "0":
        heap_regions = None
    argregs_list = abi["args"]
    retregs = abi["ret"]
    stack_call = abi.get("stack_call")
    stack_params = abi.get("stack_params")
    blocks = (ir or {}).get("blocks", [])
    if not blocks or len(blocks) > _MAX_BLOCKS:
        # A function past the block ceiling is skipped whole, and the callers could not tell
        # that from "this function has no tainted flow" -- the same shape as the
        # whole-analysis ceiling, one level down. `oversized` counts them so the stage can
        # say how much of the program was not looked at.
        if len(blocks) > _MAX_BLOCKS and oversized is not None:
            oversized.append(len(blocks))
        return set(), False, {}

    by_addr = {b["addr"]: b for b in blocks}
    order = [b["addr"] for b in blocks]
    entry = order[0]
    preds = defaultdict(set)
    for b in blocks:
        for s in b.get("succ", []):
            preds[s].add(b["addr"])
    paramregs_list = abi.get("param_regs") or argregs_list
    pre = set()
    for i in entry_params:
        if i < len(paramregs_list):
            for r in paramregs_list[i]:
                pre.add(("reg", r))
        if stack_params is not None:
            # cdecl: the callee reads parameter i from [EBP + 8 + 4i] after its prologue
            pre.add(("stack", stack_params["base"],
                     stack_params["offset0"] + stack_params["stride"] * i))

    def transfer(cur, instr, flagged, contribs, pushes, aliases, collect=None,
                 via=None):
        addr = instr.get("addr")
        ext = callmap.get(addr)
        dst = dstmap.get(addr)
        internal = dst in func_addrs
        # Argument taint is read BEFORE this instruction's own p-code runs: for a CALL the
        # arguments were staged by earlier instructions (registers, or pushes).
        argt = _arg_taints(cur, argregs_list, pushes)
        if ext in DANGEROUS:
            import os as _os2
            if _os2.environ.get("LYKOS_TAINT_DEBUG"):
                print("SINK", ext, addr, "argt:", argt[:3],
                      "stack-taint:", [k for k in cur if k[0]=="stack"][:3])
        if ext in DANGEROUS and _sink_tainted(argt, ext):
            flagged.add(addr)
        if extmap is not None and ext_out is not None:
            esym = extmap.get(addr)
            if esym and any(argt):
                ext_out.add(esym)
        tainted_params = {i for i, t in enumerate(argt) if t} if internal else set()
        seen = [] if collect is not None else None
        _apply(cur, instr.get("pcode", []), abi.get("frame", ()), aliases, seen,
               via, heap_regions)
        for acc in (seen or ()):
            collect.append({**acc, "site_addr": addr})
        if stack_call is not None:
            pushed = _push_taint(instr.get("pcode", []), cur, stack_call["base"])
            if pushed is not None:
                pushes.append(pushed)
        if seed_sources and ext in SOURCES:
            cur |= {("reg", r) for r in retregs}
            # ...and, for the ones that fill a CALLER-SUPPLIED BUFFER, the buffer itself.
            # `read(fd, buf, n)` returns a byte COUNT; the untrusted data lands in `buf`.
            # Tainting only the return register modelled getchar() correctly and every
            # file-reading parser not at all -- measured on a fixture with two paths to the
            # same sink, the argv path was corroborated and the fread path was not flagged.
            import os as _os
            if _os.environ.get("LYKOS_TAINT_DEBUG"):
                print("SRC", ext, "regaliases:",
                      {k[1]: v for k, v in aliases.items() if k[0]=="reg"})
            _bi = OUT_PARAM_SOURCES.get(ext)
            if _bi is not None and argregs_list and _bi < len(argregs_list):
                for _r in argregs_list[_bi]:
                    _slot = aliases.get(("reg", _r))
                    if _slot is not None:
                        cur.add(("stack", _slot[0], _slot[1]))
                        break
        if internal:
            if tainted_params:
                contribs[dst] = contribs.get(dst, set()) | tainted_params
            if ret_tainted.get(dst):
                cur |= {("reg", r) for r in retregs}
        if ext is not None or internal:
            # the call consumed its staged arguments (and a CALL also pushes a return
            # address, which must not be mistaken for the next call's argument 0)
            del pushes[:]

    # Inter-block taint-origin tracking (doc 30 P1.1): the per-block `via` chain drops a value's
    # frame-slot origin at a block boundary, so a guard in one block and the dereference it
    # protects in another never resolve to the same slot (the computed-index-at-O2 miss in doc 20).
    # Carry the register/stack origin map across edges, merged at entry like the taint set. Register
    # and stack keys are block-stable; uniques are not and are dropped (_carry_origins). Guarded by
    # a flag. Computed BEFORE the taint fixpoint so that pass can seed `via` and resolve the slot a
    # heap pointer came from (P1.2 region taint). Needed whenever origins feed a consumer: the
    # computed-index mem_out, or region taint.
    import os as _os3
    interblock = _os3.environ.get("LYKOS_INTERBLOCK_ORIGINS", "1") != "0"
    need_via = interblock and (mem_out is not None or heap_regions)
    VIA_OUT = {a: {} for a in order}
    if need_via:
        for _ in range(len(blocks) * 4 + 10):
            vchanged = False
            for a in order:
                vvia = dict(_merge_origins([VIA_OUT[p] for p in preds[a]]))
                valias, tdummy = {}, set()
                for instr in by_addr[a]["instructions"]:
                    _apply(tdummy, instr.get("pcode", []), abi.get("frame", ()),
                           valias, None, vvia)
                vout = _carry_origins(vvia)
                if vout != VIA_OUT[a]:
                    VIA_OUT[a] = vout
                    vchanged = True
            if not vchanged:
                break

    def _seed_via(a):
        return dict(_merge_origins([VIA_OUT[p] for p in preds[a]])) if need_via else {}

    OUT = {a: set() for a in order}
    for _ in range(len(blocks) * 4 + 10):
        changed = False
        for a in order:
            cur = set()
            for p in preds[a]:
                cur |= OUT[p]
            if a == entry:
                cur |= pre
            f, c, pushes, aliases = set(), {}, [], {}
            via = _seed_via(a)              # seed origins so region taint resolves heap pointers
            for instr in by_addr[a]["instructions"]:
                transfer(cur, instr, f, c, pushes, aliases, None, via)
            if cur != OUT[a]:
                OUT[a] = cur
                changed = True
        if not changed:
            break

    flagged, contribs = set(), {}
    for a in order:
        cur = set()
        for p in preds[a]:
            cur |= OUT[p]
        if a == entry:
            cur |= pre
        pushes, aliases = [], {}
        acc = [] if mem_out is not None else None
        # the origin chain, seeded from predecessors (P1.1) so it spans blocks, not just instrs
        via = _seed_via(a)
        for instr in by_addr[a]["instructions"]:
            transfer(cur, instr, flagged, contribs, pushes, aliases, acc, via)
        for x in (acc or ()):
            mem_out.append({**x, "block_addr": a})

    exits = [a for a in order if not by_addr[a].get("succ")] or order
    ret_bool = any(("reg", r) in OUT[a] for a in exits for r in retregs)
    return flagged, ret_bool, contribs


def analyze_function(ir, callmap, arch):
    """Intra-procedural only (kept for direct use/tests)."""
    ak = _arch_key(arch)
    if not ak or not _has_abi(ARCH_ABI[ak]):
        return set()
    flagged, _, _ = _run(ir, ARCH_ABI[ak], callmap, {}, set(), set(), {})
    return flagged


def analyze_program(func_irs, call_edges, arch, *, entry_seeds=None, mem_out=None,
                    max_funcs=None, skipped_out=None, heap_regions=None):
    """Inter-procedural: fixpoint over the call graph. Returns all flagged sink sites.

    `entry_seeds` maps an entry-point function addr -> the parameter indices that arrive
    already tainted (see catalog.entry_seed_params). This is how argv/envp enter the
    analysis: they are handed to main by the loader, so unlike SOURCES input there is no
    call site to observe. Without a seed an argv-driven program has no taint origin and
    nothing can be corroborated.

    `mem_out`, when given, also collects every attacker-influenced memory access -- a
    dereference through a pointer the input helped compute. Those are invisible to every
    other detector, which all key on CALLS, and they are where the out-of-bounds reads and
    writes live.

    `heap_regions` maps a function addr -> the set of `(base, offset)` frame slots that hold a
    heap allocation (P1.2). A tainted store through such a pointer taints its region and a later
    read of the same allocation comes back tainted -- so attacker data that lands in heap memory
    is not lost at the store.
    """
    heap_regions = heap_regions or {}
    ak = _arch_key(arch)
    if not ak or not _has_abi(ARCH_ABI[ak]):
        return set()
    abi = ARCH_ABI[ak]
    func_addrs = set(func_irs.keys())
    if not func_addrs or len(func_addrs) > (max_funcs or _MAX_FUNCS):
        return set()
    callmap = build_callmap(call_edges)
    dstmap = {e.site_addr: e.dst_addr for e in call_edges if e.site_addr and e.dst_addr}
    callers = defaultdict(set)
    for e in call_edges:
        if e.dst_addr and e.src_addr:
            callers[e.dst_addr].add(e.src_addr)

    entry_params = {a: set() for a in func_addrs}
    for a, idx in (entry_seeds or {}).items():        # argv/envp at the program entry point
        if a in entry_params:
            entry_params[a] |= set(idx)
    ret_tainted = {a: False for a in func_addrs}
    wl = deque(func_addrs)
    inq = set(func_addrs)
    cap = len(func_addrs) * 8 + 200
    while wl and cap > 0:
        cap -= 1
        f = wl.popleft()
        inq.discard(f)
        _, retf, contribs = _run(func_irs[f], abi, callmap, dstmap, func_addrs,
                                 entry_params[f], ret_tainted,
                                 heap_regions=heap_regions.get(f))
        if retf and not ret_tainted[f]:
            ret_tainted[f] = True
            for c in callers.get(f, ()):
                if c in func_addrs and c not in inq:
                    wl.append(c); inq.add(c)
        for g, params in contribs.items():
            if g in entry_params and (params - entry_params[g]):
                entry_params[g] |= params
                if g not in inq:
                    wl.append(g); inq.add(g)

    flagged = set()
    big: list = []
    for f in func_addrs:
        acc = [] if mem_out is not None else None
        ff, _, _ = _run(func_irs[f], abi, callmap, dstmap, func_addrs,
                        entry_params[f], ret_tainted, mem_out=acc, oversized=big,
                        heap_regions=heap_regions.get(f))
        flagged |= ff
        for x in (acc or ()):
            mem_out.append({**x, "function_addr": f})
    if big and skipped_out is not None:
        skipped_out.extend(big)
    return flagged


# ---------------------------------------------------- cross-binary summaries (Phase 8, 17.2)
def _program(func_irs, call_edges, arch, *, seed_params=None, seed_sources=True):
    """Inter-procedural fixpoint with optional entry-param seeds and SOURCES toggle.

    Returns (flagged_sink_sites, tainted_imported_symbols). `seed_params` maps a function
    entry addr -> set of tainted parameter indices; `seed_sources=False` makes the seed the
    only taint origin (callee-export summary).
    """
    ak = _arch_key(arch)
    if not ak or not _has_abi(ARCH_ABI[ak]):
        return set(), set()
    abi = ARCH_ABI[ak]
    func_addrs = set(func_irs)
    if not func_addrs or len(func_addrs) > _MAX_FUNCS:
        return set(), set()
    callmap = build_callmap(call_edges)
    dstmap = {e.site_addr: e.dst_addr for e in call_edges if e.site_addr and e.dst_addr}
    extmap = {e.site_addr: normalize(e.dst_name) for e in call_edges
              if e.site_addr and e.external and e.dst_name}
    callers = defaultdict(set)
    for e in call_edges:
        if e.dst_addr and e.src_addr:
            callers[e.dst_addr].add(e.src_addr)

    entry_params = {a: set() for a in func_addrs}
    for a, ps in (seed_params or {}).items():
        if a in entry_params:
            entry_params[a] |= set(ps)
    ret_tainted = {a: False for a in func_addrs}
    wl = deque(func_addrs)
    inq = set(func_addrs)
    cap = len(func_addrs) * 8 + 200
    while wl and cap > 0:
        cap -= 1
        f = wl.popleft()
        inq.discard(f)
        _, retf, contribs = _run(func_irs[f], abi, callmap, dstmap, func_addrs,
                                 entry_params[f], ret_tainted, seed_sources=seed_sources)
        if retf and not ret_tainted[f]:
            ret_tainted[f] = True
            for c in callers.get(f, ()):
                if c in func_addrs and c not in inq:
                    wl.append(c); inq.add(c)
        for g, params in contribs.items():
            if g in entry_params and (params - entry_params[g]):
                entry_params[g] |= params
                if g not in inq:
                    wl.append(g); inq.add(g)

    flagged, ext = set(), set()
    for f in func_addrs:
        ff, _, _ = _run(func_irs[f], abi, callmap, dstmap, func_addrs, entry_params[f],
                        ret_tainted, seed_sources=seed_sources, extmap=extmap, ext_out=ext)
        flagged |= ff
    return flagged, ext


def caller_tainted_imports(func_irs, call_edges, arch) -> set:
    """Imported-symbol names this component calls with tainted (untrusted-input) arguments.
    These are the outbound boundaries where tainted data leaves this component."""
    _, ext = _program(func_irs, call_edges, arch, seed_sources=True)
    return ext


def callee_sink_exports(func_irs, call_edges, arch, name_to_addr, export_names,
                        max_exports=96) -> dict:
    """For each exported function named in `export_names`, does tainting its parameters
    reach a dangerous sink? Returns {export_name: set((cwe, sink_symbol))}."""
    ak = _arch_key(arch)
    if not ak or not _has_abi(ARCH_ABI[ak]):
        return {}
    nargs = len(ARCH_ABI[ak]["args"]) or 6
    callmap = build_callmap(call_edges)
    out: dict = {}
    n = 0
    for name in export_names:
        addr = name_to_addr.get(name)
        if not addr or addr not in func_irs:
            continue
        n += 1
        if n > max_exports:
            break
        flagged, _ = _program(func_irs, call_edges, arch,
                              seed_params={addr: set(range(nargs))}, seed_sources=False)
        sinks = set()
        for site in flagged:
            sym = callmap.get(site)
            if sym in DANGEROUS:
                sinks.add((DANGEROUS[sym][0], sym))
        if sinks:
            out[name] = sinks
    return out
