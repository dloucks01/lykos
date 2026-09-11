"""Can this copy actually overflow its destination?

The rule channel flags every call to memcpy/strncpy/strcpy and the taint channel confirms
"attacker data reaches it", which on a file parser is true of nearly everything: on jhead,
25 of 27 findings were corroborated and 20 of them amounted to "this program calls memcpy".
Neither channel asks the question that decides whether it is a BUG -- can the length exceed
the destination?

This answers it for the tractable and very common case: a destination that is a recovered
stack buffer of known size, and a length that is a compile-time constant. `memcpy(buf, src,
sizeof buf)` and `strncpy(buf, src, sizeof buf - 1)` both compile to exactly that, so the
safe idioms become provably safe rather than "corroborated". A length the analysis cannot
pin stays UNKNOWN and the finding is left alone -- this only ever moves a verdict when it
has an arithmetic reason.

Deliberately NOT a general value-range analysis. It is a short backward slice inside the
call's own basic block, which is where argument set-up lives in unoptimised code.
"""
from __future__ import annotations

from .taint import ARCH_ABI, _arch_key, _key, _parse

# sink -> (destination argument index, length argument index). A sink whose length is
# implicit (strcpy/strcat copy until NUL) has no length index: the bound is the SOURCE, which
# this pass cannot see, so those stay unknown rather than being guessed at.
COPY_ARGS = {
    "memcpy": (0, 2), "memmove": (0, 2), "strncpy": (0, 2), "strncat": (0, 2),
    "snprintf": (0, 1), "strlcpy": (0, 2), "strlcat": (0, 2),
}

UNKNOWN = "unknown"
SAFE = "bounded"
SUSPECT = "exceeds-recovered-size"
# A signed bounds check with nothing excluding a negative length. `if (n < 64)` on an `int`
# admits n = -1, which memcpy's size_t parameter reads as 0xFFFFFFFFFFFFFFFF. The check looks
# careful, the upper bound is real, and the copy is still unbounded.
SIGNED = "signed-length"

# Why this pass DEMOTES but never asserts an overflow.
#
# C locals in disjoint scopes share stack slots, so a recovered frame can attribute the wrong
# variable -- and the wrong SIZE -- to an address. jhead's ProcessFile is the worked example:
# at RBP-0x3f50 the source has `char Comment[MAX_COMMENT_SIZE+1]` (16001 bytes) and copies
# 16000 into it, which is safe. Ghidra's frame table names that exact offset `st`, a 144-byte
# `struct stat` from a sibling scope. Trusting it yields a confident "16000 bytes into 144" --
# a fabricated critical finding in a function that is actually correct.
#
# The error is asymmetric. If the recovered size is too SMALL we would invent an overflow; if
# too LARGE we merely miss one. A missed finding costs a finding; a fabricated one costs the
# reader's trust in every other finding in the report. So:
#   bounded  -> trustworthy enough to DEMOTE a noisy rule hit to inventory
#   suspect  -> surfaced for review, never promoted, and always says it depends on the frame


def _const_of(tok):
    parts = tok.split(":")
    if len(parts) >= 2 and parts[0] == "const":
        try:
            return int(parts[1], 0)
        except ValueError:
            return None
    return None


def _signed(v: int, bits: int) -> int:
    """Frame displacements arrive as unsigned two's-complement words."""
    half = 1 << (bits - 1)
    return v - (1 << bits) if v >= half else v


def _slice_block(instrs, upto_addr, bases, bits, sp=None):
    """Symbolic values for registers at `upto_addr`, from the top of the block.

    A value is ("const", n), ("frame", base, offset) for the ADDRESS of a frame slot, or
    ("load", base, offset) for a value read out of one. Anything else is absent = unknown.

    With `sp` (the stack-pointer register name) it also returns the OUTGOING ARGUMENT AREA,
    keyed by displacement from the stack pointer at `upto_addr`. x86-32 and m68k pass every
    memcpy argument there rather than in registers, so without this the two ISAs produced no
    verdict at all. The values must be captured as the stores happen: x86 reuses one P-Code
    temporary for all three pushes, so reading the block's final state gives the last
    argument three times.
    """
    vals: dict = {}
    stack: dict = {}
    sp_off = 0
    for ins in instrs:
        if ins.get("addr") == upto_addr:
            # Stop BEFORE the call, not after it. The call's own P-Code pushes the return
            # address on x86 and m68k, which shifted every stack argument by one slot.
            break
        consts: dict = {}
        slots: dict = {}
        for pc in ins.get("pcode", []):
            try:
                mnem, _ins, outk, toks = _parse(pc)
            except Exception:
                continue
            if sp is not None and mnem == "STORE" and len(toks) >= 4:
                addr = _key(toks[2])
                known = slots.get(addr) or vals.get(addr)
                at = None
                if addr == ("reg", sp):
                    at = sp_off
                elif known and known[0] == "frame" and known[1] == sp:
                    at = known[2]
                if at is not None:
                    v = vals.get(_key(toks[3]))
                    if v is None:
                        stack.pop(at, None)
                    else:
                        stack[at] = v
                continue
            if outk is None:
                continue
            if sp is not None and outk == ("reg", sp) and len(toks) >= 3 and \
                    mnem in ("INT_SUB", "INT_ADD") and _key(toks[1]) == ("reg", sp):
                d = _const_of(toks[2])
                if d is None and _key(toks[2]) in consts:
                    d = consts[_key(toks[2])]
                if d is not None:
                    sp_off += -_signed(d, bits) if mnem == "INT_SUB" else _signed(d, bits)
                continue
            if mnem == "COPY" and len(toks) >= 2:
                c = _const_of(toks[1])
                if c is not None:
                    consts[outk] = c
                    vals[outk] = ("const", c)
                    continue
                src = _key(toks[1])
                if src is not None and src in vals:
                    vals[outk] = vals[src]
                elif src in slots:
                    vals[outk] = slots[src]
                elif src is not None and src[0] == "reg" and src[1] in bases:
                    # SuperH copies the frame pointer before offsetting it (`mov r14,r1`);
                    # the copy has to carry the base or the chain ends right there.
                    vals[outk] = ("frame", src[1], 0)
                else:
                    vals.pop(outk, None)
                continue
            if mnem == "INT_ADD" and len(toks) >= 3:
                a, b = _key(toks[1]), _key(toks[2])
                base = off = None
                for regk, dtok in ((a, toks[2]), (b, toks[1])):
                    if regk and regk[0] == "reg" and regk[1] in bases:
                        d = _const_of(dtok)
                        if d is None and _key(dtok) in consts:
                            d = consts[_key(dtok)]
                        if d is not None:
                            base, off = regk[1], _signed(d, bits)
                            break
                if base is None:
                    # The base may have been COPIED into a scratch register first: SuperH
                    # builds every stack reference as `mov r14,r1; add #0x8,r1`, so requiring
                    # the base register BY NAME resolved no argument at all on that ISA.
                    for vk, dtok in ((a, toks[2]), (b, toks[1])):
                        known = vals.get(vk) if vk else None
                        if known and known[0] == "frame":
                            d = _const_of(dtok)
                            if d is None and _key(dtok) in consts:
                                d = consts[_key(dtok)]
                            if d is not None:
                                base, off = known[1], known[2] + _signed(d, bits)
                                break
                if base is not None:
                    if sp is not None and base == sp:
                        off += sp_off             # SP moves within the block on these ISAs
                    slots[outk] = ("frame", base, off)
                    vals[outk] = ("frame", base, off)
                else:
                    vals.pop(outk, None)
                continue
            if mnem == "INT_OR" and len(toks) >= 3 and toks[1] == toks[2]:
                # `or r3,r9,r9` is PowerPC's register move; without it every argument set-up
                # on that ISA ends at the move and no destination resolves.
                src = _key(toks[1])
                if src is not None and src in vals:
                    vals[outk] = vals[src]
                else:
                    vals.pop(outk, None)
                continue
            if mnem == "LOAD" and len(toks) >= 3:
                addr = _key(toks[2])
                src = slots.get(addr) or vals.get(addr)
                if src and src[0] == "frame":
                    vals[outk] = ("load", src[1], src[2])
                else:
                    vals.pop(outk, None)
                continue
            if mnem in ("INT_SEXT", "INT_ZEXT", "SUBPIECE") and len(toks) >= 2:
                src = _key(toks[1])
                if src in vals:
                    vals[outk] = vals[src]
                else:
                    vals.pop(outk, None)
                continue
            vals.pop(outk, None)
    if sp is None:
        return vals, {}
    # Re-key the argument area against the stack pointer AS OF the call, so argument i is at
    # i * stride regardless of how many pushes preceded it.
    return vals, {k - sp_off: v for k, v in stack.items()}


def frame_delta(frame: dict, word: int) -> int:
    """Convert an RBP-relative displacement into the decompiler's frame coordinates.

    Ghidra numbers stack variables from the frame's return-address slot, not from the frame
    pointer: after `push rbp; mov rbp,rsp` the return address sits at RBP+word while Ghidra
    calls it `ret_offset`. So a variable Ghidra places at -16424 is addressed as RBP-16416.
    Measured across every resolvable copy site in jhead: the difference was exactly 8 (one
    word) in 8 of 8 cases.

    Deriving it from ret_offset rather than hardcoding one word keeps this right for frames
    that number themselves differently.
    """
    try:
        ret = int((frame or {}).get("ret_offset") or 0)
    except (TypeError, ValueError):
        ret = 0
    return word - ret


# The stack pointer for each ISA. A destination addressed from the FRAME POINTER and one
# addressed from the STACK POINTER land in different coordinate systems, and Ghidra reports
# variables in only one of them -- see _ghidra_offset.
_SP_REG = {
    "x86-64": "RSP", "x86": "ESP", "aarch64": "SP", "arm": "SP", "mips": "SP",
    "ppc": "R1", "ppc64": "R1", "riscv": "SP", "loongarch": "SP", "m68k": "SP",
    "sparc": "SP", "sparcv9": "SP", "sh": "R15",
}


def base_offsets(blocks, bases, ak: str) -> dict:
    """Each frame base's offset from the stack pointer AT FUNCTION ENTRY.

    Ghidra numbers stack variables from that same origin, so this is the whole coordinate
    conversion -- `ghidra_offset = base_offsets[base] + displacement` -- and it is DERIVED
    from the prologue rather than tabulated per ISA. Measured, all three conventions fall out
    of one rule:
        x86-64   PUSH RBP; MOV RBP,RSP     -> RBP = -8,   so RBP-0x40 is the var at -0x48
        aarch64  stp x29,x30,[sp,#-0x60]!  -> SP  = -96,  so SP+0x20  is the var at -0x40
        loongarch addi.d sp,-0x60; addi.d fp,sp,0x60 -> FP = 0, so FP-0x50 is the var at -0x50
    A per-ISA delta table got the first two right and loongarch wrong, because the frame
    pointer there addresses the TOP of the frame rather than the bottom.
    """
    sp = _SP_REG.get(ak)
    if not blocks or not sp:
        return {}
    off: dict = {sp: 0}
    tmp: dict = {}

    def val(tok):
        c = _const_tok(tok)
        if c is not None:
            return c
        k = _key(tok)
        if k is None:
            return None
        return off.get(k[1]) if k[0] == "reg" else tmp.get(k)

    for ins in blocks[0].get("instructions", []) or []:
        for pc in ins.get("pcode", []) or []:
            try:
                mnem, _i, outk, toks = _parse(pc)
            except Exception:
                continue
            if outk is None or len(toks) < 2:
                continue
            a = val(toks[1])
            b = val(toks[2]) if len(toks) >= 3 else None
            r = None
            if mnem == "COPY":
                r = a
            elif mnem == "INT_ADD" and a is not None and b is not None:
                r = a + b
            elif mnem == "INT_SUB" and a is not None and b is not None:
                r = a - b
            elif mnem == "INT_OR" and len(toks) >= 3 and toks[1] == toks[2]:
                r = a                                 # `or r31,r1,r1` is PowerPC's register move
            if outk[0] == "reg":
                if r is None:
                    off.pop(outk[1], None)
                else:
                    off[outk[1]] = r
            elif r is not None:
                tmp[outk] = r
            else:
                tmp.pop(outk, None)
    return {b: o for b, o in off.items() if b in bases}


def _ghidra_offset(frame: dict, base: str, disp: int, word: int, ak: str) -> int:
    """Convert a base-register displacement into the decompiler's frame coordinates.

    Two coordinate systems, because a compiler addresses locals from either base:
      frame pointer -- Ghidra's zero sits `frame_delta` above it (x86-64 -O0: RBP-0x1018 is
                       the variable it reports at -0x1020).
      stack pointer -- Ghidra's zero sits a whole frame above it (aarch64 -O0: SP+0x20 in a
                       96-byte frame is the variable it reports at -0x40).
    Using the frame-pointer rule on a stack-pointer displacement misses every variable, which
    is how guard reasoning read as absent on all 12 non-x86 architectures: the destination
    never resolved, so the guard was never consulted.
    """
    if base == _SP_REG.get(ak):
        return disp - int(frame.get("frame_size") or 0)
    return disp - frame_delta(frame, word)


def _capacity(frame: dict, base: str, offset: int):
    """(buffer name, its size), or None when we do not actually know the destination.

    Requires the destination address to be EXACTLY a recovered variable's start. Matching an
    address that merely falls INSIDE a recovered variable looks more capable and is wrong,
    because the frame table is incomplete: in jhead's ProcessFile the real destination is a
    16 KiB buffer at RBP-0x3f50 that Ghidra never recovered, and interior matching happily
    attributed it to a 144-byte `struct stat` starting 8 bytes earlier -- reporting a
    confident 16000-into-136 overflow that does not exist.

    A missed overflow is a missed finding. A fabricated one discredits every other finding in
    the report, so when the frame does not name a variable at that exact address the answer
    is "unknown".
    """
    for v in (frame or {}).get("vars", []) or []:
        try:
            vo, vs = int(v.get("offset")), int(v.get("size") or 0)
        except (TypeError, ValueError):
            continue
        if vs > 0 and vo == offset:
            return v.get("name") or "?", vs
    return None


def classify_site(instrs, site_addr, sink, frame, arch, bits=64,
                  blocks=None, site_block=None, dom=None, base_offs=None):
    """Verdict for one copy call site.

    `blocks`/`site_block` enable the dominating-guard pass: without them only a compile-time
    constant length can be judged, which on real code is the minority (5 of 42 sites on jhead).
    """
    ak = _arch_key(arch)
    if not ak or sink not in COPY_ARGS:
        return None
    abi = ARCH_ABI[ak]
    argregs = abi.get("args") or []
    bases = abi.get("frame", ())
    dst_i, len_i = COPY_ARGS[sink]
    call = abi.get("stack_call") or {}
    sp = None if argregs else call.get("base")
    if not argregs and not sp:
        return None                                   # no ABI for arguments at all
    if argregs and (dst_i >= len(argregs) or len_i >= len(argregs)):
        return None
    vals, stack = _slice_block(instrs, site_addr, bases, bits, sp=sp)
    stride = int(call.get("stride") or (bits // 8))

    def arg(i):
        if not argregs:
            return stack.get(i * stride)
        for r in argregs[i]:
            v = vals.get(("reg", r))
            if v is not None:
                return v
        return None

    dst, ln = arg(dst_i), arg(len_i)
    if not dst or dst[0] != "frame":
        return {"verdict": UNKNOWN, "why": "destination is not a recovered stack buffer"}
    word = (bits or 64) // 8
    if base_offs and dst[1] in base_offs:
        goff = base_offs[dst[1]] + dst[2]
    else:
        goff = _ghidra_offset(frame, dst[1], dst[2], word, ak)
    cap = _capacity(frame, dst[1], goff)
    if cap is None:
        return {"verdict": UNKNOWN,
                "why": (f"no variable recovered at exactly {dst[1]}{dst[2]:+d}; the frame "
                        f"table is incomplete, so the destination size is unknown")}
    name, room = cap
    # An overflow CLAIM has to survive the frame table being wrong about sizes. Ghidra splits
    # a buffer into fragments on some ISAs -- on ppc64le it reported this fixture's char[64]
    # as four separate 8-byte locals, so every correct function read as an overflow of an
    # 8-byte variable. The address is right and the size is not, and that is the asymmetry
    # this module exists to respect.
    # Headroom is the distance from the destination to the top of the frame. A copy that
    # exceeds THAT overruns the frame whatever the variable is really called; one that fits
    # inside it may simply be filling a buffer the decompiler fragmented, so it stays unknown.
    headroom = -goff if goff < 0 else int(frame.get("frame_size") or 0)

    def _over(n_bytes, detail):
        if headroom and n_bytes <= headroom:
            return {"verdict": UNKNOWN, "buffer": name, "capacity": room,
                    "why": (f"{detail}, but that still fits the {headroom}-byte frame below "
                            f"it -- the decompiler fragments buffers, so the recovered size "
                            f"is not a reliable bound here")}
        return None
    if not ln or ln[0] != "const":
        # Not a constant -- but a dominating `if (n < sizeof buf)` bounds it just as firmly.
        if ln and ln[0] == "load" and blocks and site_block:
            g = guard_bound(blocks, site_block, (ln[1], ln[2]), bases=bases, dom=dom)
            if g:
                gmax, why = g["bound"], g["why"]
                common = {"buffer": name, "capacity": room, "bound": gmax, "guard": True}
                if gmax > room:
                    soft = _over(gmax, f"a dominating check permits {gmax} bytes into "
                                       f"{name} ({room} recovered)")
                    return soft or {"verdict": SUSPECT, **common,
                                    "why": (f"{why}, but {name} holds only {room} -- the "
                                            f"check does not protect the buffer")}
                if not g["nonneg"]:
                    # The upper bound is real and it is not a bound: the comparison is signed
                    # and nothing dominating excludes a negative length, which the sink reads
                    # as a 64-bit unsigned size.
                    return {"verdict": SIGNED, **common, "signed": True,
                            "why": (f"{why}, but the check is SIGNED and nothing excludes a "
                                    f"negative length: n = -1 passes it and {sink} takes the "
                                    f"length as an unsigned size, so {name} ({room} bytes) "
                                    f"overflows")}
                return {"verdict": SAFE, **common, "why": f"{why}; {name} holds {room}"}
        return {"verdict": UNKNOWN, "buffer": name, "capacity": room,
                "why": f"length is not a compile-time constant ({name}, {room} bytes)"}
    n = ln[1]
    if n > room:
        soft = _over(n, f"copies a constant {n} bytes into {name} ({room} recovered)")
        if soft:
            return soft
        return {"verdict": SUSPECT, "buffer": name, "capacity": room, "length": n,
                "why": (f"copies a constant {n} bytes where the decompiler recovered only "
                        f"{room} bytes ({name}) -- review: stack slots are reused between "
                        f"scopes, so the recovered variable may not be the real destination")}
    return {"verdict": SAFE, "buffer": name, "capacity": room, "length": n,
            "why": f"copies a constant {n} bytes into {name} ({room} available)"}


def classify_program(func_irs: dict, call_edges, frames: dict, arch, bits=64) -> dict:
    """site_addr -> verdict, for every copy sink whose call site we can read."""
    from .catalog import normalize
    out: dict = {}
    by_site = {}
    for e in call_edges:
        n = normalize(e.dst_name)
        if n in COPY_ARGS and e.site_addr and e.src_addr:
            by_site[e.site_addr] = (e.src_addr, n)
    ak = _arch_key(arch)
    bases = (ARCH_ABI.get(ak) or {}).get("frame", ()) if ak else ()
    for faddr, ir in (func_irs or {}).items():
        blocks = (ir or {}).get("blocks", []) or []
        dom = None                                    # dominators are per function, not per site
        base_offs: dict = {}
        for b in blocks:
            bins = b.get("instructions", [])
            for i in bins:
                hit = by_site.get(i.get("addr"))
                if not hit or hit[0] != faddr:
                    continue
                if dom is None:
                    dom = dominators(blocks)
                    base_offs = base_offsets(blocks, bases, ak)
                v = classify_site(bins, i["addr"], hit[1], frames.get(faddr) or {},
                                  arch, bits=bits, blocks=blocks, site_block=b.get("addr"),
                                  dom=dom, base_offs=base_offs)
                if v:
                    out[i["addr"]] = {**v, "sink": hit[1], "function_addr": faddr}
    return out


# ---------------------------------------------------------------- dominating guards
# 37 of jhead's 42 copy sites have a length that is a local rather than a constant, so the
# constant-only pass above leaves them unknown. Most real bounds checks look like
# `if (n < sizeof buf) memcpy(buf, s, n);` -- a comparison against a constant in a block that
# DOMINATES the copy. Recovering that turns "we cannot tell" into a verdict.
#
# The condition is read out of P-Code rather than off the branch mnemonic. Mnemonics are an
# x86 table, and the three ISA idioms below do not share one; P-Code is the same IR on all of
# them, and it carries the signed/unsigned distinction explicitly (INT_SLESS vs INT_LESS),
# which is the fact the signed-length check turns on. Measured shapes, one per idiom:
#
#   flag registers (x86, x86-32, aarch64, arm, m68k)
#       INT_LESS a,K -> CF ; INT_SBORROW a,K -> OF ; INT_SUB a,K -> t
#       INT_SLESS t,0 -> SF ; INT_EQUAL t,0 -> ZF ; then boolean algebra over the flags,
#       e.g. x86 JA is !(CF|ZF) and aarch64 b.hi is CY & !ZR -- the same relation, different
#       algebra, and neither is readable without evaluating it.
#   direct compare (riscv, loongarch, sh)
#       the constant lives in a REGISTER and the operands are reversed:
#       `li a5,0x3f ; blt a5,a4` is INT_SLESS reg:a5 reg:a4, i.e. `63 < n`.
#   condition-register bitfield (ppc, ppc64, ppc64le)
#       cmplwi packs lt/gt/eq into cr0 with INT_LEFT/INT_OR, and bgt extracts one bit with
#       INT_RIGHT/INT_AND. The unrelated xer_so bit is OR'd in from an unknown value, so the
#       evaluator tracks which bit positions are unknown rather than discarding the field.
_FLIP = {"lt": "gt", "gt": "lt", "le": "ge", "ge": "le", "eq": "eq", "ne": "ne"}
_NEGATE = {"gt": "le", "ge": "lt", "lt": "ge", "le": "gt", "eq": "ne", "ne": "eq"}
# relation -> the largest value it still permits, given the compared constant K
_UPPER = {"lt": lambda k: k - 1, "le": lambda k: k, "eq": lambda k: k}
# relation -> the smallest value it still permits. Only used to prove `n >= 0`; a `!=` tells
# us nothing, since -1 != 0.
_LOWER = {"gt": lambda k: k + 1, "ge": lambda k: k, "eq": lambda k: k}
# Relations that compose into a single relation on the same constant.
_OR_REL = {frozenset(("lt", "eq")): "le", frozenset(("gt", "eq")): "ge",
           frozenset(("lt", "gt")): "ne"}
_AND_REL = {frozenset(("ne", "ge")): "gt", frozenset(("ne", "le")): "lt",
            frozenset(("ge", "le")): "eq"}
_FOLD = {
    "INT_ADD": lambda a, b: a + b, "INT_SUB": lambda a, b: a - b,
    "INT_AND": lambda a, b: a & b, "INT_OR": lambda a, b: a | b,
    "INT_XOR": lambda a, b: a ^ b,
    "INT_LEFT": lambda a, b: a << b if 0 <= b < 64 else None,
    "INT_RIGHT": lambda a, b: a >> b if 0 <= b < 64 else None,
}
_CMP_REL = {"INT_LESS": ("lt", False), "INT_SLESS": ("lt", True),
            "INT_LESSEQUAL": ("le", False), "INT_SLESSEQUAL": ("le", True)}


def _preds(blocks):
    pred: dict = {b["addr"]: set() for b in blocks}
    for b in blocks:
        for sc in b.get("succ", []) or []:
            if sc in pred:
                pred[sc].add(b["addr"])
    return pred


def dominators(blocks) -> dict:
    """Classic iterative dominator sets, keyed by block address."""
    if not blocks:
        return {}
    order = [b["addr"] for b in blocks]
    entry, allb = order[0], set(order)
    pred = _preds(blocks)
    dom = {a: (set([entry]) if a == entry else set(allb)) for a in order}
    changed = True
    while changed:
        changed = False
        for a in order:
            if a == entry:
                continue
            ps = [dom[p] for p in pred.get(a, ()) if p in dom]
            new = (set.intersection(*ps) if ps else set()) | {a}
            if new != dom[a]:
                dom[a] = new
                changed = True
    return dom


def _canon_reg(name: str) -> str:
    """Fold a register's NARROW view onto the full register.

    Ghidra names the low half differently on every ISA -- PowerPC's `_r9` and loongarch's
    `t0_lo` are both the low 32 bits of a register the evaluator already tracks, and treating
    them as unrelated registers lost the value between the load and the compare on both.
    `_hi` is deliberately NOT folded: it is a different half, not a narrower view.
    """
    n = name.upper()
    if n.startswith("_"):
        n = n[1:]
    if n.endswith("_LO"):
        n = n[:-3]
    return n


def _rel(rel, x, y, signed):
    """Normalise `x rel y` into a predicate on the tracked slot, or None.

    Either operand may be the slot: RISC-V and m68k put the constant on the left and the
    value on the right, which is the same relation flipped.
    """
    if x == ("n",) and y is not None and y[0] == "c":
        return ("p", rel, y[1], signed)
    if y == ("n",) and x is not None and x[0] == "c":
        return ("p", _FLIP[rel], x[1], signed)
    return None


def _compose(table, a, b):
    a, b = _as_pred(a), _as_pred(b)
    if not (a and b) or a[2] != b[2]:
        return None
    if a[1] == b[1]:
        return a
    rel = table.get(frozenset((a[1], b[1])))
    if rel is None:
        return None
    return ("p", rel, a[2], a[3] if a[3] is not None else b[3])


def _as_pred(x):
    """Coerce a condition value into a predicate.

    A bare sign-of-difference is a condition on some ISAs: x86 compiles the `n >= 0` half of
    `if (n >= 0 && n < 64)` to `cmp $0,n; js skip`, which branches on SF alone. That is only
    sound as `a <s 0` because subtracting zero cannot overflow -- for any other constant the
    correct signed relation is SF != OF, which is handled where those are paired.
    """
    if x is None:
        return None
    if x[0] == "p":
        return x
    if x[0] == "ng" and x[2] == ("c", 0):
        return _rel("lt", x[1], ("c", 0), True)
    return None


def _negate(p):
    p = _as_pred(p)
    return ("p", _NEGATE[p[1]], p[2], p[3]) if p else None


def _const_tok(tok):
    """A P-Code constant, read as SIGNED at its declared width.

    `const:0xffffffffffffffa4:8` is RISC-V's -0x5c frame displacement and
    `const:0x3f:4` is 63; one table for both means a comparison against a negative constant
    reads as negative rather than as four billion.
    """
    parts = tok.split(":")
    if len(parts) < 3 or parts[0] != "const":
        return None
    try:
        v, width = int(parts[1], 0), int(parts[2], 0)
    except ValueError:
        return None
    return _signed(v, width * 8) if 0 < width <= 8 else v


def branch_predicate(instrs, slot, bases):
    """(taken target, predicate) for this block's conditional branch, or None.

    The predicate is ("p", relation, constant, signed) and holds when the branch is TAKEN.
    A condition the evaluator cannot read yields None rather than a guess: claiming a bound
    that is not there would manufacture a "safe" verdict over a real overflow.
    """
    from .taint import _REG_FAMILY
    v: dict = {}

    def val(tok):
        c = _const_tok(tok)
        if c is not None:
            return ("c", c)
        k = _key(tok)
        if k is not None and k[0] == "reg":
            k = ("reg", _canon_reg(k[1]))
        return v.get(k)

    def setv(outk, x):
        if outk is None:
            return
        if outk[0] == "reg":
            outk = ("reg", _canon_reg(outk[1]))
        if outk[0] == "reg" and outk[1] in bases:
            # A frame base is an ANCHOR, not a value. aarch64's prologue is
            # `INT_ADD reg:sp, -0x60 -> reg:sp`, and resolving that to an address made every
            # later `sp + disp` carry the prologue adjustment twice, so no slot ever matched
            # and every guard on the ISA read as absent. Ghidra's stack displacements are
            # already relative to the post-prologue base, so the base must stay opaque.
            return
        keys = [outk]
        if outk[0] == "reg":
            keys = [("reg", r) for r in _REG_FAMILY.get(outk[1], (outk[1],))]
        for k in keys:
            v[k] = x if x is not None else None

    for ins in instrs:
        for pc in ins.get("pcode", []) or []:
            try:
                mnem, _i, outk, toks = _parse(pc)
            except Exception:
                continue
            if mnem == "CBRANCH" and len(toks) >= 3 and toks[1].startswith("ram:"):
                try:
                    target = "0x%x" % int(toks[1].split(":")[1], 16)
                except ValueError:
                    continue
                cond = _as_pred(val(toks[2]))
                return (target, cond) if cond else None
            if outk is None:
                continue
            a = val(toks[1]) if len(toks) >= 2 else None
            b = val(toks[2]) if len(toks) >= 3 else None
            out = None

            if mnem in ("COPY", "INT_SEXT", "INT_ZEXT"):
                out = a
                if out is None and len(toks) >= 2:
                    src = _key(toks[1])
                    if src is not None and src[0] == "reg" and _canon_reg(src[1]) in bases:
                        # A base is opaque as a VALUE but still anchors an address. SuperH
                        # builds every reference as `mov r14,r1; add #-0x38,r1`, so a copy
                        # that carries no base ends the chain at the first move.
                        out = ("addr", _canon_reg(src[1]), 0)
            elif mnem in ("INT_LEFT", "INT_RIGHT", "INT_SRIGHT") and b == ("c", 0):
                out = a                               # `slli.w t1,t0,0x0` re-narrows, no more
            elif mnem == "SUBPIECE":
                out = a if b == ("c", 0) else None
            elif mnem == "LOAD":
                out = ("n",) if b is not None and b[0] == "addr" and b[1:] == slot else None
            elif mnem in _FOLD and a is not None and b is not None and \
                    a[0] == "c" and b[0] == "c":
                folded = _FOLD[mnem](a[1], b[1])
                out = None if folded is None else ("c", folded)
            elif mnem == "INT_ADD":
                # frame-slot address: base register plus a displacement
                for x, y in ((a, b), (b, a)):
                    if x is not None and x[0] == "addr" and y is not None and y[0] == "c":
                        out = ("addr", x[1], x[2] + y[1])
                if out is None and len(toks) >= 3:
                    for reg, other in ((_key(toks[1]), b), (_key(toks[2]), a)):
                        if reg and reg[0] == "reg" and reg[1] in bases and \
                                other is not None and other[0] == "c":
                            out = ("addr", reg[1], other[1])
            elif mnem == "INT_SUB":
                out = ("sub", a, b) if a is not None and b is not None else None
            elif mnem == "INT_SBORROW":
                out = ("ov", a, b) if a is not None and b is not None else None
            elif mnem in _CMP_REL:
                rel, signed = _CMP_REL[mnem]
                # the sign bit of a subtraction: `(a - K) <s 0`. Only equivalent to `a <s K`
                # when K is 0, where the subtraction cannot overflow -- which is exactly the
                # `n >= 0` idiom (x86 JS) and nothing else.
                if mnem == "INT_SLESS" and a is not None and a[0] == "sub" and b == ("c", 0):
                    out = ("ng", a[1], a[2])
                else:
                    out = _rel(rel, a, b, signed)
            elif mnem in ("INT_EQUAL", "INT_NOTEQUAL"):
                same = mnem == "INT_EQUAL"
                for x, y in ((a, b), (b, a)):
                    if x is None or y is None:
                        continue
                    # SF == OF is the signed >=; SF != OF is the signed <. This is the only
                    # sound reading of the sign flag for a non-zero comparison constant.
                    if x[0] == "ng" and y[0] == "ov" and x[1:] == y[1:]:
                        out = _rel("ge" if same else "lt", x[1], x[2], True)
                    elif x[0] == "sub" and y == ("c", 0):
                        out = _rel("eq" if same else "ne", x[1], x[2], None)
                    elif _as_pred(x) and y is not None and y[0] == "c" and y[1] in (0, 1):
                        # `INT_EQUAL T,1` (SuperH bt) keeps the predicate; against 0 inverts it
                        keep = (y[1] == 1) == same
                        out = _as_pred(x) if keep else _negate(x)
                    if out is not None:
                        break
                if out is None:
                    out = _rel("eq" if same else "ne", a, b, None)
            elif mnem == "BOOL_NEGATE":
                out = _negate(a)
            elif mnem == "BOOL_AND":
                out = _compose(_AND_REL, a, b)
            elif mnem == "BOOL_OR":
                out = _compose(_OR_REL, a, b)
            setv(outk, out)

            # ---- condition-register bitfields (PowerPC). Kept separate from the folding
            # above because these operands mix a known bit map with an unknown one.
            if out is None and mnem in ("INT_LEFT", "INT_RIGHT", "INT_AND", "INT_OR"):
                setv(outk, _bitfield(mnem, a, b))
    return None


def _bitfield(mnem, a, b):
    """PowerPC packs lt/gt/eq into a condition register and extracts one bit to branch on.

    A field is ("bits", {position: predicate}, unknown_mask). The mask matters: cr0 has the
    unrelated xer_so OR'd into bit 0 from a value the evaluator cannot see, and discarding
    the whole field on that account would lose every PowerPC guard.
    """
    if mnem == "INT_LEFT" and a is not None and a[0] == "p" and b is not None and b[0] == "c":
        return ("bits", {b[1]: a}, 0) if 0 <= b[1] < 64 else None
    if mnem == "INT_AND" and b is not None and b[0] == "c" and 0 <= b[1] < (1 << 64):
        if a is None:
            return ("bits", {}, b[1])            # an unknown value, masked to known bits
        if a[0] == "bits":
            keep = {p: q for p, q in a[1].items() if (b[1] >> p) & 1}
            if b[1] == 1:
                return a[1].get(0) if not (a[2] & 1) else None
            return ("bits", keep, a[2] & b[1])
        if a[0] == "p":
            return a if b[1] == 1 else None      # a boolean masked with 1 is itself
    if mnem == "INT_RIGHT" and a is not None and a[0] == "bits" and b is not None and \
            b[0] == "c" and 0 <= b[1] < 64:
        return ("bits", {p - b[1]: q for p, q in a[1].items() if p >= b[1]}, a[2] >> b[1])
    if mnem == "INT_OR":
        xs = [x for x in (a, b) if x is not None and x[0] == "bits"]
        if len(xs) == 2:
            merged = dict(xs[0][1])
            merged.update(xs[1][1])
            return ("bits", merged, xs[0][2] | xs[1][2])
    return None


def guard_bound(blocks, site_block, slot, bases=(), dom=None):
    """What the dominating guards prove about `slot` on every path reaching `site_block`.

    Returns {"bound": max value permitted, "why": text, "nonneg": bool} or None when no
    dominating comparison pins an upper bound.

    `nonneg` is the other half of the proof and is tracked separately, because an upper bound
    alone is not a bound. `if (n < 64)` on a signed int admits n = -1, which every copy sink
    takes as a 64-bit unsigned size. Only an UNSIGNED comparison bounds both ends at once; a
    signed one needs a separate dominating check (`n >= 0`, `n > 0`) to close the hazard.
    """
    by_addr = {b["addr"]: b for b in blocks}
    dom = dominators(blocks) if dom is None else dom
    reaching = dom.get(site_block, ())
    best = None
    nonneg = False
    for d in reaching:                                # every block that dominates the copy
        if d == site_block:
            continue
        blk = by_addr.get(d)
        if not blk:
            continue
        got = branch_predicate(blk.get("instructions", []) or [], slot, bases)
        if got is None:
            continue                                  # unreadable condition -> no claim
        target, (_tag, rel, k, signed) = got
        succ = blk.get("succ", []) or []
        # Which way did control go to reach the copy? A guard block can have MORE than two
        # successors -- x86-32 PIC puts `CALL __x86.get_pc_thunk.bx` in the same block, so
        # the call target sits between the taken edge and the fall-through and assuming the
        # first non-target successor was the fall-through lost every single-guard function.
        other = [x for x in succ if x != target and x in reaching]
        if (target in reaching) and other:
            continue                                  # both edges reach it: no constraint
        if target in reaching:
            holds = rel
        elif other:
            holds = _NEGATE[rel]
        else:
            continue
        # A dominating lower bound is what makes a signed upper bound trustworthy. This runs
        # before the zero-test rejection below, because `n >= 0` compares against exactly 0.
        lo = _LOWER.get(holds)
        if lo is not None and lo(k) >= 0:
            nonneg = True
        fn = _UPPER.get(holds)
        if fn is None:
            continue                                  # a lower bound tells us nothing more
        if k <= 0:
            # `cmp slot, 0` is a null/zero test, not a size bound. Reading it as one produced
            # "at most 0 bytes reach this copy" on jhead's DoCommand -- a safe-looking verdict
            # derived from the wrong comparison entirely, which is exactly how a real overflow
            # would get silently demoted.
            continue
        cand = fn(k)
        if cand <= 0:
            continue
        # An unsigned compare bounds both ends; so does `==`, whose value is exactly k >= 0.
        if signed is False or holds == "eq":
            nonneg = True
        if best is None or cand < best[0]:
            best = (cand, f"guarded by a dominating check: at most {cand} bytes reach this copy",
                    signed)
    if best is None:
        return None
    return {"bound": best[0], "why": best[1], "nonneg": nonneg or best[2] is False}
