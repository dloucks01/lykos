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


def _slice_block(instrs, upto_addr, bases, bits):
    """Symbolic values for registers at `upto_addr`, from the top of the block.

    A value is ("const", n), ("frame", base, offset) for the ADDRESS of a frame slot, or
    ("load", base, offset) for a value read out of one. Anything else is absent = unknown.
    """
    vals: dict = {}
    for ins in instrs:
        consts: dict = {}
        slots: dict = {}
        for pc in ins.get("pcode", []):
            try:
                mnem, _ins, outk, toks = _parse(pc)
            except Exception:
                continue
            if outk is None:
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
                if base is not None:
                    slots[outk] = ("frame", base, off)
                    vals[outk] = ("frame", base, off)
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
        if ins.get("addr") == upto_addr:
            break
    return vals


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
                  blocks=None, site_block=None):
    """Verdict for one copy call site.

    `blocks`/`site_block` enable the dominating-guard pass: without them only a compile-time
    constant length can be judged, which on real code is the minority (5 of 42 sites on jhead).
    """
    ak = _arch_key(arch)
    if not ak or sink not in COPY_ARGS:
        return None
    abi = ARCH_ABI[ak]
    argregs = abi.get("args") or []
    if not argregs:
        return None                                   # stack-passing ABI: out of scope here
    bases = abi.get("frame", ())
    dst_i, len_i = COPY_ARGS[sink]
    if dst_i >= len(argregs) or len_i >= len(argregs):
        return None
    vals = _slice_block(instrs, site_addr, bases, bits)

    def arg(i):
        for r in argregs[i]:
            v = vals.get(("reg", r))
            if v is not None:
                return v
        return None

    dst, ln = arg(dst_i), arg(len_i)
    if not dst or dst[0] != "frame":
        return {"verdict": UNKNOWN, "why": "destination is not a recovered stack buffer"}
    word = (bits or 64) // 8
    cap = _capacity(frame, dst[1], dst[2] - frame_delta(frame, word))
    if cap is None:
        return {"verdict": UNKNOWN,
                "why": (f"no variable recovered at exactly {dst[1]}{dst[2]:+d}; the frame "
                        f"table is incomplete, so the destination size is unknown")}
    name, room = cap
    if not ln or ln[0] != "const":
        # Not a constant -- but a dominating `if (n < sizeof buf)` bounds it just as firmly.
        if ln and ln[0] == "load" and blocks and site_block:
            g = guard_bound(blocks, site_block, (ln[1], ln[2]))
            if g:
                gmax, why = g
                if gmax <= room:
                    return {"verdict": SAFE, "buffer": name, "capacity": room,
                            "bound": gmax, "guard": True,
                            "why": f"{why}; {name} holds {room}"}
                return {"verdict": SUSPECT, "buffer": name, "capacity": room,
                        "bound": gmax, "guard": True,
                        "why": (f"{why}, but {name} holds only {room} -- the check does not "
                                f"protect the buffer")}
        return {"verdict": UNKNOWN, "buffer": name, "capacity": room,
                "why": f"length is not a compile-time constant ({name}, {room} bytes)"}
    n = ln[1]
    if n > room:
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
    for faddr, ir in (func_irs or {}).items():
        blocks = (ir or {}).get("blocks", []) or []
        for b in blocks:
            bins = b.get("instructions", [])
            for i in bins:
                hit = by_site.get(i.get("addr"))
                if not hit or hit[0] != faddr:
                    continue
                v = classify_site(bins, i["addr"], hit[1], frames.get(faddr) or {},
                                  arch, bits=bits, blocks=blocks, site_block=b.get("addr"))
                if v:
                    out[i["addr"]] = {**v, "sink": hit[1], "function_addr": faddr}
    return out


# ---------------------------------------------------------------- dominating guards
# 37 of jhead's 42 copy sites have a length that is a local rather than a constant, so the
# constant-only pass above leaves them unknown. Most real bounds checks look like
# `if (n < sizeof buf) memcpy(buf, s, n);` -- a comparison against a constant in a block that
# DOMINATES the copy. Recovering that turns "we cannot tell" into a verdict.
#
# Conditional-branch mnemonic -> the relation that holds when the branch is TAKEN. x86 builds
# its condition out of flag algebra (JG is OF==SF && !ZF), which is painful to evaluate
# symbolically and completely stable to read off the mnemonic, which the IR carries anyway.
_CC_TAKEN = {
    "JG": "gt", "JNLE": "gt", "JA": "gt", "JNBE": "gt",
    "JGE": "ge", "JNL": "ge", "JAE": "ge", "JNB": "ge", "JNC": "ge",
    "JL": "lt", "JNGE": "lt", "JB": "lt", "JNAE": "lt", "JC": "lt",
    "JLE": "le", "JNG": "le", "JBE": "le", "JNA": "le",
    "JE": "eq", "JZ": "eq", "JNE": "ne", "JNZ": "ne",
}
_NEGATE = {"gt": "le", "ge": "lt", "lt": "ge", "le": "gt", "eq": "ne", "ne": "eq"}
# relation -> the largest value it still permits, given the compared constant K
_UPPER = {"lt": lambda k: k - 1, "le": lambda k: k, "eq": lambda k: k}


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


def _cmp_against_const(instrs, slot):
    """The constant `slot`'s value is last compared against in this block, or None.

    Scans the WHOLE block, not one instruction. gcc emits the check either way -- `cmpl $64,
    -4(%rbp)` keeps the load and the compare in one instruction, but `movl -4(%rbp),%eax;
    cmpl $64,%eax` is just as common and splits them. Tracking only within an instruction
    silently missed every split form, which is why the first run of this pass resolved
    nothing on the controlled guard fixture.
    """
    from .taint import _REG_FAMILY
    slots: dict = {}
    loaded: set = set()
    found = None

    def mark(outk, on):
        if outk is None:
            return
        keys = [outk]
        if outk[0] == "reg":
            keys = [("reg", r) for r in _REG_FAMILY.get(outk[1], (outk[1],))]
        for k in keys:
            loaded.add(k) if on else loaded.discard(k)

    for instr in instrs:
        for pc in instr.get("pcode", []) or []:
            try:
                mnem, _ins, outk, toks = _parse(pc)
            except Exception:
                continue
            if mnem is None:
                continue
            if mnem in ("INT_LESS", "INT_SLESS", "INT_SUB", "INT_EQUAL", "INT_NOTEQUAL",
                        "INT_LESSEQUAL", "INT_SLESSEQUAL") and len(toks) >= 3:
                a, b = _key(toks[1]), _key(toks[2])
                if a in loaded and _const_of(toks[2]) is not None:
                    found = _const_of(toks[2])
                elif b in loaded and _const_of(toks[1]) is not None:
                    found = _const_of(toks[1])
            if outk is None:
                continue
            if mnem in ("COPY", "INT_SEXT", "INT_ZEXT", "SUBPIECE") and len(toks) >= 2:
                mark(outk, _key(toks[1]) in loaded)
                continue
            if mnem == "INT_ADD" and len(toks) >= 3:
                for regk, dtok in ((_key(toks[1]), toks[2]), (_key(toks[2]), toks[1])):
                    if regk and regk[0] == "reg":
                        d = _const_of(dtok)
                        if d is not None:
                            slots[outk] = (regk[1], _signed(d, 64))
                mark(outk, False)
                continue
            if mnem == "LOAD" and len(toks) >= 3:
                mark(outk, slots.get(_key(toks[2])) == slot)
                continue
            mark(outk, False)               # any other definition kills the tracked value
    return found


def _branch_mnemonic(instr) -> str:
    return (instr.get("text") or "").strip().split()[0].upper() if instr.get("text") else ""


def guard_bound(blocks, site_block, slot):
    """Largest value the guards permit for `slot` on every path reaching `site_block`.

    Returns (max_value, describing text) or None when no dominating comparison pins it. A
    polarity we cannot read yields None rather than a guess: claiming a bound that is not
    there would manufacture a "safe" verdict over a real overflow.
    """
    by_addr = {b["addr"]: b for b in blocks}
    dom = dominators(blocks)
    best = None
    for d in dom.get(site_block, ()):                 # every block that dominates the copy
        if d == site_block:
            continue
        blk = by_addr.get(d)
        if not blk:
            continue
        ins = blk.get("instructions", []) or []
        k = _cmp_against_const(ins, slot)
        if k is None:
            continue
        branch = ins[-1] if ins else None
        target = None
        for pc in (branch or {}).get("pcode", []):
            if pc.startswith("CBRANCH"):
                toks = pc.split()
                if len(toks) >= 2 and toks[1].startswith("ram:"):
                    target = "0x%x" % int(toks[1].split(":")[1], 16)
        if target is None:
            continue
        rel = _CC_TAKEN.get(_branch_mnemonic(branch))
        if rel is None:
            continue                                  # unknown polarity -> no claim
        succ = blk.get("succ", []) or []
        other = [x for x in succ if x != target]
        # which way did control go to reach the copy?
        if target in dom.get(site_block, ()):
            holds = rel
        elif other and other[0] in dom.get(site_block, ()):
            holds = _NEGATE[rel]
        else:
            continue
        fn = _UPPER.get(holds)
        if fn is None:
            continue                                  # a lower bound tells us nothing here
        if k <= 0:
            # `cmp slot, 0` is a null/zero test, not a size bound. Reading it as one produced
            # "at most 0 bytes reach this copy" on jhead's DoCommand -- a safe-looking verdict
            # derived from the wrong comparison entirely, which is exactly how a real overflow
            # would get silently demoted.
            continue
        cand = fn(k)
        if cand <= 0:
            continue
        if best is None or cand < best[0]:
            best = (cand, f"guarded by a dominating check: at most {cand} bytes reach this copy")
    return best
