"""Data-flow taint over Ghidra low-P-Code (deterministic, zero-AI).

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

from .catalog import DANGEROUS, SINK_TAINT_ARGS, SOURCES, normalize

# Per-arch calling convention (register NAMES, upper-cased; families cover sub-registers).
ARCH_ABI = {
    "x86-64": {"ret": {"RAX", "EAX"},
               "args": [{"RDI", "EDI"}, {"RSI", "ESI"}, {"RDX", "EDX"},
                        {"RCX", "ECX"}, {"R8", "R8D"}, {"R9", "R9D"}]},
    "x86":    {"ret": {"EAX"}, "args": []},                 # cdecl: stack args (not tracked)
    "aarch64": {"ret": {"X0", "W0"},
                "args": [{"X%d" % i, "W%d" % i} for i in range(8)]},
    "arm":    {"ret": {"R0"}, "args": [{"R0"}, {"R1"}, {"R2"}, {"R3"}]},
    "mips":   {"ret": {"V0"}, "args": [{"A0"}, {"A1"}, {"A2"}, {"A3"}]},
    "ppc":    {"ret": {"R3"}, "args": [{"R%d" % i} for i in range(3, 11)]},
    "ppc64":  {"ret": {"R3"}, "args": [{"R%d" % i} for i in range(3, 11)]},
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
_FRAME_BASES = ("RBP", "RSP", "EBP", "ESP", "X29", "SP", "R11", "FP")


def _const_val(tok):
    parts = tok.split(":")
    if len(parts) >= 2 and parts[0] == "const":
        try:
            return int(parts[1], 0)
        except ValueError:
            return None
    return None


def _frame_slot(toks):
    """Recognise `INT_ADD <frame base> <const>` and return its slot key, else None."""
    if len(toks) < 3:
        return None
    a, b = _key(toks[1]), _key(toks[2])
    if a and a[0] == "reg" and a[1] in _FRAME_BASES:
        off = _const_val(toks[2])
        return ("stack", a[1], off) if off is not None else None
    if b and b[0] == "reg" and b[1] in _FRAME_BASES:     # const on the left
        off = _const_val(toks[1])
        return ("stack", b[1], off) if off is not None else None
    return None


def _define(taint, key, tainted):
    """Define `key` (and its sub-register aliases) as tainted or clean."""
    keys = [key]
    if key[0] == "reg":
        keys = [("reg", r) for r in _REG_FAMILY.get(key[1], (key[1],))]
    for k in keys:
        taint.add(k) if tainted else taint.discard(k)


def _apply(taint, ops):
    slots = {}                       # varnode key -> frame-slot key (this instruction only)
    for pc in ops:
        try:
            mnem, ins, outk, toks = _parse(pc)
        except Exception:
            continue

        if mnem == "INT_ADD" and outk is not None:
            slot = _frame_slot(toks)
            if slot is not None:
                slots[outk] = slot

        if mnem == "STORE":
            # STORE space, addr, value -- spill a value into a frame slot (kill on overwrite)
            if len(toks) >= 4:
                dst = slots.get(_key(toks[2]))
                if dst is not None:
                    val = _key(toks[3])
                    _define(taint, dst, val is not None and val in taint)
            continue

        if outk is None:
            continue

        if mnem == "LOAD" and len(toks) >= 3:
            # LOAD space, addr -> out. A known frame slot answers definitively; any other
            # address falls through to the generic rule, which keeps "load through a tainted
            # pointer yields tainted data" (that is how argv[1] stays tainted).
            src = slots.get(_key(toks[2]))
            if src is not None:
                _define(taint, outk, src in taint)
                continue

        _define(taint, outk, any(k in taint for k in ins))


def _arg_regs(abi):
    regs = set()
    for a in abi["args"]:
        regs |= a
    return regs


def _args_tainted(taint, argregs):
    return any(("reg", r) in taint for r in argregs)


def _sink_tainted(taint, sink, argregs_list, argregs_all):
    """Is the argument that MAKES this sink a bug tainted?

    Falls back to "any argument" for sinks with no declared position (see
    catalog.SINK_TAINT_ARGS), so an unlisted sink keeps the old conservative behaviour.
    """
    idx = SINK_TAINT_ARGS.get(sink)
    if idx is None:
        return _args_tainted(taint, argregs_all)
    return any(("reg", r) in taint
               for i in idx if i < len(argregs_list)
               for r in argregs_list[i])


def build_callmap(call_edges):
    return {e.site_addr: normalize(e.dst_name) for e in call_edges if e.site_addr}


def _run(ir, abi, callmap, dstmap, func_addrs, entry_params, ret_tainted, *,
         seed_sources=True, extmap=None, ext_out=None):
    """Analyze one function. Returns (flagged_sink_sites, return_is_tainted, callee_contribs).

    Cross-binary hooks (Phase 8, doc 17.2):
      * seed_sources=False disables SOURCES seeding so taint originates only from the
        seeded entry params -- used to summarise a callee export (does tainting its
        parameter reach a sink?).
      * extmap {site: imported_symbol} + ext_out set: record imported symbols called with
        tainted arguments -- used to summarise a caller (which imports does it taint?).
    """
    argregs_list = abi["args"]
    argregs_all = _arg_regs(abi)
    retregs = abi["ret"]
    blocks = (ir or {}).get("blocks", [])
    if not blocks or len(blocks) > _MAX_BLOCKS:
        return set(), False, {}

    by_addr = {b["addr"]: b for b in blocks}
    order = [b["addr"] for b in blocks]
    entry = order[0]
    preds = defaultdict(set)
    for b in blocks:
        for s in b.get("succ", []):
            preds[s].add(b["addr"])
    pre = set()
    for i in entry_params:
        if i < len(argregs_list):
            for r in argregs_list[i]:
                pre.add(("reg", r))

    def transfer(cur, instr, flagged, contribs):
        addr = instr.get("addr")
        ext = callmap.get(addr)
        dst = dstmap.get(addr)
        internal = dst in func_addrs
        if ext in DANGEROUS and _sink_tainted(cur, ext, argregs_list, argregs_all):
            flagged.add(addr)
        if extmap is not None and ext_out is not None:
            esym = extmap.get(addr)
            if esym and _args_tainted(cur, argregs_all):
                ext_out.add(esym)
        tainted_params = set()
        if internal:
            for i, regset in enumerate(argregs_list):
                if any(("reg", r) in cur for r in regset):
                    tainted_params.add(i)
        _apply(cur, instr.get("pcode", []))
        if seed_sources and ext in SOURCES:
            cur |= {("reg", r) for r in retregs}
        if internal:
            if tainted_params:
                contribs[dst] = contribs.get(dst, set()) | tainted_params
            if ret_tainted.get(dst):
                cur |= {("reg", r) for r in retregs}

    OUT = {a: set() for a in order}
    for _ in range(len(blocks) * 4 + 10):
        changed = False
        for a in order:
            cur = set()
            for p in preds[a]:
                cur |= OUT[p]
            if a == entry:
                cur |= pre
            f, c = set(), {}
            for instr in by_addr[a]["instructions"]:
                transfer(cur, instr, f, c)
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
        for instr in by_addr[a]["instructions"]:
            transfer(cur, instr, flagged, contribs)

    exits = [a for a in order if not by_addr[a].get("succ")] or order
    ret_bool = any(("reg", r) in OUT[a] for a in exits for r in retregs)
    return flagged, ret_bool, contribs


def analyze_function(ir, callmap, arch):
    """Intra-procedural only (kept for direct use/tests)."""
    ak = _arch_key(arch)
    if not ak or not _arg_regs(ARCH_ABI[ak]):
        return set()
    flagged, _, _ = _run(ir, ARCH_ABI[ak], callmap, {}, set(), set(), {})
    return flagged


def analyze_program(func_irs, call_edges, arch, *, entry_seeds=None):
    """Inter-procedural: fixpoint over the call graph. Returns all flagged sink sites.

    `entry_seeds` maps an entry-point function addr -> the parameter indices that arrive
    already tainted (see catalog.entry_seed_params). This is how argv/envp enter the
    analysis: they are handed to main by the loader, so unlike SOURCES input there is no
    call site to observe. Without a seed an argv-driven program has no taint origin and
    nothing can be corroborated.
    """
    ak = _arch_key(arch)
    if not ak or not _arg_regs(ARCH_ABI[ak]):
        return set()
    abi = ARCH_ABI[ak]
    func_addrs = set(func_irs.keys())
    if not func_addrs or len(func_addrs) > _MAX_FUNCS:
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
                                 entry_params[f], ret_tainted)
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
    for f in func_addrs:
        ff, _, _ = _run(func_irs[f], abi, callmap, dstmap, func_addrs,
                        entry_params[f], ret_tainted)
        flagged |= ff
    return flagged


# ---------------------------------------------------- cross-binary summaries (Phase 8, 17.2)
def _program(func_irs, call_edges, arch, *, seed_params=None, seed_sources=True):
    """Inter-procedural fixpoint with optional entry-param seeds and SOURCES toggle.

    Returns (flagged_sink_sites, tainted_imported_symbols). `seed_params` maps a function
    entry addr -> set of tainted parameter indices; `seed_sources=False` makes the seed the
    only taint origin (callee-export summary).
    """
    ak = _arch_key(arch)
    if not ak or not _arg_regs(ARCH_ABI[ak]):
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
    if not ak or not _arg_regs(ARCH_ABI[ak]):
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
