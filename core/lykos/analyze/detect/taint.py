"""Data-flow taint over Ghidra low-P-Code (deterministic, zero-AI).

Intra-procedural: flow-sensitive CFG fixpoint, def-use with kill-on-redefine, per-arch ABI
registers. Inter-procedural: a summary-based fixpoint over the call graph that (a) pushes
tainted call arguments into callees' entry parameters, and (b) pulls tainted return values
back to callers. So a source in a caller reaching a sink deep in a callee, and source-wrapper
functions, are handled.

Honest limits: register-granularity (no precise memory/points-to model, so buffer taint via
pointer args is not tracked) and raw low-P-Code (call args inferred from ABI registers).
"""
from __future__ import annotations

from collections import defaultdict, deque

from .catalog import DANGEROUS, SOURCES, normalize

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
        return None, [], None
    ins = [k for k in (_key(t) for t in toks[1:]) if k is not None]
    return toks[0], ins, outk


def _apply(taint, ops):
    for pc in ops:
        try:
            mnem, ins, outk = _parse(pc)
        except Exception:
            continue
        if outk is None or mnem == "STORE":
            continue
        if any(k in taint for k in ins):
            taint.add(outk)
        else:
            taint.discard(outk)


def _arg_regs(abi):
    regs = set()
    for a in abi["args"]:
        regs |= a
    return regs


def _args_tainted(taint, argregs):
    return any(("reg", r) in taint for r in argregs)


def build_callmap(call_edges):
    return {e.site_addr: normalize(e.dst_name) for e in call_edges if e.site_addr}


def _run(ir, abi, callmap, dstmap, func_addrs, entry_params, ret_tainted):
    """Analyze one function. Returns (flagged_sink_sites, return_is_tainted, callee_contribs)."""
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
        if ext in DANGEROUS and _args_tainted(cur, argregs_all):
            flagged.add(addr)
        tainted_params = set()
        if internal:
            for i, regset in enumerate(argregs_list):
                if any(("reg", r) in cur for r in regset):
                    tainted_params.add(i)
        _apply(cur, instr.get("pcode", []))
        if ext in SOURCES:
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


def analyze_program(func_irs, call_edges, arch):
    """Inter-procedural: fixpoint over the call graph. Returns all flagged sink sites."""
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
