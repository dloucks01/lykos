"""Sink-directed basic-block distance (AFLGo-style), computed from the recovered CFG.

Directed greybox fuzzing (AFLGo, CCS'17) steers a fuzzer toward chosen locations by giving every
basic block a *distance* to the targets and biasing the search to keep inputs that get closer.
Upstream AFLGo needs a special instrumented compile; lykos computes the distance **statically from
the P-Code CFG it already recovered**, so it works on a stripped, cross-architecture binary with no
source -- and the targets are lykos's OWN sink sites (the CWE candidates its detectors flagged).

The distance is the classic AFLGo decomposition, simplified to a shortest-path form that is robust
on approximate binary CFGs:

  * **function distance** ``df(f)`` -- backward call-graph hops from ``f`` to the nearest function
    that contains a target sink (0 at such a function). Reuses the campaign's call-graph BFS.
  * **block anchors** -- a block that *contains a target site* is an anchor at cost 0; a block that
    *calls a function g with finite df* is an anchor at cost ``call_weight * (df(g) + 1)`` (a call
    that lands one hop from a sink is worth reaching, but strictly further than the sink itself).
  * **block distance** ``db(m)`` -- shortest path (in block hops) BACKWARD over the intra-function
    CFG from ``m`` to the nearest anchor, plus that anchor's cost. Inter-function reachability is
    folded into the call-anchor cost, so the whole thing is one Dijkstra over reversed edges.

Lower is closer. Blocks that cannot reach any target have no entry. The campaign scores each input
by the *minimum* distance among the blocks it actually reached (lykos already traces block
coverage), and prefers lower-scoring inputs -- directed greybox fuzzing with no recompilation.
"""
from __future__ import annotations

import heapq
from typing import Iterable, Optional


def _addr(x) -> Optional[int]:
    if x is None:
        return None
    if isinstance(x, int):
        return x
    try:
        return int(x, 16) if isinstance(x, str) and x.lower().startswith("0x") else int(x)
    except (TypeError, ValueError):
        return None


def _blocks_of(func) -> list:
    """[(block_addr, [succ_addr...], [instr_addr...])] for a hydrated function, or []."""
    ir = getattr(func, "ir", None) or (func if isinstance(func, dict) else {}) or {}
    out = []
    for b in (ir.get("blocks") or ()):
        ba = _addr(b.get("addr"))
        if ba is None:
            continue
        succ = [s for s in (_addr(x) for x in (b.get("succ") or ())) if s is not None]
        ins = [ia for ia in (_addr(i.get("addr")) for i in (b.get("instructions") or ()))
               if ia is not None]
        out.append((ba, succ, ins))
    return out


def callgraph_distance(call_edges, target_fn_addrs) -> dict:
    """distance[fn] = min call-hops from fn down to a target function (0 at a target). Backward BFS
    over the call graph. Duplicated from directed.py's helper so this module stands alone."""
    targets = {a for a in (_addr(t) for t in target_fn_addrs) if a is not None}
    if not targets:
        return {}
    callers = {}                                      # callee_fn -> {caller_fn}
    for e in call_edges or ():
        src = _addr(getattr(e, "src_addr", None) if not isinstance(e, dict) else e.get("src_addr"))
        dst = _addr(getattr(e, "dst_addr", None) if not isinstance(e, dict) else e.get("dst_addr"))
        if src is not None and dst is not None:
            callers.setdefault(dst, set()).add(src)
    dist = {t: 0 for t in targets}
    frontier = list(targets)
    while frontier:
        nxt = []
        for fn in frontier:
            for caller in callers.get(fn, ()):
                if caller not in dist:
                    dist[caller] = dist[fn] + 1
                    nxt.append(caller)
        frontier = nxt
    return dist


def block_distance(functions, call_edges, target_sites, *, call_weight: int = 10) -> dict:
    """{block_addr -> distance} to the nearest target sink, over the recovered CFG (see module doc).

    ``target_sites`` are instruction addresses of sinks (a CWE candidate's ``site_addr``). A block
    whose instruction range contains a target site is a zero-distance anchor.
    """
    targets = {a for a in (_addr(s) for s in target_sites) if a is not None}
    if not targets:
        return {}

    # Index blocks: block_addr -> (func_addr, succ, instrs); and instr_addr -> block_addr.
    block_succ = {}
    block_func = {}
    instr_block = {}
    func_blocks = {}
    for f in functions or ():
        fa = _addr(getattr(f, "addr", None))
        if fa is None:
            continue
        for ba, succ, ins in _blocks_of(f):
            block_succ[ba] = succ
            block_func[ba] = fa
            func_blocks.setdefault(fa, []).append(ba)
            for ia in ins:
                instr_block[ia] = ba
            instr_block.setdefault(ba, ba)             # block entry maps to itself

    def _block_containing(site) -> Optional[int]:
        b = instr_block.get(site)
        if b is not None:
            return b
        # fall back: the greatest block start <= site within any function (approximate)
        best = None
        for ba in block_succ:
            if ba <= site and (best is None or ba > best):
                best = ba
        return best

    # Functions that contain a target site -> call-graph distance to them.
    target_funcs = set()
    site_anchor = {}                                  # block -> cost 0 (contains a target)
    for s in targets:
        b = _block_containing(s)
        if b is not None:
            site_anchor[b] = 0.0
            fa = block_func.get(b)
            if fa is not None:
                target_funcs.add(fa)
    df = callgraph_distance(call_edges, target_funcs)

    # Call-site blocks toward a target function -> anchor cost call_weight*(df(callee)+1).
    anchors = dict(site_anchor)
    for e in call_edges or ():
        site = _addr(getattr(e, "site_addr", None) if not isinstance(e, dict)
                     else e.get("site_addr"))
        dst = _addr(getattr(e, "dst_addr", None) if not isinstance(e, dict) else e.get("dst_addr"))
        if site is None or dst is None or dst not in df:
            continue
        b = _block_containing(site)
        if b is None:
            continue
        cost = call_weight * (df[dst] + 1)
        if b not in anchors or cost < anchors[b]:
            # a block that also contains a target site stays at 0 (min wins)
            anchors[b] = min(anchors.get(b, cost), cost)

    if not anchors:
        return {}

    # Reverse intra-function edges: pred[succ_block] += [block]. Only within a function (inter-
    # function reachability is already priced into the call anchors).
    preds = {}
    for ba, succ in block_succ.items():
        fa = block_func.get(ba)
        for s in succ:
            if block_func.get(s) == fa:
                preds.setdefault(s, []).append(ba)

    # Dijkstra backward from every anchor: db(block) = anchor_cost + hops.
    dist = {}
    heap = [(cost, b) for b, cost in anchors.items()]
    heapq.heapify(heap)
    while heap:
        d, b = heapq.heappop(heap)
        if b in dist and dist[b] <= d:
            continue
        dist[b] = d
        for p in preds.get(b, ()):
            nd = d + 1
            if p not in dist or nd < dist[p]:
                heapq.heappush(heap, (nd, p))
    return dist


def min_distance(reached_blocks: Iterable[int], dist: dict) -> Optional[float]:
    """The closeness-to-a-sink score of an input: the smallest block-distance among the blocks it
    reached, or None when it reached no block that can reach a target. Lower is better."""
    if not dist:
        return None
    best = None
    for b in reached_blocks or ():
        ba = _addr(b)
        if ba is None:
            continue
        d = dist.get(ba)
        if d is not None and (best is None or d < best):
            best = d
    return best
