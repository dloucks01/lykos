"""Automatic heap-layout search (Phase 9 frontier, MAZE-style, analyst-in-the-loop).

Given the allocation/free operations a target exposes and a desired layout GOAL, search for a
sequence of operations that achieves it -- the core of MAZE's heap-layout manipulation. This
plans over a deterministic glibc **tcache** model (per-size-class LIFO): allocating a freed
size-class reclaims the most-recently-freed chunk, so grooming is a reachability problem over
allocator states, solved here by breadth-first search (shortest sequence).

Emits the operation sequence; wiring it to the target's concrete alloc/free interface is the
analyst-in-the-loop step (doc 15). The model's chunk addresses are symbolic (bump from a base)
-- the SEQUENCE it finds is what matters, and it is verifiable against a real allocator.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .heap import in_tcache_range, request2size, tcache_index

SIZE_SZ = 8


@dataclass(frozen=True)
class HeapState:
    """An immutable tcache snapshot for search. `bins` maps tcache index -> tuple of freed
    user addresses (LIFO: the last element is the head, popped next). `live` maps a handle to
    its address; `last_alloc` is the address returned by the most recent alloc."""
    bins: tuple = ()                 # ((idx, (addr, ...)), ...) sorted by idx
    top: int = 0x1000
    live: tuple = ()                 # ((handle, addr), ...)
    sizes: tuple = ()                # ((addr, chunk_size), ...)
    next_handle: int = 0
    last_alloc: int = 0

    # ---- helpers to read the maps ----
    def _bins(self):
        return {i: list(a) for i, a in self.bins}

    def _live(self):
        return dict(self.live)

    def _sizes(self):
        return dict(self.sizes)

    @staticmethod
    def _pack(bins, top, live, sizes, next_handle, last_alloc):
        return HeapState(
            bins=tuple(sorted((i, tuple(a)) for i, a in bins.items() if a)),
            top=top, live=tuple(sorted(live.items())),
            sizes=tuple(sorted(sizes.items())), next_handle=next_handle,
            last_alloc=last_alloc)

    def alloc(self, req: int):
        cs = request2size(req)
        i = tcache_index(cs)
        bins, live, sizes = self._bins(), self._live(), self._sizes()
        if in_tcache_range(cs) and bins.get(i):
            addr = bins[i].pop()                         # LIFO reclaim
        else:
            addr = self.top + SIZE_SZ * 2
            top = self.top + cs
            sizes[addr] = cs
            h = f"h{self.next_handle}"
            live[h] = addr
            return self._pack(bins, top, live, sizes, self.next_handle + 1, addr), h, addr
        sizes[addr] = cs
        h = f"h{self.next_handle}"
        live[h] = addr
        return self._pack(bins, self.top, live, sizes, self.next_handle + 1, addr), h, addr

    def free(self, handle: str):
        live, bins, sizes = self._live(), self._bins(), self._sizes()
        addr = live.pop(handle, None)
        if addr is None:
            return self
        cs = sizes.get(addr, request2size(0))
        if in_tcache_range(cs):
            bins.setdefault(tcache_index(cs), []).append(addr)
        return self._pack(bins, self.top, live, sizes, self.next_handle, self.last_alloc)


def prime(freed_sizes, *, base=0x1000):
    """Build a starting state where chunks of the given sizes were alloc'd then freed in order
    (so the tcache bins hold them LIFO). Returns (state, [addr, ...] in free order)."""
    st = HeapState(top=base)
    handles = []
    for s in freed_sizes:
        st, h, _a = st.alloc(s)
        handles.append(h)
    addrs = [dict(st.live)[h] for h in handles]
    for h in handles:
        st = st.free(h)
    return st, addrs


def search(initial: HeapState, goal, *, sizes=(24,), max_steps=16, allow_free=False):
    """Breadth-first search for the shortest op sequence reaching `goal(state) -> bool`.
    Actions: alloc(size) for each size in `sizes`, and (if allow_free) free(handle) for each
    live handle. Returns [op, ...] (e.g. ('alloc', 24), ('free', 'h2')) or None."""
    seen = {initial}
    q = deque([(initial, [])])
    while q:
        st, path = q.popleft()
        if goal(st):
            return path
        if len(path) >= max_steps:
            continue
        succ = []
        for s in sizes:
            ns, _h, _a = st.alloc(s)
            succ.append((("alloc", s), ns))
        if allow_free:
            for h, _a in st.live:
                succ.append((("free", h), st.free(h)))
        for op, ns in succ:
            if ns not in seen:
                seen.add(ns)
                q.append((ns, path + [op]))
    return None


def reclaim_goal(target_addr: int):
    """Goal: a controlled allocation now occupies `target_addr` (the freed target is live
    again -- reclaimed by an alloc that returned its address)."""
    return lambda st: any(a == target_addr for _h, a in st.live)


def adjacency_goal(size: int):
    """Goal: two live chunks of `size` are exactly one chunk apart (adjacent)."""
    cs = request2size(size)
    return lambda st: any(
        abs(a - b) == cs
        for i, (_, a) in enumerate(st.live) for (_, b) in st.live[i + 1:])


def plan_reclaim(freed_sizes, target_index, *, size=24, max_steps=16):
    """Convenience: prime a bin from `freed_sizes`, then search for the ops that allocate a
    controlled chunk at the freed chunk `target_index` (in free order). Returns (ops, addrs)."""
    st, addrs = prime(freed_sizes)
    if not (0 <= target_index < len(addrs)):
        return None, addrs
    ops = search(st, reclaim_goal(addrs[target_index]), sizes=(size,), max_steps=max_steps)
    return ops, addrs
