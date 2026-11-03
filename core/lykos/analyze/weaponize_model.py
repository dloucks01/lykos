"""Weaponization feasibility model -- capability #6 (triage what is L3-able, and why not).

Turning a confirmed memory bug into a demonstrated L3 (control-flow hijack / arbitrary write) is
gated by two things this engagement learned the hard way, and that lykos should decide UP FRONT
instead of discovering mid-exploit:

  * WHERE the corrupted buffer lives. glibc serves large / aligned allocations from mmap, not the
    main heap; a forward overflow of an mmap chunk runs through adjacent mmap pages to a guard page
    and never reaches groomable heap objects. The ClearCodec TempBuffer (winpr_aligned_recalloc ->
    posix_memalign, ~MB) landed in mmap -- which is exactly why heap grooming could not steer its
    write. `allocator_placement` predicts this.

  * HOW GOOD the primitive is. A linear, fixed-value (memset-like) overflow is a far weaker RCE
    primitive than a controlled write-what-where or a UAF with attacker-reclaimed contents. The
    ClearCodec write repeats one 4-byte colour -- useful for a crash, poor for a clean hijack.
    `primitive_quality` rates it and names what each class needs to reach L3.

This is a planning model (pure, testable): it does not weaponize, it tells the weaponizer which
bugs are worth the attempt, on which allocator, and what extra primitive (leak / groom / arbitrary
offset) each still needs. It encodes the measured glibc-2.3x behaviour, not a guess.
"""
from __future__ import annotations

from dataclasses import dataclass

#: glibc default mmap threshold: requests at/above this go to mmap (a standalone region), not the
#: main heap. Also raised dynamically by free() of large mmapped chunks, but 128 KiB is the floor.
MMAP_THRESHOLD = 128 * 1024


@dataclass
class Placement:
    region: str                    # "heap" | "mmap"
    groomable: bool                # can heap-grooming place a victim adjacent to it?
    reason: str


def allocator_placement(size: int, *, alignment: int = 16, allocator: str = "glibc") -> Placement:
    """Predict where an allocation of `size` (bytes) with `alignment` lands, and whether a
    heap-grooming hijack can steer an overflow of it to an adjacent victim object.

    A size at/above MMAP_THRESHOLD -> mmap (not groomable with malloc-heap victims). An over-aligned
    request (alignment > 16) is served via posix_memalign/aligned_alloc, which for non-trivial sizes
    also tends to mmap or sit in its own carved region away from the small-bin heap -- so a large
    aligned buffer is treated as not-groomable too. Small, default-aligned chunks are heap and
    groomable (tcache/fastbin adjacency)."""
    if allocator != "glibc":
        return Placement("unknown", False, f"no model for allocator {allocator!r}")
    if size >= MMAP_THRESHOLD:
        return Placement("mmap", False,
                         f"{size}B >= mmap threshold ({MMAP_THRESHOLD}B): standalone mmap region; "
                         f"a forward overflow runs into adjacent mmap/guard pages, not heap victims")
    if alignment > 16 and size >= 4096:
        return Placement("mmap", False,
                         f"over-aligned ({alignment}B) {size}B via posix_memalign: carved away from "
                         f"the small-bin heap, so malloc-heap grooming cannot place a victim adjacent")
    return Placement("heap", True,
                     f"{size}B, {alignment}B-aligned: main-heap chunk; tcache/fastbin adjacency is "
                     f"groomable (free a hole, place a victim after it)")


#: per primitive class: (L3 reachability rating, what it still needs). Rating is a coarse rank used
#: to prioritise which confirmed bug to weaponize first.
_PRIMITIVE = {
    # a controlled, attacker-offset write of attacker contents: the strongest primitive
    "write-what-where": (0.9, "overwrite a function pointer / GOT / saved return (needs a target "
                               "address; an ASLR leak if the target is randomized)"),
    "uaf": (0.85, "reclaim the freed object with attacker bytes to control a vtable/callback, then "
                  "trigger the use"),
    "arbitrary-free": (0.6, "free an attacker-controlled pointer into tcache, then a controlled "
                            "allocation returns it (needs heap grooming; a leak to beat safe-linking "
                            "on glibc >= 2.32)"),
    # a linear overflow whose written VALUE is attacker-controlled but repeated (memset-like)
    "linear-overflow-controlled-value": (0.4, "groom a code-pointer object into the forward overflow "
                                               "path on the SAME allocator region (heap, not mmap); "
                                               "value is repeated so the overwrite is coarse"),
    # a linear overflow of fixed/uncontrolled bytes: essentially only a crash
    "linear-overflow-fixed": (0.15, "overwrite is uncontrolled -> realistically a DoS; needs an "
                                    "adjacent length/size field to corrupt into a better primitive"),
    "oob-read": (0.3, "steer the read to disclose a pointer (info leak) -- an ENABLER for another "
                      "bug's L3, not an L3 by itself"),
    "dos": (0.0, "process abort: denial of service only (no memory control)"),
}


@dataclass
class PrimitiveVerdict:
    cls: str
    score: float
    region: str
    l3_reachable: bool
    needs: str


def primitive_quality(cls: str, *, buffer_size: int = 0, alignment: int = 16,
                      allocator: str = "glibc") -> PrimitiveVerdict:
    """Rate a confirmed primitive's path to a demonstrated L3, combining its class strength with the
    allocator placement of the corrupted buffer. A strong class on an mmap-resident buffer is
    downgraded (the ClearCodec case: controlled-value linear overflow, but mmap -> not groomable ->
    L3 not reachable by grooming). Returns the score, the region, whether L3 is reachable as-is, and
    what is still needed."""
    base, needs = _PRIMITIVE.get(cls, (0.2, "unknown primitive class"))
    place = allocator_placement(buffer_size, alignment=alignment, allocator=allocator) \
        if buffer_size else Placement("unknown", True, "buffer size not provided")
    # a linear overflow's hijack needs heap adjacency; on mmap it is not groomable -> downgrade.
    linear = cls.startswith("linear-overflow")
    l3 = base >= 0.4
    if linear and place.region == "mmap":
        base *= 0.3
        l3 = False
        needs = (f"buffer is mmap-resident ({place.reason}); needs mmap-region grooming + an ASLR "
                 f"leak, OR a different (heap-resident) primitive -- grooming cannot steer it")
    return PrimitiveVerdict(cls=cls, score=round(base, 2), region=place.region,
                            l3_reachable=bool(l3), needs=needs)
