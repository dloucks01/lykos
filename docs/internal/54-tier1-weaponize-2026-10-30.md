# 54 — Step 4 weaponization + Tier-1 readiness (2026-10-30)

Continues doc 52's build order. Steps 0–3 were already satisfied (the driver proposes sites from
lifted IR with predicates and scores the corpus with no hand-given sites). This records Step 4
(weaponize) as DONE and the first real work on Step 5 (Tier-1 CGC).

## Step 4 — ladder consumes validated hypotheses → ret2win L3 (DONE)

`core/lykos/hypo/weaponize.py`. A control-flow-hijack hypothesis (the driver proves the instruction
pointer is attacker-controlled) is climbed to an exploit:

1. `exploit.find_win` (reused from the ladder, DB-free) locates an attacker-chosen win function in
   the ELF symbol table.
2. The hijack is RE-SOLVED through the driver with the saved return address pinned to the win
   address (new driver spec `hijack_to`). The solved input is **framing-aware** — it still satisfies
   the path to the overflow, which doc 52 §1 identified as exactly what the old blind-cyclic recipes
   lacked.
3. Confirmation is a **differential replay in the same sandbox the validator uses**: the payload
   exits cleanly via win, while the identical payload with the return-address bytes corrupted
   crashes. Only the win address turned a crash into controlled flow — a marker-free, sound proof of
   control AND arrival. (Needed because `fault_pc` is None on a hijack, so native site-attribution
   cannot confirm it.)

Honest ceiling (same as the ladder's): no-PIE x86-64 ELF, fixed win address, cleanly-terminating
win. No win symbol / PIE / shell-spawning win → reported L2 (control proven, framing-aware payload
built), never faked as L3.

Corpus: `w01_ret2win` (stack overflow → RIP control → win) and `n17_ret2win_bounded` (negative).
`bench/tier0/weaponize_check.py` drives the full loop on no-PIE builds: **w01 → confirmed L3
ret2win, n17 → no exploit.** The Hypothesis gained an `exploit` field; `store.py` writes
`exploit.bin` and annotates `findings.md`.

## Step 5 — Tier-1 CGC: first measurement + the scaling fix

Corpus: DARPA CGC `cb-multios` Linux port, `bench/external/cb-multios/build64` (225/241 built). Each
challenge ships a **vulnerable + patched pair** and reference POVs. Ground truth = the pair: a crash
counts only when the solved input crashes the vulnerable binary and NOT the patched one. Harness:
`bench/tier1/score_cgc.py`.

### Blocker found, with evidence (Palindrome, a ~1 MB static binary)

The CGC binaries are **statically linked** (full libc/loader inlined) and stdin/stdout driven.
Running the loop unscoped:

- input channel was mis-inferred as `file`/`@@`; CGC is stdin-driven (the harness forces stdin).
- the proposer **flooded on libc**: 3145 hypotheses, top functions `__vfscanf_internal` (252),
  `printf_positional`, `_dl_relocate_object`, `_int_malloc`, `__mempcpy_avx_unaligned`… The CB's own
  code barely got a look, and the per-hypothesis CFG distance pass (O(hyps × CFG)) burned the budget.

### Fix landed: CB scoping

DWARF cleanly separates the two: the program's own functions resolve to a real `source.c:line`
(`…/challenges/Palindrome/src/service.c:14`), while libc/CRT resolve to `??:?` or object-only
`malloc.o:?`. `Driver._own_functions()` batch-runs addr2line over every function entry and keeps
only those with a real, non-system source line; `propose()` scopes to them under `spec["cb_scope"]`.
`loop.py` auto-enables it for a large static ELF (no PT_INTERP, > 400 KB), so `lykos hunt` handles
CGC-shaped targets without a flag. Gated, so Tier-0 (verified 2/2, 0 false confirmations) is
unaffected.

Result on Palindrome: **3145 → 40 hypotheses**, now all CB code (KeyExpansion, cgc_check, cgc_fdwait
…), 71 own functions. The scaling blocker is removed.

### Step-5 reach/trigger — hybrid fuzz fallback LANDED (0b7c245)

The first and biggest reach/trigger lever is built: **AFL++ with CmpLog as the fallback engine**
(doc 52 §3c). When the directed symbolic engine confirms nothing in budget, the loop fuzzes an
afl-clang-fast build (+ a CmpLog build, `AFL_LLVM_CMPLOG=1`), seeded with every input the driver
reached the sinks with, and hands each crash to the SAME validator (so the fuzzer only proposes —
0 false confirmations by construction). Reach-gated (only when directed came up empty) and bounded.

Verified: `h02_offbyone_nul` (off-by-one heap overflow behind a `comment:` tag parser) is a directed
MISS; the fallback produced 4 crashes and the validator confirmed `copy@prog.c:29` (the declared
bug) + `int-overflow-alloc@26`. **CmpLog was essential** — plain AFL found 0 (could not guess the
keyword), CmpLog discovered `comment:`. This also subsumes the input-sizing gap (AFL grows inputs,
so the 64 KB case i02 is now reachable by the fallback). `bench/tier0/fuzz_check.py` regresses it.

Caveat: source targets get the instrumented + CmpLog builds; a bare CGC binary falls back to AFL
qemu-mode, which is slower and flaky here — so the fallback helps Tier-2 (Magma/ARVO source) and
Tier-0 recall most; binary-CGC reach still leans on the directed engine + CCBSE.

### Remaining Step-5 work

1. **CCBSE backward climb (doc 52 §3b).** When directed reach from the entry stalls on a deep
   function, start symbolic execution at the site's function and climb callers (the main lever left
   for binary CGC, where qemu-mode fuzzing is weak).
2. **Per-hypothesis budgets** so one deep function cannot starve the rest (today one budget covers
   the whole run).
3. Then the **Tier-1 CGC sweep** for a real number (now that scoping + the fallback exist).

### Baseline

Measurement path established; no full sweep run yet (it would mostly report "undecided" until the
reach/trigger work lands — burning compute for little signal). Run a sample with:
`python3 bench/tier1/score_cgc.py --limit 5 --budget 180`.

## Step 6 — scale (open)

Function summaries, libc models checked against execution, loop bounding; then a Tier-2 (Magma/ARVO)
subset measured. CB scoping is the first piece of this.
