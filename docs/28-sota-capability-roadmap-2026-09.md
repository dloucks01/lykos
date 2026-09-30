# 28 — SOTA capability audit & zero-day-technique roadmap (2026-09-30)

A deep-dive survey of the state of the art in **non-AI, air-gappable** zero-day discovery for
binaries and source, mapped against what lykos already does, with a prioritized roadmap. Ground
rules for everything below (they are the project's constraints, not preferences):

- **No AI/ML/LLM.** Classical program analysis only. Where a well-known technique has an ML
  variant, only the non-ML core is in scope (e.g. IJON yes, AIJon no; MOpt/EcoFuzz/K-Scheduler are
  classical optimization/graph algorithms, so in scope).
- **Air-gapped.** Every engine must run offline once vendored; no cloud, no license server, no
  call-home. Licensing that *forbids* offline commercial use is a blocker even when the tech is
  offline-capable (see CodeQL note).
- **Prefer what we already vendor.** AFL++, angr, SymQEMU, Unicorn+Keystone, rizin+rz-ghidra,
  pypcode, Ghidra headless, qemu-user/-system, gcc/clang with ASan/UBSan/MSan. A technique that
  reuses these beats one that needs a new heavy runtime.

## What lykos already has (so the roadmap only lists real gaps)

| Area | Present in lykos |
|---|---|
| Coverage fuzzing | AFL++ fork-server + **QEMU mode** (cross-arch) with per-guest `afl-qemu-trace`, `AFL_COMPCOV_LEVEL=2`, a `-c cmplog` code path; libFuzzer with auto-synthesized harnesses |
| Structure-aware | Format-spec inference (magic / integer fields / length-prefixed), a structure mutator, menu-state seeds |
| Directed fuzzing | `directed.py`: backward call-graph distance to sinks, targeted string dictionary, source-reachability |
| Concolic / hybrid | angr driver that **re-fuzzes from solved inputs**, SymQEMU vendored as a 2nd backend |
| Coverage w/o instrumentation | ptrace block-tracer (`batch_runner`), output-shape behaviour proxy |
| Memory-safety (source) | ASan + UBSan + **MSan** instrumented builds; sanitizer→CWE+file:line |
| Static detection | interprocedural **P-Code taint**, bounds / integer-overflow, CWE detector suite (dangerous-API, TOCTOU, format-string, hardcoded-secret, Go/Rust injection/traversal/SSRF via call-graph) |
| Binary RE | rizin + rz-ghidra decompile + **pypcode P-Code** (no JVM); multi-arch (12 ISAs) |
| Firmware | Unicorn **Cortex-M rehosting** with Fuzzware-style MMIO modeling + MMIO fuzzing; binwalk-style carving → ELF sub-targets |
| N-day | **source** patch-diff (`patchdiff.py`) + `poc_diff` |
| Exploitation | L2 primitives (IP-control, write-what-where) + a broad L3 ladder, all self-confirmed |

This is already an advanced platform. The roadmap below is the delta to *state of the art*.

---

## Shipped in this pass

Four new capabilities were built, tested and integrated (all non-AI, offline, reusing engines
lykos already ships). Each is covered below; the roadmap that follows marks the corresponding
Tier entries **[DONE]**.

| Capability | Module | Tests | What it adds |
|---|---|---|---|
| Static input-to-state dictionary | `analyze/fuzz/cmpdict.py` | `test_cmpdict.py` | Mines magic/tag/length constants from P-Code comparisons into the fuzzer dictionary (works black-box on stripped cross-arch binaries where CmpLog can't run) |
| Binary memory-safety oracle | `analyze/dynamic/memoracle.py` | `test_memoracle.py` | Valgrind memcheck → CWE classification for stripped-binary crashes + a guard-page (`libdislocator`) oracle wired into the fuzz loop |
| Sink-directed block distance | `analyze/fuzz/blockdist.py` | `test_blockdist.py` | AFLGo-style block distance to lykos's own sinks, steering the fuzzer to keep inputs that get closer (no recompile) |
| Binary N-day variant hunting | `analyze/variant.py` + `lykos variant-scan` | `test_variant.py` | Fuzzy function matching + corpus-wide hunt for an unpatched vulnerable function |
| Corpus distillation (minset) | `analyze/fuzz/distill.py` | `test_distill.py` | afl-cmin-style coverage-preserving corpus minimization via the block tracer, before every campaign |
| Grammar-aware mutation | `analyze/fuzz/grammar.py` | `test_grammar.py` | Recursive/structure-valid input generation (Gramatron/Nautilus-style) reaching code behind nested parsers a flat model never builds |
| Source variant analysis | `analyze/weggli.py` + `lykos weggli-scan` | `test_weggli.py` | weggli AST vuln-pattern pack over C/C++ + generalize-from-a-patch variant hunting (source-side complement to variant-scan) |
| Differential testing | `analyze/fuzz/differential.py` + `lykos diff-test` | `test_differential.py` | NEZHA-style discrepancy oracle: fuzz 2+ implementations, flag disagreement (a non-crashing bug class) |
| Static->dynamic loop wiring | `weggli.to_targets`, `differential.disagreement_seeds`, `directed.plan_directed_campaign(extra_targets=)` | in the above test files | weggli source hits become directed-fuzz TARGETS (steered by blockdist); diff-test disagreements become fuzz SEEDS |

### 1. Static input-to-state dictionary (`analyze/fuzz/cmpdict.py`)

**Technique:** RedQueen / AFL++ CmpLog "input-to-state" — the single highest-ROI fuzzing gap in the
research (top pick of both the fuzzing and binary-only surveys). A byte-level mutator never guesses
a 4-byte magic, a version tag or a length gate; RedQueen/CmpLog learn these from comparison
operands **at runtime**. lykos already recovers the P-Code, so the **same constants are visible
statically**: every `INT_EQUAL const:0x47464923 reg` is a value some branch wants to see.

`cmpdict.py` mines every comparison constant (`INT_EQUAL/NOTEQUAL/LESS/SLESS/…`, plus `INT_SUB`
compare-lowering) from the recovered P-Code and emits it as dictionary tokens in both byte orders
and at each width it fits, dropping trivial (0/±1/all-ones) and, when a range predicate is given,
address-like constants. It is wired into `directed.py`'s dictionary (near-target functions first,
and the undirected fallback), so the existing token-splicing mutator plants magic/length constants
in the first havoc rounds.

**Why it earns its place even though we ship CmpLog:** CmpLog needs an instrumented second build
(source) or `afl-qemu` cmplog; it is **unavailable for a stripped cross-arch binary fuzzed
black-box under plain qemu** — a case lykos explicitly supports. Static mining works from P-Code
alone, on any architecture, at zero fuzz-time cost, and gives CmpLog material immediately where it
*does* run. Non-AI, deterministic, offline. Tests in `tests/test_cmpdict.py`.

### 2. Binary memory-safety oracle (`analyze/dynamic/memoracle.py`)

lykos had precise memory-safety detection only on a **source** ASan build; a stripped/third-party
binary's heap OOB or use-after-free merely *sometimes* faulted. Two classic non-instrumentation
oracles close that:

- **Valgrind memcheck triage → CWE** (`valgrind_triage`/`parse_memcheck`): re-run a crashing input
  under memcheck and classify the exact class — heap OOB read/write, use-after-free, double-free,
  invalid free, uninitialised read, leak — into a CWE (CWE-122/125/416/415/590/457/401). Wired into
  the `root_cause` stage so a stripped-binary crash gets the same defect-naming a source ASan build
  gets, *sharpening* the generic signal-based verdict exactly as the ASan-report override does.
- **Guard-page allocator (`libdislocator`)**: `LD_PRELOAD`ed into the fuzz target children via
  `LYKOS_PRELOAD` (translated to `LD_PRELOAD` for the target only, never a sanitizer build, never
  the tracer), so a heap overflow faults *immediately* instead of running on silently — validated
  to turn a silent 48-into-16-byte overflow into a caught SIGSEGV on both the traced and non-traced
  batch paths.

`valgrind`, `libdislocator`, `libtokencap` and (optional) `libqasan` are now reported by `doctor`.
Tests in `tests/test_memoracle.py`; installed `valgrind`.

### 3. Sink-directed block distance (`analyze/fuzz/blockdist.py`)

Directed greybox fuzzing (AFLGo) steers toward chosen locations by giving each basic block a
*distance* to the targets. lykos computes this **statically from the P-Code CFG** (so it needs no
special compile and works on stripped cross-arch binaries) toward its **own** flagged CWE sink
sites: function-level call-graph distance + call-anchor costs + a Dijkstra over reversed
intra-function edges. The campaign scores each input by the minimum block-distance it reached
(lykos already traces block coverage) and **retains inputs that get strictly closer** to a sink
even without new coverage — the exploitation half of directed fuzzing, no recompilation. Wired
into `directed.py` (distance from its sink targets) and `fuzz_campaign` (`block_dist=`, reporting
`directed_kept`/`nearest_sink_dist`). Tests in `tests/test_blockdist.py`.

### 4. Binary N-day variant hunting (`analyze/variant.py`, `lykos variant-scan`)

`patchdiff.py` already diffs two binaries by name (exact-hash fallback for stripped). `variant.py`
adds the two things that turn a diff into a HUNT: **fuzzy** function similarity (callee-set Jaccard
0.4 + P-Code mnemonic-profile cosine 0.4 + structural 0.2 — matches recompiled/lightly-edited
copies exact hashes miss) and **corpus-wide `variant_scan`**. New CLI `lykos variant-scan --ref
<binary> --func <name> <corpus…>` finds a vulnerable function and hunts every binary carrying an
unpatched variant — a candidate N-day (or 0-day if unreported). Validated end-to-end: an unpatched
copy matches at 1.0 while a `strncpy`-patched build reads clean. Tests in `tests/test_variant.py`
(incl. a real vuln-vs-patched decompile+diff).

---

## Roadmap — prioritized by (value × buildability-with-what-we-vendor)

### Tier 1 — cheap, high-ROI, buildable on the engines we already ship

1. **[DONE — `memoracle.py`] Binary-only memory-safety oracle: `libdislocator` + Valgrind (`libqasan` optional).** *(highest-value gap.)* Today
   memory-safety detection exists only on **source** builds; a stripped binary gets a crash oracle
   only for signals it already raises. `libqasan` (ships in AFL++ `qemu_mode/`, `AFL_USE_QASAN=1`)
   turns silent heap OOB/UAF/double-free in stripped **cross-arch** binaries into catchable crashes
   (~1.3–2.7× overhead); `libdislocator`/Electric-Fence guard-page allocators are the arch-agnostic
   fallback (LD_PRELOAD, any qemu arch, including firmware). Build cost: **low** — enable a QASan
   QEMU variant + a preload fallback + a Valgrind-memcheck triage lane for survivors. Refs: QASan
   (IEEE SecDev'20) https://github.com/andreafioraldi/qasan ; AFL++ `libqasan` README.
2. **[PARTIAL — `cmpdict.py` static I2S shipped] Full CmpLog / laf-intel enablement + auto-dictionary to file.** We have the `-c cmplog` path
   and COMPCOV; make CmpLog first-class (second cmplog-instrumented target for source, `afl-qemu`
   cmplog for binaries) and add `AFL_LLVM_DICT2FILE` / `AFL_LLVM_LAF_ALL` on source builds. Pairs
   with `cmpdict` (static seed) + CmpLog (runtime). Build cost: **low** (mostly harness wiring).
   Refs: RedQueen (NDSS'19); AFL++ CmpLog.
3. **[DONE — `blockdist.py`] Sink-directed *block-level* distance (Beacon-style pruning still open).** `directed.py` has
   call-graph distance; upgrade to **basic-block** distance over the rizin/P-Code CFG (AFLGo
   formula) and expose it as an AFL++ custom power-schedule / seed-scorer steering toward lykos's
   own CWE sinks; v2 adds Beacon-style static preconditions to abort provably-infeasible paths.
   Unlike upstream AFLGo/Beacon this needs **no source** — it suits our stripped/cross-arch targets.
   Build cost: **medium**, all static/offline. Refs: AFLGo (CCS'17); Beacon (S&P'22); ParmeSan
   (USENIX'20, sanitizer-check blocks as targets).
4. **[DONE — `distill.py`] Corpus distillation before every campaign (greedy minset; OptiMin optional).** ISSTA'21 shows *minset
   quality dominates fuzzer choice*. Start with `afl-cmin` (already in AFL++), then OptiMin
   (MaxSAT-optimal, ships in AFL++ tree, bundle a MaxSAT solver). Also distill angr-produced inputs.
   Build cost: **low**. Refs: "Seed Selection for Successful Fuzzing" (ISSTA'21).
5. **Expanded compile-time oracles (source lane): high-signal UBSan checks + LeakSanitizer, plus a
   TSan build lane.** Add LSan (leaks) and a **ThreadSanitizer** lane (libFuzzer supports TSan) for
   data-race/deadlock bugs ASan/UBSan/MSan are blind to; keep noisy UBSan checks
   (implicit-conversion) opt-in so they do not manufacture false crashes. Build cost: **low**
   (compiler flags + a separate build variant). Refs: clang TSan; Muzz (USENIX'20) for schedule
   steering (later).
6. **Persistent-mode harness loop + value-profile / CTX coverage.** Emit `__AFL_LOOP` in
   auto-synthesized harnesses (10×-ish throughput on top of the fork-server); flip
   `-use_value_profile=1` on libFuzzer and try `AFL_LLVM_INSTRUMENT=CTX/NGRAM`. Build cost:
   **low** (templates + flags on engines we run).

### Tier 2 — medium effort, high value, needs a vendored engine or new glue

7. **[DONE — `variant.py` + `lykos variant-scan`, lightweight built-in matcher instead of ghidriff/BSim] Binary N-day → variant hunting.** Extends our **source** patch-diff to
   **binaries**: `ghidriff` (Ghidra-headless, pure-Python, no IDA) diffs a vuln/patched pair and
   localizes the changed function; **BSim** (H2 backend, zero external services) sweeps a whole
   binary corpus for the unpatched variant. Nearly half of in-the-wild 0-days are variants of prior
   bugs — this is the biggest *new-bug-source* gap after the memory oracle. Build cost:
   **low–medium** (both self-contained JVM/native). Refs: https://github.com/clearbluejar/ghidriff ;
   Ghidra BSim tutorial.
8. **[DONE — `weggli.py` integration + query pack + `lykos weggli-scan`; binary install-on-demand] Source variant analysis (weggli).** Turn a root-caused bug into a
   query and sweep the codebase for siblings. **weggli** is a single static Rust binary (easiest to
   vendor) with a "generalize-from-a-patch" workflow; Joern (CPG + data-flow) as the heavier
   cross-language backend. **CodeQL is deliberately excluded as a default** — free only for
   open-source; analyzing closed source needs a paid GHAS license (offline-capable, but the license
   blocks air-gapped commercial/red-team use). Ship weggli + a curated lykos query pack. Build cost:
   **low** (weggli) / medium (Joern). Refs: https://github.com/weggli-rs/weggli ;
   https://github.com/joernio/joern .
9. **[DONE — `grammar.py`] Grammar / structure-aware mutation.** We already *infer* a format spec —
   almost no fuzzer has that. Emit it as a **Gramatron** automaton / Grammar-Mutator grammar / LPM
   schema and load via the AFL++ custom-mutator API, so fuzzing stays structurally valid and reaches
   deep parser states. Build cost: **medium** (the converter is the novel glue; engines are
   off-the-shelf). Refs: Gramatron (ISSTA'21); AFLplusplus/Grammar-Mutator.
10. **Taint-guided (FTI) + approximate-concolic mutation stage.** GreyOne-style *fuzzing-driven
    taint inference* (flip a byte, watch which compared values move — no heavyweight DTA) to map
    input bytes → stalled branches, then Eclipser-style approximate constraint solving to flip most
    branches cheaply, escalating only residual hard branches to SymQEMU/angr with QSYM/Driller
    scheduling (invoke on coverage-stall, optimistic solving, block pruning). Cuts expensive
    symbolic runs sharply. Build cost: **medium**, all on vendored engines. Refs: GreyOne
    (USENIX'20); Eclipser (ICSE'19); QSYM (USENIX'18); Driller (NDSS'16).
11. **[DONE — `differential.py` + `lykos diff-test`] Differential testing (NEZHA-style oracle).** Run one input through ≥2 local
    implementations of a spec (parsers, TLS/crypto, decompressors) and flag divergence — a
    **non-crashing** oracle for logic/validation bugs (auth bypass, request smuggling, cert-check
    gaps) sanitizers never see; historically very high CVE yield. Build cost: **medium** (reusable
    equivalence-oracle scaffold + target-registration format). Refs: NEZHA (S&P'17).
12. **Local ensemble + collaborative fuzzing (EnFuzz).** Run AFL++ havoc, AFL++ cmplog, libFuzzer
    value-profile and angr-concolic over one shared seed dir with periodic sync (`-M/-S`), turning
    the concolic loop into just another ensemble member. "Whole > sum of parts", entirely offline.
    Build cost: **low–medium** (a supervisor over tools we ship). Refs: EnFuzz (USENIX'19).
13. **Interface-aware harness synthesis for whole library APIs.** Move beyond single-entry-fn
    drivers: GraphFuzz (lifetime-aware multi-API graphs from a YAML schema auto-seeded from headers)
    or Hopper (harness-free interpretative fuzzing). Build cost: **medium**. Refs:
    https://github.com/hgarrereyn/GraphFuzz ; https://github.com/FuzzAnything/Hopper .

### Tier 3 — heavy lifts / narrower scope (defer until a target demands them)

14. **Bounded model checking as a candidate verifier: CBMC or ESBMC.** For each high-confidence
    static candidate, auto-harness the implicated function and run BMC to a chosen unwind bound;
    promote candidates that yield a concrete counterexample trace, down-rank those proven safe.
    Turns heuristic findings into witness-backed reports. Refs: https://github.com/diffblue/cbmc ;
    https://github.com/esbmc/esbmc .
15. **Sound abstract-interpretation bounds oracle: Frama-C/Eva or IKOS.** Sound value-range
    over-approximation to prove-safe (kill false positives) or flag alarms the heuristics miss.
    Heavy (OCaml / LLVM). Pick one.
16. **Firmware breadth beyond Cortex-M.** *(a)* **Greenhouse-style user-space service rehosting** —
    highest firmware ROI, extends our carving + qemu-user: auto-stub env (fake NVRAM via
    `libnvram` LD_PRELOAD, synthetic /proc,/sys,/dev, syscall patching) and fuzz one service under
    `afl-qemu-trace` (MIPS/ARM/PPC routers). *(b)* **Interrupt (AIM just-in-time IRQ firing) + DMA
    (DICE buffer injection)** layered on the existing Fuzzware MMIO hooks — interrupt/DMA-gated code
    is where MCU bugs hide. *(c)* **Qiling** (same Unicorn engine) for MIPS/PPC/RISC-V/ARM-A
    bare-metal; **Icicle** (Ghidra-p-code Rust emulator) as the coverage backend for exotic ISAs
    (MSP430/Xtensa/AVR) our afl-qemu-trace cannot instrument; **Firmadyne/FirmAE** full-system boot
    for whole-router images. Refs: Greenhouse (USENIX'23); AIM (arXiv 2312.01195); DICE (S&P'21);
    Qiling; Icicle (ISSTA'23); Firmadyne (NDSS'16)/FirmAE (ACSAC'20) — *verify artifact repo URLs
    against the papers before vendoring.*
17. **Static binary rewriting for compiler-speed coverage/ASan: e9afl / RetroWrite / ZAFL.**
    Near-native throughput and stack-ASan vs QEMU, for PIC x86-64/AArch64 ELF. Throughput win, not a
    new bug class. **Intel PT** (libxdc/honggfuzz-PT) is x86-64-host-only (can't trace our cross-arch
    targets) — situational.
18. **Snapshot / full-system fuzzing: Nyx (KVM) / what-the-fuzz.** For stateful/kernel/daemon/Windows
    targets that can't fork cleanly. Highest ceiling, biggest engineering lift — defer to a target
    that needs it. Refs: Nyx (USENIX'21); https://github.com/0vercl0k/wtf .

---

## Recommended next builds

The four highest-ROI items (`cmpdict`, `memoracle`, `blockdist`, `variant`) are now **shipped**
(see "Shipped in this pass"). The next tier, in priority order:

1. **Grammar / structure-aware mutation from the inferred format spec** (Tier 2 #9): emit lykos's
   already-inferred format spec as a Gramatron/Grammar-Mutator grammar through the AFL++
   custom-mutator API — uniquely leverages an asset most fuzzers lack.
2. **weggli source variant analysis** (Tier 2 #8): vendor the single weggli binary + a curated
   query pack and a "generalize-from-a-patch" workflow — the source-side complement to the binary
   `variant-scan` just shipped.
2. **Differential testing (NEZHA-style)** (Tier 2 #11): a non-crashing oracle for logic/parsing
   bugs sanitizers never see — highest *new bug class* yield.
2. **OptiMin** (MaxSAT-optimal minset) on top of `distill.py` when a bundled solver is acceptable.
3. **Auto-derive a grammar from the inferred format spec / mined tokens** so the new grammar engine
   fires without an analyst-supplied grammar (a from_spec bridge already exists; extend it).
4. **Joern** as a heavier cross-language / data-flow variant-analysis backend beside weggli.

Beacon-style path pruning on top of `blockdist`, and `libqasan` (built from AFL++ qemu_mode) to add
shadow-memory depth to the `memoracle` lanes, are natural follow-ons to the shipped work.

## Method note

This roadmap synthesizes five parallel SOTA surveys (coverage-guided fuzzing; binary-only /
hybrid / directed / binary sanitizers; static analysis; firmware rehosting; patch-diff / harness
synthesis / oracles), each constrained to non-AI + air-gappable techniques and each asked to
target lykos's specific gaps. The primary sources are collected in the surveys; the load-bearing
ones are cited inline above. Repo-URL attributions for a few firmware artifacts (FirmAE, Greenhouse,
Ember-IO) were flagged as needing verification against their papers before vendoring.
