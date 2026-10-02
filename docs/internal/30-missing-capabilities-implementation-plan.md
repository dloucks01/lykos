# 30 — Implementation plan for the open gaps

Operationalizes the **[PLANNED]** queue in doc 20 (28 items) plus the environment/corpus gaps,
into sequenced workstreams with concrete approaches, acceptance gates, and risk. The pipeline is
complete end to end (detect → corroborate → weaponize → PoC → exploit, across ISAs, for binary +
source + firmware); the gaps cluster in **precision depth**, **fuzzing yield on real parsers**,
**optimized/exotic-arch coverage**, and **CI/benchmark enforcement**.

Size key: **S** ≈ ≤1 day, **M** ≈ 2–4 days, **L** ≈ ≥1 week. Every item keeps the module contract
"demote/surface, never fabricate": a precision change must not create a false NEGATIVE (a demoted
real bug), and that is the acceptance bar, not just "FP count down".

## Sequencing rationale

```
Phase 0  Enforcement        ── makes every later change measurable, catches regressions on push
   │
Phase 1  Taint memory model ── the backbone: unblocks computed indices, heap/alias recall,
   │                           inter-procedural guards (precision AND recall)
   ├── Phase 2  Precision completeness  (CWE-798, assertable overflows, crash grain, blocked arches)
   │
Phase 3  Fuzzing yield      ── largely independent; gated by Phase 0 benchmarks
Phase 4  Firmware depth     ── hardest/most uncertain; feasibility spike before commit
Phase 5  Dynamic & UX polish── small, independent, do opportunistically
```
Phase 0 first on purpose: without Ghidra-in-CI and a real scored benchmark, every precision change
in Phases 1–2 is unverifiable on push and a regression (a demoted real bug) ships silently.

---

## Phase 0 — Enforcement & measurement (do first)

**0.1 Ghidra in CI so `eval-gate` runs on push.** (M) `.github/workflows/ci.yml` runs the 491 unit
tests but not `eval-gate` (needs a decompiler). Add a CI job that provisions Ghidra (cache the
release tarball; `collect-toolchain.sh` already knows how) and runs `lykos eval --min-state
corroborated` with a pass threshold of **0 false positives / no new FN**. *Acceptance:* a PR that
reintroduces a CWE-120 FP fails CI. *Risk:* CI minutes + Ghidra flakiness → cache aggressively, set
a generous per-case timeout.

**0.2 Cross-arch cases in the bundled corpus + per-arch scoring.** (M) `eval-gate` measures x86-64
only; an arch regression (e.g. the materialised-displacement bug) never trips it. Compile a subset
of `corpus.bundled()` for aarch64/arm/ppc64(le)/mips(el)/riscv64 (cross-gcc + qemu, already present)
and score detection per arch. *Acceptance:* `eval-gate` reports a precision/recall row per arch; a
drop on any arch fails. *Depends on:* nothing. *Risk:* static cross binaries bloat Ghidra — bound
the subset.

**0.3 Real scored benchmark, separate from the tripwire.** (L) ✅ **DONE.** `lykos eval --benchmark`
scores detection as a TRACKED number, never a gate (always exits 0). It runs a vendored, offline,
fixed breadth corpus (`corpus.benchmark()` = the 24-case tripwire **plus** `_BENCH_EXTRA` — good/bad
pairs for CWE-377/330/190, classes the gate does not exercise; 10 classes total) at BOTH channels —
candidate (detection breadth, incl. the rule/weak-primitive detectors) and corroborated (the
taint-discriminated precision lever) — plus the **LAVA-M** recall mini, and records each run to the
dashboard history (`lykos dashboard`). Measured on the native backend: candidate P=0.52 R=1.00
F1=0.69, corroborated P=1.00 R=0.73 F1=0.84, LAVA 3/8 — the candidate→corroborated recall gap is the
three rule-channel extras, exactly the breadth-vs-precision distinction a benchmark should show.
`--juliet`/`--lava` point it at a real NIST drop for a larger score (the loaders already exist). CI
runs it as a non-gating visibility step so the numbers print on every push. *Acceptance:* `lykos
eval --benchmark` prints a stable score; wired into doc 20's dashboard. ✅ *Deferred:* bundling real
CVE **binaries** (size/provenance) — the external-drop path and the realgate's ncompress CVE cover
real targets today; a vendored CVE mini is a later add.

**0.4 32-bit ARM tests runnable in CI.** (S) ✅ **DONE.** `tests/test_arm.py` skipped unless the
musl-built `vuln_arm` corpus binary was present (a dev-box artefact). It now builds the binary on
demand from the corpus source with the distro `arm-linux-gnueabihf-gcc` (`-O0 -fno-stack-protector
-static`, verified to reproduce the same handle()-frame offset 132 as the musl build) when the musl
one is absent, and skips only when neither a cross-gcc nor `qemu-arm` is available — both are already
installed in the `tests` CI job, so the four ARM tests now execute there. Doing so surfaced a real
monitor bug: `qemu_gdb.monitor_calls` armed fixed 4-byte ARM breakpoints at raw symbol addresses and
never masked the Thumb bit, so against a **glibc/armhf** libc (Thumb-built — `system`/`strcpy`/… have
bit0 set) every breakpoint sat at an odd address and never fired → zero hits. Fixed to mask the
address (`&~1`) and use a 2-byte length hint for Thumb symbols, mirroring what `capture()` already
did; the cross-arch call monitor now works against Thumb libcs, not just musl's ARM-mode one.
*Acceptance:* the arm tests execute in CI, not skip. ✅

---

## Phase 1 — Taint memory model (the backbone)

This is the root enabler: doc 20's "memory model beyond constant-offset frame slots", "computed
indices", and "guard reasoning is intra-procedural" all reduce to the taint engine (`detect/taint.py`)
losing a value's origin across blocks/calls and dropping taint at non-slot memory.

**1.1 Inter-block taint-origin tracking.** (L) ✅ **DONE.** `via` was reset per block (`taint.py`),
so the frame slot an index/length was loaded from was lost before the deref's block — exactly why
the computed-index guard read as UNCHECKABLE at -O2 (doc 20; the register-name shortcut had been
rejected as unsound). Now a register/stack→frame-slot origin map is carried across block edges and
merged at block entry (`_merge_origins`, intersection — a binding survives a join only if every
predecessor agrees, so nothing is fabricated), with `_apply` killing a carried origin on any
redefinition it does not itself track. Uniques (block-local p-code temps) are not carried
(`_carry_origins`). Gated by `LYKOS_INTERBLOCK_ORIGINS` (default on) so the before/after is testable.
*Acceptance (met):* the `-O2` `if (i<N) buf[i]=…` fixture — with the guard and the use in separate
blocks — resolves the index to its slot and the sound `guard_bound`/`classify_derefs` marks it
GUARDED, while the unguarded sibling stays UNKNOWN (no fabricated guard); flag OFF leaves it
`index-not-tracked`. `tests/test_interblock_origins.py`. *Risk handled:* the corroborated `eval-gate`
is byte-identical ON vs OFF (8/0/0, recall 1.00, fp_rate 0.00) — `via` feeds only the computed-index
`mem_out` channel, never the sink taint set, so no FN/FP change. (The planned "corpus cases" were
dropped: a computed-index deref is always a candidate-state `tainted_deref` finding regardless of the
guard, so the harness cannot discriminate the pair — the verdict unit test is the meaningful check.)

**1.2 Taint through computed/heap addresses (stop dropping taint at non-slot STOREs).** (L) ✅
**DONE.** A `STORE` through a computed address (`heap[i]`) dropped taint, so a downstream read of
that memory was untainted → missed findings. Now a coarse, region-granular points-to: a tainted
STORE through a pointer whose origin is a known heap slot taints an `("hmem", slot)` token (keyed by
the frame slot that holds the `malloc`'d pointer — reusing `bounds._heap_capacities`' sound
single-writer provenance), and a LOAD through the same slot reads it. The tokens live in the taint
set, so they flow across blocks through the existing fixpoint; P1.1's cross-block origins make the
pointer slot resolvable (and this fixed a related gap: an in-place `add rdx,rax→rdx` for `base+index`
lost the base's origin — `_apply` now folds in each input's resolved origins before overwriting).
Gated by `LYKOS_REGION_TAINT` (default on). *Acceptance (met):* the `heap[i]=input; n=heap[0];
memcpy(dst,src,n)` fixture flags the sink with the flag on and not off (`tests/test_region_taint.py`);
on the Phase-0 benchmark corroborated recall rose 0.727 → **0.750** (F1 0.842 → **0.857**) with
precision held at **1.000** (0 FP), and the corroborated eval-gate still PASSes (8/0/0). The bundled
benchmark gained a heap-round-trip good/bad pair to track it. *Risk handled:* keyed only on proven
heap slots (not arbitrary pointers), region-granular, measured against the benchmark precision number.

**1.3 Inter-procedural guard reasoning.** (M, after 1.1) ✅ **DONE** (callee-return direction).
Guard reasoning was intra-procedural: a length bounded by a callee's return was invisible, so
`unsigned n = cap(); memcpy(buf,src,n)` read as an unbounded copy. `bounds._return_bounds` now
summarises a function's provable constant return UPPER BOUND — every return path yields a
non-negative constant, or a return slot a dominating guard bounds (reusing the sound `guard_bound`,
which refuses a slot reassigned on one path, so a cmov/branch clamp is conservatively skipped rather
than mis-bounded). `classify_program` carries that bound to a caller's copy length when the length
is a **single-writer** slot holding that callee's return — the slot then always holds the bounded
value, the same soundness trust `_heap_capacities` uses, so no dominance tracking is needed. Gated
by `LYKOS_INTERPROC_BOUNDS` (default on). *Acceptance (met):* `cap()` returns ≤ 64 and
`f(){ char buf[128]; n=cap(); memcpy(buf,src,n); }` is proven **SAFE** with the flag on and UNKNOWN
without — the guard came from a different function (`tests/test_interproc_bounds.py`); corroborated
eval-gate still 8/0/0, 0 FP. *Scope:* the callee-RETURN-bound direction (the acceptance's "a callee
that returns a bounded value"). The caller-parameter-bound direction into a copy WRAPPER (`copy(buf,
src,n)` whose body is the sink) needs the destination pointer resolved across the call — that is
inter-procedural points-to (1.2 territory), tracked separately and not attempted here.

**1.4 `argc` as a size/range source.** (S) ✅ **DONE.** `argc` stays out of the data-flow taint
channel (a count, not data; tainting it would push taint through every `argc` guard), but the detect
stage now treats the entry function that receives it as scanned for the integer-overflow shapes
(`touched |= entry_seeds`) and `_intover_candidates` gained an allocation-size-wrap detector: a
narrow (sub-pointer-width) arithmetic feeding an allocator's size argument — `malloc(argc*K)`,
`calloc`/`realloc` sizes — emits `int_overflow_alloc` (CWE-190). A constant operand is allowed here
(`n*elemsize` is the canonical overflow, not a loop counter), kept quiet by confining it to
allocator size args. *Acceptance (met):* `malloc(argc*4096)` flags CWE-190 and a constant-size
allocation does not (`tests/test_argc_sizesource.py`); it is a candidate-grade channel, so no
data-flow taint and no change to the corroborated eval-gate (still 8/0/0, 0 FP).

**Phase 1 complete** (1.1–1.4). The taint engine now carries value origins across blocks, taints
through heap/computed addresses, propagates callee return bounds, and treats `argc` as a size source
— each behind its own flag, each eval-gate-neutral, with regression tests.

---

## Phase 2 — Precision completeness (rides on Phase 1 where noted)

**2.1 CWE-798 corroboration.** (S) ✅ **DONE** (pulled forward in P0.1). `hardcoded_secrets` is a
string detector with no call site, so neither taint channel applies → it could never be corroborated,
capping corroborated recall at a structural 0.833 (5/6). Resolved via approach (b): the eval harness
carries `_CORROBORATION_EXEMPT = {CWE-798, CWE-321, CWE-259}` and counts those classes as detected on
their poc-backed promotion (`synthesize_secret`) rather than requiring a taint second channel. The
CWE-798 bad case now scores found at corroborated and its goods discriminate, so corroborated recall
reflects reality. *Acceptance met:* the corroborated gate holds recall 1.00 with CWE-798 in the
corpus.

**2.2 Assertable overflows from trustworthy frame recovery.** (L) ✅ **DONE.** A constant/guard bound
exceeding the recovered buffer was only SUSPECT (surfaced, never asserted) because the decompiler
fragments a buffer into several locals and the recovered size is unreliable. A new `CONFIRMED`
verdict asserts the overflow, but ONLY when a second, independent source agrees on the destination
size: `_memset_sizes` records each stack buffer's `memset(&buf, _, CONST)` extent (the program's own
init, keyed by the same raw `(base, disp)` a copy's destination resolves to), and `classify_site`
upgrades to CONFIRMED when that extent EQUALS the frame-recovered capacity and the copy exceeds it.
On disagreement — the fragmented-frame case — it stays SUSPECT, so the module's cardinal sin (a
fabricated overflow) cannot happen. `stage.py` promotes a CONFIRMED copy to high/corroborated.
*Acceptance (met):* the two-source-agreement test confirms a true overflow and refuses both the
disagreeing (fragment) and no-second-source cases (`test_bounds.py`), the existing fragmented
fixtures are untouched (no `confirmed_sizes` → unchanged), and the corroborated eval-gate still
PASSes 8/0/0. *Note:* the native backend's coarse frame recovery often disagrees with the memset
(e.g. recovers a `char[64]` as 72), in which case CONFIRMED correctly abstains — a precise backend
gets the assertion.

**2.3 Crash finding grain: one row per DISTINCT crash.** (M) ✅ **DONE** (already resolved; the
plan's "keyed by signal" described the pre-fix state). `crash_dedup_key` keys a crash by its FAULT
SIGNATURE: `dynamic-crash:{signal}:{fault_pc}` for a real fault, a sanitizer-report discriminator
(`class@source`) for an ASan/UBSan abort so two different sanitizer defects that both abort stay
distinct, a signal-only bucket for a plain glibc abort (whose PC is in the abort machinery, not the
defect), and a `:cfh` collapse for a control-flow hijack (where the PC is attacker-garbage and would
otherwise fan one stack smash into dozens). *Acceptance met:* two distinct crashers (different fault
PCs) produce two findings and the same defect found repeatedly stays one — `test_crash_attribution.py`
(`test_two_defects_that_both_segfault_are_two_findings` and siblings). Access-kind/backtrace are not
added because the native SIGSEGV path captures neither (only the JVM/Wine paths carry frames), so the
faulting PC is the best signature the data offers.

**2.4 Unblock the three arches upstream of the bounds pass.** (M) ⚠️ **INVESTIGATED — plan premises
did not survive the evidence; real blockers are backend-level, deferred with findings.** Measured on
the bundled corpus (native backend, riscv64-/sh4-linux-gnu toolchains, both present):
- **riscv64** recall is 0.125 at BOTH candidate and corroborated — not a bounds-slicer problem. The
  native backend (rizin + pypcode) recovers **no call edges** for riscv64 (`dst_name` set empty) and
  emits a garbage symbol from the ISA string (`_xrv64i2p1_...`), so the rule-channel detectors that
  key on calls (`dangerous_api`/`lang_sinks`) never fire. The planned `lui`/`addi` immediate pairing
  is a bounds refinement and cannot help a candidate-channel miss — the blocker is call-graph
  recovery in the disassembler, not `_slice_block`. Fixing it needs backend work (rizin riscv64
  analysis) or a lykos-side call-recovery path (`auipc`/`jalr`, PLT/relocations) — a separate effort.
- **sh4** recovers calls (finds every bad case, fn=0) but has 9 false POSITIVES, and they are exactly
  the discrimination negatives — `printf("literal")`, `system("const")`, `memcpy_clamped`,
  `strncpy_bounded`, `strcpy_length_guarded`, … — flagged at corroborated. The cause is the
  PC-relative literal pool: the format strings, constant commands and clamped lengths are
  materialised via `mov.l @(disp,pc)`, which the analysis cannot resolve, so it cannot recognise them
  as compile-time constants and defaults to "attacker-influenced." So 2.4b's direction is right, but
  the fix is larger than a `_const_of` pool read: it must plumb the binary's rodata (or reuse rizin's
  string xrefs) into the detect stage and feed resolved constants/literals through the taint, bounds
  AND injection discriminators — a multi-detector change, not the table-driven slicer tweak scoped.

Not landed: shipping the planned `lui`/`addi` slicer would be dead code (riscv64 reaches no sink to
bound), and a half-wired pool reader risks the precision bar. Both arches stay on their ratchet
baselines (unregressed). Recommended follow-ups recorded in doc 20.

---

## Phase 3 — Fuzzing yield on real parsers

**3.1 `coverage_fuzz` (AFL) reliability.** (M) ✅ **DONE.** The guest/host-mismatch detection and
clean decline were already in place (`aflpp.qemu_trace_arch` names the guest the trace actually
emulates; `_unsupported` declines a cross-arch target with a fix-it message; the fork-server abort
is avoided by checking first). The remaining defect: `coverage_stage` raised `toolchain_missing`
(which always demanded `afl-qemu-trace`) BEFORE honoring `qemu=false`, so the afl-INSTRUMENTED path
— which executes the target natively under afl-fuzz and needs no emulator — was unreachable, and
coverage_fuzz "failed loudly" on the native arch wherever `afl-qemu-trace` was absent (the common
case; Ubuntu's `afl++` omits it). Fixed: `toolchain_missing`/`_unsupported` take `use_qemu`, so the
instrumented path requires only afl-fuzz and declines only a cross-arch target (which can't run
natively). *Acceptance (met):* `test_coverage_fuzz_real_campaign_confirms` now RUNS (was skipping)
and confirms a crash via coverage-guided afl-cc instrumentation — coverage feedback reaching the
campaign; `test_afl_arch.py` locks the native-runs/cross-arch-declines behavior. CI installs `afl++`
so the real campaign executes on the native arch there (provisioning documented in `ci.yml`).

**3.2 Format-aware, complete seeds.** (L) ✅ **DONE** (landed in commit `1792ebd` "seed structural
crash shapes (offset/size wrap)"; verified this session). `fuzz/structure.py` carries a `FormatModel`
with field-aware synthesis for jpeg/png/gif/bmp/riff/zip/rtp/h264/mpegts and more: each builds a
COMPLETE, valid container from the target's own format strings + magic (`detect_format` →
`seed_for_name`), with described fields the `StructMutator` edits surgically while keeping the
length/offset relationships intact. The JPEG/EXIF model is complete through the SOF0+SOS frame (so
jhead reaches `ShowImageInfo`, 83/114 functions vs 41 for a skeleton) and models the IFD entry count,
GPS sub-directory and the offset/size pair that is jhead's exact bug (a 32-bit `0x00ffffff +
0xff000002 = 1` wrap in `ProcessGpsInfo`). *Acceptance (met):* `tests/test_format_models.py` (34
tests) verifies the complete seed, the surgical nested-field edits, the constructed wrapping
offset/size pair, and that real decoders (jhead/gif2rgb/unzip/Pillow/wave) accept the seeds — and a
real campaign against `examples/vuln-targets/bin/jhead_x86-64` using the built-in structure mutator
**crashes jhead (SIGSEGV) in 17 executions**, against the blind baseline of 98,500 execs / 0 finds.

---

## Phase 4 — Firmware depth (feasibility spike before committing)

**4.1 Task-level RTOS execution.** (L, uncertain) Running code INSIDE a scheduled task needs faithful
M-profile exception entry/return — Unicorn 2.1.4 raises `UC_ERR_EXCEPTION` on EXC_RETURN, exposes no
controllable NVIC, and its SCS is shadowed when mapped as RAM (documented this session in
[[firmware-rehost-init-loop]]). **Spike first (S):** evaluate (a) a hand-rolled M-profile exception
model over Unicorn (stack/unstack frames, NVIC/SysTick, VTOR), vs (b) QEMU-system with an SVD-derived
machine, vs (c) Renode. Only then commit to one. *Acceptance of the spike:* a decision memo with the
first task's code reached on the real FreeRTOS image. *Risk:* high — this is the "board model" the
rehoster exists to avoid; time-box the spike and accept "documented out of scope" as a valid outcome.

**4.2 Non-constant allocation sizes + allocator wrappers.** (M) ✅ **(b) DONE; (a) noted.**
`_heap_capacities` handled only direct `malloc(const)` single-writer slots. `_allocator_wrappers`
now resolves a project's own allocator WRAPPER (`xmalloc`/`my_alloc`-style) by its structure — the
function's ONLY allocation call feeds a base allocator the function's own first parameter as the
size (`_param0_spill_slot`, tracking the param through its prologue copy), and it RETURNS the
allocator's result (reusing the P2.2 `_returned_value` at every value-returning exit; a no-return
abort path is ignored). A `p = wrapper(n)` then sizes `p` exactly as `malloc(n)` would. The
signature is deliberately strict so the heap-sizing channel never fabricates a size. *Acceptance
(met):* a copy into a `my_alloc(64)` buffer is SAFE and a `my_alloc(16)` buffer overflowed by 64 is
flagged (`tests/test_alloc_wrappers.py`); the corroborated eval-gate is unchanged (8/0/0).
*(a) deferred with finding:* the sound demotion for a *variable* size is the EQUALITY case
`p = malloc(n); copy(p, src, n)` (copy length == alloc size → exact fit → SAFE), which needs
size-value ↔ copy-length linkage; a guard `n <= K` only yields an UPPER bound on the allocation, so
it supports ASSERTING an overflow (copy > K), not proving SAFE. Tracked as a follow-on.

**4.3 `libwebp` and other ABI-only-version libraries.** (S) Dropped from the CVE DB because it
exposes only `WEBP_*_ABI_VERSION`. *Approach:* map the ABI/decoder version constant → release
version, or fingerprint by a embedded build string, as an operator-extensible table. *Acceptance:*
a libwebp binary with CVE-2023-4863's version matches.

---

## Phase 5 — Dynamic & UX polish (small, independent)

- **5.1 `debug_monitor` beyond the loader.** (M) Its 13 recorded calls on a real target were mostly
  `ld.so`. Filter to the target's own address range and set symbol breakpoints on user code.
- **5.2 `boundary_fuzz` graceful on inapplicable targets.** (S) Returns `error` for a single-binary
  target with no boundary; make it a clean `skipped`/no-op (like the self-gating stages).
- **5.3 PE `behavior_trace`/monitor.** (M) The Wine `+relay` monitor exists; extend the behavior
  trace + execution/crash path to PE so Windows targets get the same loop as ELF.
- **5.4 Stage parameter consistency.** (M) `dynamic_run` and others accept inconsistent params and
  fail silently. Add a per-stage param schema + validation that fails loud (surfaces in the run
  record), and a test that every registered stage declares its params.
- **5.5 Runs list shows yield.** (S) `fuzz · 177s · DONE` that found nothing reads like success.
  Show found/none (and crash count) in the run row.
- **5.6 Live Events backfill.** (S) The WebSocket starts at connect, so a case with history shows an
  empty Live Events. Replay the stored event log on connect.
- **5.7 Second positive L2 target.** (S) Close out the open L2 validation (doc 20 §F): a second
  real program driven to a demonstrated primitive, beyond the ncompress/jhead fixtures.

---

## Dependency summary & suggested order

1. **Phase 0** (0.1 → 0.2 → 0.4 → 0.3) — enforcement, so everything after is measured.
2. **Phase 1.1** (inter-block origins) — unblocks the most, lands behind a flag with before/after
   `eval-gate`.
3. **Phase 2.1, 2.3** (CWE-798, crash grain) — independent, quick precision wins.
4. **Phase 1.2, 1.3, 1.4** (memory model, inter-proc guards, argc) — the recall backbone.
5. **Phase 2.2, 2.4** (assertable overflows, blocked arches) — ride on 1.x + Phase 0 cross-arch.
6. **Phase 3** (fuzzing yield) — parallelizable with Phase 1/2.
7. **Phase 4.1 spike** early (decision gate), 4.2/4.3 anytime.
8. **Phase 5** — opportunistic throughout.

**Global acceptance for every phase:** `eval-gate --min-state corroborated` stays at **0 false
positives with no new false negatives**, the Phase-0 benchmark score does not regress, and each item
ships with a corpus case (both directions where a demotion is involved) so the gate guards it going
forward. No attribution trailers on commits (repo rule).
