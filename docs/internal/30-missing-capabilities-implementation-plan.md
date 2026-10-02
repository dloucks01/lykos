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

**1.2 Taint through computed/heap addresses (stop dropping taint at non-slot STOREs).** (L) A
`STORE` through a computed address (`buf[i]`, a heap pointer, an alias) drops taint, so downstream
reads of that memory are untainted → missed findings (recall). *Approach:* a coarse points-to: model
a tainted STORE to an unknown address as tainting a "heap region" token associated with its base
pointer's origin, and a LOAD from the same base as tainted. Keep it conservative (region-granular,
not byte-precise) to avoid over-tainting. *Acceptance:* a `heap[i] = input; use(heap[j])` fixture
flags the downstream use; recall up on the Phase-0 benchmark with precision held. *Risk:*
over-tainting → FP inflation; gate on the benchmark precision number.

**1.3 Inter-procedural guard reasoning.** (M, after 1.1) Guard reasoning is intra-procedural: a
length/index bounded in a caller (or by a callee's return check) is invisible. *Approach:* propagate
a proven bound across the one-level call edges `dctx.call_edges` already provide — a parameter bound
at the call site, or a callee that returns a bounded value. *Acceptance:* a `check(n); copy(buf,src,n)`
split across two functions demotes correctly. *Risk:* unsound if the callee re-derives the value;
require the bound to dominate the call and the argument to be pass-through.

**1.4 `argc` as a size/range source.** (S) Deliberately excluded from the data-flow channel (a count,
not data). Integer-overflow and bounds classes want it. *Approach:* a separate **size/range** source
set feeding only `int_overflow` and `bounds`, never the data-flow taint (which would push taint
through every `argc` guard). *Acceptance:* `malloc(argc*K)` int-overflow fixture flags; no new
data-flow FPs.

---

## Phase 2 — Precision completeness (rides on Phase 1 where noted)

**2.1 CWE-798 corroboration.** (S) `hardcoded_secrets` is a string detector with no call site, so
neither taint channel applies → it can never be corroborated, capping corroborated recall at 0.833
(5/6). *Approach:* give the string channel its own second-channel notion (the secret's byte offset +
a re-extraction, which `synthesize_secret` already computes is the natural corroborator), OR exclude
CWE-798 from corroborated-stage scoring and score it on the poc-backed promotion it already gets.
*Acceptance:* corroborated recall reflects reality (not a structural 0.833 floor). *Risk:* none —
scoring/semantics only.

**2.2 Assertable overflows from trustworthy frame recovery.** (L) Today a constant/guard bound that
EXCEEDS the recovered buffer is only SUSPECT (surfaced, never asserted), because Ghidra fragments a
buffer into several locals and the recovered size is unreliable. To CONFIRM an overflow we need a
reliable destination size. *Approach:* corroborate the frame table against a second source — the
copy's own access pattern, adjacent-variable gaps, or a lightweight re-derivation of the buffer
extent from the prologue — and only assert when two sources agree. *Acceptance:* a true stack
overflow is reported CONFIRMED (not just corroborated) with no fabricated overflow on the fragmented
fixtures in `test_bounds.py`. *Risk:* the module's cardinal sin (a fabricated overflow) — keep the
two-source-agreement bar; default to SUSPECT on disagreement.

**2.3 Crash finding grain: one row per DISTINCT crash.** (M) Two unrelated SIGSEGVs merge into one
finding (keyed by signal), so distinct bugs are undercounted and a fixed one masks a live one.
*Approach:* key crash findings by fault signature (faulting PC + access kind + normalized
backtrace), not by signal — consistent with the fuzz-calibration multi-fault handling. *Acceptance:*
two distinct crashers produce two findings; a regression corpus with N planted bugs reports N.
*Risk:* over-splitting flaky crashes → normalize the backtrace, cap per-function.

**2.4 Unblock the three arches upstream of the bounds pass.** (M) `riscv` resolves only one constant
of a split immediate; SuperH materialises constants in a **PC-relative literal pool** the slicer
cannot read; a third arch mis-tracks spills. *Approach:* (a) riscv `lui`/`addi` immediate pairing in
`_slice_block`; (b) a PC-relative pool reader (resolve `mov.l @(disp,pc)` against the function's
rodata) feeding `_const_of`. *Acceptance:* the bounds/guard corpus cases pass on riscv64 and sh in
Phase-0.2 cross-arch scoring. *Risk:* per-ISA encoding detail — table-driven, unit-tested per shape.

---

## Phase 3 — Fuzzing yield on real parsers

**3.1 `coverage_fuzz` (AFL) reliability.** (M) AFL-QEMU fails on this host and `file` reports the
host arch for a fixed-guest emulator (the afl-qemu-trap in doc 20). *Approach:* detect the
afl-qemu-trace guest/host mismatch at setup and fall back cleanly; document the provisioning;
fix the fork-server handshake abort. *Acceptance:* `coverage_fuzz` runs (not "fails loudly") on at
least the native arch in CI; coverage feedback actually reaches the campaign.

**3.2 Format-aware, complete seeds.** (L) The generated seed is not a complete file (jhead's
`ShowImageInfo` is 210 blocks the blind campaign never enters; jhead's own bug is still unfound).
*Approach:* extend the structure/grammar fuzzers (`fuzz/structure.py`, `fuzz/grammar.py`,
`fuzz/xmlgrammar.py`) to synthesize a *valid* container from the target's own format strings +
magic, then mutate fields — so the parser accepts the seed and the campaign reaches the vulnerable
decoder. *Acceptance:* the built-in fuzzer finds jhead's bug (currently a known miss); block coverage
on a format parser climbs past the header. *Risk:* grammar breadth — start with the formats the CVE
DB libs cover (PNG/JPEG/TIFF/XML/zip).

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

**4.2 Non-constant allocation sizes + allocator wrappers.** (M) `_heap_capacities` handles
`malloc(const)` single-writer slots. Extend to (a) a size bounded by a dominating guard (reuse
`value_guard_bound`), and (b) a project's allocator wrapper (`xmalloc`-style) resolved by its own
`malloc(arg)` forwarding. *Acceptance:* a guarded-variable-size heap copy demotes; a wrapper'd alloc
is recognized. *Risk:* keep the single-writer soundness guard.

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
