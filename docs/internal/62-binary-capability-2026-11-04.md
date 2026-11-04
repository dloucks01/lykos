# 62 — Audit + binary capability program (2026-11-04)

Operator ask: "do a code review and full audit … we need to start building out a more robust binary
capability now. We've gotten the source tree down to a good point."

Constraints unchanged: LLM-free, air-gapped, non-fuzzing-first (fuzzing additive, bounded,
reach-gated), validated PoC or honest actionable dead-end, forgery-proof oracles.

## 1. Audit results (all fixed on `rework/poc-engine-doc58` unless noted)

**Code review of b603fbe..HEAD (doc-61 program + follow-ups)**

| # | Defect | Fix |
|---|---|---|
| 1 | DOP hands-off oracle forged by any echoing / length-printing target (negative control was one byte shorter) | same-length zero-byte control, second truthy flip, raw-substring compare (dd053c0) |
| 2 | DOP detonation never ran: `from . import dop` ImportError swallowed; test vacuous | import fixed, 45 s deadline, test asserts the detonator fired (dd053c0) |
| 3 | i2s pre-pass unbounded (~21k runs worst case) and accepted echo output as "past the gate" | 10 s deadline; a layout must generalize + the field must BE the gate (6eab028); now sandboxed (888d038) |
| 4 | race_scan: body-relative line numbers; FreeRDP 67/67 false positives | true lines; concurrency-mutable memory required; 67 → 0 (25febe1) |
| 5 | directed-confirm seeds never passed; seeds pinned byte-for-byte (fully concrete) | wired; prefix-only pinning (6f7ed90, 888d038) |
| 6 | House of Water: no 16-byte alignment check; function object in the recipe dict | checked; JSON-safe (bc74354) |
| 7 | run_and_verify reported a crashed run complete from a reused case store | rows newer than this launch only (6a6ae21) |
| 8 | deep_decoder_fuzz: 30 harnesses × fork=4 ASan, no memory cap | bounded + systemd-run MemoryMax (6a6ae21) |
| 9 | alloc_overflow flagged u16×u16 (cannot wrap 32 bits) and reads after the alloc | width model (8297b74) |
| 10 | guard_gap labelled a static heuristic "VARIANT-CONFIRMED … forgery-proof" | "variant-corroborated" (bc74354) |

**Found while auditing**

- **Test suite OOM-killed twice (60 GB, then 90 GB cap).** Root cause: `gadget_emu` built a fresh
  Unicorn per gadget window; a hooked `Uc` sits in a reference cycle and is only freed by the
  cyclic GC, which counts Python objects, not native memory. The riscv64 LR-solver test peaked at
  69 GB. Explicit finalizer: 1.3 GB peak (3449f38). This is a PRODUCTION path (cross-arch L3).
- **`confirm` promoted audit advisories and roll-ups** — `dangerous_api` "calloc -- check the size
  …" rows citing ~300 call sites were CONFIRMED and handed weaponization recipes once binary reach
  worked. Never promote an advisory or a multi-site roll-up (45f62aa).
- **Stages ignored cancellation for ~2 min** (taint fixpoint, chain_primitive), and the abandoned
  thread kept burning CPU ~6 min: jhead-3.04 executed the target 0 times in two recall runs
  (792a360).

**Hygiene (open, low-risk):** remote branch diverged — `origin/rework/poc-engine-doc58` holds the 5
reverted Oct-31 detector commits; publishing needs `--force-with-lease` (operator decision).
`codeql` is registered but never autopilot-scheduled. `sink_determine`, `potential_poc`,
`dos_harvest`, `stateful_harness`, `poc/heap_search` are imported only by tests. ruff 186 / mypy 15.
docs/overview.md + pipeline.md stage lists predate 17 stages.

## 2. Where binary-only stood

Recall bench, binary surface, 600 s (bench/recall/runs-final, 2026-11-02): **2 / 35 defects**
(jhead-3.06 CVE-2022-41751 via injection probes, ncompress CVE-2001-1413 L2 via stack_frame). Four
of five runs spent 77-89% of budget fuzzing (25k-57k executions each) and saw **zero crashes**.

Root causes found this session:

1. **No memory oracle for binaries.** The CVEs are mostly heap over-reads / small over-writes — they
   do not crash a native binary. The bundled AFL++ `afl-qemu-trace` + `libqasan.so` worked all
   along; nothing set `AFL_PATH`/`AFL_USE_QASAN`.
2. **The binary reach spine was broken.** `taint_reach` seeded BFS from the `read`/`recv` IMPORT
   names (no callees) → 0-1 reachable functions per binary; `main` was not an entry and x86-64
   stripped `main` was not recovered; triage filed undecided as off-surface; UC resolved 0
   functions on stripped code (`fcn.*` names, no PIE rebase).
3. **Budget starvation** from non-cancellable static stages on static binaries.

## 3. Built this session

- **Binary spine** (888d038): entries = `main` + every caller of an input source; x86-64
  `main_from_start`; undecided ≠ off-surface; angr resolves `fcn./sub_/FUN_` + PIE rebase.
  Reachable functions on the baseline cases: jhead 0→384, unzip 1→123, giflib 0→80, ncompress 1→38.
- **QASan memory oracle** (`dynamic/qasan.py`, d5fab5d): one input, sandboxed, deadline, parsed
  report (class, R/W, size, in-target site → link VA → function, alloc site, CWE). Forgery checks:
  nonce'd module name must appear in a frame (guest argv[0] neutralised via qemu `-0` — a fake that
  printed argv[0] then raised SIGSEGV was accepted before), report not in the input, report-then-
  clean-exit rejected; QASan can spin after a second error, so report + still-alive-after-1 s counts.
- **QASan lane in coverage_fuzz** (2063a2f): AFL `-Q` under QASan; crashes that do not reproduce
  natively + AFL HANGS (QASan detections land there) replayed through the oracle; each distinct
  (class, access, site) filed `confirmed`; excluded from the native prove loop.

**Proof:** shipped `gif2rgb` (no source, no debug info). 2 min of AFL+QASan → heap over-read in
`main+0x8f70` ("6 bytes to the right of 6-byte region"); native exit 0. Replayed against an ASan
build of the same giflib source: `DumpScreen2RGB gif2rgb.c:294` = CVE-2016-3977 / CVE-2020-23922 /
CVE-2022-28506. Both earlier recall runs missed this group entirely.

A/B (120 s AFL -Q, same seed, plain vs QASan): gif 5,323 vs 1,779 execs (QASan hangs cost the
timeout), zip 86k vs 35k, jpg 156k vs 137k; edges within 5%. Cost is real but the oracle is the
difference between seeing and not seeing the bug class.

## 4. Binary build program (priority order)

1. **QASan everywhere execution happens** — DONE for AFL; NEXT: replay the sandbox fuzzers'
   (`fuzz`/`directed_fuzz`) interesting inputs and every concolic/hypothesis-generated input under
   QASan; a QASan-aware PoC (bundle `afl-qemu-trace` + `libqasan`, verify by report) so these reach
   `poc-backed` and count as *proven* in the bench. Lower the AFL `-t` for QASan campaigns so a
   spin-after-report costs ~1 s, not 5 s.
2. **Binary ground truth.** Stripped twins (`-O2 -s`) of the recall/Tier-2 targets + FreeRDP 3.20.0
   (its 10 source-confirmed bugs = free binary ground truth); the bench matcher needs an
   address→source map for no-debug binaries (it matches on (file, function); the gif2rgb hit says
   `main` because DumpScreen2RGB is inlined).
3. **Hypothesis loop as an autopilot binary stage** (`hypo/loop.hunt`, today CLI-only): directed
   propose → solve → validate at `detect_cwe` sites, validated by native crash OR QASan. This is the
   non-fuzzing-first path for binaries.
4. **Precise detectors on P-Code** (`detect/pcode_guards.py`): the binary analogues of guard_gap /
   alloc_overflow / intwidth / lifecycle / sibling_guard, using P-Code's explicit
   `INT_ZEXT/SEXT/SUBPIECE` and `INT_CARRY` — one finding per SITE, never a roll-up. Prerequisite:
   FLIRT for malloc/free/fread/recvfrom + musl; jump-table / indirect-call edges.
5. **Unicorn function harness as autopilot driver-synth for binaries** (redzone allocator,
   aarch64/arm), with honest "function-level, caller constraint unproven" provenance until replay
   from the entry confirms it.
6. **Static-binary scoping**: on a statically linked binary, scope taint/bounds to non-libc code
   (FLIRT-identified or symbol-named libc bodies excluded) — jhead-3.04 spent 229 s analysing glibc.

## 5. Bench after this session

(filled in from bench/recall/runs-binary-20261104b)
