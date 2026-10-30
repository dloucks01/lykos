# 53 — Tools inventory and issue log for the hypothesis loop (2026-10-30)

Companion to doc 52. Produced while landing Step 1 (`lykos hunt`, commit 61611df). Read-only audit
of `vendor/`, the host, `core/lykos/analyze/` and `tools/` against the loop
(propose → solve → validate → weaponize). Nothing was deleted on the strength of this document.

## 1. Tools the loop and the remaining bug classes need

| Need | For | Status | Plan |
|---|---|---|---|
| Product validator | every class | **done** in Step 1 (`hypo/validate.py`, sandboxed; the scorer now uses it) | — |
| Backtrace attribution for native crashes | binary-only targets (crash inside libc, or at a smashed return address) | `poc/ptrace_capture._backtrace` (frame pointers), `debug/gdb.py run_gdb` (gdb is bundled) exist, unused by the loop | wire into `validate._native_runs`; CFI unwinding via gdb for -O2 code |
| Syscall-effect oracle (execve/openat/connect args) | CWE-78/88, 22, 367 | `strace` on host but not bundled; `fuzz/batch_runner.py` is already a ptrace runner; qemu `-strace` for cross-arch (`debug/syscalls.trace_qemu`) | in-house syscall-stop decoding in batch_runner (~250 lines), no new dependency |
| clang validator builds | CWE-197 (implicit-conversion), 190 without alloc (unsigned wrap), 476 (nullability), 843 (vptr) | clang 21 present and bundled; gcc lacks these checks | add a clang sanitizer flavour to `hypo/build.py` / `source_project` |
| MSan / TSan / LSan builds | 457/908, 367 (threads), 401 | `ingest.compile_source_msan/_tsan/_lsan` single-file only | extend `source_project` flavours (~150 lines); valgrind (`dynamic/memoracle.py`) for binaries |
| Driver predicates | 476, 369, 457, 200, 401, 400/835, 843, 287/863 | none; driver zero-fills unconstrained memory (hides uninit), `malloc` never fails (hides NULL paths) | per-class oracles in `hyp_driver.py`; failing-malloc model + replay shim (`dynamic/heappoison.c`) |
| Exec-family sinks | CWE-78/88 | `CMD_SINKS = {system, popen}` only | add execve/execv*/execl*/posix_spawn |
| Step 3 proposers | recall without hand-given sites | angr's ReachingDefinitions, Propagator, VariableRecovery, LoopFinder, BackwardSlice, Decompiler/AIL unused; pypcode already feeds `detect/bounds.py`, `detect/taint.py` | interval/value-set domain over AIL/VEX (~1.5–2.5k lines); IKOS/Frama-C/CBMC rejected (heavy, not bundle-friendly) |
| Corpora | Steps 5/6 | none on host | cb-multios (MIT, clang -m32 works here); Magma/ARVO pre-built on a connected box (dev-side, not bundled) |
| Source enrichment (optional) | proposer recall | joern (~GB, not bundled), `clang --analyze`, cppcheck | optional; CodeQL dev-only (licence) |

Host notes: rizin missing (doctor reports OK through the r2 fallback — issue 7); honggfuzz, rr,
klee, infer, ropper, libqasan absent; symqemu is x86-64 only.

### 1a. Fetched 2026-10-30 (user space, no root; versions + SHA-256 in `vendor/tools/MANIFEST.txt`)

| Tool | Version | Where | Notes |
|---|---|---|---|
| rizin | 0.9.1 static | `vendor/tools/rizin` | doctor now finds real rizin (issue 7 closed on this host) |
| infer | v1.3.0 | `vendor/tools/infer` | |
| honggfuzz | 2.6 @ 940b958 | `vendor/tools/honggfuzz` | release 2.6 predates binutils 2.46's `disassembler()` API; dev headers via `apt-get download` into `hfdeps/` |
| libqasan | AFL++ v4.33c | `vendor/tools/aflpp/libqasan.so` | needed a glibc-2.43 `_Generic` compat include; `LYKOS_QASAN` set by vendorenv |
| ropper | Ropper@a2ffccf | `vendor/tools/ropper-venv` | release 1.13.10 no longer builds on Python 3.14 (`ast.Str`) |
| KLEE | 3.3 (container, pinned digest) | `vendor/tools/bin/klee` | dev-side; not air-gap bundled |
| rr | — | — | **needs root**: `sudo apt install rr && sudo sysctl kernel.perf_event_paranoid=1` |
| strace | 6.19 (host) | — | added to the bundle's package list (`toolchain.py`) |
| clang sanitizers | clang 21 | host | memory, thread, integer+implicit-conversion+nullability, address+undefined all build and run |
| corpora | cb-multios 810d7b2 (225/241 built), Magma 75d1ae7, ARVO bc2a373 + ARVO-Meta 51cfeab | `bench/external/` (gitignored) | cb-multios needs `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` on CMake 4 and legacy-C errors downgraded |

`vendorenv.activate` puts `vendor/tools/bin` on PATH (behind the toolchain's scoped wrappers) and
points `LYKOS_QASAN` at the built libqasan; `lykos doctor` reports each tool. The bundle builder
does not yet carry `vendor/tools/` into the air-gap package — open item.

## 2. Reused by the loop (keep)

sandbox (`analyze/dynamic/sandbox.py`: `run`, `run_batch` fault PCs are file vaddrs), batch_runner,
crash capture (`poc/ptrace_capture.py`, `debug/gdb.py`, `debug/qemu_gdb.py`), builds
(`ingest.compile_source*`, `source_project`, `dep_preflight`), DWARF (`symbolic/dwarfline.py`),
heap oracles (`dynamic/memoracle.py`, `heappoison.c`), the exploit ladder (`poc/exploit_stage.py`,
`rop*.py`, `gadget_emu.py`, `archmodel.py`, `leak.py`, `fmt.py`, `fmt_recipe.py`, `heap.py`),
PoC bundles (`poc/bundle.py`), effect probes (`poc/injection.py`, `poc/dos.py`, `debug/secrets.py`),
invocation/runtime env, fallback fuzzers, case store / report / GUI API (CLI parity required),
packaging.

## 3. No longer needed under doc 52 (retire plan — none deleted yet)

| Candidate | Lines | Decision | When |
|---|---|---|---|
| `orchestrate.py` 58-stage autopilot | 2,653 | fold: the loop becomes the default plan | after `hunt` is in the GUI (parity) |
| `detect/detectors.py` disasm regex | 5,661 | demote to a proposer feed (secret_stage, firmware still use it) | Step 3 |
| `detect/bounds.py`, `detect/taint.py` | 1,940 / 1,005 | fold into Step 3 proposers | Step 3 |
| source regex detectors (`fingerprint/source_sinks.py`, `srcwalk.py`, `cpg_scan.py`, `assert_guard.py`, `int_overflow.py`, `oob_write.py`, `uaf.py`, `srctaint.py`) | ~2.0k | freeze, then become proposers; delete only at Tier-0 recall parity | Step 3 |
| recipes as findings (`poc/recipe.py`, `overflow_recipe.py`, `source_recipe.py`, `oob_recipe.py`) | ~700 | annotation on a validated PoC only (keep `fmt_recipe.py`: a weaponizer) | Step 4 |
| grounding/confirm (`grounding*.py`, `taint_reach.py`, `verify_stage.py`) | ~990 | replaced by the validator; keep the `confirm_ladder` schema for report/GUI | after loop files ladder rungs |
| overlapping angr drivers (`symbolic/angr_driver.py`, `directed_confirm.py`, `uc_symbolic.py`/`uc_stage.py`) | ~1.0k | fold into `hyp_driver` (`uc_symbolic` → CCBSE "potential"); keep `concolic.locate_angr_python` | Step 5 |
| `source_confirm_stage.py`, `synth_confirm_stage.py` | ~630 | fold into the loop's source path | after Step 3 |
| fuzz stages (~12k) | | demote to fallback engine | Step 5 |
| `link/`, `firmware/`, `fingerprint/cvedb`, cve_poc, `harness/` | | frozen (doc 52 §4), optional tools | — |

## 4. Issue log

| # | Issue | Status |
|---|---|---|
| 1 | `symbolic/concolic.py` `_mem_preexec` caps angr with RLIMIT_AS/RLIMIT_DATA: z3/native SIGABRT with no output; inherited by emulate, angr_mmio, uc_stage, directed_confirm | open — replace with `hypo.engine.scoped` + RSS guard |
| 2 | no product validator (confirmation logic only in bench/) | **fixed** in Step 1 |
| 3 | sanitizer validator builds at -O1 (UB optimised away; LSan needs -O0) | **fixed for hunt** (-O0); the old pipeline's `ingest.compile_source` still -O1 |
| 4 | driver zero-fill hides uninit reads and NULL paths | open — per-class switch (bug-class work) |
| 5 | SIGALRM deadline cannot interrupt native z3; only FullFrontend-routed solver calls have a timeout | open |
| 6 | driver memory-guard thread dumps hypotheses while the main thread mutates them | open (partial results may be lost at a memory cutoff) |
| 7 | doctor reports rizin OK via the r2 fallback | open |
| 8 | no tests / Make target for the loop | **fixed**: `tests/test_hypo.py`, `make bench-tier0` |
| 9 | `analyze` refuses source dirs | **fixed via `hunt`**; GUI entry still needed for parity |
| 10 | binary-only validation cannot attribute crashes outside the site function (smashed return address, crash inside libc) | open — backtrace attribution (§1) |
| 11 | multi-line (line-protocol) input: angr's fgets reads the whole input as one line; forking `line_fgets` works but ~1 s/step | open — seed-shaped line lengths |
| 12 | the validator replays each input up to 3× serially; fine at Tier-0 scale, slow for hundreds of solutions | open — batch replays via run_batch for sanitizer builds too |
| 13 | `hunt` is CLI-only; the web GUI must reach parity | open |
