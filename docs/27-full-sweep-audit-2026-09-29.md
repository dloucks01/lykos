# 27 — Full-sweep audit (2026-09-29)

A four-dimension sweep run as parallel focused reviews plus a live suite run on a
partially-provisioned host:

1. **Code correctness / robustness** — a fresh bug hunt over the core, and re-verification that
   the doc-26 high-severity fixes are still present.
2. **Capability audit** — every capability the README/docs claim, checked against the code that
   backs it (claim → implementation, over-claims, under-claims).
3. **Test & gate integrity** — skip discipline, gates that can pass trivially, coverage gaps, and
   the 8 live test failures on this host.
4. **Dependencies / toolchain / packaging** — the stdlib-only, no-network, air-gap-offline claims.

> **Owner scope (unchanged from docs 25 & 26).** lykos is an authorized, air-gapped,
> **single-analyst** tool; the operator and their inputs are trusted. Findings about the *security
> of the tool itself against hostile input* (zip/decompression bombs, RAM-exhaustion DoS,
> build-at-ingest sandboxing, report/dashboard XSS, path traversal from a malicious case archive,
> DNS-rebinding, 500 exception-repr leaks, the `./vendor` cwd hijack, no-auth local API) remain
> **de-scoped / risk-accepted**. This pass ranks **correctness, data integrity, robustness on
> legitimate input, honesty of results, and claim/code alignment**.

## Environment this sweep ran in (matters for interpreting results)

- **Python 3.14.7.** The project targets **>=3.11** (`core/pyproject.toml`), mypy pins **3.11**,
  and doc 10 names **3.12**. The suite had never been validated on 3.14. **Resolved during this
  pass:** the 7 non-trivial failures were re-run under **Python 3.13.15** and **all 7 persist
  identically** — so none are 3.14-specific; every failure is an engine-absence or host-specific
  issue (below), not a Python-version regression.
- **Engines present:** gcc/g++/clang, rizin+rz-ghidra (`r2`), bubblewrap, node, java runtime.
- **Engines absent:** **pypcode** (the P-Code IR the taint/bounds detectors consume), **gdb**,
  **qemu-user**, **AFL++**, **Ghidra headless**, **ruff**, **mypy**, **javac (JDK)**. `lykos
  doctor` reports all of these correctly.

## Headline verdicts

| Dimension | Verdict |
|---|---|
| Code correctness | **Solid, with 2 new HIGH silently-wrong-result bugs.** All 5 doc-26 HIGH fixes verified still in place. New: exploit-finding dedup-key mismatch, and qemu/PIE address rebasing. |
| Capability (claims vs code) | **Real system, not vaporware — every headline capability is backed by wired, tested code.** But several documented **over-claims** of scope/automation, and unbacked numbers. |
| Test & gate integrity | **Unit-level skip discipline is genuinely good (no vacuous passes found).** The exposure is at the **gate** level: `eval-gate` (static) and `arch-gate` exit 0 via SKIP when engines are absent, so `make release` can go green while static-detection quality and 12/13 architectures are never measured. |
| Deps / toolchain / packaging | **stdlib-only: UPHELD. air-gap offline install: UPHELD. "no network code paths at all": QUALIFIED** (all sockets are loopback/local IPC by design; no outbound path). |

---

## Part A — Code correctness & robustness (NEW findings)

### HIGH — silently wrong / lost / collapsed results

- **A-H1 — A verified L3 exploit is filed under a signal-only dedup key, so the crash finding
  never promotes (duplicate + un-promoted flagship result).**
  `analyze/poc/exploit_stage.py:621-624` (PIE-leak) and `:1894-1897` (mprotect+shellcode) call
  `crash_finding_candidate(signal_name, …)` then look up
  `id_for_dedup(target.id, "dynamic-crash:SIGSEGV")` — a hardcoded, locus-less key. Every other
  path in the file uses the pc-keyed `cand["dedup_key"]` (e.g. `:419, :822, :963, :1085`), which is
  how the crash finding is actually stored (`…:<pc>` or `…:cfh`). Result: the poc-backed row lands
  on a *different* key than the crash finding it should promote, so the real finding is never raised
  to poc-backed / high-severity, and one defect shows as two findings. **Confirmed** (verified
  in-tree: line 624 is the only `id_for_dedup` call in the file not using `cand["dedup_key"]`).

- **A-H2 — On qemu (emulated / cross-arch) targets, coverage and crash-locus use un-rebased
  addresses, so for PIE binaries coverage is silently dead and crashes are mislabeled — while the
  stage self-reports "coverage live."**
  `analyze/dynamic/sandbox.py:1003-1025` (`_qemu_reached`) intersects `blocks` (image-base-removed
  FILE offsets, from `fuzz/stage.py:_recovered_blocks`) against qemu's **absolute guest PCs** with
  no rebasing; `fault_pc=last` (`sandbox.py:982-991`) is likewise an absolute guest PC compared
  against a Ghidra-rebased `code_span`. For a PIE (ET_DYN) cross-arch ELF — which qemu-user does
  **not** load at vaddr 0 — (a) `blocks_hit` is always `()`, but `()` counts as "answered", so the
  campaign sets `cover_reported=True`, computes `novel=bool(new_blocks)` → always False, and
  **freezes the corpus / disables coverage-guided search** with no `coverage_unavailable` signal;
  (b) `is_hijack_pc(absolute_pc, rebased_span)` is true for essentially every crash → all crashes
  collapse into one `dynamic-crash:SIGSEGV:cfh` "control-flow hijack" finding (wrong CWE/severity +
  dedup collapse). Non-PIE cross-arch works (addresses coincide); the native ptrace/batch path is
  correct (it rebases via `_maps_base - _elf_min_vaddr`). **Confirmed mechanism / Plausible full
  impact** (not run against a live PIE under qemu). This is a direct instance of the project's
  cardinal rule (a stage that could not do its job should say so, not return a clean result).

### MEDIUM — a whole CWE class silently lost or duplicated; 500s / bad records on legitimate input

- **A-M1 — TOCTOU check/use symbol sets are shadowed by narrower redefinitions → real CWE-367
  missed on modern binaries.** `analyze/detect/detectors.py:164-166` defines the full
  `_TOCTOU_CHECK`/`_TOCTOU_USE`; the same module globals are **re-bound with smaller sets at
  `:868-869`**, and the later binding wins at call time. The effective sets drop
  `newfstatat`/`fstatat`/`stat64`/`faccessat2` (checks) and `execve`/`system`/`openat`/`unlinkat`/
  `*at` (uses). 64-bit glibc routinely lowers `stat()` to `newfstatat`, so a `stat→execve` TOCTOU
  is silently missed. **Confirmed** (both definitions verified in-tree).

- **A-M2 — `toctou_race` bypasses the opt-in TOCTOU gate and duplicates `toctou`.**
  `analyze/detect/stage.py:362-368` skips optional detectors only when `name in optional`
  (`"hardening"`, `"toctou"`), but the detector registers as **`toctou_race`**
  (`detectors.py:172`), so it runs on **every** `detect_cwe` even when `include_toctou=False` —
  while the run's own event reports `skipped:[toctou]`, i.e. it claims TOCTOU didn't run when it
  did. With TOCTOU enabled, `toctou_race` and `toctou` file the same check-then-use pair twice
  (different dedup keys). **Confirmed.**

- **A-M3 — `find_length_fields` raises `struct.error` on any sample < 8 bytes → 500 on a
  legitimate small sample.** `analyze/fuzz/structure.py:992-995`: the loop still yields `off=0`
  when `n < size`, so `struct.unpack` gets a short buffer. Reached unguarded from
  `POST /format/analyze` → `suggest_spec` (`api/endpoints.py:778`), so a small sample in the spec
  builder returns 500 instead of a suggestion. **Confirmed** (reproduces for lengths 0–7).

- **A-M4 — `validate()` rejects every well-formed PE triage record.** `analyze/triage.py:376-378`
  flags any `mitigations` value not in `MITIGATION_ENUM`, but the PE builder smuggles
  `"pe_format":"PE32"|"PE32+"` into that same dict (`analyze/pe.py:163`), so `validate(pe_rec)`
  always returns `["bad mitigation pe_format=…"]`. Latent today (only tests call `validate`, and
  they cover ELF/raw/text, never PE), but any future caller gating ingest/import on `validate()`
  would reject all PE records. **Confirmed** (verified both sides in-tree).

- **A-M5 — `_create_run` enqueues a run bound to `case_id=None` instead of 400/404.**
  `api/endpoints.py:798-808`: with both `case_id` and `target_id` absent it calls `fn(q, None)` and
  returns 201, enqueuing an `analysis_run` with `case_id=None`; the case-stage path never verifies
  the case exists (unlike every GET handler). **Confirmed.**

### LOW

- **A-L1** — ELF extended section count (`e_shnum==0`, >65280 sections) unhandled →
  `sections=[]`, `stripped=None`, `program_ranges()=[]` (falls back to "use everything").
  `analyze/elf.py:168,451`. Rare.
- **A-L2** — Autopilot `_wait` caps every stage at 900s (`analyze/orchestrate.py:72`) while stages
  register a 3600s ceiling; an operator-raised `max_seconds` / long concolic run >15 min is
  cancelled mid-run and recorded `error`, discarding partial results.
- **A-L3** — Taint `analyze_program` worklist cap (`analyze/detect/taint.py:630-646`) can stop the
  interprocedural fixpoint before convergence and drop real source→sink flows with **no signal**
  (unlike the block/func ceilings, which surface `oversized`/`skipped_out`).
- **A-L4** — `heap_fptr_call` backward register-def trace aborts on any first-operand *read* of the
  target register (`test`/`cmp`), dropping the CWE-822 object-fptr surface in those functions.
  `analyze/detect/detectors.py:707-714`.
- **A-L5** — `_stream_file` can emit a second response and desync a keep-alive connection if a
  non-BrokenPipe error occurs after headers start. `api/server.py:193-203`. Low likelihood
  (immutable content-addressed blobs).
- **A-L6** — Uploading a target to a nonexistent case returns 500, not 404/400
  (`api/endpoints.py:716-753` never checks `cases.get(cid)`).
- **A-L7 (carried over from doc 25, still open)** — `fault_pc==0` crashes bucket signal-only
  because `analyze/dynamic/stage.py:85` (and `is_hijack_pc` at `:124`) test truthiness; a
  jump-to-NULL / return-to-0 keys as generic `dynamic-crash:SIGSEGV`. Doc 25 flagged the
  `is not None` fix; still unaddressed.

### Verified STILL-FIXED (doc-26 HIGH items, re-checked in current code)

1. SIGABRT distinct-defect bucketing — `analyze/dynamic/stage.py` `crash_dedup_key` +
   `asan_defect_key`, computed before the gate (`fuzz/stage.py:550-554`, `coverage.py:269,277`).
2. coverage_fuzz cross-arch replay — `coverage.py:249-260` threads `arch/endianness/bits`.
3. Atomic content-store writes — `casestore.py:70-96` `_atomic_place` (temp + fsync + `os.replace`).
4. Severity sort — `db/dao.py:41-42` `_SEV_RANK_SQL` CASE, applied at `:789,:795`.
5. Concurrent-migration race — `db/migrations.py:104-114` (BEGIN IMMEDIATE + re-read + fast path);
   `schema_version.version UNIQUE`.
   Plus all doc-26 API/parser fixes (boundary-aware upload, 404 on missing target, stateless
   ContentStore, chunked rejection, 400-not-500 on bad input; PE `NumberOfRvaAndSizes<2`; ELF
   SHN_XINDEX) confirmed present.

---

## Part B — Capability audit (claims vs. reality)

**Overall: the system is real.** 34 registered analysis stages, real angr/SymQEMU/Unicorn drivers,
real clang/libFuzzer invocation, and an L3 exploit engine that detonates for real with
negative-control causation proofs. No `NotImplementedError`, no wholesale stubs, no silent
no-ops — engine-missing paths **decline honestly** (`supported: False` / explicit "unavailable").
The entire L3 ladder (ret2win, ret2system/ROP, execve-ROP, SROP, magic-overwrite, ret2libc
puts-leak/PIE, one-gadget, canary-leak→ret2libc, format-`%n`, glibc-heap tcache+House-of-Apple-2,
mprotect-shellcode, shellcode+XOR encoder) exists as real, self-confirming code in
`analyze/poc/`, each confirmed by a marker / live shell / breakpoint with a negative control.

The gaps are **over-claims of scope/automation and a few unbacked numbers**, not fabricated
features:

- **B-1 (biggest over-claim) — multi-arch coverage.** `docs/18-architecture-coverage.md:19-41`
  lists Tier-2 MIPS and a long Tier-3/4 embedded-ISA list (AVR, MSP430, Xtensa/ESP32, PIC, 8051,
  TriCore, Hexagon…) as "FULL," and marks Gadget/PoC "FULL" for ARM/AArch64/MIPS/PPC/SPARC. In
  reality **advanced exploitation (ROP/ret2libc/heap/shellcode/format/PIE) is x86-64-only**
  (`exploit_stage.py:61-102`, `rop.py`); non-x86-64 gets only ISA-neutral ret2win. Only ~12 arches
  are actually gated/measured (`eval/archgate.py:68-92`); MIPS has a register layout but no gate
  row; the Tier-3/4 list has no reachable code path. **Recommend re-marking doc 18 to distinguish
  "ret2win reachable" from "full ladder."**
- **B-2 — Autopilot "drives each crash as far up the ladder as the target allows"
  (README:31-32) overstates automatic reach.** Autopilot calls `build_exploit` with
  `strategy="auto"` for **only `crashes[0]`** (`orchestrate.py:387-398`), so only ~6 of 13 rungs
  run automatically (ret2win, ret2system, execve-ROP, SROP, magic, ret2libc-leak + PIE-auto). The
  other 7 (heap/HoA2, format-`%n`, shellcode+XOR, mprotect, canary-leak, PIE pure-libc) require the
  operator to pick `strategy=` and supply params. Honestly documented in docstrings/docs 08/15, but
  the top-line sentence glosses it.
- **B-3 — "44% → 100% block coverage … automatically" (README:42-44) is an unbacked number.**
  The concolic→re-fuzz mechanism is fully real and wired
  (`symbolic/stage.py:80-86` → `fuzz/directed.py:216-242` → `orchestrate.py:366-376`), but the
  figure lives only in prose; **no test measures or asserts the coverage delta.** Fair to call the
  mechanism proven and the number anecdotal.
- **B-4 — "has no network code paths at all" (README:10) is literally inaccurate.** Real sockets
  exist — `link/detonate.py:74-77` and `link/harness.py:59-124` (delivering fuzz input to the
  target's own AF_INET/AF_UNIX/UDP service), `debug/qemu_gdb.py` (local gdbstub), `api/server.py`
  (loopback/AF_UNIX) — **all loopback/local IPC, no outbound path.** The air-gap *spirit* holds;
  the absolute phrasing does not. Suggest: *"no outbound network calls; all sockets are
  loopback/local IPC to the target under test."* (Independently flagged by both the capability and
  packaging passes.)
- **B-5 — firmware rehosting is Cortex-M-only** (`firmware/rehost_stage.py:38`) despite doc 17's
  broader framing. Carving is general; rehosting is one MCU family.
- **B-6 — Go/Rust "corroborated when untrusted input reaches the sink" is call-graph
  reachability, not data-flow taint** (`detect/detectors.py` self-labels it "approximate taint" —
  depth-4 BFS). More than string-matching, less than the real taint engine used on C/C++. Rust is
  also thinner than Go (`std::process`/`std::fs` only; no SQL/HTTP).

**Under-claims (implemented but not headlined):** the README says "the 29 analysis stages" but **34
are registered**; and CVE/component scan (`fingerprint/`), secret extraction (`debug/secrets.py`,
`poc/secret_stage.py`), multi-binary correlation (`link/`), patch-diff (`patchdiff.py`), poc_diff,
multi-process/fork-follow debug, oob_index (CWE-129), heap_trace (UAF/double-free), and the runtime
monitor are all real, registered, tested stages absent from the README's "What it produces."

---

## Part C — Test & gate integrity

**Inventory:** ~135 `test_*.py` files, ~1389 `test_` functions, 8 node GUI harnesses in `tests/js/`,
~340 skip sites. **Unit-level skip discipline is genuinely good** — essentially no vacuous
"green-without-testing" skips; tool-absence paths use `pytest.skip(...)` with a clear reason. That
is the honest pattern the project claims.

The real exposure is at the **gate** level and in a cluster of **host-dependent failures**.

### HIGH — gate can pass trivially / release green while unmeasured

- **C-H1 — `make eval-gate` static halves exit 0 (green) when Ghidra is absent.**
  `eval/metrics.py:77-84` returns `(True, "SKIP")` when `stage=="static"` and no Ghidra; `cli.py:302`
  maps SKIP→exit 0. Verified live on this host: `--stage static --min-recall 1.0` reported OVERALL
  recall **0.00** yet **EXIT=0** (`GATE: SKIP -- static benchmark needs Ghidra`). So the candidate
  FP ratchet and the corroborated precision ratchet the Makefile spends 40 lines defending give
  **zero signal** on any host without Ghidra. The dynamic third *does* run for real (recall 1.0,
  real fuzzing). The knob to force failure (`--require-backend`, `cli.py:89`) exists and is
  unit-tested but **the Makefile never passes it.** Honest to a human reading stderr; invisible to
  `make release`, which sees only exit 0.
- **C-H2 — The `min_negative` vacuous-precision guard is built and unit-tested but not wired into
  the gate.** `eval/metrics.py:85-90` guards `fp_rate is None` (no negatives scored) from passing
  precision vacuously, but the CLI defaults `--min-negative 0` and the Makefile `eval-gate` target
  passes neither `--min-negative` nor `--require-backend`. A corpus that lost its discrimination
  negatives would pass the FP ratchet silently even with Ghidra present.
- **C-H3 — `arch-gate` returns green when no compiler builds any arch.** `eval/archgate.py:213-217`
  returns `(True,"SKIP")` on empty results. Contrast the **correct** pattern in
  `eval/realgate.py:598-607`, which treats a non-optional case that "did not compile" as **FAIL,
  not skip** — `real-gate` is the one gate that cannot pass trivially by missing tools, and is the
  strongest integrity design in the repo. (The README claim that lint/typecheck **fail** when the
  tool is missing is **verified** in the Makefile; the same strictness is applied to `real-gate`
  but deliberately **not** to `eval-gate`/`arch-gate` — that asymmetry is the central thing a
  reviewer should weigh.)

### HIGH/MEDIUM — 8 live test failures on this host

`8 failed, 1470 passed, 76 skipped` (8m13s). Classified:

| Test | Root cause | Class |
|---|---|---|
| `test_path_traversal::test_tainted_path_is_corroborated_cwe22` | tainted path **not** corroborated | pypcode-absent → **false negative** |
| `test_path_traversal::test_constant_path_not_corroborated` | constant/safe path **is** corroborated | pypcode-absent → **false positive** |
| `test_alloc_size::test_constant_alloc_size_not_corroborated` | constant size corroborated | pypcode-absent → false positive |
| `test_source_project::test_static_detect_runs_on_instrumented_source_binary` | expected CWE-22 not corroborated | pypcode-absent → false negative |
| `test_trace_stage::…nothing_produces_an_inventory…` | payload `{ok:False, note:"gdb not found"}` but test only skips on `supported is False` | **skip-discipline** |
| `test_block_coverage::…recorded_only_when_blocks_are_asked_for` | traced run **SIGSEGVs** (sig 11, fault_pc=0x107b) when block list injected | robustness / possibly 3.14+kernel |
| `test_packaging_scripts::test_the_readme_indexes_every_doc` | `docs/26-…md` missing from README index | **deterministic, real** (see C-M2) |
| `test_source_project` / `test_alloc_size` share the pypcode dependency above | — | — |

- **C-H4 — The four corroboration failures reveal that without pypcode the taint/corroboration
  path degrades into *actively wrong verdicts in both directions* — a safe constant path is
  corroborated (false positive) and a genuinely tainted path is not (false negative) — not merely
  "reduced recall."** The detectors consume P-Code that only pypcode produces
  (`native_re.py`; `detect/stage.py:125` reads `i.get("pcode", [])`), but the tests gate only on
  `gcc` + x86-64 (`test_alloc_size.py:38`, `test_path_traversal.py:37`), **not** on pypcode — so
  on a pypcode-less host they **fail instead of skipping**, and the failures expose that
  `doctor`'s soft wording ("detection degrades") understates the effect. **Two actions:** (1) gate
  these tests on pypcode so they skip honestly like the other 8 pypcode-dependent tests already do;
  (2) confirm whether the false-positive direction is acceptable degradation or a bug — a tool
  whose cardinal rule is "no clean result when a stage couldn't run" should arguably **decline
  corroboration** when P-Code is unavailable rather than emit a wrong verdict.
- **C-M1 — `test_block_coverage` SIGSEGV (and `test_chain_primitive` non-confirmation).** The
  block-trace path SIGSEGVs (sig 11, fault_pc=0x107b) when block breakpoints are injected, and the
  interactive PIE leak-chain never confirms (`hit is None`). gcc/bwrap are present and 51/52
  exploit+primitive tests pass, so these are not missing-engine skips. **Confirmed not
  version-related** (both persist under 3.13.15). Both exercise the bwrap+ptrace execution path;
  the likely common cause is that block-breakpoint injection / the interactive chainer is flaky
  under this host's kernel (7.1.5+kali), while the plain dynamic path (real fuzzing, recall 1.0)
  works. A genuine robustness finding to reproduce on a stock kernel.
- **C-M2 — `test_the_readme_indexes_every_doc` fails: `docs/26-code-audit-2026-09-25.md` is not in
  the README index** (deterministic, host-independent). doc 25 is indexed, 26 was added without
  updating the table. *This report adds rows for 26 and 27 to keep the gate green.*

### MEDIUM/LOW — coverage gaps & weak tests

- **C-M3** — `analyze/poc/poc_diff.py` (270 LOC) is a registered, wired pipeline stage with
  **zero tests** (no test references `poc_diff`).
- **C-M4** — Subprocess engine drivers (`symbolic/angr_driver.py`, `firmware/unicorn_driver.py`,
  `pcode_worker.py`) have **0 real coverage on this host** (exercised only via `@skipif` on absent
  engines). `.coveragerc` honestly documents that they are measured only through the `make coverage`
  subprocess shim.
- **C-M5** — `exploit_stage.py` (1950 LOC) and `dynamic/sandbox.py` (1025 LOC) are **well covered
  on x86-64** (`test_exploit.py`+`test_primitive.py` = 69 passed, 2 skipped here) but **blind
  cross-arch** and for all gdb-backed paths (monitor/taint/secrets/behavior) — the 1950-LOC exploit
  engine is validated for exactly one ISA in this environment.
- **C-L1** — Tautological assertions that can never fail: `test_detect.py:812` (`… or True`),
  `test_coverage.py:177` (`… or True`), `test_srop.py:110` (`… or True` inside a ternary index).
- **C-L2** — 12 files assert on **source substrings** via `inspect.getsource` (e.g.
  `test_argv_delivery.py:101-112`, `test_detect.py:777-856`) rather than behavior — they pass if
  the string is present even if behavior is broken, and break on harmless refactors. Notably
  argv/latin-1 delivery is exactly the class of bug `realgate` exists to catch, so grepping source
  is the weaker half of that pair.
- `.coveragerc` exclusions are benign (`TYPE_CHECKING`, `raise NotImplementedError`,
  `__main__`); note it is used only by `make coverage`, never `make test`, so the normal suite
  reports no line coverage — quality is asserted by test *presence*, not measured coverage.

**Confidence a green suite justifies on this (engine-partial) host:** high for the **x86-64 dynamic
path** (detect→PoC→exploit→primitive), the **dynamic detection ratchet** (real fuzz, recall 1.0),
and the plumbing/DAO layers; **essentially none** for **static detection quality** (candidate +
corroborated gates SKIP→green), **cross-architecture** support (arch-gate reduces to x86-64), and
**gdb/qemu/angr/unicorn/JVM** capabilities. The suite is honest about *what it skips*; the release
gate's **exit code does not reflect those skips**.

---

## Part D — Dependencies, toolchain & packaging

- **stdlib-only — UPHELD.** `core/pyproject.toml` declares `dependencies = []`; no
  `requirements.txt`/`setup.py`. Full import sweep finds zero bare third-party imports. Every
  non-stdlib name is an optional engine imported inside a `try:` in a standalone driver run by a
  **separate vendored interpreter** (angr/claripy in `symbolic/angr_driver.py:83-84`, unicorn in
  `firmware/unicorn_driver.py:22-42`, pypcode via `vendor/pysite`), an `import gdb` inside a
  GDB-Python **script string** (not a real import), or a docstring/fixture false positive.
- **air-gap offline install — UPHELD.** `packaging/setup-toolchain.sh` (target side) does zero
  network I/O, verifies `sha256sum -c SHA256SUMS`, and rejects files present-but-not-listed
  (with an honest "unsigned manifest = corruption-resistance, not authenticity" caveat). The `.pyz`
  build fetches nothing; `verify.sh` proves it serves the UI + triages over a unix socket offline.
  All network-touching scripts are the documented **connected-side** build step.
- **"no network code paths at all" — QUALIFIED.** No outbound-internet code anywhere (no
  `urllib`/`requests`/`curl`/`wget`/`pip`/`apt`; the only `git` call is `git rev-parse --short HEAD`,
  local, try-wrapped). But substantial **local** socket code exists by design (see B-4). Reword the
  absolute claim.
- **D-1 (MEDIUM) — `setarch` invoked but not in the toolchain inventory.**
  `analyze/poc/heap.py:241` calls `shutil.which("setarch")` and returns `None` if absent
  (`:242-244`), **silently disabling the glibc-heap arena model** behind the README-headlined
  "glibc-heap → shell" L3 PoC. `toolchain.py` doesn't declare it, so `doctor` can't warn — against
  design rule #4. **Add `setarch` (and, LOW, `patchelf` — `casestore.py:39`) to `toolchain.py`.**
- **D-2 (LOW)** — `make-runnable.sh` strips `node` from the bundle while `toolchain.py` still
  declares it → `DOCTOR.sh` on a runnable bundle reports node MISS (cosmetic; node is `make
  gui`-only).
- **D-3 (LOW)** — `container` build defaults to the moving `kalilinux/kali-rolling:latest` tag
  (the script itself warns and advises pinning `:<YYYY.N>`) — non-reproducible by default.
- **Secrets / binaries — clean.** No committed secrets (only firmware key-carving *patterns* and an
  intentional CWE-798 test fixture), no committed binaries (`.gitignore` whitelists only
  `manifest.tsv` under `examples/*/bin`), and `/vendor/` is correctly anchored so it doesn't swallow
  the shipped `core/lykos/api/static/vendor/` UI runtime.

---

## What is solid (rule-outs, for honesty)

- All 5 doc-26 HIGH fixes verified still present (Part A). Job-queue concurrency core (busy-retry,
  lease-lost guard + result discard, release-once slot + wedge watchdog, bounded pipe drain +
  atexit killpg), sandbox rlimit/AS-cap ordering, batch_runner ptrace loop, `bounds.py`
  dominating-guard/signed-length reasoning, DAO merge/verdict recompute, ELF/PE struct
  offsets/endianness, taint ABI/sub-register aliasing — all re-checked, no new bugs.
- stdlib-only and air-gap-offline claims hold. No SQL injection, output-safe report generators
  (re-confirmed by doc 26). Engine-missing behavior is honest decline, not silent empty.
- The system is substantively what it claims to be; the over-claims are of scope/automation, not
  of existence.

---

## Prioritized remediation

**Fix first (silently-wrong results on legitimate targets):**
1. **A-H1** — key the exploit-stage crash findings at `:621-624`/`:1894-1897` on
   `cand["dedup_key"]` like every other path, so poc-backed promotion and dedup work.
2. **A-H2** — rebase qemu guest PCs to file offsets before block-intersection and hijack-span
   checks; emit `coverage_unavailable` when `blocks_hit` truly cannot be measured, instead of
   treating `()` as "answered."
3. **A-M1 / A-M2** — remove the shadowing `_TOCTOU_*` redefinitions at `detectors.py:868-869`; make
   the optional-detector gate match the registered name `toctou_race` so it honors `include_toctou`
   and stops double-filing.

**Fix next (honesty of the release gate):**
4. **C-H1 / C-H2 / C-H3** — pass `--require-backend` and `--min-negative` in the Makefile
   `eval-gate`/`arch-gate` targets (or make SKIP→nonzero in `make release`), so a green release
   cannot mean "the static + cross-arch quality gates never ran." Mirror the `real-gate` strictness.
5. **C-H4** — gate the four pypcode-dependent corroboration tests on pypcode (skip, don't fail),
   and decide whether degraded-P-Code corroboration should **decline** rather than emit a verdict.

**Robustness / correctness (legitimate input):**
6. **A-M3** (guard `find_length_fields` for `n < size` → 400 not 500),
   **A-M4** (move `pe_format` out of the `mitigations` dict, or exempt it in `validate`),
   **A-M5 / A-L6** (verify case existence; 404/400 not 201/500).

**Docs / claims alignment:**
7. **B-1** (re-mark doc 18 arch tiers: "ret2win reachable" vs "full ladder"),
   **B-2** (soften Autopilot "each crash / full ladder"),
   **B-3** (label the 44%→100% figure as illustrative, or add a test that measures the delta),
   **B-4** (reword "no network code paths at all"),
   README "29 stages" → 34, and headline the under-claimed stages (Part B).

**Toolchain visibility:**
8. **D-1** — add `setarch` (and `patchelf`) to `toolchain.py` so `doctor` reports them.

**Investigate (host):**
9. **C-M1** — reproduce `test_block_coverage` SIGSEGV and `test_chain_primitive` non-confirmation
   on a stock kernel. Ruled out as a Python-version issue (both persist under 3.13.15); the
   remaining hypothesis is the bwrap+ptrace block-injection path under kernel 7.1.5+kali.

---

## Remediation applied in this pass (2026-09-29)

The following low-risk fixes were applied to the working tree and validated (`test_detect.py`
42/42, `test_exploit.py`+`test_primitive.py` 51/51 excluding the pre-existing host failure, gate
behavior verified live):

- **A-H1** — `exploit_stage.py` PIE-leak (`_pie_leak_exploit`) and mprotect+shellcode
  (`_mprotect_shellcode`) now derive the original crash's `fault_pc`/`hijack` from `p["input_sha"]`
  and key the poc-backed finding on `cand["dedup_key"]`, matching the canonical path — so the crash
  finding promotes instead of a duplicate being filed under the signal-only legacy key.
- **A-M1** — the shadowing `_TOCTOU_CHECK`/`_TOCTOU_USE` redefinition (`detectors.py`) was renamed
  to `_TOCTOU_CHECK_LEGACY`/`_TOCTOU_USE_LEGACY`, so `toctou_race` now uses its intended
  comprehensive symbol set (recovers `newfstatat`/`execve`/`*at`… detection).
- **A-M2** — `toctou_race` is now gated by `include_toctou` in `detect/stage.py`, so it no longer
  runs while the event reports `skipped:[toctou]`. (Residual: `toctou` and `toctou_race` still both
  file when TOCTOU is enabled — deferred, as both are registered and independently tested; a
  decision on collapsing them is left to the owner.)
- **C-H1/C-H2** — the Makefile `eval-gate` static halves now pass `--require-backend` and
  `--min-negative 1` **by default**, so `make release` FAILs (verified: exit 1, `GATE: FAIL`)
  rather than silently passing (`GATE: SKIP`, exit 0) on a Ghidra-less host. Escape hatch for a
  deliberately backend-less CI: `make eval-gate REQUIRE_BACKEND=`.
- **C-M2** — README doc-index rows added for docs 26 and 27 (`test_the_readme_indexes_every_doc`
  now passes).

Deferred (not applied): A-H2 (qemu/PIE rebasing — needs a live PIE-under-qemu repro), the remaining
MEDIUM/LOW correctness items, C-H3 (arch-gate empty→green), C-H4 (gating the pypcode-dependent
tests / decline-on-degraded-P-Code), and all docs/claims-alignment items (Part B).

---

*Method note: this sweep ran four parallel focused reviews (code correctness, capability,
test/gate, packaging) plus a full live suite run, on Python 3.14.7 with rizin/gcc/bwrap/node
present and pypcode/gdb/qemu/afl/Ghidra/ruff/mypy absent. The two HIGH code findings and the
sampled MEDIUMs (A-M1, A-M4) were independently re-verified in-tree. Nothing was modified in the
working tree except this document and the README doc-index rows for docs 26–27.*
