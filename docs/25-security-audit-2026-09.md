# 25 — Code audit & security review (2026-09-22)

Full-codebase audit run as six parallel focused reviews: sandbox/isolation, concurrency/jobs/DB,
untrusted-input parsing, API server + web GUI, analysis-pipeline correctness, and
packaging/distribution. Findings below are de-duplicated and ranked by severity. `VERIFIED` marks
items reproduced or confirmed by direct inspection during consolidation; the rest are
evidence-backed (code quoted by the reviewer) but not independently re-run.

## What is solid (rule-outs, for honesty)
- Primary **bwrap** tier: netns + pidns + fresh /proc + ro-root + tmpfs /tmp + `--die-with-parent`,
  secret-dotfile masking, spoof-resistant `bwrap:`-stderr fallback, ASLR-off. No FS-write escape,
  no network reach, no host-file write found in that tier.
- **DB concurrency core**: per-thread sqlite connections (no shared-conn bug), WAL + `busy_timeout`,
  atomic `BEGIN IMMEDIATE` + status-guarded `claim()`. Request ids always bound with `?` (no SQLi).
- **API surface**: static-asset server rejects traversal; `/artifacts/<sha>` is `[0-9a-f]+` only;
  WS/SSE re-run the Host+Origin guard; no SSRF; header CRLF stripped. SPA (Preact/htm) auto-escapes.
- **PoC soundness**: ret2win/mprotect/cmdi all use negative-control/echo guards before claiming
  "demonstrated". `merge_effects` keeps demonstrated > potential. Candidate cannot outrank poc-backed.
- The `stdin=DEVNULL` default in `run_subprocess` and the sanitizer RLIMIT_AS exemption (this
  session's fixes) are correct.

---

> **Security findings H1–H3 (arbitrary local-file read via `#include`, Classic-UI stored XSS,
> cross-case secret exfil) and the auth/tar-filter items were de-scoped by the owner** — lykos is
> an authorized, air-gapped, single-analyst tool and that residual risk is accepted. They are
> intentionally omitted below. The remaining items are robustness/availability/correctness bugs.

## HIGH

### H4 — Memory bombs are uncapped on several detonation paths → host OOM
(a) Non-traced batch path `batch_runner.py:420-424` runs `subprocess.run` with **no RLIMIT_AS**, and
that path is the *steady state* of every campaign once coverage saturates (`arm == set()`), plus any
target with no recovered blocks. (b) qemu and wine targets get `set_as=False` **and** no
`hard_rss_limit_mb` (`sandbox.py:853-861`, `:787`) → no memory bound at all; qemu/wine map the guest
heap on the host. A single `while(1) malloc(1<<30)` mutation OOM-kills the platform. **Fix:** make the
AS/RSS bound a single choke point applied on every execution path (fixes H4 + the UBSan-only and
AS-cap-ordering weaknesses at once).

### H5 — `_trace_one` deadlocks on any stdin payload > 64 KiB; the per-input deadline never fires  · VERIFIED
`batch_runner.py:251` writes the **entire** stdin payload before the tracee is continued
(`:255` waitpid at execve); with a full 64 KiB pipe buffer `os.write` blocks forever, and `deadline`
(`:264`) is computed/after and only checked in the never-reached trace loop. Only the outer batch
budget (~timeout×N) eventually kills it; the whole 64-input batch is discarded and re-run per-input.
Stalls media/format fuzzing badly. (Related: `os.write` return ignored → silent truncation on EINTR.)
**Fix:** feed stdin inside the trace loop with the existing `_pump` drain, or spill to the input file
and dup onto fd 0.

### H6 — SIGABRT signal-only bucketing over-merges DISTINCT sanitizer defects (false negatives on the flagship source path)
`_SIGNAL_ONLY_BUCKET={"SIGABRT"}` (`dynamic/stage.py:40`) + `_distinct_crashes` (`orchestrate.py:150`)
key every SIGABRT as `dynamic-crash:SIGABRT`. An ASan build with BOTH a heap-overflow AND a
use-after-free (both abort SIGABRT) collapses to ONE finding; only one reaches the prove loop and gets
`parse_asan_report`; the second CWE/source-line disappears. This is the pendulum swing from the
double-free over-split fix made this session — the discriminating data (ASan class+source) exists but
is discarded before dedup. **Fix:** for SIGABRT on a sanitizer build, put the ASan class+source in the
key (`dynamic-crash:SIGABRT:heap-use-after-free@parser.c:88`), not signal alone.

### H7 — coverage_fuzz never captures fault_pc → distinct AFL crashes collapse to one finding
`coverage.py:226-250` replays with no blocks (`fault_pc` always None), so N coverage-unique SIGSEGVs
key `(SIGSEGV,None)` → only the first gets a finding/minimize (reports `unique:1`), defeating the
stage's own "bucket by fault site" comment. Its key also diverges from fuzz/directed
(`dynamic-crash:SIGSEGV` vs `…:{pc}`) → duplicate findings for one defect. **Fix:** arm blocks / use
`run_batch` in the replay to get a locus; thread `fault_pc` into `dd.insert` + `crash_finding_candidate`.

### H8 — Queue writers aren't resilient to `database is locked`; a succeeded job can be recorded `error`
Only `claim()` guards its `BEGIN IMMEDIATE`; `complete/fail/enqueue/reap/…` (`queue.py:193,220,…`) do
not. A large single-writer transaction (`FunctionDAO.replace_for_target`, thousands of rows) held >5 s
`busy_timeout` makes a finishing worker's `complete()` throw; `fail()` throws again → worker thread
dies (respawned) and the just-succeeded job is left `running` → reaped to `error`. **Fix:** bounded
write-side busy-retry on all queue writers; treat complete/fail as must-succeed.

### H9 — A hung / non-cooperative stage is unkillable and the heartbeat masks the reaper → pool deadlock
Cancellation/timeout are cooperative (`should_cancel` polling); a stage stuck in a CPU loop or a native
angr/unicorn/pypcode call never checks. `_Heartbeat` extends the lease every 10 s regardless of
progress, so `reap()` never fires; UI cancel only sets a flag the stage never reads. One hung stage
permanently eats a worker; enough of them starve the pool, uncancellable. **Fix:** a wall-clock
watchdog that kills the stage's process tree (run stages in a killable child), and stop the heartbeat
once a deadline/cancel is set.

### H10 — Packaging version-match check has a hole: no venvs ⇒ pypcode ABI never verified
`make-runnable.sh:67-79` derives the ABI target only from the engine venvs. If both venvs failed to
build (common — angr/unicorn are heavy; collectors `rm -rf` on failure), `venv_py` is empty, the guard
is skipped, and it vendors the build host's Python — but `vendor/pysite/pypcode` is *also* ABI-locked
and never consulted. Collector on 3.11 + build host on 3.12 → `import pypcode` fails on the laptop:
exactly the failure this feature was meant to prevent. **Fix:** also derive/verify the minor from the
pypcode `.so` tag; `die` on mismatch or when there is nothing to match against but pysite exists.

---

## MEDIUM

- **M1 — ASan/UBSan report is trusted `authoritative` but is attacker-controlled output.** UBSan branch
  `re.search(r"runtime error:\s*(.+)")` (`rootcause.py:295`) matches the substring anywhere → any
  sanitizer crash whose stderr contains "runtime error:" is relabeled CWE-758, overriding the true
  class; and a source-path attacker can `fprintf(stderr,"SUMMARY: AddressSanitizer: heap-use-after-free…")`
  then abort() to forge CWE/severity/source. `is_sanitizer_build` is a byte-scan (`__asan_init` in data)
  the attacker can trip. **Fix:** anchor the UBSan regex to the sanitizer preamble + denylist setup
  failures; treat sanitizer class as attester-attested, corroborate against signal/fault before promoting.
- **M2 — DoS via unbounded parsing.** `native_re` iterates every rizin function/string with no cap →
  multi-million-line command scripts + inode/disk exhaustion + OOM reading whole output files
  (`native_re.py:296-315,437-458`); `elf._symbol_owners` accepts `sh_entsize=1` and steps byte-by-byte
  (`elf.py:445-465`); `pe.py:112-130` entropy loop has no cumulative byte cap (ELF has one). **Fix:** cap
  counts/iterations and bound file reads.
- **M3 — Request bodies buffered fully in memory (up to 1 GiB) + no socket timeouts** → concurrent
  uploads OOM (`server.py:282-304`, `multipart.py:26`) and slowloris holds unbounded threads. **Fix:**
  stream uploads to a temp file; set `Handler.timeout`; cap worker threads.
- **M4 — No authentication; loopback guard is the only control.** Any local user on a shared host has
  full access (read cases, run binaries, open `/console`, delete). Empty `Host` passes the guard
  (`server.py:271`); a `--http 0.0.0.0` bind + spoofed Host bypasses it entirely and nothing warns.
- **M5 — `run_reaped` inherits stdin (un-fixed sibling of the rizin hang).** `sandbox.py:476` — gdb
  `-batch` over a hostile inferior with no input file inherits fd 0 (`debug/{syscalls,secrets,monitor}.py`).
  Bounded by timeout (stall, not permanent), but the same class. **Fix:** `setdefault("stdin", DEVNULL)`.
- **M6 — Discarded/requeued results leave committed side-effects; `dyn_result` duplicates.** A lease-lost
  `complete()` returns False, but the stage already committed findings/dyn_results; `DynResultDAO.insert`
  is additive with no run-scoped dedup → re-runs accumulate crash rows (`queue.py:196-203`, `dao.py:762`).
- **M7 — Client `dedupeFindings` over-merges distinct memory-corruption defects (GUI ≠ report).**
  `util.js:84-106` folds ALL MEMCORRUPT-CWE findings of a hijack signal to one — *before* the "never merge
  a poc-backed" rule — so a second, independently-poc-backed overflow is dropped from the GUI while the
  server report lists it. **Fix:** fold only bare unlocated findings into the located one; never drop a
  poc-backed finding.
- **M8 — Packaging is x86_64-locked in body** while `uname -m` names the output (`make-runnable.sh:148-186,
  102,209`): an arm64 build host deletes the native `aarch64-linux-gnu-gcc` as if it were a cross compiler,
  and the RUN.sh/patchelf LD paths name only the x86_64 multiarch dir. **Fix:** derive the native triple
  (`gcc -dumpmachine`) or `die` early "x86_64 build hosts only".
- **M9 — Vendored interpreter ships without non-libpython deps; no import/ldd smoke-test**
  (`make-runnable.sh:82-108`): if the apt closure misses libffi/libssl/libsqlite3/liblzma… a stdlib module
  ImportErrors on the laptop with no fallback. **Fix:** smoke-test `import ctypes,ssl,sqlite3,lzma` under the
  bundle LD and copy missing deps; `die` on an unresolved one.
- **M10 — patchelf-absent fallback breaks venv engines off the RUN.sh path** (`make-runnable.sh:101-106`):
  without the `$ORIGIN` rpath the venv pythons find libpython only via RUN.sh's exported LD, so `make test` /
  a direct `doctor` fail. **Fix:** treat patchelf as required for this path (`die` if absent).
- **M11 — RUN.sh exports a process-wide LD_LIBRARY_PATH** (`make-runnable.sh:207-216`), which every tool
  subprocess inherits (`sandbox.py env=dict(os.environ)`) — violating vendorenv's stated "libraries stay
  private to the bundle's tools" guarantee. **Fix:** rely on the patchelf rpath and drop the global export.
- **M12 — Packaging dedup guard is a no-op** (`make-runnable.sh:187-189`) · VERIFIED: it scans the staging
  *filesystem* (which can't hold a duplicate path) and only WARNs. The real dup lives in the *zip*. **Fix:**
  `zipinfo -1 "$OUT" | sort | uniq -d` and `die` on a hit.
- **M13 — Large single-writer transactions serialize the whole engine** (`dao.py:343-354,503-537`) — the
  trigger for H8/M-slow-jobs. **Fix:** chunk large writes, shorten lock hold.
- **M14 — tmpfs /tmp and the qemu trace bind have no size cap** (`sandbox.py:64-66,879-880`) → RAM/disk
  fill (AS caps don't charge tmpfs). **Fix:** `--tmpfs /tmp` with `--size`; memory cgroup.
- **M15 — Wine tier is the softest isolation**: unwrapped (no netns/ro-root/secret-mask/mem-cap), and
  `wineserver` daemonizes past the launcher's `killpg` (`sandbox.py:761-810`). Documented tradeoff; a
  beaconing PE has the means. Consider a dedicated netns/cgroup for the wine prefix.

---

## LOW / IMPROVEMENTS
- Unguarded `bytes.fromhex` on rizin/gdb output → stage crash (`native_re.py:377`, `rootcause.py:449`).
- `crash_dedup_key` uses `if fault_pc` truthiness → a real PC=0 hijack buckets signal-only; use `is not None`.
- `_is_runtime_fn` prunes user functions named like libc (`read`/`time`/…) → under-counts user code
  (`fuzz/stage.py:604-624`); gate on symbol range, not name.
- Coverage % written as `0.0` when block coverage was *unavailable* (not zero) → report says "0% exercised"
  and autopilot fires concolic needlessly (`fuzz/stage.py:833`, `orchestrate.py:81`); write `None`/a flag.
- `_format_analyze`/`_create_run`/etc. return 500 (not 400) and leak `repr(e)` on non-dict JSON bodies /
  bad base64 (`server.py:548,586,794`); normalise body validation.
- `_get_artifact` serves attacker bytes without `nosniff` / `Content-Disposition: attachment`.
- `_safe_extract` is symlink-blind; pass `filter='data'` explicitly (`casestore.py:188-197`).
- `Handler._AUTOPILOTS` and every-request migration re-run grow/waste over process life.
- `PocDAO.set_finding` + link stages issue bare `conn.commit()` — premature-commit hazard inside a txn.
- `vendorenv.activate()` first-run is a check-then-act race (2 native-RE stages) — add a module lock.
- Container: unpinned base/apt/pip (reproducibility/supply-chain), runs as **root**, binds 0.0.0.0
  (safe only with the documented `-p 127.0.0.1`), no non-root `USER`.
- One-zip integrity is a single whole-archive sha256 (no per-file "no extras" check the toolchain path has);
  snapshot ships the working tree with no source-revision provenance; both unsigned.
- `_symbol_owners`/`program_ranges` re-parse the ELF several times per call; `fmt_confirm` format-string
  false positive lacks a negative control; `_CWE_CLASS` missing 119/120/127 → overflows read DoS-only.

---

## Remediation status (owner chose to fix the robustness/correctness set; security H1–H3 de-scoped)
- [x] **H4, H5, M5** — detonation-path robustness (host OOM + fuzzing deadlock + run_reaped stdin). `3fa1869`
- [x] **H6, H7, M7** — dedup correctness (over-split → over-merge regressions). `36edd6c`
- [x] **H8, H9** — job-queue resilience + heartbeat/reaper reclaim of a hung stage. `45e0243`
- [x] **H10, M8–M12** — packaging robustness (self-contained-Python ABI check, arch-neutral trim,
  import smoke-test, patchelf-required, no global LD, real zip dedup guard).
- Deferred: the MEDIUM DoS/validation set (M1–M4, M13–M15) and LOW/improvements.

## Follow-up feature requests (owner, this session — not audit findings)
1. **Stop/resume at any point** — a run can be halted and later continued. Partly enabled by H9
   (a cancel now actually reclaims a stuck job) + the existing cache-key resume (completed stages
   cache-hit on re-run). Needs: explicit pause/resume controls and a resumable autopilot cursor.
2. **Progress/status: done vs remaining** — surface, per case, which stages are complete, running,
   queued, and still to come (the pipeline plan), not just a live log.
3. **Richer per-job logs** — each run should report, in detail, what it is doing step by step
   (tool invoked, phase, counts), beyond the current coarse progress events.
4. **Folder/whole-project source** — build an uploaded source TREE (detect Makefile/CMake, inject
   sanitizers, sandbox the build) and analyse the produced binaries; minimal-viable first
   (tarball → Makefile/plain-C → sandboxed sanitized build → existing pipeline). See chat notes.
