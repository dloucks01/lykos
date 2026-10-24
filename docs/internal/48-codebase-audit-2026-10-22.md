# Codebase audit — 2026-10-22

A whole-codebase read-only audit by six parallel reviewers (one per subsystem), hunting real
correctness / security / precision-rule bugs (not style). Each finding was verified against the
source before reporting. The **cardinal-sin** fixes (never fabricate a finding, never hide a real
one) and the quick, safe robustness fixes were applied in commit `089802d`; the heavier items are
recorded here as prioritized follow-ups.

## Overall verdict

The codebase is **disciplined and mature**. The anti-fabrication rule is deeply engineered in the
places that matter most (bounds.py's asymmetric demote-don't-assert, the two-source CONFIRMED gate,
the exploit confirm paths' breakpoint-reach + arg-register + negative-control grading, the
drained-vs-cutoff concolic honesty invariant). The job queue, the taint ABI tables, the ROP/gadget
math, the server's security posture (CSRF/path-traversal/XSS/size-limits all defended), and the
air-gap relink hardening all checked out. The real defects are at the **edges**: a confirm family
that was never upgraded off a weak substring check, a stage with no per-detector isolation, a pause
that burned the budget, and a cluster of sandbox-hardening gaps in the secondary fuzzers.

## FIXED in `089802d`

| # | Sev | Subsystem | Defect | Fix |
|---|-----|-----------|--------|-----|
| 1 | CRIT | exploit (leak.py) | L3 shell confirms used `marker in out [or b"/bin/sh" or b"$ "]` → filed verified L3 RCE @0.99; benign menu / echoed command fabricated a working exploit (leak.py:1136/1320/1478/1584/1638/2558/2843/2882/2928) | Dropped benign clauses + reject echo-reflection at all 9 sites |
| 2 | HIGH | detect (stage.py) | detector loop had no exception isolation; a degenerate frame (offset=None/hex-string) crashed the WHOLE `detect_cwe` → zero findings (detectors.py:530, 1060; stage.py:680) | Per-detector try/except |
| 3 | HIGH | orchestrate/budget | **pause** didn't stop the budget clock → resume left ~0 budget, run finished near-empty | Bank paused interval, exclude from `elapsed()` |
| 4 | MED | api (autopilot) | status poll shallow-copied + json.dumps'd the still-mutating plan dicts outside the lock → intermittent 500 | deepcopy under lock |
| 5 | MED | api (autopilot) | `_start_autopilot` did `_json_body() or {}` → double-response + unwanted run on a bad body | return on None like siblings |
| 6 | MED | GUI (app.js) | background poll rescheduled only while running → one transient fetch error froze the live UI for the rest of the run | retry on transient/unknown |
| 7 | MED | harness (emulate) | read-only libc-stub fault hardcoded `access="write"` → OOB reads filed as CWE-787 writes | read-only stubs → CWE-125 |
| 8 | LOW-MED | libfuzzer | source-tree extraction naive name check (misses symlink escape) | `extractall(filter="data")` |
| 9 | MED | patchdiff | fingerprint ignored the callee set → a call-target swap (memcpy→wrapper) hashed "unchanged", hiding the patched fn | fold callees into the hash |

## FOLLOW-UPS — status 2026-10-24

**All follow-ups below were fixed in the 2026-10-24 audit (see doc 51).**
One correction: `variant.similarity` does NOT catch an immediate-only edit (its
profile is P-Code op names only); the fix landed in `patchdiff` operand hashing instead (5735eea).

## FOLLOW-UPS (as recorded 2026-10-22) — prioritized

### Precision (fabrication / FP) — do first
- **leak.py: finish the confirm hardening** — the echo-reflection guard removes the identified
  fabrications, but the *ideal* is `attribution.make_code_markers()` + `markers.proves(out)`
  (already used in `format_got_shell`, leak.py:878) so even a shell that echoes its input can't
  fake it. Convert the 9 sites + `_pivot_exploit`/`_spawn_and_mark` (exploit_stage.py:3160, add the
  `int3`/benign-echo negative control its siblings `_self_exec`/`_mprotect_shellcode` have).
- **scanf_bounded_overflow** (detectors.py:941) — `max(widths)` is applied to the FIRST buffer only;
  `scanf("%4s %64s", small, big)` asserts a HIGH CWE-787 on `small` (real bound %4s=4). Match each
  width to its own buffer.
- **uaf.py** (uaf.py:116) — one-line `if(err){free(p);return;}` isn't recognised as a clearing exit,
  so a later legit `use(p)` is a false CWE-416. Clear the dangling set for a one-line guarded free.
- **privilege_drop_order** (detectors.py:761) — `seteuid(0)` (a privilege *raise*) is in `_SETUID_FAM`
  → read as a uid-drop (FP); and the global-`min` masks a wrong-order on one branch (FN).
- **cve_corroborate** (corroborate.py:25) — CWE-20/CWE-369 classed as "memory corruption" → over-broad
  corroboration nudge.

### Sandbox safety (lykos runs untrusted targets)
- **net_fuzz / native env_fuzz / afl coverage_fuzz** run the target with rlimits only — no bwrap, no
  FS isolation, no secret mask (netfuzz.py:100, envfuzz.py:91, aflpp.py:349). A malicious target can
  read `~/.ssh` / write host files; net_fuzz shares host network. Route through
  `sandbox.isolate_prefix(exedir, net=True)` (keeps loopback) as the sibling paths do.

### Silent "0 crashes" (a broken run read as a clean negative)
- **batch runner** never inspects exit_code/stderr for a loader/exec failure (sandbox.py:356,
  batch_runner.py:288) → a missing-`.so` dynamic ELF is "fuzzed" thousands of times, reported clean.
  Have `run_batch` apply `_exec_failed` per result.
- **netfuzz** spawns the server with `stderr=PIPE` and never drains it (netfuzz.py:124) → a logging
  server wedges on a full pipe → live wedged target reported no-crash. Drain stderr or `=DEVNULL`.

### Robustness
- **per-target exception isolation** (orchestrate.py per-target body, ~1653-2268) — an unhandled
  exception proving target #3 (e.g. a transient "database is locked") aborts targets #4..N. Wrap the
  per-target body in try/except + continue (the `_staged` calls are already guarded).
- **worker respawn leak** (worker.py:438) — a reclaimed-then-recovered worker becomes an untracked
  surplus thread+connection. Pass a spawn generation and exit when replaced.
- **fault-PC temp-dir leak** (orchestrate.py:1160) — `_recover_missing_fault_pcs` mkdtemps + stages a
  full binary copy and never cleans up; leaks per crash-dedup call. Add `rmtree` in finally.
- **heartbeat starvation** (worker.py:88, queue.py:347) — a healthy long stage can be marked `error`
  and have its result discarded under a write storm (max_attempts=1).
- **_distinct_crashes** `out[:12]` cap + `(signal,None)` collapse on argv/file/foreign-arch → a 13th
  distinct crash, or a second distinct crash on a wine/foreign target, is never proved.

### Air-gap / patchdiff / symbolic
- **relink-bundle.sh re-relink after MOVE** corrupts loader-wrappered tools (gcc cc1) → gcc can't
  compile offline after the operator moves the extracted folder (first-run-in-place is fine).
- **toolchain._probe_symqemu** is existence-only → `doctor` reports a present-but-broken symqemu OK
  (unlike _probe_angr/_probe_unicorn which execute).
- **symbolic reachability certificate** records `argv=base_argv` though angr explored without the
  flags (stage.py:133 vs angr_driver.py:133) — unfaithful cert for argv-flag targets (harmless when
  argv empty).
- **patchdiff operand blindness** — `cmp 64→32` (immediate-only edit) still collapses; `variant.similarity`
  catches it but `patch_diff_stage` uses `patchdiff.diff`. Consider the variant path or operand hashing.
- **offline e2e gate** can't exercise a SPLIT (large) bundle (test-offline-e2e.sh:28) — large bundles
  (the real-engagement shape) are never functionally gated.

## Checked and found SOUND (so these aren't re-flagged later)
Job-queue atomic claim / dedup / lease-lost guards / reaper; per-thread SQLite discipline; ROP &
cross-arch byte decoders (aarch64/riscv/loongarch/s390/sh4/ppc) and shellcode PC-relative math; BROP;
injection confirms (reflection-guarded); the main `build_exploit` dispatch + archmodel driver (reach +
arg0==&"/bin/sh" + neg control + markers.proves); server CSRF/DNS-rebinding/path-traversal/XSS/size
limits; version/CVE compare; the taint ABI tables + bounds CONFIRMED gate; the afl wrapper+symbol-lookup
fixes (generalized, no surviving same-class bug); static-PIE relink skip; the drained-vs-cutoff concolic
honesty invariant.
