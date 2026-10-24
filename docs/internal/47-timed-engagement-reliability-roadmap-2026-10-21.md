# 47 — Timed-engagement reliability & UX roadmap (open items)

Status date: 2026-10-21. This is the **living open-items tracker** for the work that makes lykos
usable in a real, time-boxed engagement from the **web GUI**. Mark items off here as they land;
each item names its acceptance criterion so "done" is unambiguous.

## Why this exists

The operator analyses binaries under time pressure — **usually 10-20 minutes each**, occasionally
hours. Two things have repeatedly broken that workflow on the air-gapped laptop:

1. **The fuzzing silently didn't work** (engines present but failing), so a run returned
   static-only findings with no indication *which* engine failed or *why*.
2. **The target was never driven correctly** — it needed a config file or a parameter, wasn't given
   one, so the fuzzer bounced off argv it ignores and never reached the real input surface.

And the operator needs to **choose the depth** (quick vs thorough), **see live progress + ETA**, and
**trust that every pipeline stage is wired into the web-GUI autopilot and cross-references the
others' findings**.

Hard constraints (standing): **web GUI must do everything the CLI does**; **large binaries lose no
capability / nothing degraded (additive only)**; **never fabricate a finding / never hide a real
one** (precision is paramount). Core stays **stdlib-only**; heavy engines under `vendor/`.

## Priority order (confirmed by the operator)

**R1 → R2 → I1 → U1 → U2.** Reliability first: a progress bar and a mode slider are meaningless if
the fuzzing silently fails or never reaches the input surface.

---

## R1 — Fuzzing engines must actually run (no silent failures)   `[x] DONE`

**Goal.** A per-engine health verdict confirms each fuzzing engine actually *executes the target*,
and when one can't (the air-gap breakage) the autopilot reports **which engine and why** instead of
silently degrading to static-only.

- [x] **Per-engine health verdict + surfacing** — `fuzz/health.py` (`summarize`, unit-tested) folds
      the scattered per-stage signals (afl handshake abort, starved, noprogress, did-not-run,
      declined) into one `{engines, verdict, note}`; `orchestrate` emits it as a `fuzz.health` event
      + stores it in the scorecard; the web GUI renders it (`FuzzHealthPanel`). A `verdict: none`
      is the alert that a static-only result is a tooling outcome, not a clean binary. FAILED is
      reserved for a concrete execution failure (aborted/did_not_run) so it stays trustworthy;
      "not applicable" (no source / not a server) is a DECLINE, not a failure.
- [x] **A static-only run says why** each engine contributed nothing (ran / failed+reason /
      starved / no-progress / n/a / skipped), never a bare empty result.
- [x] **Upfront functional preflight — NOT NEEDED (concluded).** afl's forkserver aborts at the
      handshake within ~1-2s when it can't instrument/load the target (it does not burn the `-V`
      slice first), and `campaign_failed` + `coverage.done{aborted}` already surface that reason
      immediately. A separate afl-showmap preflight would only re-run the same check a second earlier,
      at the cost of an extra micro-campaign per run — net negative. The health verdict (above) is
      the R1 deliverable.
- [x] **Live per-engine state during the run** — the U2 live badge (finding coverage / coverage
      steady / stalled) shows the fuzzing state the moment the heartbeat changes, and a failed engine
      surfaces in its own `.done{aborted}` immediately. Done via U2.

**Acceptance.** On a cold air-gap bundle, a broken engine is named with a reason in the GUI; the
autopilot still completes via a working engine; `make verify-e2e` stays green.  *(Surfacing done +
validated on fp3: `fuzz.health` event lands, verdict + per-engine reasons render. Upfront preflight
+ live-during-run still open.)*

**Cross-refs.** memory: offline-bundle-tool-gaps, airgap-engagement-gaps, engagement-large-binary-round.

---

## R2 — Automatic invocation & seed discovery   `[~] IN PROGRESS`

**Goal.** Detect when a target can't be driven as-is and **synthesize + supply** what it needs, so
the fuzzer reaches the real input surface rather than bouncing off ignored argv.

**Finding (2026-10-21): R2 is far more built than the roadmap implied.** `invocation.discover()` →
`propose_argv()` → `materialize()` already parse usage/getopt/help, pick an input slot, and
**synthesize real config/jar/path files on disk** behind value flags, wired into the fuzz stage
(`fuzz/stage.py`), synthesize_stage, and the `/invocation` endpoint. So R2 is closing specific gaps
found by running the machinery on a REAL daemon (asterisk), not building it from scratch.

- [x] **Self-name usage anchoring** (`discover(..., prog=<binary name>)`). A large daemon embeds
      hundreds of INTERNAL-command usages ("Usage: core show version", "Usage: bridge kick <id>");
      `from_usage` mixed their flags into a garbage option set and picked the richest internal line,
      so asterisk got invented flags + an **empty** proposed argv and was fuzzed with no args →
      static-only. `prog` makes the program's OWN usage (`Usage: asterisk [OPTIONS]`) authoritative.
      Threaded into the fuzz stage, synthesize_stage, and both invocation endpoints. Unit-tested;
      32 invocation tests green. *(Measured on asterisk: garbage flags → correctly isolated own
      usage.)*
- [x] **Native shared-library dep resolution (the keystone).** A native dynamically-linked daemon
      off its own system exited at the loader ("error while loading shared libraries ...") and read
      as not-runnable, so its `--help` mining, baseline and fuzzing ALL silently found nothing.
      `sandbox.run` now, for a native target, prepends an operator `LYKOS_QEMU_SYSROOT`'s lib dirs to
      `LD_LIBRARY_PATH` **and binds the sysroot into bwrap** (a /tmp sysroot is otherwise masked) --
      mirroring `aflpp.run_campaign`. Additive + opt-in (fires only when the sysroot is set; can turn
      a not-runnable into a run, never the reverse). Unit-tested; 23 dynamic tests green. **Proven on
      the real asterisk**: with the rig sysroot, `asterisk -h` now reaches main, prints its help, and
      `discover(help_text=...)` recovers `-C` (config) + the exact version string (22.5.2 -> a bonus
      for N-day / avenue #2).
- [x] **R2.c · Dynamic `--help`/`-h` extraction** already existed (`fuzz/stage.py:_help_text` tries
      `--help`/`-h`/`help`/`--usage`, scores the option table, feeds `discover`). It was dead for
      dynamically-linked daemons because the target couldn't load; the dep fix above unblocks it, and
      self-name anchoring keeps the terse static usage from poisoning the richer `--help` result.
- [x] **R2.b · Isolate the getopt optstring + relax the cap** -- DONE — now a FALLBACK for the static-only
      case (no `--help` obtainable). `from_optstring` UNIONS matches (asterisk → 50 bogus flags) and
      `discover`'s `<=12` cap drops the real `BC:cde:FfG:...`. Pick the single best getopt string and
      trust one well-formed optstring past 12. **Precision-sensitive** → needs the conformance guard.
- [~] **R2.d · Daemon runtime needs (overlaps P5).** *(2026-10-24: `analyze/runtime_env.py` discovers + confirms + stages config-with-content / dirs / env (889c237); NOT yet wired into `sandbox.run` / `fuzz/stage._discover_argv` — see doc 51 "Open".)* A plausible config *with content* (not an empty
      `-C` file), a working/data dir, and env vars the target reads — asterisk needs a config + runtime
      dir to fully initialize, which `materialize`'s single-file synth misses.
- [x] **Surface the chosen invocation in the GUI** — a "DRIVING AS `<target> <argv>` · operator /
      auto-discovered" line under the run bar, so "did the fuzzer reach the parser" is visible rather
      than a guess. Operator value from the client's invocation input; auto-discovered value from the
      `coverage.invocation` event. Verified live (`fileparser3 parse @@ · operator`). Also fixed the
      cancelled/errored run state collapsing the whole run bar to a bare "Resume run" (the operator
      lost the budget/invocation/convergence controls) — it now keeps the full controls.
- [x] **R2.f · Discover `tool <subcommand> <file>` invocations.** `verb_subcommand()` recognizes a
      written-out VERB before a file positional (`tool parse <file>`, `check <input>`, `run FILE`) --
      the generic subcommand finder missed it (the verb is not a `<command>` metavar), so a
      verb-dispatched parser was fuzzed as `tool <file>` and never got past its usage. Now
      `discover` → `['parse', '@@']`. Conservative (verb + file positional, no flags before it);
      converters/flagged tools unchanged. Unit-tested; 34 invocation tests green. *(fp3: `parse
      <file>` now auto-discovers — the autopilot drives the parser instead of bouncing off usage.)*

**Acceptance.** A binary that needs `-c <config>` or a positional file is auto-driven to its parser
(or an honest "couldn't synthesize a valid invocation: <reason>") without the operator hand-setting
argv; the web GUI shows and allows editing the chosen invocation.

**Cross-refs.** memory: webgui-cli-parity (the #1 reason real binaries return static-only).

---

## I1 — Full web-GUI-autopilot wiring + cross-pipeline finding cross-reference   `[~] substance done`

**Goal.** Every stage (incl. the non-fuzz avenues, taint, harness, CVE BOM) runs inside the web-GUI
autopilot, and stages feed each other instead of sitting siloed.

- [x] **Inventory — VERIFIED.** The web-GUI "Run Autopilot" uses the SERVER background run
      (`startBackground` → `POST /autopilot` → `run_case_autopilot` = the full `orchestrate.py`
      pipeline), so every registered stage is reachable from the GUI. (The "In this tab" button is a
      separate, shorter client-side path by design.)
- [x] **Cross-references — AUDITED, extensive and working.** detect_cwe's flagged sinks steer
      `directed_fuzz` (AFLGo-style `nearest_sink_dist`: inputs that get closer to a flagged CWE site
      are retained); a first crash seeds a REINFORCEMENT directed pass biased toward the flagged
      sinks and seeded by the crashes found so far; `cve_scan`'s matched CVEs feed `cve_poc`;
      `heap_trace`/`oob_index` findings feed `chain_primitive`; crashes feed `root_cause` →
      `build_exploit`; `extract_secrets` constants feed gate-passing. The pipeline is not siloed.
- [ ] **(optional polish) Per-finding provenance in the GUI** ("steered toward N flagged sinks",
      "seeded from 2 crashes"). The hand-offs WORK and some are already logged (the reinforcement
      pass emits "found N more distinct crashes"); surfacing a count on every consumer is buried in
      the directed-stage internals and low value — deferred.

**Acceptance.** Met: the GUI runs the full pipeline and the cross-references are wired. (The
cosmetic per-finding provenance line is the only open, low-value remainder.)

---

## U1 — Run depth: a minutes slider + a run-to-convergence checkbox   `[~] IN PROGRESS`

**Design (operator's call):** a single **slider in minutes** plus a **run-to-convergence checkbox**
— clearer than three detents (no ambiguous "half-converged" position). Drives the **server-side
background autopilot** (`startBackground`, the mature phase/budget model), not a duplicated JS one.
Unchecked → the minutes are a hard wall-clock budget (exact ETA countdown). Checked → the minutes
become the **safety ceiling** and the search runs until coverage plateaus. Non-fuzz analysis is
**complete either way** — only fuzzing depth changes.

- [x] **GUI control + plumbing** — minutes slider (5–120) with a live readout; `run to convergence`
      checkbox (slider relabels "budget"→"ceiling"); `api.startBackground(..., converge)` →
      `POST /autopilot {converge}` → `_start_autopilot` → `run_case_autopilot(converge=)` →
      `status["converge"]`. In convergence mode the per-target budget is the ceiling (slider minutes,
      or a 6h default when blank). JS + py imports clean; 12 autopilot tests green.
- [x] **U1-engine · coverage-plateau auto-stop** — in convergence mode the coverage campaign runs
      with AFL's own `AFL_EXIT_WHEN_DONE=1`, so it stops when AFL has cycled every path with no new
      find for a while (its coverage-plateau signal) instead of burning the full `-V` ceiling; the
      ceiling stays the hard upper bound. Threaded `converge` through `run_case_autopilot` → the
      dynamic params → `coverage_stage` → `aflpp.run_campaign`. **Stuck/hung is covered natively**:
      AFL's forkserver marks a hung target (per-exec timeout) and skips it, and a wedged campaign is
      caught by the orchestrator's stage-deadline reaper. ADDITIVE (fires only for `converge=True`),
      so existing conformance (all `converge=False`) is unchanged; unit-tested (the flag is set iff
      converge) + afl/coverage tests green.
- [x] **U1-engine (remaining) · plateau for the non-AFL campaigns + a live "Converged/Stalled"
      badge.** The blind/`directed_fuzz` sandbox campaigns run to the ceiling in convergence mode
      (no AFL plateau signal there); a coverage-growth monitor could stop them too. Surface the
      live Running/Converged/Stalled state in the GUI (overlaps U2).
- [ ] (dropped) Quick/Standard/Thorough detents + Quick's smart-only+blind-slice profile — folded
      into "pick fewer minutes" + the checkbox; revisit only if the operator wants named presets.

**Acceptance.** The checkbox visibly switches budget↔ceiling; a convergence run keeps fuzzing past a
fixed clock and (U1-engine) stops itself when coverage plateaus; non-fuzz findings are complete in
both modes.

---

## U2 — Live progress + ETA + health (Running / Converged / Stalled-hung)   `[~] IN PROGRESS`

**Goal.** A live panel in the GUI driven by `backgroundStatus` (`status.budget` =
{total, elapsed, remaining, phase}) + the event stream (`*.progress` heartbeats:
execs, rate, coverage blocks_hit/known, crashes).

- [x] **Live fuzz telemetry + ETA** — the `FuzzConsole` shows elapsed/budget, a progress bar, **ETA**
      (`~Xm left`), execs, exec/s, coverage %, behaviours, crashes. MOVED out of the bottom of the
      long pipeline rail (below the fold, never seen) to directly under the run bar in the main
      content, so it is visible DURING a run. Verified live on fileparser3.
- [x] **Live health badge** — derived from the heartbeat trend in the GUI: **finding coverage**
      (green, coverage still growing) → **coverage steady** (amber, flat for 20s at a healthy rate —
      the convergence signal) → **stalled — no heartbeat** (red, >15s with no `.progress` during an
      active run, decided in the poll tick). Verified live: badge went running → coverage steady as
      coverage plateaued at 40%.
- [x] **ETA honesty in convergence mode** — when `converge` is on the console labels the ETA
      `ceiling ~Xm` (the hard cap, not a real countdown) and the live badge carries the true state
      (coverage steady = plateauing); in time-boxed mode it stays `~Xm left`.
- [x] **Server-authoritative stall → auto-skip in Thorough** *(6cd5719: `<prefix>.converged` / `<prefix>.stalled`, budget handed back)* — the badge now SHOWS stalled; wiring a
      Stalled campaign to a short-grace auto-skip belongs with the U1-engine (AFL already self-skips
      a hung target; this is for the non-AFL campaigns).

**Acceptance.** During a GUI run the operator can see how much is left, how fast it's going, how much
of the program is covered, and whether it's progressing / done / stuck — without reading logs. *(Met
for the live telemetry/ETA/badge; convergence-ETA wording + non-AFL auto-skip remain.)*

---

---

## Carried-over / parallel open items (deeper-analysis capability — detail in doc 46)

These are **not** part of the timed-engagement UX line above, but they are open and must not be lost.
Full design + evidence live in `docs/internal/46-deeper-binary-analysis-program-2026-10-21.md`;
tracked here so there is one index. Several of these feed the reliability work (e.g. the taint
upgrade improves what the non-fuzz recover phase can confirm).

- [x] **(b) Taint-engine buffer-pointer-param taint** — DONE, done right. The empirical finding
      REFINED the design: the engine already PROPAGATES taint from a seeded buffer-pointer param
      (stack-spill tracking + the load-through-tainted-pointer rule), verified on the daemon-parser
      shape. The real gap was SEEDING — the stage only seeds `argv` at `main` (or every export for a
      `.so`), so a parser reached by a callback/dispatch in an executable is never seeded and its
      sinks are invisible (avenue #1's wall). Fix: `_parser_buffer_seeds` seeds the T1-RANKED parser
      entries' buffer parameter (recovered pointer params, or arg 0 on a stripped build) as
      attacker-controlled; a second A/B pass diffs the new sink sites and files them as honest
      CANDIDATES (attacker-reachability ASSUMED, never corroborated), with a `taint-buffer-param`
      evidence note. Gated by `LYKOS_BUFFER_SEED`. **Validated:** recovers a callback-reached
      parser's injection a register-only + export-fallback run misses (unit + stage A/B tests);
      corroborated precision 1.000 UNCHANGED on the eval benchmark with it on (no fabrication);
      29 taint+ranker tests green. *(Default off/opt-in until a full conformance green; enabling by
      default is then a one-line change.)*
- [x] **Avenue #1 — static injection confirmation** — UNBLOCKED by (b). The buffer-pointer seeding
      confirms a daemon-parser buffer-content injection (a callback-reached parser's buffer feeding a
      dangerous sink) statically, as an honest candidate. (Further depth possible, but the wall is
      down.)
- [x] **Avenue #2 — N-day fingerprinting (first increment)** — DT_NEEDED BOM + dependency-.so banner
      scan + CVE match, commit `f876e40` (validated on asterisk: OpenSSL 3.5.5 + 27 CVEs).
- [ ] **Avenue #2 extension** — main-binary structural / FLIRT version fingerprinting (identify the
      product+version of the MAIN binary, not just its linked deps). **Not started.**
- [x] **Avenue #3 — structural decompiler queries** — ALREADY BUILT: `analyze/weggli.py` runs a
      curated pack of structural (AST) pattern queries; `directed.py` uses weggli hits to steer the
      campaign toward source-flagged code. (Audit 2026-10-21.)
- [~] **Avenue #4 — logic / auth bugs** (broken-contract checks beyond memory safety) — a genuine
      NEW capability class (lykos did memory-corruption + injection only). **First increment landed:**
      the **unchecked privilege-management return** detector (`detect/detectors.py unchecked_privdrop`,
      CWE-252 / CWE-273). A privileged daemon that calls setuid/setgid/seteuid/…/chroot and ignores
      the result keeps its privileges on failure — a logic bug that never crashes, so no fuzzer or
      memory-safety detector sees it. Pure-static: reads the disassembly after the call and flags a
      return value that is REDEFINED (or clobbered by the next call) before any read; a value that is
      TESTED, STORED, or PASSED ON is correctly left alone (high precision). Honest CANDIDATE
      (attacker-reachability/exploitability not claimed). x86/x86-64. Validated unit + e2e A/B
      (`tests/test_unchecked_privdrop.py`, 10 tests); 69 existing detector tests green.
      **Second increment landed:** the **world-writable file permissions** detector
      (`detect/detectors.py world_writable_perms`, CWE-732). A `chmod`/`fchmod`/`fchmodat` with an
      others-writable mode leaves a file any local user can rewrite (a config/script/lock/binary the
      program trusts) — an access-control contract broken with a constant, not a crash. umask does
      not apply to chmod/fchmod, so the literal mode IS the final permission: the detector reads the
      mode immediate from the ABI arg register and flags only the others-writable ones (0777/0666
      flagged; 0755/0644 not; a computed mode is never guessed — no FP). x86-64. Validated unit +
      e2e A/B (`tests/test_world_writable.py`, 10 tests).
      **Third increment landed:** the **privilege-drop order** detector (`privilege_drop_order`,
      CWE-696 / CERT POS36-C). Dropping the user id before the group id is a revocation-order bug:
      once `setuid()` gives up root the process may lack the privilege to `setgid()`, which then
      fails silently and leaves it in the privileged group. Per function, flags when the first
      uid-drop precedes the first gid-drop. Arch-agnostic (reasons over call-site addresses, no
      disasm). Honest candidate (notes "confirm both calls lie on the same execution path" — the one
      known approximation). Validated unit + e2e A/B (`tests/test_privilege_drop_order.py`, 7 tests).
      *Remaining in the class:* auth-comparison / hardcoded-credential-gate shapes (precise only when
      scoped to hash/key-shaped literals, else FP-prone), precise CWE-134 format-string (literal-vs-
      computed format arg needs real taint — the walled engine limit, so a naive version fabricates
      FPs and is deliberately NOT built), protocol-state violations (the hard, spec-modeling tier).
- [x] **Avenue #5 — exploit composition on stripped (partial)** — the (a) ret2win shell-call fix is
      one increment; more composition work possible.
- [x] **Harness track T1 / T2** — T1 fuzz-worthiness ranker + T2 emulated single-function executor +
      coverage-guided loop + the `harness` stage (NOT in the default plan yet). Commits per doc 46.
- **Harness track T3-T6** (building on T1/T2):
  - [x] **T4 · Constant-guided input** — `dictionary_from_ir` mines the function's own comparison
        constants (magic values / length limits / opcodes, LE+BE) off its disassembly and feeds them
        to the harness fuzz loop as a dictionary (spliced + seeded at offset 0). Validated A/B: a bug
        hidden behind a `0xCAFEBABE` magic gate is UNREACHED by the blind campaign and REACHED once
        the constant is in the dictionary; 70 harness tests green.
  - [x] **T5 · Richer oracles** — beyond SIGSEGV. First oracle landed: **unbounded allocation**
        (CWE-789/400 DoS). The libc stubs record `HarnessResult.huge_alloc` when `malloc/calloc/realloc`
        is driven with a size ≥ 64 MiB; the fuzz loop collects `oracle_hits` (smallest-input witness)
        and `harness_stage` files them as medium-severity DoS leads with honest function-level
        provenance (no fault = not a memory-corruption crash). Validated A/B: `malloc(attacker_len)`
        trips the oracle, a fixed `malloc(16)` does not, and the DoS lead is NOT mis-filed as a crash.
        210 harness/emulate/rank/fuzz tests green.
  - [x] **T3 · Sink-directed concolic (reachability certificates)** — the concolic lane already
        steered angr `find=` at each finding's `site_addr`/`function_addr`; T3 adds the *certificate*
        and makes the verdict three-valued and honesty-preserving:
        · **REACHED** → the lead is promoted to `corroborated` AND a replayable **reachability
          certificate** (concrete input + real invocation terms: mode/argv/@@, input artifact,
          angr version, model note) is filed as an artifact and cited in the evidence. Matching is
          now detector-agnostic (static dangerous-api, taint, and harness function-level leads all
          qualify), by site OR function addr, raising only not-yet-proven leads.
        · **UNREACHABLE** → only when the search hit a NATURAL FIXPOINT (driver reports `drained`
          and not `cutoff`: no active/deferred/spilled/errored states left). The lead is ANNOTATED
          for de-prioritization on a separate zero-weight `reachability` channel — NEVER dropped or
          downgraded (the model is partial: libs unloaded, one modeled entry, bounded).
        · **INCOMPLETE** → a search cut off by budget/timeout/state-cap makes NO reachability claim.
        Driver (`angr_driver.py`) now emits `drained`/`cutoff`; stage (`symbolic/stage.py`) files
        certificates + annotations. A/B validated (`tests/test_concolic_reach.py`): reached→certified,
        drained→annotated-not-dropped (confidence preserved), cutoff→untouched; existing stub +
        real-angr concolic tests green.
  - [x] **T6 · State-machine / sequence driving** (v1) — the executor now drives a function with an
        ORDERED SEQUENCE of messages in ONE emulator state (`emulate.run_sequence`): globals (.bss/
        .data) and the heap persist between calls, each call gets a fresh stack + input buffer, so a
        fault that lives in a state only entered after a specific message prefix becomes reachable.
        `run_function` is now the single-message case of `run_sequence` (no behavior change -- 210
        tests confirm). Fuzz gained a `sequence=True` mode (`fuzz.py`): the flat buffer is framed into
        messages on a separator (default '\n'), dictionary tokens are also chained into a multi-message
        seed. The `harness` stage runs a bounded, ADDITIVE sequence pass per candidate, filing only
        faults the single-call pass could not reach (reports message count + faulting index).
        Validated A/B (`tests/test_harness_t6.py`): an A->B->C state-gated fault is reached by the
        sequence (seq_index=2) and by sequence-fuzzing, and is UNREACHABLE by any single call or the
        wrong order. v1 scope: delimiter-framed sequences; length-prefixed / binary framing and
        automatic dispatch-loop recovery are the follow-up tier.
- [x] **Make the `harness` stage reachable from the web GUI** — resolved as ON-DEMAND, not default
      (the operator steer is "stop adding fuzzing to every run", so wiring it into the default plan
      would be wrong). Added `harness` to the API's on-demand `_TARGET_STAGES` map and a **"Deep
      function fuzzing"** button in the GUI's Code→Functions view (`createRun("harness")` → progress
      → findings). Also fixed, found by running it on a real -O0 binary through the GUI: the ranker
      drove the `memcpy`/`puts` **PLT import thunks** and skipped the actual `parse_record` parser
      (its param types weren't recovered → `ptr_len=0`), returning zero findings. `harness_stage`
      now excludes import thunks and drives any non-thunk function with a sink/source signal even
      without recovered param types, defaulting the unknown shape to `f(buf,len)`. Verified live:
      the GUI button drives `parse_record` (T4 magic dictionary passes the gate) and files a CWE-787
      out-of-bounds-write finding. Commits `b50021e` (ranker), `338c0cf` (exposure), `73ef53a` (note).

---

## Proactively-identified gaps (model-sourced — confirm against code, then prioritize)

**AUDITED 2026-10-21 — most already exist in the mature system** (the "confirm against code before
building" caveat paid off; these were largely re-discoveries, not gaps).

**Already built (verified):** P1 crash triage/ranking (`crash_dedup_key` by signal+fault_pc+
discriminator, `exploitability` ratings, `CrashesPanel`); P4 target-corpus seeding (`_strings_for`
dictionary + format models + boundary configs + menu op-sequences); P5 env/filesystem (env_fuzz +
getenv detection + a writable per-run CWD); P6 stateful/menu driving (`fuzz/menu.py`,
`fuzz/command.py`, `interaction.py`); P7 hang/DoS (CWE-835 "input that does not terminate" +
resource-exhaustion); P9 multi-binary (`CaseOverview` + link_case/cross_taint/whole_system).

**Genuine remaining (nicher):** P2 mid-fuzz checkpoint-resume (the server run already survives
tab-close + persists; true mid-campaign resume is the gap, low value), P8 bundle/version freshness
warning, P10 BinDiff/patch-diff.

- [x] **P1 · Crash triage & exploitability ranking.** *(04b91c7: `/targets/{id}/crash-triage` + ranked CrashesPanel)* A run that yields many crashes should
      auto-dedup by root cause and rank by exploitability so the operator sees the few that matter,
      not fifty. (Partly exists — unique-sig dedup, `distinctCrashes`; confirm + surface a ranked
      view in the GUI.)
- [ ] **P2 · Run resume / checkpointing.** Resume an interrupted or long Thorough run from the case
      DB instead of restarting the search from zero — matters most for convergence runs and if the
      environment kills a background run (which it does here).
- [x] **P3 · Operator curation of findings.** *(4984123 GUI/API, bc8a916 reports)* In the GUI: mark false-positive / confirm / annotate,
      feeding the engagement report. Precision is the standing bar, so the operator must be able to
      triage and the tool must remember it.
- [ ] **P4 · Comprehensive auto-corpus seeding from the target.** Mine strings, embedded samples,
      format magic, and companion files for valid seeds so fuzzing starts from real inputs, not
      noise. (Partly exists — strings/format models; make it exhaustive + show what was seeded.)
- [~] **P5 · Environment & filesystem setup discovery.** *(module landed 889c237; live wiring open)* Beyond config/param (R2): env vars the
      target reads (getenv), files it opens at fixed paths, a required CWD / data dir — detect and
      supply so the target runs at all.
- [ ] **P6 · Stateful / interactive / menu-driven driving.** Detect op-sequence protocols (a
      handshake, a numbered menu) and drive them; many real daemons need a sequence to reach the
      bug. (Overlaps harness T6.)
- [x] **P7 · Target hang / DoS capture.** *(757191e capture, 2d431be verified L1 bundle, 5c61b0a proved in the prove phase)* A target that hangs on an input is itself a finding
      (CWE-835 / CWE-400), not a discarded timeout — capture and reproduce it.
- [x] **P8 · Bundle / version freshness check.** *(04b91c7 `/version` + footer, f0d62b8 BUILD_INFO.json stamp)* The GUI warns when the running air-gap disc lags
      main (missing fixes) — "it didn't work" has partly been stale discs (memory notes several
      fixes landed after the 20261021 disc).
- [ ] **P9 · Multi-binary engagement view.** An engagement is many binaries; a cross-target queue +
      dashboard (done / has-findings / needs-attention) and batch analysis, not one case at a time.
- [ ] **P10 · BinDiff / patch-diff N-day.** Diff a target against a known-good or prior version to
      localize the changed (patched/vulnerable) code; complements avenue #2.

## Done

- [x] **(L3-1) harness (the one non-pipeline stage) now reaches L3** — commit `de16dd3`. It dead-ended
      at a corroborated FUNCTION-level finding (no DynResult crash → no escalation). Now `harness_stage`
      replays each function-level crashing input against the WHOLE program over the operator's channel
      and records a REAL DynResult: a genuine program crash is escalated by the existing prove-ladder to
      L3 (verified live: harness fault → program-level crash → L1→L2→L3 PoC), a non-crash becomes a
      reachability seed. `harness` added to `directed._TARGET_DETECTORS`; the autopilot forces the
      steered concolic+prove pass when unproven harness leads exist. Honest: every row is a real run,
      L3 only on a real crash. See memory [[l3-reachability-map]].
- [x] **(L3-2) full finding-source → L3 audit** (memory [[l3-reachability-map]]). Every memory-corruption
      / format-string (CWE-134 feeds `build_exploit(strategy=format)`) / C-injection / memory-leak source
      reaches L3; source int_overflow/uaf reach it via the source-fuzz path. Honest ceilings (NOT
      fabricated): logic/auth (CWE-252/732/696), hygiene (weak crypto/rand/tmp), secrets (L0-secret),
      managed runtimes, cross-arch fmt/heap. One real fixable-but-unwired gap remains → P11.
- [x] **P11 · Go/Rust injection L3** — commit `e1f90f0`. `inject_stage` folds `lang_sinks` findings into
      its applicable probes by CWE (78→command, 22→path, 89→sql, 918→ssrf) and runs the SAME dynamic
      probe, so a native Go `os_exec.Command` / Rust `Command::spawn` injection reaches L3. `lang_sinks`
      also fixed to detect Go/Rust with no recorded toolchain (Go `runtime.*`, Rust `::h<hex>` mangling)
      and match Rust sinks as current rizin renders them (`::`, trait-impl `...Command>::do_exec`), keying
      on EXEC methods not `Command::new` (clap false positive). Verified live: Go vuln→L3, Go safe→flagged
      but NO L3 (dynamic confirm declines), Rust vuln→L3. 5 unit tests. See [[l3-reachability-map]].
- [x] **P12 · Offline gate proves L3 BREADTH** — `packaging/test-offline-e2e.sh` now drives a SECOND,
      distinct L3 synthesizer in the cold `--network none` container: command injection → `inject_stage`
      (argv→system), alongside the existing memory-corruption→ret2win (`build_exploit`). Both must reach a
      verified L3 from the bundle alone or the gate fails, so an offline-specific regression in EITHER
      synthesizer is caught. VERIFIED by running the gate against `dist/lykos-offline-20261021` (podman,
      --network none): all CAP lanes OK, ret2win L3 (13/13), command-injection L3 (1/1), "GATE PASSED".
      (Format-string was evaluated as a third class but its ad-hoc target topped out at L2 — a reliable
      CWE-134 L3 target needs the hand-crafted conformance shape, so it was left out to keep the gate
      deterministic; heap/leak-ret2libc/cross-arch/BROP/SROP L3 stay on the connected-host gates.)

- [x] **(a) Single-address ret2win to an in-image shell call** (stripped/no-PIE, NUL-safe) —
      `rop.find_shell_call_wins` + `_shellcall_ret2win_exploit`, commit `11499af`. Reaches L3 where
      the recovered call-graph misses the `system`-calling function and a NUL-truncating strcpy sink
      forbids a multi-word ROP chain. Validated: fp3 → L3 (shell + negative control); 42/42
      exploit+poc unit tests; conformance stripped_opt_overflow / no_pie_ret2win / file_overflow
      green. (Full 60-case conformance couldn't complete — the environment kills heavy background
      runs with exit 144 — so the guard was the most-exposed subset run in the foreground.)

## Notes / environment gotchas

- Heavy conformance runs launched in the **background** get killed here (exit 144). Run the
  most-exposed cases in the **foreground** (`python3 -u tools/pipeline_conformance.py <case...>`).
- Do **not** prefix a conformance launch with `pkill -f pipeline_conformance` — it matches the
  launching shell's own argv and self-terminates the run (also exit 144).
