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
- [ ] **R2.d · Daemon runtime needs (overlaps P5).** A plausible config *with content* (not an empty
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

## I1 — Full web-GUI-autopilot wiring + cross-pipeline finding cross-reference   `[ ] TODO`

**Goal.** Every stage (incl. the non-fuzz avenues, taint, harness, CVE BOM) runs inside the web-GUI
autopilot, and stages feed each other instead of sitting siloed.

- [ ] Inventory: confirm every registered stage is reachable from the web-GUI autopilot path (parity
      with the server `orchestrate.py` pipeline).
- [ ] Cross-references audited and complete: detect_cwe sinks → directed_fuzz; CVE BOM → cve_poc;
      taint → exploit composer; crashes → root_cause → build_exploit; leaks → ROP chains;
      extract_secrets constants → gate-passing in later stages.
- [ ] A stage that consumed another's finding says so in its evidence ("biased toward 3 sinks from
      detect_cwe", "seeded from 2 fuzz crashes").

**Acceptance.** A GUI run shows the hand-offs in the log; no stage that *could* use an upstream
finding is running blind to it.

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
- [ ] **U1-engine (remaining) · plateau for the non-AFL campaigns + a live "Converged/Stalled"
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
- [ ] **Server-authoritative stall → auto-skip in Thorough** — the badge now SHOWS stalled; wiring a
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
- [ ] **Avenue #3 — structural decompiler queries** (weggli/structural pattern queries over recovered
      code). **Not started.**
- [ ] **Avenue #4 — logic / auth bugs** (broken-contract checks beyond memory safety). **Not started.**
- [x] **Avenue #5 — exploit composition on stripped (partial)** — the (a) ret2win shell-call fix is
      one increment; more composition work possible.
- [x] **Harness track T1 / T2** — T1 fuzz-worthiness ranker + T2 emulated single-function executor +
      coverage-guided loop + the `harness` stage (NOT in the default plan yet). Commits per doc 46.
- [ ] **Harness track T3-T6** — T3 sink-directed concolic (reachability certificates), T4 constant/
      grammar-guided input, T5 richer oracles, T6 state-machine / sequence driving. **Not started.**
- [ ] **Wire the `harness` stage into the default autopilot plan** (currently registered + in the
      stage map but not in the default pipeline) — overlaps with I1.

---

## Proactively-identified gaps (model-sourced — confirm against code, then prioritize)

Operator-real gaps surfaced without being asked, grounded in how a time-boxed, air-gapped
engagement on real binaries actually goes. Each needs a quick confirm against the current code
before building (some are partly done — note that rather than rebuild).

- [ ] **P1 · Crash triage & exploitability ranking.** A run that yields many crashes should
      auto-dedup by root cause and rank by exploitability so the operator sees the few that matter,
      not fifty. (Partly exists — unique-sig dedup, `distinctCrashes`; confirm + surface a ranked
      view in the GUI.)
- [ ] **P2 · Run resume / checkpointing.** Resume an interrupted or long Thorough run from the case
      DB instead of restarting the search from zero — matters most for convergence runs and if the
      environment kills a background run (which it does here).
- [ ] **P3 · Operator curation of findings.** In the GUI: mark false-positive / confirm / annotate,
      feeding the engagement report. Precision is the standing bar, so the operator must be able to
      triage and the tool must remember it.
- [ ] **P4 · Comprehensive auto-corpus seeding from the target.** Mine strings, embedded samples,
      format magic, and companion files for valid seeds so fuzzing starts from real inputs, not
      noise. (Partly exists — strings/format models; make it exhaustive + show what was seeded.)
- [ ] **P5 · Environment & filesystem setup discovery.** Beyond config/param (R2): env vars the
      target reads (getenv), files it opens at fixed paths, a required CWD / data dir — detect and
      supply so the target runs at all.
- [ ] **P6 · Stateful / interactive / menu-driven driving.** Detect op-sequence protocols (a
      handshake, a numbered menu) and drive them; many real daemons need a sequence to reach the
      bug. (Overlaps harness T6.)
- [ ] **P7 · Target hang / DoS capture.** A target that hangs on an input is itself a finding
      (CWE-835 / CWE-400), not a discarded timeout — capture and reproduce it.
- [ ] **P8 · Bundle / version freshness check.** The GUI warns when the running air-gap disc lags
      main (missing fixes) — "it didn't work" has partly been stale discs (memory notes several
      fixes landed after the 20261021 disc).
- [ ] **P9 · Multi-binary engagement view.** An engagement is many binaries; a cross-target queue +
      dashboard (done / has-findings / needs-attention) and batch analysis, not one case at a time.
- [ ] **P10 · BinDiff / patch-diff N-day.** Diff a target against a known-good or prior version to
      localize the changed (patched/vulnerable) code; complements avenue #2.

## Done

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
