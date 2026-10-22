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

## R1 — Fuzzing engines must actually run (no silent failures)   `[~] IN PROGRESS`

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
- [ ] **Upfront functional preflight** — run each engine once *before* committing the search budget
      (afl-showmap-style instrumentation check) so a broken engine is caught in seconds and the
      budget is redirected, not spent on a doomed campaign. (Current increment is post-hoc: it
      reports health from the run's own signals at scorecard time.)
- [ ] **Live per-engine health during the run** (not only at scorecard time) — fold into U2's
      health badge so a failing engine shows the moment it aborts.

**Acceptance.** On a cold air-gap bundle, a broken engine is named with a reason in the GUI; the
autopilot still completes via a working engine; `make verify-e2e` stays green.  *(Surfacing done +
validated on fp3: `fuzz.health` event lands, verdict + per-engine reasons render. Upfront preflight
+ live-during-run still open.)*

**Cross-refs.** memory: offline-bundle-tool-gaps, airgap-engagement-gaps, engagement-large-binary-round.

---

## R2 — Automatic invocation & seed discovery   `[ ] TODO`

**Goal.** Detect when a target can't be driven as-is and **synthesize + supply** what it needs, so
the fuzzer reaches the real input surface rather than bouncing off ignored argv.

- [ ] Detect "needs a config file" / "needs a parameter" from usage strings, getopt/argv parsing,
      required-arg patterns (`usage: x -c <file>`, `x parse <file>`).
- [ ] Synthesize a plausible config/param + a valid seed automatically and thread it to every
      dynamic stage (not just the fuzzer) — matches the `--argv`/`--input-mode` override path.
- [ ] Surface the chosen invocation in the GUI ("driving as: `x -c <generated.conf> @@`") and let the
      operator correct it.

**Acceptance.** A binary that needs `-c <config>` or a positional file is auto-driven to a crash
(or an honest "couldn't synthesize a valid invocation: <reason>") without the operator hand-setting
argv; web GUI shows and allows editing the chosen invocation.

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

## U1 — Mode slider: Quick / Standard / Thorough   `[ ] TODO`

**Goal.** A slider in the GUI (three labeled detents) that sets run depth; drives the **server-side
background autopilot** (`startBackground`, the mature phase/budget model), not a duplicated JS one.

| Mode | Non-fuzz | Fuzzing | Stop condition | ETA |
|---|---|---|---|---|
| **Quick** | full | smart engines (directed → concolic → coverage) + a short blind slice (~60-90s) | ~10 min cap | exact countdown |
| **Standard** | full | all engines, time-boxed | ~20-30 min cap (default) | exact countdown |
| **Thorough** | full | all engines → **run to coverage convergence** | coverage plateau; hard safety ceiling (default 6h, editable) | plateau/trend, not a false countdown |

- [ ] Slider UI with the three detents + a live readout of the concrete meaning (minutes, or "until
      convergence"); minutes nudgeable for Quick/Standard.
- [ ] Quick keeps a small blind slice (not smart-only) — catches shallow surface bugs cheaply.
- [ ] Server budget profiles for Quick/Standard (smart-engine priority in Quick).
- [ ] Thorough = convergence mode: search runs until coverage plateaus (no new edge for N min),
      bounded by a hard safety ceiling.
- [ ] Non-fuzz analysis is **complete in every mode** — only fuzzing depth varies.

**Acceptance.** Picking a mode visibly changes the budget/behavior; Quick finishes ~10 min with full
non-fuzz + a crash hunt; Thorough runs to a reported convergence and stops.

---

## U2 — Live progress + ETA + health (Running / Converged / Stalled-hung)   `[ ] TODO`

**Goal.** A live panel in the GUI driven by `backgroundStatus` (`status.budget` =
{total, elapsed, remaining, phase}) + the event stream (`*.progress` heartbeats:
execs, rate, coverage blocks_hit/known, crashes).

- [ ] Overall: current phase, elapsed/total, **ETA** (remaining; a hard countdown in time-boxed
      modes; a coverage-trend indicator in Thorough).
- [ ] Live fuzz telemetry: execs/s, coverage %, crash tally, current stage.
- [ ] Health badge off real signals: **Running** (new edge/corpus recently, healthy rate),
      **Converged** (healthy rate, flat coverage for a window), **Stalled/hung** (rate ≈ 0, or no
      heartbeat for H seconds). In Thorough a Stalled campaign gets a short grace then auto-skip so
      it can't eat the safety ceiling.

**Acceptance.** During a GUI run the operator can see how much is left, how fast it's going, how much
of the program is covered, and whether it's progressing / done / stuck — without reading logs.

---

---

## Carried-over / parallel open items (deeper-analysis capability — detail in doc 46)

These are **not** part of the timed-engagement UX line above, but they are open and must not be lost.
Full design + evidence live in `docs/internal/46-deeper-binary-analysis-program-2026-10-21.md`;
tracked here so there is one index. Several of these feed the reliability work (e.g. the taint
upgrade improves what the non-fuzz recover phase can confirm).

- [ ] **(b) Taint-engine memory / points-to upgrade** — `AGREED NEXT after (a)`. `detect/taint.py` is
      register-granularity, so static dataflow cannot confirm a buffer-content injection reaching a
      daemon parser (avenue #1 is WALLED by this). Upgrade to a memory/points-to model
      (buffer-pointer-param taint, mirroring the heap-region model), gated + A/B-able +
      conformance-guarded. Design scoped in doc 46 "Engine-extension design". **Not started.**
- [ ] **Avenue #1 — static injection confirmation** — blocked on (b); unblocks once the taint engine
      tracks buffer-pointer taint.
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
