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

## R1 — Fuzzing engines must actually run (no silent failures)   `[ ] TODO`

**Goal.** Before/at run start, a per-engine **preflight self-test** confirms each fuzzing engine
actually *executes the target and produces real execs/coverage*. When one can't run (the air-gap
breakage), the autopilot reports **which engine and why** and falls back, instead of silently
degrading to static-only.

- [ ] Preflight for each engine: afl-qemu-trace (instrumentation), coverage_fuzz / afl, blind
      `fuzz`, concolic — each must demonstrably run the target once and return execs/coverage.
- [ ] On failure: a visible, specific diagnosis event (e.g. "afl-qemu-trace failed to instrument on
      this host: <reason>; fell back to coverage_fuzz") surfaced in the web-GUI run log.
- [ ] A run that produces static-only findings must say *why* fuzzing contributed nothing (declined
      vs failed vs starved), never look like a clean empty result.
- [ ] Fold the live "is this engine producing execs/coverage" signal into the health indicator (see
      U2) so a stalled/failed engine is visible immediately.

**Acceptance.** On a cold air-gap bundle, a deliberately-broken engine is named with a reason in the
GUI; the autopilot still completes via a working engine; `make verify-e2e` stays green.

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
