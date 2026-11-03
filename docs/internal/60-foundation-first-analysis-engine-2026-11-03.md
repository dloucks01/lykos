# 60 — Foundation-first analysis engine (source + binary → findings → PoCs)

2026-11-03. Written after an engagement pattern the operator (rightly) called out: gaps kept being
surfaced one at a time, each patched in a scratch script *beside* the engine rather than wired into
it. This doc names the ROOT CAUSE, the target architecture, and an ordered build list executed
foundation-first. "Done" criteria are explicit so the list cannot silently stall.

## Root cause

Every precision gap raised this engagement — unreliable reachability, shallow taint, "off-surface"
findings that were actually reachable, the 346-candidate backlog, CodeQL unused — traces to ONE
missing layer: **the engine has no real code-representation (call graph / CFG / interprocedural
dataflow) for SOURCE runs.** The DB `call_edge`/`function` tables are empty for a source project, so:

* `taint_reach.attacker_reachable_names` returns ∅ → grounding falls back to a weak heuristic
  ("is the file compiled into a fuzz harness") for reachability;
* there is no interprocedural source taint (only `srctaint`, intraprocedural + 1 hop);
* triage dispositions are therefore computed on heuristics, not facts.

Point-fixes above this layer (verification scripts, one-off reach/taint passes) are bandages. The
fix is to build the foundation INTO the engine so every finding, every run, is grounded in real
reach + dataflow.

## Target architecture (the layers a SOTA air-gapped, non-AI tool needs)

1. **Code representation** — call graph + CFG + def-use, for source AND binary. Source: build it
   from the tree (`source_reach` is the start). Binary: already recovered by disassembly.
2. **Detection (per-CWE over the representation)** — CodeQL as the CPG/dataflow backbone (installed,
   air-gapped, non-AI), plus the catalog sweep for completeness accounting, plus the existing
   pattern detectors as a recall floor.
3. **Dataflow / taint** — interprocedural source→sink (CodeQL), register-level binary taint
   (`detect/taint`), source taint-lite (`srctaint`) as the cheap first pass.
4. **Reachability** — BFS from attacker entries over the real call graph (`source_reach`).
5. **Grounding / triage** — disposition = f(real reachability, real taint, CWE ceiling). No
   heuristics.
6. **Confirmation** — reach → synth harness → fuzz → sanitizer, auto-driven for the reachable
   codec/channel surface (the only recall-complete oracle; it found all 4 confirmed FreeRDP bugs).
7. **Weaponization** — heap solver, exploit templates, primitive chaining (exists).

## Build list (foundation-first; execute in order)

- **F1 — Source call-graph in the engine.** Promote `source_reach` to populate a real reachable-set
  the pipeline can query for a source target. Done when: a stage/DAO exposes the attacker-reachable
  function set for a source case and a test pins it on a fixture.
- **F2 — Grounding uses real reachability.** Grounding's reach decision for a source finding comes
  from F1, not the fuzz-harness heuristic. Done when: grounding marks a provably-unreached function
  off-surface and a provably-reached one on-surface, test-pinned; the FreeRDP "off-surface but
  reachable" disagreements collapse.
- **F3 — CodeQL as a detection+taint stage.** A stage builds the DB (cmake trace) and runs the
  security-extended + custom per-CWE queries; results ingested as findings carrying their dataflow
  path. Done when: a run on a source project yields CodeQL-backed findings in the case DB, guarded
  so a missing `codeql` binary degrades gracefully.
- **F4 — Interprocedural source taint into triage.** Combine reach (F1) + taint (CodeQL path from
  F3, `srctaint` fallback) so a DRIVABLE disposition requires the dangerous operand be
  attacker-tainted. Done when: triage downgrades a reachable-but-untainted sink (the rfx case) and
  keeps a reachable-tainted one, test-pinned.
- **F5 — Confirmation harness-synth as a stage.** Auto-drive the reachable exported codec/channel
  parsers (dispatcher_harness + decoder fuzzing) on the instrumented build; confirm via the 0-FP
  gate. Done when: a run fuzzes the reachable parser surface and files any fault as a poc-backed
  finding, bounded (no marathon).
- **F6 — Gap self-audit.** A check that flags, each run, any registered capability not applied in
  the pipeline (so a built technique can't sit in a drawer). Done when: it lists unwired
  capabilities in the scorecard.

## Standing rule (process)

Identify gaps proactively and apply them to the ENGINE (a stage + test + wiring), never a scratch
script. A capability that isn't a wired stage with a test does not count as done. See
[[drive-the-roadmap-proactively]].
