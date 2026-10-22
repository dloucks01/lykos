# The Workbench UI

The analyst-facing interface is a **dependency-free Preact + htm single page**, served by the local
API (`core/lykos/api/`, static assets under `core/lykos/api/static/app/`). There is **no build step**
and no framework install: the ESM runtime is vendored, the page is plain JavaScript modules, and the
core stays stdlib-only. It was chosen over a Tauri/Electron desktop target for zero-install, offline
delivery — `./start` serves it on loopback and the operator opens it in a browser.

> Historical note: an earlier `gui.md` specified a Tauri (Rust webview) + React + TypeScript + WebGL
> desktop app. That target was **not** built; this document describes the shipped browser workbench.
> The design-system principles from that plan (§"Visual & interaction design", below) *were* kept.

## Frontend architecture

- **Stack:** Preact + htm (tagged-template JSX, no transpile), ES modules, served static by the API.
- **Files** (`core/lykos/api/static/app/`): `app.js` (the top-level workbench view and run state),
  `components.js` (the finding cards, tabs, panels, call-graph, charts), `autopilot.js` (the run
  lifecycle + polling), `api.js` (fetch wrappers), `util.js` (formatting/helpers), `archive.js`
  (Recent analyses). A `/classic.html` fallback view remains for a minimal UI.
- **Live data:** the page polls the API for run status and streams the run log; "Run in background"
  keeps the run alive server-side (`orchestrate.py`) after the tab closes, and a case is reopenable
  from **Recent analyses** with its run log, coverage, findings and verify badges restored.
- **Backend coupling:** the Python backend loads once at startup — static GUI files update on a
  browser reload, but backend changes need a server restart.

## Layout

A three-zone workbench for **one engagement at a time**:

- **Header** — the lykos mark, a `server ready` status pill, **New analysis**, a light/dark theme
  toggle, and a **Classic UI** link to the fallback view.
- **Left rail** — **TARGETS** (the binaries in the case, with "add more binaries / source folder" to
  unlock IPC modelling and cross-binary taint) and the full **PIPELINE** as a live checklist: every
  stage with its real status (✓ ran, – not run / not applicable), driven by the server's per-stage
  `state`.
- **Run bar** — grouped controls: **BUDGET** (a slider + "to convergence"), **ENGINES** (black-box,
  coverage, directed, concolic, libfuzzer, deep-seed toggles), **INVOCATION** (target-libraries dir,
  argv, input-mode channel), and **Continue run** / pause / resume.
- **Main pane** — the per-target header (format · arch · size + mitigation chips: `NX`, `PIE`,
  `RELRO`, `CANARY`, `FORTIFY`, `SECCOMP` for ELF; `ASLR`, `DEP`, `SafeSEH`, `CFG` for PE), a status
  card (crash state, static-finding count, coverage %, and the **L1 ▸ L2 ▸ L3** ladder), then a tab
  strip with **HTML / SARIF / JSON** export.

## The tabs

1. **Overview** — a severity donut, top CWEs, the **weaponization ladder** (L0 Detected → L1 Crash →
   L2 Primitive → L3 Exploit, with the reached rung highlighted and the contributing sources), and
   the findings list. Each finding is **results-first**: the headline is the worst demonstrated end
   effect (e.g. "out-of-bounds write in parse_record"), with a state badge (Candidate / Corroborated
   / Confirmed / PoC-backed), a **"HOW IT CAN BE EXPLOITED — click any line to go deeper"** block
   whose EVIDENCE lines state the honest provenance (e.g. "demonstrated at the FUNCTION level … Not a
   program-level verified PoC"), and **View code** / **Inspect evidence** actions. Inspect evidence
   opens the **evidence trail** (the recorded signals + "View code at 0x…" + raw JSON). A `candidate`
   section collapses lower-confidence, not-yet-demonstrated patterns.
2. **Exploits** — the crash → primitive → working-exploit chain for this target, or an explanation of
   why it is empty, plus the **"What this run did"** panel that frames a null result by the work
   behind it (total executions, per-engine split).
3. **Code** — **Functions & call graph** (a live, pan/zoom/clickable call graph), **Disassembly**,
   **Strings**, and a **Deep function fuzzing** action.
4. **Dynamic** — per-binary **fuzzing coverage** (block coverage = % of recovered code exercised,
   drill into a binary's functions) and the **Fuzzing engine health** table.
5. **Diff** — two-binary (patch) comparison: add a second build and lykos diffs the findings and, when
   one version has a working PoC, re-runs it against the other to confirm a fix.
6. **Console** — the run log (live, and reconstructed on reopen, with per-stage errors).

### Honesty surfaced in the UI

The **Fuzzing engine health** table reports, for every engine, whether it `ran` / `skipped` / is
`n/a` and *why* ("no budget left / not reached", "no source for this target", "nothing here reads the
environment") — so a clean "0 crashes" is never mistaken for a thorough negative. Findings state their
ceiling in plain language, and the L-ladder shows which rungs are reached and which are honestly not.

## Run controls

Every CLI capability is reachable from the run bar (web-GUI/CLI parity is a firm requirement): the
per-phase/stage budget, the engine toggles, the per-stage skip allowlist (black-box mode), target
libraries / sysroot, deep-seed (Autopilot derives the seeds/inputs it needs), and the operator
invocation (argv / input-mode / channel). A run can be **paused**, **resumed**, and explicitly
**continued**; pausing does not burn the budget clock. "Run in background" detaches the run from the
tab.

## Visual & interaction design system

Kept from the original design plan, and realized with CSS custom properties:

- **Dark-first operator console**, high contrast, restrained accent palette, generous spacing, strong
  typographic hierarchy. A **light/dark theme** toggle (persisted, OS-preference aware) derives both
  themes from the **same tokens** defined once on `:root` in `index.html`.
- **Semantic color = state, consistently** — severity (info → critical) and finding-state colors are
  tokens reused across the board, tables, graph and report. Color is never the only signal (paired
  with icon/shape/label) for accessibility.
- **Typography** — a crisp UI sans for chrome, a monospace for code/hex/disassembly.
- **Near-duplicate crashes collapse** — a control-flow-hijack's attacker-controlled fault PC never
  splits one overflow into many findings (`dedupeFindings`).

## Pointers

Pipeline stages and their outputs: `pipeline.md`. The layered system (GUI → local API →
orchestration → engines → storage): `architecture.md`. The candidate → confirmed → PoC-backed
promotion model and the L-ladder: `pipeline.md` and `docs/internal/` (current-state doc).
