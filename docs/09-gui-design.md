# 09 — GUI: Architecture, Views, and Visual Design System

The UI is a first-class deliverable: IDA/Ghidra/Binary-Ninja-class RE views + a fuzzing dashboard + a
findings board, unified and *stylized*. It must make the **human the decision-maker** at every
candidate→confirmed→PoC promotion (the ~32% ceiling means the analyst is in charge).

## 9.1 Frontend architecture
- **Shell:** Tauri (Rust + system webview) preferred for a light, offline, native-feeling desktop app;
  Electron acceptable if webview inconsistencies bite. (Decision + rationale in doc 10.)
- **UI stack:** React + TypeScript, a component library themed to our design system, virtualized lists for
  huge disassembly/finding tables, a canvas/WebGL graph renderer (Sigma/Cytoscape/custom) for CFG/callgraph.
- **Live data:** websocket to the backend event bus — fuzzing metrics, job progress, log tails stream in real time.
- **Layout:** dockable/tab panels (VS Code-style) so analysts arrange disasm + decompile + hex + debugger
  as they like; per-case saved layouts.

## 9.2 Core views
1. **Case dashboard** — pipeline DAG (doc 02) with per-stage status, run/skip/re-run, resource usage,
   headline finding counts by state and severity.
2. **Reverse-engineering workspace** — synchronized: disassembly | decompiled+summarized pseudo-C |
   interactive CFG | callgraph | hex/bytes | strings/imports. Click a function anywhere → all panes follow.
   Inline the deterministic name/type suggestions (signatures, corpus-diff, runtime metadata, heuristics)
   with accept/reject + provenance (doc 04).
3. **Findings board** — the heart of the tool. Cards move across lanes **Candidate → Corroborated →
   Confirmed → PoC-backed** (doc 05). Each card: CWE tags, confidence, evidence trail, involved functions,
   and one-click jumps to the RE site / crash / PoC. Filter by CWE/severity/state/vector.
4. **Dynamic-analysis + debugger** — sandbox tier selector, run controls, live trace, register/stack/memory,
   heap visualizer, breakpoints/watchpoints, syscall/API log. (doc 06)
5. **Fuzzing dashboard** — live coverage-over-time, execs/sec, unique-crash feed, corpus stats, per-instance
   status, campaign start/stop/resume; click a crash → triage view. (doc 07)
6. **Triage + PoC studio** — crash detail, minimized input, root-cause slice, exploitability, the PoC ladder
   with a "build/verify PoC" action and the recorded demo player. (doc 08)
7. **Report builder** — assemble findings into a report, preview, export HTML/PDF/SARIF. (doc 08)
8. **Recovery view** — the deterministic naming stack (doc 04): signature/FID matches, corpus-diff name
   transfers (BinDiff), runtime-metadata recovery (Go pclntab / C++ RTTI), and behavioral tags, each with
   provenance and confidence, batch accept/reject. (No AI agent — decision doc 15.)

## 9.3 Visual & interaction design system ("highly stylized, organized, neat")
- **Aesthetic:** dark-first, high-contrast "operator console" — think a refined SOC/RE cockpit. Restrained
  accent palette (one cool base + semantic accents), generous spacing, strong typographic hierarchy.
- **Semantic color = state, everywhere consistent:** severity (info→critical) and finding-state colors are
  defined once as tokens and reused across board, tables, graphs, reports. Color never the *only* signal
  (accessibility): pair with icon/shape/label.
- **Typography:** a crisp UI sans for chrome; a good monospace (ligature-free) for code/hex/disasm.
- **Density modes:** "comfortable" vs "dense" for long RE sessions.
- **Motion:** subtle, purposeful (state transitions on the board, live-metric easing) — never decorative jitter.
- **Consistency primitives:** shared tokens (color/space/radius/elevation), one icon set, one graph style, a
  documented component kit. Light + dark themes from the same tokens.
- **Keyboard-first:** command palette, vim-ish nav in code panes, shortcut for every frequent action.
- Build a small **living style guide** page inside the app so views stay visually coherent as they grow.

## 9.4 As built — the "workbench" (shipped UI)
The shipped interface is a **dependency-free Preact + htm** single page served by the API
(`core/lykos/api/static/`, no build step, ESM vendored under `static/vendor/`) — chosen over the
Tauri/React target for zero-install air-gap delivery. The classic view remains at `/classic.html`.

Centered on **one-click Autopilot**: drop a binary or C/C++ **source** file → Autopilot runs the
full pipeline (recover → detect → fuzz → **coverage loop** → prove → enrich → review) and drives
each crash up the PoC ladder to a demonstrable end effect. "Run in background" survives closing
the tab (server-side `orchestrate.py`); the case is reopenable from **Recent analyses** with its
run log, coverage, findings and verify badges restored.

Finding card, results-first:
- **Headline = the end effect** (§8.6): e.g. *"Remote code execution / control-flow hijack
  (demonstrated): L3 working exploit"*, not "reproduced crash".
- **END EFFECT badges** — each achievable effect as `demonstrated` (green) or `potential` (amber),
  and every demonstrated effect prints its concrete evidence with a **download link to the proof
  artifact** (the L2/L3 PoC bundle, the crashing input, or the captured leaked bytes).
- Exploitability rating, "How it can be exploited" (mechanism → reached → primitive → exploit),
  "What an attacker does next", the false-positive **replay verdict** badge, and "View code".
- Near-duplicate crashes collapse; a control-flow-hijack's attacker-controlled fault PC never
  splits one overflow into many findings (`dedupeFindings`).

Also: rich file/mitigations panel, a **run log** (live + reconstructed on reopen, with per-stage
errors), a **fuzzing-coverage** panel (block coverage = % of recovered code exercised), the
cross-binary **system map**, and a **light/dark theme** toggle (persisted, OS-preference aware) —
both themes from the same CSS tokens.
