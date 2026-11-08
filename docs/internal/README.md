# Internal working notes

Development-process notes, not user- or operator-facing. The reference docs a user needs are in the
parent [`docs/`](../) directory (overview, architecture, pipeline, gui, coverage, offline-packaging).

This folder now holds **only the current set**. The dated planning / strategy / audit series that
preceded it (docs 01–46, plus the early `prototype/` and `tasks/` tickets) has been moved to
[`archive/`](archive/) — kept for the decision/rationale record, not as a description of the current
build.

## Current docs

- **[`63-binary-finding-resolution-2026-11-06.md`](63-binary-finding-resolution-2026-11-06.md) — start here.** Every binary finding driven to a measured verdict (finding_resolve: reached? fires at its site? verdict), the precision bugs it exposed, and the remaining foundation (one address model, an execution-evidence index).
- **[`62-binary-capability-2026-11-04.md`](62-binary-capability-2026-11-04.md)** The
  2026-11-04 audit (review findings + fixes) and the binary-only capability program: the broken
  reach spine, the QASan memory oracle that made silent heap bugs in shipped binaries visible, and
  the prioritized binary build list.
- [`61`](61-advanced-ttp-research-2026-11-03.md) advanced-TTP research (DOP, input-to-state, House
  of Water, race/uninit detectors) · [`60`](60-foundation-first-analysis-engine-2026-11-03.md)
  foundation-first engine (reach + taint + CodeQL wired into stages) ·
  [`59`](59-gui-rebuild-2026-10-30.md) GUI rebuild · [`58`](58-poc-engine-redesign-2026-10-30.md)
  PoC engine redesign (constructed vs detonated PoCs) · [`57`](57-measurement-gap-2026-10-30.md)
  measurement gap · [`56`](56-where-we-stand-2026-10-30.md) where we stand ·
  [`55`](55-phase-audit-2026-10-30.md) phase audit · [`54`](54-tier1-weaponize-2026-10-30.md)
  Tier-1 weaponize · [`53`](53-tools-and-issues-2026-10-30.md) tools and issues ·
  [`52`](52-ground-up-rethink-2026-10-29.md) ground-up rethink (the hypothesis loop).
- **[`51-full-audit-2026-10-24.md`](51-full-audit-2026-10-24.md)** — the 2026-10-24 full audit +
  improvement pass: highest-impact defects fixed (AFL ran ~1 s; large binaries strings-only;
  reports calling unexecuted targets clean), new capabilities, and the prioritized open list.
- **[`50-current-state-2026-10-22.md`](50-current-state-2026-10-22.md)** — What lykos
  actually does today: the L0→L3 capability matrix across architectures, the Windows/PE depth and its
  L2/L3 wall, the large-binary (100 MB+) ceiling, and the honest-degradation posture. Supersedes the
  archived series as the "what is true now" reference.
- **[`49-next-build-vision-2026-10-22.md`](49-next-build-vision-2026-10-22.md)** — the forward plan:
  the code/GUI/report overhaul (make the existing target→…→L3→PoC path a navigable spine) plus the
  Theme 5 capability track (architecture depth, Windows L2→L3, 100 MB+ scale) that targets the gaps in
  doc 50.
- **[`48-codebase-audit-2026-10-22.md`](48-codebase-audit-2026-10-22.md)** — the latest whole-codebase
  audit: the fixes applied and the prioritized follow-ups still open.
- **[`47-timed-engagement-reliability-roadmap-2026-10-21.md`](47-timed-engagement-reliability-roadmap-2026-10-21.md)**
  — the open-items tracker (fuzz robustness, auto-invocation, progress/ETA/health).

## Ground truth

These notes are a point-in-time view. **When they disagree with the code, the code wins** —
`./lykos doctor` and the test suite are the source of truth for what the tool actually does.

## [`archive/`](archive/)

The dated 01–46 series (gap analyses, roadmaps, strategy expansions, weaponization-depth and
large-binary programs, dated audits and handoffs) and the early prototype / phase-0 tickets. Historical:
each describes the state as of its date. Kept so the *why* behind a decision is recoverable; not current.
