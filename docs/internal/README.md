# Internal working notes

Development-process notes, not user- or operator-facing. The reference docs a user needs are in the
parent [`docs/`](../) directory (overview, architecture, pipeline, gui, coverage, offline-packaging).

This folder now holds **only the current set**. The dated planning / strategy / audit series that
preceded it (docs 01–46, plus the early `prototype/` and `tasks/` tickets) has been moved to
[`archive/`](archive/) — kept for the decision/rationale record, not as a description of the current
build.

## Current docs

- **[`50-current-state-2026-10-22.md`](50-current-state-2026-10-22.md) — start here.** What lykos
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
