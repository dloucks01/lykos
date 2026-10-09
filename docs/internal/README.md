# Internal working notes

Development-process artifacts, kept for reference but not part of the user- or
operator-facing documentation. The reference docs a user needs are in the parent
[`docs/`](../) directory (architecture, CWE detection, data model, the air-gap runbook, …).

What's here:

- **Roadmap & backlog** — `13-roadmap-milestones.md`, `20-open-work-backlog.md`
- **Reviews & plans** — `21-crs-harvest-review.md`, `24-modernization-plan.md`,
  `30-missing-capabilities-implementation-plan.md` (sequenced plan for doc 20's open queue)
- **Dated audits & handoffs** — `25-`…`29-`, `32-` (point-in-time code/capability audits and
  session handoffs; they describe the state as of their date, not necessarily the current tree).
  The newest, `32-next-steps-2026-10-09.md`, is the current forward queue and explains how to
  measure breadth (`tools/breadth_probe.py`) versus conformance
  (`tools/pipeline_conformance.py`) — they answer different questions.
- **`archive/`** — early prototype and phase-0 planning tickets (historical)

These are snapshots of thinking at a moment in time. When they disagree with the code, the code
wins; `./lykos doctor` and the test suite are the source of truth for what the tool actually does.
