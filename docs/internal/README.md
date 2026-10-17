# Internal working notes

Development-process artifacts, kept for reference but not part of the user- or
operator-facing documentation. The reference docs a user needs are in the parent
[`docs/`](../) directory (architecture, CWE detection, data model, the air-gap runbook, …).

What's here:

- **Roadmap & backlog** — `13-roadmap-milestones.md`, `20-open-work-backlog.md`
- **Reviews & plans** — `21-crs-harvest-review.md`, `24-modernization-plan.md`,
  `30-missing-capabilities-implementation-plan.md` (sequenced plan for doc 20's open queue)
- **`37-weaponization-depth-2026-10-17.md`** — every matrix cell showed the level a case DEMANDS,
  so four mechanism rows read L0/L2 and nobody could say whether that was the engine or the
  fixture. `--ceiling` measures the reach; four rungs raised, three honest ceilings recorded.
- **`36-door-selection-2026-10-17.md`** — in-process fuzzing reaches a library through one
  function at a time, so "did we fuzz it?" is answered by a function NAME. Four real trees, three
  wrong names, and why no instrument could see it: a door that is not a door produces a clean row.
- **Dated audits & handoffs** — `25-`…`29-`, `32-`, `33-`, `34-` (point-in-time code/capability
  audits and session handoffs; they describe the state as of their date, not necessarily the
  current tree).
- **`35-the-chain-2026-10-13.md` — start here.** The canonical process (vulnerability → PoC →
  exploit → effect), the evidence each link must produce, the measured status of each, and the
  four instruments that validate it: the unit suite, `tools/pipeline_conformance.py` (planted
  bugs, end to end), `tools/real_corpus_gate.py` (plumbing health on real material) and
  `tools/corpus_regression.py` (did we still find — and still demonstrate — what we found
  before). `tools/breadth_probe.py` reports work on arbitrary binaries and has no pass mark.
- **`archive/`** — early prototype and phase-0 planning tickets (historical)

These are snapshots of thinking at a moment in time. When they disagree with the code, the code
wins; `./lykos doctor` and the test suite are the source of truth for what the tool actually does.
