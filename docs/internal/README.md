# Internal working notes

Development-process artifacts, kept for reference but not part of the user- or
operator-facing documentation. The reference docs a user needs are in the parent
[`docs/`](../) directory (architecture, CWE detection, data model, the air-gap runbook, …).

What's here:

- **Roadmap & backlog** — `13-roadmap-milestones.md`, `20-open-work-backlog.md`
- **Reviews & plans** — `21-crs-harvest-review.md`, `24-modernization-plan.md`,
  `30-missing-capabilities-implementation-plan.md` (sequenced plan for doc 20's open queue)
- **`42-strategy-expansion-2026-10-19.md`** — the outcome of the strategy tracks past ret2libc:
  NX-off execstack ret2shellcode is done for every buildable arch (riscv64/ppc64le/s390x/ppc32
  added; mips blocked on toolchain), and multi-register syscall-ROP (execve-syscall/mprotect) is
  shown empirically to be gadget-blocked on the RISC arches — a research track, not a bounded task.
- **`41-weaponization-breadth-2026-10-19.md`** — breadth, where 37/38 measured depth: the plan
  to push more ISAs from L1 to a real L3 (an `ArchModel` abstraction + a strategy march across
  architectures, each live-verified under qemu-user), plus the Windows/PE weaponization gap and
  the `Exploit_Dev` (XDS) validation corpus. Sequenced; cross-arch depth leads.
- **`38-technique-program-2026-10-17.md`** — every exploitation technique in one of three
  states: driven end to end, knowledge-base only, or absent. The ordered program for the
  second two, and the two that honestly end in a version-gated refusal.
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
