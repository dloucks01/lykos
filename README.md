# Project: BinAnalysis — Air-Gapped Binary Vulnerability Analysis Platform

> **Authorized use only.** Offensive-security tool for use exclusively on binaries and systems you are
> authorized to test. Authorization is an operator-process matter and is intentionally not modeled in the
> software (see `docs/15-risks-open-questions.md`).

BinAnalysis is a standalone, fully offline (air-gapped) Linux workstation application that ingests a
binary — including stripped and custom-format binaries — reverse engineers it, detects CWE-class
vulnerabilities through combined static + dynamic + symbolic analysis, builds a fuzzing/debug harness
and sandboxed execution environment around it, and produces reproducible, demonstrable Proof-of-Concept
artifacts for confirmed findings. It ships with a highly styled analyst GUI.

## Design philosophy (read this first)

1. **Orchestrate, don't reinvent.** The world already has Ghidra, angr, AFL++, QEMU, GDB, rizin, etc.
   Our value is the *glue*: a unified data model, correlation across tools, automated harnessing,
   confidence scoring, PoC synthesis, and a first-class analyst UI. We do **not** rewrite a decompiler.
2. **Every finding must be earned.** Static analysis over-reports. A "finding" is only promoted to
   *Confirmed* when dynamic or symbolic evidence reproduces it. We track a confidence lifecycle, not a
   flat list of warnings.
3. **Assume the binary is hostile.** Dynamic analysis runs untrusted, possibly malicious code.
   Isolation is not optional — it is the backbone of the dynamic subsystem.
4. **Air-gap is a first-class constraint, not an afterthought.** No component may assume network access.
   Everything (toolchains, signatures, models, CVE/libc DBs) is bundled and updated via signed
   sneakernet packages.

## Document index

| # | Doc | What it covers |
|---|-----|----------------|
| 00 | `docs/00-overview-goals.md` | Vision, users, non-goals, capability tiers, honest feasibility |
| 01 | `docs/01-gap-analysis.md` | **Gaps in the current plan** + everything that must be added |
| 02 | `docs/02-architecture.md` | Layered architecture, pipeline/job engine, module boundaries |
| 03 | `docs/03-static-analysis.md` | Loading, disasm, decompile, CFG/callgraph, type recovery |
| 04 | `docs/04-stripped-binary-recovery.md` | Function ID, signatures, ML embeddings, custom ISAs |
| 05 | `docs/05-cwe-detection.md` | CWE taxonomy engine, per-class detection strategies |
| 06 | `docs/06-dynamic-analysis-sandbox.md` | Isolation, emulation, tracing, coverage, debugging |
| 07 | `docs/07-harness-fuzzing.md` | Input-vector discovery, harness synthesis, fuzzing orchestration |
| 08 | `docs/08-triage-poc.md` | Crash dedup, exploitability, root cause, PoC synthesis |
| 09 | `docs/09-gui-design.md` | GUI architecture, views, visual/interaction design system |
| 10 | `docs/10-tech-stack.md` | Concrete technology choices + rationale + licensing |
| 11 | `docs/11-airgap-packaging.md` | Offline packaging, bundled deps, signed update channel |
| 12 | `docs/12-data-model.md` | Case/project model, DB schema, artifact store, notes |
| 13 | `docs/13-roadmap-milestones.md` | Phased delivery (MVP → v1 → v2) with exit criteria |
| 14 | `docs/14-validation-benchmarks.md` | How we measure detection quality (Juliet, LAVA-M, CGC…) |
| 15 | `docs/15-risks-open-questions.md` | Risks, legal/ethical gating, decisions you must make |
| 16 | `docs/16-sota-references.md` | State-of-the-art survey (2022-2026) incl. DARPA AIxCC / CRS |
| 17 | `docs/17-multibinary-firmware.md` | Multi-binary/inter-component analysis + firmware rehosting |
| 18 | `docs/18-architecture-coverage.md` | **All-architecture** coverage matrix, tiers, per-arch backends |
| 19 | `docs/19-cwe-coverage.md` | **All-CWE** coverage matrix by family + channel + feasibility |
| 21 | `docs/21-crs-harvest-review.md` | CRS harvest-review memo *template* (Phase 0 P0.8 deliverable) |
| 22 | `docs/22-toolchain-setup.md` | Optional toolchain setup + status (Ghidra/AFL++/angr/GDB/SymQEMU) |

## Start here
1. Read `docs/01-gap-analysis.md` — it reframes the scope and is the most important document.
2. Answer the open questions in `docs/15-risks-open-questions.md` (they change the architecture).
3. Then `docs/13-roadmap-milestones.md` for the build order, and `tasks/phase-0-foundations.md` for the
   concrete first-milestone task breakdown.

## Running it

The core is stdlib-only and runs offline. Requires Python 3.11+. Optional heavy backends
(angr/Unicorn/SymQEMU) live in vendored venvs under `vendor/` and are auto-detected when present;
everything runs without them.

```sh
make test        # run the full test suite (PYTHONPATH=core pytest)
make lint        # ruff check over core + tests
make typecheck   # mypy: strict over the infra core, off for the stage layers (see mypy.ini)
make ci          # lint + typecheck + test
make run         # serve the API + UI on 127.0.0.1:8787 (case store in .cases/)
make bundle      # build the standalone dist/lykos.pyz zipapp
make verify      # build the zipapp, then prove it serves the UI + triages a binary offline
make eval-gate   # detection-quality gate over the bundled corpus (see below)
```

`make lint` and `make typecheck` FAIL when their tool is missing rather than skipping, so
`make ci` cannot go green without having actually run them. CI (`.github/workflows/ci.yml`)
runs the same targets on 3.11 and 3.13 and prints every test skip, so gaps stay visible.

### What the detection gate measures

`make eval-gate` scores the bundled micro-corpus (`core/lykos/eval/corpus.py`) through the
real pipeline. The corpus carries two kinds of negative, and only the second kind can fail:

* **absence negatives** — the safe variant omits the dangerous API entirely.
* **discrimination negatives** — the safe variant *calls* the sink correctly (strcpy behind
  a `strlen() < sizeof` guard, clamped memcpy, literal-format printf, constant-command
  `system`). These are what make `fp_rate` a measurement instead of a constant.

Current measured numbers (x86-64, Ghidra 12.1): at `--min-state candidate`, recall **1.00**,
fp_rate **0.57** — a rule-only channel flags the safe uses too, which is honest behaviour for
a pattern rule. At `--min-state corroborated`, recall is **0.00**: the taint channel seeds
only from `SOURCES` library calls (`read`/`fgets`/`getenv`/…) and does not model `argv`, so
argv-driven programs never promote past `candidate`. The corroborated line is recorded but
not gated until that gap is closed. The corpus is 20 cases over 4 CWE classes — a regression
tripwire, not a benchmark; use `lykos eval --juliet` / `--lava` for real measurement.

Run the server directly and drive it over HTTP:

```sh
PYTHONPATH=core python3 -m lykos serve --http 127.0.0.1:8787 --case-store .cases --workers 2
# then, from another shell:
curl -s -X POST http://127.0.0.1:8787/cases -d '{"name":"demo"}'                       # -> {"id": ...}
curl -s -X POST http://127.0.0.1:8787/cases/<CASE_ID>/targets \
     -H 'X-Filename: ls' --data-binary @/bin/ls                                        # ingest + triage
curl -s http://127.0.0.1:8787/runs/<RUN_ID>                                            # poll run status
```

Open `http://127.0.0.1:8787/` in a browser for the analyst UI. The packaged zipapp runs the same way:
`python3 dist/lykos.pyz serve --http 127.0.0.1:8787 --case-store .cases`.
