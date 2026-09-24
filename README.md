# lykos — air-gapped binary vulnerability analysis platform

> **Authorized use only.** An offensive-security tool, for binaries and systems you are
> authorized to test. Authorization is an operator-process matter and is deliberately not
> modelled in the software (see `docs/15-risks-open-questions.md`).

lykos ingests a binary — stripped, cross-architecture, firmware, JAR, or PE — recovers its
structure, detects CWE-class defects through static, dynamic and symbolic analysis, builds a
fuzzing harness around it, and produces a **reproducible proof-of-concept** for what it
confirms. It runs entirely offline and has no network code paths at all.

```sh
git clone <lykos> && cd lykos
PYTHONPATH=core python3 -m lykos doctor    # what this host can do, and how to fix the gaps
make run                                   # the analyst UI on 127.0.0.1:8787
```

Nothing to install to get that far: the core is **stdlib-only**, no pip packages. The heavy
engines (Ghidra, qemu-user, AFL++, GDB, angr…) are optional and separately bundled — and that
bundle installs nothing either. It extracts to a relocatable tree under `vendor/` that lykos
runs in place: no `dpkg`, no root, and the host's own libraries are never overwritten or put on
any shared search path. See **[docs/23-airgap-install.md](docs/23-airgap-install.md)**.

**New here?** [QUICKSTART.md](QUICKSTART.md) walks you from a fresh install to your first
finding in five minutes.

## What it produces

The **workbench** (`make run`) is a one-click **Autopilot**: drop a binary — or a C/C++ **source
file**, compiled instrumented on the way in — and it runs the whole pipeline and drives each
crash as far up the exploitation ladder as the target allows.

- **Demonstrated end effects, not just "a crash."** Every finding headlines the worst effect it
  can reach — **DoS, memory disclosure, memory corruption, control-flow hijack / RCE, command
  injection** — each marked *demonstrated* (a PoC achieves it) or *potential*, and every
  demonstrated effect ships the **proof artifact**: the crashing input, an **L2 primitive**
  (confirmed instruction-pointer / write-what-where control), an **L3 working exploit** (ret2win /
  ROP hijacking control to chosen code), or the **captured leaked bytes** of a format-string
  disclosure. Nothing is over-claimed — ASan-guarded source stays *potential* for RCE and
  *demonstrated* for DoS. (docs [08](docs/08-triage-poc.md))
- **Coverage that compounds.** When fuzzing stalls at a guarded branch, concolic execution solves
  it and the search **re-fuzzes from the solved inputs**, reaching the code beyond — 44% → 100%
  block coverage on a magic-gated target, automatically. (docs [07](docs/07-harness-fuzzing.md))
- **Every finding earned + reviewed.** `candidate → corroborated → confirmed → poc-backed`, with a
  false-positive **replay verdict** on each demonstrated crash.

## Design philosophy

1. **Orchestrate, don't reinvent.** Ghidra, angr, AFL++, QEMU and GDB already exist. The value
   is the glue: one data model, correlation across tools, automated harnessing, a confidence
   lifecycle, PoC synthesis, and an analyst UI.
2. **Every finding must be earned.** Static analysis over-reports. A finding is promoted to
   *confirmed* only when dynamic or symbolic evidence reproduces it — `candidate →
   corroborated → confirmed → poc-backed`.
3. **Assume the binary is hostile.** Dynamic analysis runs untrusted code; isolation is the
   backbone of the dynamic subsystem, not a wrapper around it.
4. **Absence of evidence is not evidence of absence.** A stage that could not run says so, in
   its own words, and never as a clean result. This is the single most load-bearing rule in
   the codebase and most of its hard-won bug fixes are instances of it.
5. **Air-gap is a constraint, not a feature.** No component may assume network access.

## Commands

```sh
make doctor            # capability report for this host
make test              # the full suite
make lint typecheck    # ruff; mypy (strict over the infra core — see mypy.ini)
make gui               # headless GUI harnesses (needs node)
make ci                # lint + typecheck + gui + test
make coverage          # line/branch coverage INCLUDING the subprocess-only engines
make run               # serve the API + UI on 127.0.0.1:8787 (case store in .cases/)
make bundle            # build the standalone dist/lykos.pyz zipapp
make verify            # build it, then prove it serves the UI and triages offline
make eval-gate         # detection-quality gate over the bundled corpus
make arch-gate         # every architecture still reaches its PoC level
make real-gate         # full chain on real programs (detect -> PoC -> attribution)
make release           # ci + verify + all four gates
make toolchain-bundle  # build the air-gap toolchain tarball (on a CONNECTED machine)
make repo-tarball      # snapshot the repo for sneakernet (tracked files at HEAD, + sha256)
make runnable          # ONE unzip-and-run .zip: repo + fully-populated vendor/ (no install)
make container         # self-contained OCI image + air-gap tarball (most portable; needs podman/docker)
make dashboard         # detection-quality regression dashboard from eval-history.jsonl
make clean             # remove build artifacts and caches
```

`make lint` and `make typecheck` **fail** when their tool is missing rather than skipping, so
`make ci` cannot go green without having actually run them.

## Where things are

```
core/lykos/        the platform (stdlib only)
  analyze/         the 29 analysis stages, grouped by what they do
  api/             HTTP + WebSocket server and the single-page UI
  db/              schema, migrations, DAOs
  eval/            benchmark corpora and the quality gates
  jobs/            the job queue and worker pool
  toolchain.py     one inventory of every external tool  <- `lykos doctor` reads this
tests/             the suite (~1290), incl. js/ harnesses for the UI
docs/              design docs 00-25; archive/ is historical, not maintained
examples/          runnable demos and fixture builders
packaging/         zipapp build, offline verify, air-gap bundle scripts
```

## Documents

| # | Doc | What it covers |
|---|-----|----------------|
| 00 | `docs/00-overview-goals.md` | Vision, users, non-goals, capability tiers |
| 01 | `docs/01-gap-analysis.md` | Gaps in the original plan and what had to be added |
| 02 | `docs/02-architecture.md` | Layers, pipeline/job engine, module boundaries |
| 03 | `docs/03-static-analysis.md` | Loading, disasm, decompile, CFG/callgraph, types |
| 04 | `docs/04-stripped-binary-recovery.md` | Function ID, signatures, custom ISAs |
| 05 | `docs/05-cwe-detection.md` | CWE taxonomy engine, per-class strategies |
| 06 | `docs/06-dynamic-analysis-sandbox.md` | Isolation, emulation, tracing, coverage, debugging |
| 07 | `docs/07-harness-fuzzing.md` | Input-vector discovery, harness synthesis, fuzzing |
| 08 | `docs/08-triage-poc.md` | Crash dedup, exploitability, root cause, PoC synthesis |
| 09 | `docs/09-gui-design.md` | GUI architecture, views, design system |
| 10 | `docs/10-tech-stack.md` | Technology choices, rationale, licensing |
| 11 | `docs/11-airgap-packaging.md` | Air-gap *design position* (procedure is doc 23) |
| 12 | `docs/12-data-model.md` | Case model, DB schema, artifact store |
| 13 | `docs/13-roadmap-milestones.md` | Phased delivery with exit criteria |
| 14 | `docs/14-validation-benchmarks.md` | How detection quality is measured |
| 15 | `docs/15-risks-open-questions.md` | Risks, legal/ethical gating, open decisions |
| 16 | `docs/16-sota-references.md` | State-of-the-art survey incl. DARPA AIxCC |
| 17 | `docs/17-multibinary-firmware.md` | Multi-binary analysis + firmware rehosting |
| 18 | `docs/18-architecture-coverage.md` | All-architecture coverage matrix and tiers |
| 19 | `docs/19-cwe-coverage.md` | All-CWE coverage matrix by family and channel |
| 20 | `docs/20-open-work-backlog.md` | **What is done, what is not, and what was measured** |
| 21 | `docs/21-crs-harvest-review.md` | CRS harvest-review memo template |
| 22 | `docs/22-toolchain-setup.md` | What each engine is and how it was provisioned |
| 23 | `docs/23-airgap-install.md` | **Air-gap setup runbook (no install)** — bundle, carry, verify, run in place |
| 24 | `docs/24-modernization-plan.md` | **2026 SOTA refresh** — source path, lean RE stack (drop the JVM), exploit-path automation, optional LLM |
| 25 | `docs/25-security-audit-2026-09.md` | **Code audit & review** — ranked robustness/correctness findings, remediation status, follow-ups |

New here? `docs/20-open-work-backlog.md` is the honest state of the system: what works, what
was measured, and what is still open. `docs/02-architecture.md` for the shape of it.

## What the detection gate measures

`make eval-gate` scores a micro-corpus through the real pipeline. It carries two kinds of
negative, and only the second can fail:

* **absence negatives** — the safe variant omits the dangerous API entirely.
* **discrimination negatives** — the safe variant *calls* the sink correctly (`strcpy` behind
  a `strlen() < sizeof` guard, clamped `memcpy`, literal-format `printf`, constant-command
  `system`). These are what make `fp_rate` a measurement rather than a constant.

Measured on x86-64 with Ghidra, 20 cases over 4 CWE classes:

| stage | recall | fp_rate |
|---|---|---|
| `--min-state candidate` (rule channel) | 1.00 | 0.571 |
| `--min-state corroborated` (data-flow channel) | 1.00 | 0.214 |

That gap is the confidence lifecycle earning its keep: the rule channel flags every safe use
too — honest behaviour for a pattern rule — and the taint channel discards most of them. The
CWE-120 false positives that remain are path-insensitivity: attacker bytes really do reach the
`strcpy`, and the guard that makes it safe is a value-range fact the taint model does not
carry. Promotion to *confirmed* still requires dynamic evidence.

All gates are ratchets at their measured values and fail in **either** direction. The corpus
is a regression tripwire, not a benchmark — use `lykos eval --juliet` / `--lava` for real
measurement.

## Driving it over HTTP

```sh
PYTHONPATH=core python3 -m lykos serve --http 127.0.0.1:8787 --case-store .cases --workers 2
curl -s -X POST http://127.0.0.1:8787/cases -d '{"name":"demo"}'            # -> {"id": ...}
curl -s -X POST http://127.0.0.1:8787/cases/<CASE_ID>/targets \
     -H 'X-Filename: ls' --data-binary @/bin/ls                            # ingest + triage
curl -s http://127.0.0.1:8787/runs/<RUN_ID>                                # poll
```

The packaged zipapp runs identically:
`python3 dist/lykos.pyz serve --http 127.0.0.1:8787 --case-store .cases`.
