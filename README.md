# lykos — air-gapped binary vulnerability analysis platform

> **Authorized use only.** An offensive-security tool, for binaries and systems you are
> authorized to test. Authorization is an operator-process matter and is deliberately not
> modelled in the software (see `docs/overview.md`).

lykos ingests a binary — stripped, cross-architecture, firmware, JAR, or PE — recovers its
structure, detects CWE-class defects through static, dynamic and symbolic analysis, builds a
fuzzing harness around it, and produces a **reproducible proof-of-concept** for what it
confirms. It runs entirely offline and has no network code paths at all.

```sh
git clone https://github.com/dloucks01/lykos && cd lykos
./start                                    # the analyst UI on http://127.0.0.1:8787
./lykos doctor                             # what this host can do, and how to fix the gaps
```

Nothing to install to get that far: the core is **stdlib-only**, no pip packages. The heavy
engines (Ghidra, qemu-user, AFL++, GDB, angr…) are optional and separately bundled — and that
bundle installs nothing either. It extracts to a relocatable tree under `vendor/` that lykos
runs in place: no `dpkg`, no root, and the host's own libraries are never overwritten or put on
any shared search path. See **[docs/air-gap.md](docs/air-gap.md)**.

**New here?** [QUICKSTART.md](QUICKSTART.md) walks you from a fresh install to your first
finding in five minutes.

## What it produces

The **workbench** (`./start`) is a one-click **Autopilot**: drop a binary — or a C/C++ **source
tree** (a single file, or a multi-file **project** with a Makefile / CMake / autotools, or a
**library** with no `main`), compiled instrumented on the way in — and it runs the whole pipeline
and drives each crash as far up the exploitation ladder as the target allows.

- **Demonstrated end effects, not just "a crash."** Every finding headlines the worst effect it
  can reach — **DoS, memory disclosure, memory corruption, control-flow hijack / RCE, command
  injection** — each marked *demonstrated* (a PoC achieves it) or *potential*, and every
  demonstrated effect ships the **proof artifact**: the crashing input, an **L2 primitive**
  (confirmed instruction-pointer / write-what-where control), an **L3 working exploit** (ret2win /
  ROP hijacking control to chosen code), or the **captured leaked bytes** of a format-string
  disclosure. Nothing is over-claimed — ASan-guarded source stays *potential* for RCE and
  *demonstrated* for DoS. (docs [08](docs/pipeline.md))
- **Coverage that compounds.** When fuzzing stalls at a guarded branch, concolic execution solves
  it and the search **re-fuzzes from the solved inputs**, reaching the code beyond — 44% → 100%
  block coverage on a magic-gated target, automatically. (docs [07](docs/pipeline.md))
- **Every finding earned + reviewed.** `candidate → corroborated → confirmed → poc-backed`, with a
  false-positive **replay verdict** on each demonstrated crash.
- **Source-first when source is available.** A source project builds ASan+UBSan-instrumented (a
  compiler wrapper forces the flags through the project's own build), so a fuzzing crash is a
  *confirmed* finding with the exact **source file:line** and CWE from the sanitizer — no CTF
  oracle needed. **libFuzzer** drives coverage-guided fuzzing with an **auto-synthesized harness**
  (an in-tree `LLVMFuzzerTestOneInput`, or one generated for a library's entry function, C or C++).
  (docs [07](docs/pipeline.md))
- **Language-aware.** Triage identifies the source language — **C, C++, Go, Rust** — and analysis
  follows: the memory-safety engine for C/C++, and for the memory-safe languages a call-graph
  **injection / traversal / SSRF** channel (Go `os/exec`/`os.Open`/`database/sql`/`net/http`, Rust
  `std::process`/`std::fs`), corroborated when untrusted input reaches the sink. (docs
  [05](docs/pipeline.md))
- **A broad L3 ladder.** ret2win, ret2system/ROP, SROP, execve-syscall, ret2libc (puts-leak, PIE
  pure-libc, one-gadget fallback), stack-canary leak→ret2libc, **magic-value overwrite**,
  **format-string `%n` write**, **glibc-heap → shell** (tcache poison + House of Apple 2), mprotect
  shellcode, and **shellcode injection** with a **bad-char XOR encoder** for filtered input — every
  L3 confirmed by a live shell / marker / breakpoint, never asserted. (docs [08](docs/pipeline.md))

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
./start                # serve the API + UI on 127.0.0.1:8787 (case store in .cases/)
make bundle            # build the standalone dist/lykos.pyz zipapp
make verify            # build it, then prove it serves the UI and triages offline
make eval-gate         # detection-quality gate over the bundled corpus
make arch-gate         # every architecture still reaches its PoC level
make real-gate         # full chain on real programs (detect -> PoC -> attribution)
make release           # ci + verify + all four gates
make toolchain-bundle  # build the air-gap toolchain tarball (on a CONNECTED machine)
make repo-tarball      # snapshot the repo for sneakernet (tracked files at HEAD, + sha256)
./package              # ONE unzip-and-run .zip: repo + fully-populated vendor/ (no install)
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

| Doc | What it covers |
|-----|----------------|
| [`docs/overview.md`](docs/overview.md) | Vision, users, non-goals, capability tiers; risks, constraints, open decisions |
| [`docs/architecture.md`](docs/architecture.md) | Layers, pipeline/job engine, module boundaries; tech stack & licensing; data model & reproducibility |
| [`docs/pipeline.md`](docs/pipeline.md) | The analysis engine end to end: static/RE → stripped recovery → CWE detection → dynamic & sandbox → fuzzing → triage & PoC → multi-binary/firmware |
| [`docs/coverage.md`](docs/coverage.md) | Architecture coverage matrix, CWE coverage matrix, and how detection quality is measured |
| [`docs/air-gap.md`](docs/air-gap.md) | Packaging design, per-host toolchain setup, and the no-install air-gap runbook |
| [`docs/gui.md`](docs/gui.md) | The workbench UI: architecture, views, design system |

New here? [QUICKSTART.md](QUICKSTART.md) is the five-minute path to your first finding;
[`docs/architecture.md`](docs/architecture.md) is the shape of the system. (Working notes,
audits and the backlog live under `docs/internal/`.)

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
./lykos serve --http 127.0.0.1:8787 --case-store .cases --workers 2
curl -s -X POST http://127.0.0.1:8787/cases -d '{"name":"demo"}'            # -> {"id": ...}
curl -s -X POST http://127.0.0.1:8787/cases/<CASE_ID>/targets \
     -H 'X-Filename: ls' --data-binary @/bin/ls                            # ingest + triage
curl -s http://127.0.0.1:8787/runs/<RUN_ID>                                # poll
```

The packaged zipapp runs identically:
`python3 dist/lykos.pyz serve --http 127.0.0.1:8787 --case-store .cases`.
