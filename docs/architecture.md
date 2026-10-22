# Architecture

---

## Architecture

### Layered model
```
+-------------------------------------------------------------------------+
|  Browser workbench (Preact + htm, no build step)      `gui.md`            |
|  results-first Autopilot view · findings board · fuzzing/coverage panels  |
|  · disasm/strings/call-graph · PoC bundles · reports                      |
+------------ local API (stdlib HTTP + WebSocket, loopback only) ----------+
|  Orchestration / pipeline engine        (`analyze/orchestrate.py`)        |
|  stage DAG · job queue · scheduler · concurrency governor · run cache ·   |
|  per-case budget (`analyze/budget.py`) · event stream                     |
+-------------------------------------------------------------------------+
|  Analysis stages (workers)                                                |
|   ingest/triage | static RE / disasm | stripped recovery (FLIRT-style)    |
|   CWE detection | dynamic/sandbox | harness + fuzz                         |
|   symbolic/concolic | triage + PoC ladder | reporting                     |
+-------------------------------------------------------------------------+
|  Core: case DB + content-addressed artifact store · plugin API ·          |
|  config · logging + absorbed-error counter                                |
+-------------------------------------------------------------------------+
|  Optional vendored engines (extracted under vendor/, run in place):       |
|  rizin + pypcode (SLEIGH), Ghidra (optional), angr, SymQEMU, AFL++ /       |
|  libFuzzer, qemu-user, GDB, Unicorn, libqasan; bundled sig/CVE/CWE packs   |
+-------------------------------------------------------------------------+
```

### Process model
- **Backend core** = a long-lived local service — a Python **stdlib** `ThreadingHTTPServer` over a Unix
  domain socket (or loopback TCP), with a hand-rolled WebSocket for events. No FastAPI/uvicorn, no pip
  packages. Owns the data model, job queue, and event stream. No external network binding — ever.
- **Workers** = a thread pool with per-resource-class concurrency caps and a coarse memory guard
  (`jobs/worker.py`). Heavy/native tools (Ghidra headless, fuzzers, qemu) run as managed **subprocesses**
  (killed as a process group on timeout), so a crashing engine or a detonating target can't take down the
  server. (Full process-level worker isolation is deferred until more native tools land.)
- **Frontend** = the browser workbench — Preact + htm as ES modules loaded via an **import map from the
  bundled `vendor/`** (no build step, no npm, no CDN) — served as static files by the local API and talking
  to it over HTTP + a WebSocket for live events (fuzzing stats, log tails, job progress). See `gui.md`.
- **Isolation domains** = dynamic-analysis targets run under **bubblewrap + a network namespace** (or an
  rlimit fallback), and cross-arch targets under **qemu-user**, never in a worker's own address space
  (except deliberate Unicorn in-process emulation of a *single function*, which cannot execute host
  syscalls). Stronger microVM / full-system tiers are a design target, not yet shipped. See `pipeline.md`.

### Pipeline / job engine
- A **DAG of stages** per case: `load → disasm → decompile → recover(strip) → static-cwe → dynamic-triage
  → harness → fuzz → crash-triage → symbolic-confirm → poc → report`. Stages are individually
  runnable/re-runnable; the UI shows the graph and lets the analyst run/skip/re-run any node.
- The stage set has grown to **~40** stages. Recent additions: `source_cve_scan` (CVE matching over a
  source project's dependency manifests + vendored headers), `embedded_audit` (RTOS config review, e.g.
  `FreeRTOSConfig.h`), `int_overflow_scan` (CWE-190 integer-overflow-into-allocation, guard-aware),
  `net_fuzz` (TCP/UDP socket fuzzing of network servers), `cve_corroborate` (link a matched CVE to a
  demonstrated crash), and `cve_poc` (weaponize a matched CVE with a trigger that confirms a repro only on
  a real fault).
- **Job queue** backed by SQLite (offline-friendly, no broker). Each job: inputs (content-hashed),
  tool version, params, status, artifacts out. Idempotent + **result-cached by (stage, input-hash,
  params, tool-version)** so re-opening a case is instant and re-runs are cheap.
- **Scheduler + resource governor:** concurrency caps per resource class (CPU-heavy decompile vs
  IO-heavy fuzz vs VM slots). Prevents a single box from thrashing when Ghidra + 8 fuzzers + a VM all run.
- **Event bus:** workers publish progress/log/metric events; UI subscribes. Also drives the audit log.
- **Cancellation + resume:** long fuzzing/symbolic campaigns checkpoint; case reopen resumes them.

### Module boundaries (each is independently testable + swappable)
| Module | Input | Output | Backed by |
|---|---|---|---|
| Loader | file bytes | memory map, arch, entry, sections | stdlib parsers (`elf.py`/`pe.py`/`macho.py`), rizin/Ghidra |
| Disassembler | mapped image | instructions, basic blocks | rizin + pypcode (default), Ghidra (optional) |
| Decompiler | function | pseudo-C + types | rizin + rz-ghidra / pypcode P-Code |
| Recovery | stripped image | named funcs, lib IDs | sig DBs (FLIRT-style) + corpus diff (`pipeline.md`) |
| CWE detectors | IR + decomp + traces | candidate findings | rules/taint/symbolic |
| Sandbox runner | binary + input + policy | trace, coverage, crash | bubblewrap + qemu-user |
| Harness builder | vector spec | runnable harness | templates + codegen |
| Fuzzer | harness + corpus | crashes, coverage | AFL++ / libFuzzer |
| Symbolic | image + target state | solved input / constraints | angr / SymQEMU |
| Triage | crash | dedup key, exploitability | in-house (stdlib) + GDB |
| PoC synth | confirmed finding | PoC bundle | templates + symbolic |
| Reporter | findings | HTML/PDF/SARIF | templating |

### Plugin API (build it early — cheap later is expensive)
A stable Python plugin interface with typed hooks:
- `register_loader(match, load_fn)` — custom/"your" binary formats.
- `register_detector(cwe_ids, analyze_fn)` — custom CWE rules over the shared IR.
- `register_harness_template(...)`, `register_report_section(...)`.
- Detectors receive a normalized **Program IR** (see `pipeline.md`) so a rule works across architectures.

### Normalized data flow
Everything writes into one case DB + artifact store. Cross-tool correlation (e.g., a static
candidate at address X ↔ a fuzzing crash whose faulting IP is X) is done in the core, not in any tool.
This correlation is what lets a noisy candidate get promoted to Confirmed.

---

## Data Model, Persistence & Reproducibility

### Case-centric model
Everything lives under a **Case** (one engagement/target set). A case is self-contained and portable
(export/import as a directory or archive) so it can move between offline hosts.

```
Case
 ├─ Binaries (Target)        one or more analyzed files
 ├─ ComponentGraph inter-binary edges: link/dlopen/IPC/RPC/exec (`pipeline.md`)
 ├─ AnalysisRuns (jobs)      pipeline stage executions
 ├─ Functions / IR recovered program model (`pipeline.md`, `pipeline.md`)
 ├─ Findings with state lifecycle + evidence (`pipeline.md`)
 ├─ Harnesses generated/edited (`pipeline.md`)
 ├─ FuzzCampaigns + Crashes metrics, corpus refs, crash records (`pipeline.md`, `pipeline.md`)
 ├─ PoCBundles inputs, runner, recording, verification (`pipeline.md`)
 ├─ Reports HTML/PDF/SARIF exports (`pipeline.md`)
 └─ Provenance tool/model/pack versions, input hashes
```

### Storage
- **SQLite** for all structured data (cases, targets, functions, findings, jobs, crashes, poc metadata).
  One file per case; each worker thread opens its own connection. No external DB engine.
- **Function similarity** is deterministic structural/graph hashing (`pipeline.md`) — no vector index / embedding DB.
- **Content-addressed artifact store:** every artifact (binary, corpus, crash input, trace, analysis output,
  recording) stored by hash; DB rows reference hashes. Dedup + integrity for free.

### Key entities (illustrative fields)
- **Target (Component):** hashes (md5/sha256/sha1), arch, format, size, mitigations, libc-id, entropy, imports/exports.
- **ComponentEdge:** src→dst component, type (link/dlopen/ipc/rpc/file/exec), channel contract, evidence refs (`pipeline.md`).
- **Finding** may be **cross-component:** source_site in one component, sink_site in another.
- **Finding:** id, cwe_ids[], state (Candidate/Corroborated/Confirmed/PoC-backed), confidence, severity/CVSS,
  function, address/site, tainted_vector, evidence[] (channel + artifact refs), analyst_notes, dedup_key.
- **AnalysisRun (job):** stage, inputs[] (by hash), params, tool+version, status, started/ended, outputs[],
  cache_key = hash(stage, input-hashes, params, tool-version) → **result caching** + resumability.
- **Crash:** signal, faulting_ip, backtrace_hash (dedup), sanitizer_verdict, exploitability, minimized_input ref.
- **PoCBundle:** level (L0–L3), input refs, harness ref, env spec, runner script, expected_observable,
  recording ref, verified_bool + verification_run ref, isolation_tier.

### Reproducibility (not "chain of custody" — engineering reproducibility)
- Hash every input and artifact; pin every tool/model/pack **version** into each run and report.
- A finding records exactly *how* it was produced so re-running yields the same result — critical when
  bundles are stale (`offline-packaging.md`) and when a colleague on another offline host must reproduce a PoC.
- Deterministic seeds where engines allow; record RNG seeds for fuzz/symbolic runs.

### Logging & audit
- Structured event log (job lifecycle, analysis runs, sandbox detonations, PoC verifications). Local only.
- Deterministic pipeline → every result is reproducible from its recorded inputs/params/tool-versions.

---

## Technology Stack & Licensing

Bias: **orchestrate proven, deterministic OSS** behind a lean custom core we own (decision `overview.md`).
The engines are CPU-only, with no GPU dependency. Prefer permissive licenses (offline redistribution). "Primary"
= default; "alt" = swappable behind the module interface.

> **Shipped vs. planned.** The engines lykos drives **today** are rizin + pypcode, Ghidra (optional),
> angr, SymQEMU, AFL++ / libFuzzer, qemu-user, GDB, Unicorn, libqasan and bubblewrap, plus in-house
> stdlib parsers, triage and gadget/ROP finders. Rows below that name **Qiling, microVM isolation
> (Firecracker/cloud-hypervisor), LibAFL, Nyx, Triton, honggfuzz, CASR, RetroWrite/MTSan, BinDiff,
> Semgrep** are design targets behind the module interface, **not yet bundled**.

### Deployment target (decision `overview.md`)
- **Kali VM**, ~32 GB RAM, 4+ cores, **nested virtualization available** (KVM inside the VM works, verify per
  host). So KVM-backed microVMs and accelerated system emulation are viable, not just TCG.
- **No GPU.** Modest core count → a few parallel fuzz instances, not a farm; size the resource governor accordingly.
- **Fully self-contained package:** everything needed to run ships in the installer (`offline-packaging.md`).

### Languages
- **Backend/orchestration:** Python 3.12, **standard library only — no pip packages in the core.** The
  heavy engines (Ghidra, rizin, angr, AFL++, qemu, GDB) are optional, separately bundled, and driven as
  **subprocesses** from `vendor/`; the one optional in-process extension is **pypcode** (Ghidra's SLEIGH
  lifter, no JVM), imported defensively in a separate worker process.
- **Fuzzing substrate:** **AFL++** for binary targets; **libFuzzer** (via a clang wrapper) for source targets.
- **Frontend:** **Preact + htm** as ES modules (import map, no build step, no npm/CDN), served as static
  files by the local API. Not a desktop shell.

### Core engines (module → tool → license)
| Role | Primary | Alt | License notes |
|---|---|---|---|
| Loader/parser | **hand-rolled stdlib** (`elf.py`/`pe.py`/`macho.py`) | Ghidra / rizin loaders | n/a (own code) |
| Disassembly/decompile | **rizin + rz-ghidra + pypcode** (Ghidra P-Code, no JVM) | Ghidra headless (optional alternate, `LYKOS_DECOMPILER=ghidra`), angr | permissive / LGPL |
| Quick disasm/lift | pypcode / rizin linear sweep | — | permissive |
| Signature matching | Ghidra FID · FLIRT-style · rizin zignatures | — | permissive |
| Binary diffing / name transfer | **BinDiff** | Diaphora, Ghidra Version Tracking | free/GPL — separate process |
| Runtime-metadata recovery | Go pclntab / C++ RTTI / DWARF parsers (stdlib) | — | n/a (own code) |
| CPU / single-function emulation | Unicorn | — | GPLv2 (separate process) |
| Foreign-arch userland emulation | qemu-user | — | GPLv2 (separate process) |
| MicroVM isolation | *(planned)* Firecracker / cloud-hypervisor | gVisor | Apache-2.0 |
| Process sandbox | bubblewrap (+ netns) | rlimit fallback | permissive |
| Symbolic/concolic | angr · SymQEMU | *(planned)* Triton | BSD / permissive |
| Fuzzing | AFL++ · libFuzzer | *(planned)* LibAFL, honggfuzz | Apache / check AFL++ deps |
| Snapshot fuzzing | *(planned)* Nyx | — | verify license before bundling |
| Binary sanitizer | libqasan (QASan) | *(planned)* RetroWrite, MTSan | permissive/research — verify |
| Debugger | GDB (+Python) | LLDB | GPLv3 (separate process) |
| Crash triage | **in-house (stdlib)** dedup + classify | GDB | n/a (own code) |
| Gadgets/exploit | **in-house (stdlib)** gadget/ROP finder (`poc/rop.py`) | — | n/a (own code) |
| Rule pattern-match (secondary) | Weggli over decompiled C | Ghidra P-Code scripts | permissive |
| Vector/similarity | structural/graph + function hashing (stdlib) | — | (deterministic) |
| Data store | SQLite | — | public-domain |

> **Licensing action item:** GPL tools (QEMU, Unicorn, Qiling, GDB, BinDiff) are fine as **separate bundled
> processes**; avoid static linking that would impose copyleft on our code. Dropping ML model weights removes
> the thorniest redistribution risk from the earlier plan.

### Deterministic core (decision `overview.md`)
- The shipped package is **deterministic and CPU-only**: all naming is deterministic (`pipeline.md`); all
  detection is rules + taint + symbolic + dynamic (`pipeline.md`), so every result is reproducible from its
  recorded inputs. A plugin hook is left in the API for an operator who later wants to wire in a local model
  for naming/summary *suggestions*; nothing depends on it and it is not bundled.

### Data & platform
- **DB:** SQLite only (cases, findings, jobs, provenance) — one file per case, no external DB engine.
- **Artifact store:** content-addressed files on disk (hash-named), referenced from SQLite.
- **Packaging:** a single **extract-and-run** offline package (the repo + a fully populated `vendor/`
  tree, no install) plus a standalone `dist/lykos.pyz` zipapp (`offline-packaging.md`).
- **Target OS:** pinned Kali/Debian-family matching the VM; document the exact base.

### Harvest the engines, own the glue (decision `overview.md`)
Build a **lean custom orchestration core** (job queue, stage DAG, data model, GUI) that one person can
understand and maintain over a long horizon. **Harvest aggressively at the tool/library level** (Ghidra,
rizin, angr, AFL++, qemu, GDB, signature DBs). **Study** open Cyber Reasoning Systems
(e.g., Trail of Bits' Buttercup) for orchestration *ideas only* — do not fork them; they are online
and source/patch-shaped, the opposite of our offline, binary-only, deterministic posture.

### Why not build our own decompiler/fuzzer/emulator
Each represents many person-years. The moat is the orchestration, correlation, the confidence pipeline,
harness synthesis, PoC bundling/verification, and the UI — the glue and the workflow — not the engines.
