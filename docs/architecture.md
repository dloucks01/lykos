# Architecture

---

## Architecture

### Layered model
```
+-------------------------------------------------------------------------+
|  GUI (analyst workstation)      `gui.md`                                    |
|  RE views · findings board · fuzzing dashboard · debugger · reports       |
+---------------------------- local API (IPC) ----------------------------+
|  Orchestration / Pipeline Engine the architecture section                                |
|  job queue · scheduler · resource governor · run cache · event bus        |
+-------------------------------------------------------------------------+
|  Analysis Services (workers)                                              |
|   Ingestion/Loaders (03) | Static RE (03) | Stripped Recovery (04)        |
|   CWE Detection (05)      | Dynamic/Sandbox (06) | Harness+Fuzz (07)       |
|   Symbolic/Concolic (05/08) | Triage+PoC (08) | Reporting (08/12)          |
+-------------------------------------------------------------------------+
|  Core: Data Model + Artifact Store (12) · Plugin API · Config · Logging   |
+-------------------------------------------------------------------------+
|  Bundled toolchain (11): Ghidra, rizin, angr, AFL++, QEMU/Qiling, GDB,    |
|  capstone/unicorn/keystone, CASR, sig DBs, CWE catalog, local models      |
+-------------------------------------------------------------------------+
```

### Process model
- **Backend core** = a long-lived local service (Python + FastAPI over a Unix socket / loopback only).
  Owns the data model, job queue, and event bus. No external network binding — ever.
- **Workers** = separate processes so a crashing analyzer (or a detonating target) can't take down the UI.
  Heavy/native tools (Ghidra headless, fuzzers, QEMU) run as managed subprocesses.
- **Frontend** = desktop shell (Tauri or Electron) rendering a web UI, talking to the backend over the
  local socket + a websocket for live events (fuzzing stats, log tails, job progress). See this document.
- **Isolation domains** = dynamic-analysis targets run in their own sandbox/VM, never in a worker's own
  address space (except deliberate Unicorn/Qiling in-process emulation of *foreign* code, which cannot
  execute host syscalls). See `pipeline.md`.

### Pipeline / job engine
- A **DAG of stages** per case: `load → disasm → decompile → recover(strip) → static-cwe → dynamic-triage
  → harness → fuzz → crash-triage → symbolic-confirm → poc → report`. Stages are individually
  runnable/re-runnable; the UI shows the graph and lets the analyst run/skip/re-run any node.
- **Job queue** backed by SQLite (air-gap friendly, no broker). Each job: inputs (content-hashed),
  tool version, params, status, artifacts out. Idempotent + **result-cached by (stage, input-hash,
  params, tool-version)** so re-opening a case is instant and re-runs are cheap.
- **Scheduler + resource governor:** concurrency caps per resource class (CPU-heavy decompile vs
  IO-heavy fuzz vs VM slots). Prevents a single box from thrashing when Ghidra + 8 fuzzers + a VM all run.
- **Event bus:** workers publish progress/log/metric events; UI subscribes. Also drives the audit log.
- **Cancellation + resume:** long fuzzing/symbolic campaigns checkpoint; case reopen resumes them.

### Module boundaries (each is independently testable + swappable)
| Module | Input | Output | Backed by |
|---|---|---|---|
| Loader | file bytes | memory map, arch, entry, sections | LIEF, Ghidra, custom |
| Disassembler | mapped image | instructions, basic blocks | Ghidra/rizin/capstone |
| Decompiler | function | pseudo-C + types | Ghidra (P-Code) |
| Recovery | stripped image | named funcs, lib IDs | sig DBs + ML (`pipeline.md`) |
| CWE detectors | IR + decomp + traces | candidate findings | rules/taint/symbolic |
| Sandbox runner | binary + input + policy | trace, coverage, crash | QEMU/Qiling/nsjail |
| Harness builder | vector spec | runnable harness | templates + codegen |
| Fuzzer | harness + corpus | crashes, coverage | AFL++/honggfuzz/libFuzzer |
| Symbolic | image + target state | solved input / constraints | angr/Triton |
| Triage | crash | dedup key, exploitability | CASR/GDB |
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
(export/import as a directory or archive) so it can move between air-gapped hosts.

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
- **SQLite** for structured data (cases, targets, functions, findings, jobs, crashes, poc metadata).
- **DuckDB** (optional) for heavy analytical queries over large trace/coverage tables.
- **Vector index** (FAISS/hnswlib) for function embeddings (`pipeline.md`).
- **Content-addressed artifact store:** every artifact (binary, corpus, crash input, trace, model output,
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
  bundles are stale (`air-gap.md`) and when a colleague on another air-gapped host must reproduce a PoC.
- Deterministic seeds where engines allow; record RNG seeds for fuzz/symbolic runs.

### Logging & audit
- Structured event log (job lifecycle, analysis runs, sandbox detonations, PoC verifications). Local only.
- Deterministic pipeline → every result is reproducible from its recorded inputs/params/tool-versions.

---

## Technology Stack & Licensing (Zero-AI)

Bias: **orchestrate proven, deterministic OSS** behind a lean custom core we own (decision `overview.md`). No ML/LLM
in the shipped product, no GPU dependency. Prefer permissive licenses (air-gapped redistribution). "Primary"
= default; "alt" = swappable behind the module interface.

### Deployment target (decision `overview.md`)
- **Kali VM**, ~32 GB RAM, 4+ cores, **nested virtualization available** (KVM inside the VM works, verify per
  host). So KVM-backed microVMs and accelerated system emulation are viable, not just TCG.
- **No GPU.** Modest core count → a few parallel fuzz instances, not a farm; size the resource governor accordingly.
- **Fully self-contained package:** everything needed to run ships in the installer (`air-gap.md`).

### Languages
- **Backend/orchestration:** Python 3.12 (richest deterministic RE/exploit ecosystem: angr, pwntools,
  Qiling, LIEF, Ghidra bridge). Hot paths in **Rust** or C where needed.
- **Fuzzing substrate:** **AFL++** primary; **LibAFL** (Rust) where a composable custom engine helps.
- **Frontend:** TypeScript + React in a desktop shell (Tauri preferred; Electron acceptable).

### Core engines (module → tool → license)
| Role | Primary | Alt | License notes |
|---|---|---|---|
| Loader/parser | LIEF | Ghidra loaders | permissive |
| Disassembly/decompile | **rizin + rz-ghidra + pypcode** (Ghidra P-Code, no JVM) | Ghidra headless (optional alternate, `LYKOS_DECOMPILER=ghidra`), angr | permissive / LGPL |
| Quick disasm/asm | capstone/keystone | — | BSD |
| Signature matching | Ghidra FID · FLIRT-style · rizin zignatures | — | permissive |
| Binary diffing / name transfer | **BinDiff** | Diaphora, Ghidra Version Tracking | free/GPL — separate process |
| Runtime-metadata recovery | Go pclntab / C++ RTTI / DWARF parsers | LIEF | permissive |
| CPU emulation | Unicorn | — | GPLv2 (separate process) |
| OS/syscall emulation | Qiling | — | GPLv2 |
| System/foreign emulation | QEMU (+KVM, nested) | — | GPLv2 |
| MicroVM isolation | Firecracker / cloud-hypervisor (nested KVM) | gVisor | Apache-2.0 |
| Process sandbox | bubblewrap / nsjail | firejail | permissive |
| Symbolic/concolic | angr | Triton, SymCC/SymQEMU | BSD / permissive |
| Fuzzing | AFL++ / LibAFL | honggfuzz, libFuzzer | Apache / check AFL++ deps |
| Snapshot fuzzing | Nyx (nested KVM+QEMU) | — | verify license before bundling |
| Binary sanitizer | QASan | RetroWrite, MTSan | permissive/research — verify |
| Debugger | GDB (+Python, GEF/pwndbg-style) | LLDB | GPLv3 (separate process) |
| Crash triage | CASR | custom gdb | Apache-2.0 |
| Gadgets/exploit | ROPgadget/ropper + pwntools | — | permissive |
| Rule pattern-match (secondary) | Semgrep / Weggli over decompiled C | Ghidra P-Code scripts | permissive |
| Vector/similarity | structural/graph + function hashing | — | (deterministic, no ML) |
| Data store | SQLite (+ DuckDB for trace analytics) | — | public-domain/MIT |

> **Licensing action item:** GPL tools (QEMU, Unicorn, Qiling, GDB, BinDiff) are fine as **separate bundled
> processes**; avoid static linking that would impose copyleft on our code. Dropping ML model weights removes
> the thorniest redistribution risk from the earlier plan.

### No-AI posture (decision `overview.md`)
- **Zero AI in the shipped package.** No model weights, no GPU runtime, no agentic loop, no neural
  decompiler/naming. All naming is deterministic (`pipeline.md`); all detection is rules + taint + symbolic +
  dynamic (`pipeline.md`).
- **Optional, unshipped plugin hook for a local Ollama** instance is left in the plugin API for operators who
  want naming/summary *suggestions* later. Nothing depends on it; it is never bundled. A low-quality small
  model would hurt more than help — so the default is off and unshipped.

### Data & platform
- **DB:** SQLite (cases, findings, jobs, provenance) + DuckDB for analytics over large trace tables.
- **Artifact store:** content-addressed files on disk (hash-named), referenced from SQLite.
- **Packaging:** offline OCI/Podman images or a Nix/`apt` offline repo for reproducible installs (`air-gap.md`).
- **Target OS:** pinned Kali/Debian-family matching the VM; document the exact base.

### Harvest the engines, own the glue (decision `overview.md`)
Build a **lean custom orchestration core** (job queue, stage DAG, data model, GUI) that one person can
understand and maintain over a long horizon. **Harvest aggressively at the tool/library level** (Ghidra,
angr, AFL++/LibAFL, QEMU, CASR, BinDiff, ROPgadget, signature DBs). **Study** open Cyber Reasoning Systems
(e.g., Trail of Bits' Buttercup) for orchestration *ideas only* — do not fork them; they are online,
AI-integrated, and source/patch-shaped, the opposite of our offline, binary-only, zero-AI posture.

### Why not build our own decompiler/fuzzer/emulator
Each represents many person-years. The moat is the orchestration, correlation, the confidence pipeline,
harness synthesis, PoC bundling/verification, and the UI — the glue and the workflow — not the engines.
