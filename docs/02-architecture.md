# 02 — Architecture

## Layered model
```
+-------------------------------------------------------------------------+
|  GUI (analyst workstation)      doc 09                                    |
|  RE views · findings board · fuzzing dashboard · debugger · reports       |
+---------------------------- local API (IPC) ----------------------------+
|  Orchestration / Pipeline Engine    doc 02                                |
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

## Process model
- **Backend core** = a long-lived local service (Python + FastAPI over a Unix socket / loopback only).
  Owns the data model, job queue, and event bus. No external network binding — ever.
- **Workers** = separate processes so a crashing analyzer (or a detonating target) can't take down the UI.
  Heavy/native tools (Ghidra headless, fuzzers, QEMU) run as managed subprocesses.
- **Frontend** = desktop shell (Tauri or Electron) rendering a web UI, talking to the backend over the
  local socket + a websocket for live events (fuzzing stats, log tails, job progress). See doc 10.
- **Isolation domains** = dynamic-analysis targets run in their own sandbox/VM, never in a worker's own
  address space (except deliberate Unicorn/Qiling in-process emulation of *foreign* code, which cannot
  execute host syscalls). See doc 06.

## Pipeline / job engine
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

## Module boundaries (each is independently testable + swappable)
| Module | Input | Output | Backed by |
|---|---|---|---|
| Loader | file bytes | memory map, arch, entry, sections | LIEF, Ghidra, custom |
| Disassembler | mapped image | instructions, basic blocks | Ghidra/rizin/capstone |
| Decompiler | function | pseudo-C + types | Ghidra (P-Code) |
| Recovery | stripped image | named funcs, lib IDs | sig DBs + ML (doc 04) |
| CWE detectors | IR + decomp + traces | candidate findings | rules/taint/symbolic |
| Sandbox runner | binary + input + policy | trace, coverage, crash | QEMU/Qiling/nsjail |
| Harness builder | vector spec | runnable harness | templates + codegen |
| Fuzzer | harness + corpus | crashes, coverage | AFL++/honggfuzz/libFuzzer |
| Symbolic | image + target state | solved input / constraints | angr/Triton |
| Triage | crash | dedup key, exploitability | CASR/GDB |
| PoC synth | confirmed finding | PoC bundle | templates + symbolic |
| Reporter | findings | HTML/PDF/SARIF | templating |

## Plugin API (build it early — cheap later is expensive)
A stable Python plugin interface with typed hooks:
- `register_loader(match, load_fn)` — custom/"your" binary formats.
- `register_detector(cwe_ids, analyze_fn)` — custom CWE rules over the shared IR.
- `register_harness_template(...)`, `register_report_section(...)`.
- Detectors receive a normalized **Program IR** (see doc 03) so a rule works across architectures.

## Normalized data flow
Everything writes into one case DB + artifact store (doc 12). Cross-tool correlation (e.g., a static
candidate at address X ↔ a fuzzing crash whose faulting IP is X) is done in the core, not in any tool.
This correlation is what lets a noisy candidate get promoted to Confirmed.
