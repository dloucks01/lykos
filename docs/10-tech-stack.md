# 10 — Technology Stack & Licensing (Zero-AI)

Bias: **orchestrate proven, deterministic OSS** behind a lean custom core we own (decision doc 15). No ML/LLM
in the shipped product, no GPU dependency. Prefer permissive licenses (air-gapped redistribution). "Primary"
= default; "alt" = swappable behind the module interface.

## Deployment target (decision doc 15)
- **Kali VM**, ~32 GB RAM, 4+ cores, **nested virtualization available** (KVM inside the VM works, verify per
  host). So KVM-backed microVMs and accelerated system emulation are viable, not just TCG.
- **No GPU.** Modest core count → a few parallel fuzz instances, not a farm; size the resource governor
  (doc 02) accordingly.
- **Fully self-contained package:** everything needed to run ships in the installer (doc 11).

## Languages
- **Backend/orchestration:** Python 3.12 (richest deterministic RE/exploit ecosystem: angr, pwntools,
  Qiling, LIEF, Ghidra bridge). Hot paths in **Rust** or C where needed.
- **Fuzzing substrate:** **AFL++** primary; **LibAFL** (Rust) where a composable custom engine helps.
- **Frontend:** TypeScript + React in a desktop shell (Tauri preferred; Electron acceptable).

## Core engines (module → tool → license)
| Role | Primary | Alt | License notes |
|---|---|---|---|
| Loader/parser | LIEF | Ghidra loaders | permissive |
| Disassembly/decompile | **Ghidra** (headless, deterministic decompiler) | rizin/Cutter, angr | Apache-2.0 / LGPL |
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

## No-AI posture (decision doc 15)
- **Zero AI in the shipped package.** No model weights, no GPU runtime, no agentic loop, no neural
  decompiler/naming. All naming is deterministic (doc 04); all detection is rules + taint + symbolic +
  dynamic (doc 05).
- **Optional, unshipped plugin hook for a local Ollama** instance is left in the plugin API for operators who
  want naming/summary *suggestions* later. Nothing depends on it; it is never bundled. A low-quality small
  model would hurt more than help — so the default is off and unshipped.

## Data & platform
- **DB:** SQLite (cases, findings, jobs, provenance) + DuckDB for analytics over large trace tables.
- **Artifact store:** content-addressed files on disk (hash-named), referenced from SQLite (doc 12).
- **Packaging:** offline OCI/Podman images or a Nix/`apt` offline repo for reproducible installs (doc 11).
- **Target OS:** pinned Kali/Debian-family matching the VM; document the exact base.

## Harvest the engines, own the glue (decision doc 15)
Build a **lean custom orchestration core** (job queue, stage DAG, data model, GUI) that one person can
understand and maintain over a long horizon. **Harvest aggressively at the tool/library level** (Ghidra,
angr, AFL++/LibAFL, QEMU, CASR, BinDiff, ROPgadget, signature DBs). **Study** open Cyber Reasoning Systems
(e.g., Trail of Bits' Buttercup) for orchestration *ideas only* — do not fork them; they are online,
AI-integrated, and source/patch-shaped, the opposite of our offline, binary-only, zero-AI posture.

## Why not build our own decompiler/fuzzer/emulator
Each represents many person-years. The moat is the orchestration, correlation, the confidence pipeline,
harness synthesis, PoC bundling/verification, and the UI — the glue and the workflow — not the engines.
