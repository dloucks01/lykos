# Overview & Goals

---

## Overview, Goals, and Honest Feasibility

### Vision
A single offline Linux workstation app that takes an arbitrary binary and drives it through the full
offensive-analysis lifecycle — load → reverse engineer → detect weaknesses → confirm dynamically →
demonstrate with a PoC — inside one coherent, styled analyst workflow.

### Primary users
- **Vulnerability researcher / exploit developer** on an authorized engagement.
- **Reverse engineer** triaging unknown or custom binaries.
- **Red-team operator** who needs a demonstrable PoC to prove impact to a client.

The tool is single-operator per workstation but multi-*case*. It is not a SaaS and not multi-tenant.

### Capability tiers (set expectations honestly)
These capabilities are not equal in maturity. Be explicit internally about what is *solved engineering*
vs *frontier research*, so the roadmap does not over-promise.

| Capability | Reality | Our stance |
|---|---|---|
| Load ELF/PE/Mach-O, disassemble, decompile | Solved (Ghidra/rizin) | Orchestrate + present |
| CFG/callgraph/xref, string/const analysis | Solved | Orchestrate + present |
| Stripped-binary function recovery via signatures | Mostly solved (FLIRT/FCG/sig DBs) | Bundle DBs + ML assist |
| Static CWE pattern + taint detection | Solved but **noisy** | Orchestrate + confidence scoring |
| Known-CVE detection (binary version banners **+** source dependency manifests + vendored headers) | Solved for known components | Fingerprint → bundled offline CVE DB (OSV + NVD-CPE) match |
| CVE **weaponization** (per-CVE + CWE-class triggers) | Hard, scoped | Trigger fires; repro recorded **only** on a real fault |
| Sandboxed execution / tracing / coverage | Solved (QEMU/Qiling/DynamoRIO) | Orchestrate + isolate |
| Coverage-guided fuzzing of binaries | Solved (AFL++ qemu/frida mode) | Orchestrate + auto-harness |
| **Automatic harness synthesis** | **Hard, partially solved** | Assisted, human-in-loop |
| Crash triage / exploitability scoring | Mostly solved (CASR/GEF) | Orchestrate |
| Root-cause of a crash | Semi-solved | Symbolic + backward slice |
| **PoC that reaches the bug (crashing input)** | Feasible for mem-corruption | Primary PoC target |
| **Weaponized exploit / full AEG** | **Frontier research** | Best-effort, template-driven, scoped |
| Analysis of truly *custom ISA* | Solved *only if* you write a processor spec | Provide SLEIGH authoring workflow |

**Key honesty point for the roadmap:** "determine if it is vulnerable to any CWE" with low false
positives, and "create a PoC," are the two hardest asks. We deliver them as a *confidence pipeline*
(candidate → corroborated → confirmed-with-repro) rather than a magic yes/no. Full automatic exploit
generation is explicitly a stretch goal, not an MVP promise.

### Non-goals (v1)
- Not a live malware C2/sandbox network emulator (INetSim-style) beyond what dynamic analysis needs.
- Not a source-code SAST tool (we assume binary-only, though we ingest debug info if present).
- Not multi-user collaboration server. Single workstation.
- Not a general disassembler replacement — we embed one.
- Not cloud/online CVE correlation (offline); CVE/version data is bundled and clearly dated.

### Success criteria (v1)
1. Ingest a stripped x86-64 ELF and produce a navigable RE view with recovered functions.
2. Detect at least the memory-safety CWE family with dynamic confirmation.
3. Auto-propose a fuzzing harness for a file/stdin/argv input vector and run a campaign.
4. Triage crashes and emit a reproducible crashing-input PoC bundle with a written report.
5. All of the above with zero network access, from a single installer.

---

## Risks, Constraints & Open Questions You Must Decide

### Decisions that change the architecture (answer these first)
1. **Target scope. [DECIDED]** Broad multi-architecture support is a goal: **x86/x86-64, ARM/AArch64,
   PowerPC, MIPS, and more.** The loader/disasm/emulator layers are architecture-agnostic by design (`architecture.md`).
   Build order: x86-64 + AArch64 first for depth, then PPC/MIPS, since Ghidra/QEMU already cover them — the
   work is per-arch emulation/sanitizer/gadget wiring, not new engines. **Firmware/embedded rehosting is
   [DECIDED in scope]** as a dedicated track (`pipeline.md`.5, roadmap Phase 8).
2. **"Custom binary" meaning. [DECIDED]** Means a **custom file format wrapping a known ISA** → handled by a
   **loader plugin** + headerless-blob wizard (`pipeline.md`.6 case 1). Custom/unknown *ISA* / SLEIGH authoring
   (`pipeline.md`.6 case 2) is **optional / deprioritized**, kept as a plugin path but not a v1 requirement.
3. **Multi-binary / inter-component analysis. [DECIDED in scope]** The case model is a **component graph** —
   binaries linked by dynamic-link/dlopen/IPC/RPC/exec edges — with cross-binary callgraph, cross-boundary
   taint, whole-system detonation, and cross-component findings (`pipeline.md`). Firmware is the extreme case of this.
4. **Coverage breadth. [DECIDED]** Plan for **all practical architectures** (native + bytecode; `coverage.md`) and
   the **entire CWE corpus** partitioned into detectable families vs an explicit out-of-scope list (`coverage.md`).
   Both are made possible by architecture-neutral IR (detectors written once) + a live in-app capability
   matrix so coverage is always shown honestly. Breadth is delivered in waves (Tier 1 → 2 → 3 → 4), not
   all at v1 — but the design accommodates all of it from day one.
5. **Analysis approach. [DECIDED — deterministic orchestration.]** Every capability is a **deterministic**
   pipeline that orchestrates proven OSS (Ghidra/rizin, angr, AFL++, QEMU, GDB) behind a custom core we own
   (naming: `pipeline.md`; detection: `pipeline.md`; PoC: `pipeline.md`). The deterministic bug-finding stack
   (signatures + rules + taint + symbolic + fuzzing + sanitizers) is the industry standard and is what every
   finding and PoC is reproducible from. A plugin hook is left in the API for an operator who later wants to
   wire in a local model for naming/summary *suggestions*, but nothing in the pipeline depends on it and it is
   not bundled.
6. **Hardware envelope. [DECIDED — Kali VM, no GPU.]** Design for ~**32 GB RAM, 4+ cores, nested
   virtualization available** (KVM inside the VM). Consequences: KVM-backed microVMs (T2) and accelerated
   system emulation (T3) are viable, not just software TCG (`pipeline.md`). Modest core count → a **few** parallel
   fuzz instances, not a farm; the resource governor (`architecture.md`) is sized for this. The engines are
   CPU-only, consistent with the deterministic approach in decision 5.
7. **PoC ceiling. [DECIDED — a finding is "confirmed" only when a demonstrable effect is reproduced.]** This is
   the definition of vulnerable, and it drives the confidence lifecycle (`pipeline.md`): **Confirmed** is tied to a
   reproducible artifact that produces an observable effect (a crash + sanitizer report, PC control, a leak, an
   unexpected file access). The PoC need **not** be auto-generated — it may be an input, a script, or a small
   program, authored by the tool *or* the analyst. The tool is therefore also a **PoC workbench**: author,
   capture, replay, and **re-verify** the demonstration in a clean sandbox before marking Confirmed (`pipeline.md`).
   Commitment: **L0/L1 guaranteed baseline, L2 best-effort, L3 scoped analyst-in-the-loop** (`pipeline.md` ladder).
8. **Build vs harvest. [DECIDED — build a lean custom core, harvest engines.]** Build and own the orchestration
   spine (job queue, stage DAG, data model, GUI) so one person can understand and maintain it over a long
   horizon. **Harvest aggressively at the tool/library level** (Ghidra, angr, AFL++/LibAFL, QEMU, CASR,
   BinDiff, ROPgadget, signature DBs). **Study** open Cyber Reasoning Systems (Trail of Bits' Buttercup et al.)
   for orchestration *ideas only* — do not fork them; they are online and source/patch-shaped, the
   opposite of our offline, binary-only, deterministic posture. Rationale: solo + long horizon makes
   comprehension and ownership beat a head-start, and the orchestration spine is a manageable amount of code.

### Technical risks
- **False positives** overwhelm the analyst → mitigated by the confidence pipeline (`pipeline.md`); this is the make-
  or-break design choice.
- **Auto-harnessing for library functions** is unreliable → keep human-in-the-loop; don't over-promise.
- **AEG (L3)** is frontier; even CGC auto-exploited one heap bug → scope it as a research track, not a feature.
- **The ~32% RE-agent ceiling** → the human must stay the decision-maker; design UI accordingly.
- **Sandbox escape** when detonating malicious binaries → default to strong isolation (T2/T3), no network,
  snapshot rollback (`pipeline.md`). Treat isolation bugs as security-critical.
- **Resource thrash** (Ghidra + VMs + fuzzers + LLM on one box) → the resource governor (`architecture.md`) is essential,
  not optional.
- **Bundle staleness** on an offline host → surface data-pack ages everywhere; never imply currency (`offline-packaging.md`).
- **Benchmark contamination** inflating perceived quality → use 2026 contamination-free sets (`coverage.md`).

### Licensing / distribution risk
- GPL tools (QEMU, Unicorn, Qiling, GDB) are fine as **separate bundled processes**; avoid static linking that
  imposes copyleft on our code. Do a full license review before bundling any ML **model weights** or research
  code — several have non-commercial or ambiguous terms (`architecture.md`). This can block redistribution; resolve early.

### Operational note
Offensive-security tool for authorized engagements only. (Per your instruction, no in-app authorization gate
or chain-of-custody module is planned; that's an operator-process matter, out of scope for the software.)

### Non-technical
- **Effort realism:** full scope is multi-person, multi-year. Phases 0–7 (`internal/13-roadmap-milestones.md`) are the credible v1;
  8–9 are research. Right-size the team or the scope, not both optimistically.
- **Maintenance:** signatures/CVE/data packs rot; plan the sneakernet update cadence (`offline-packaging.md`) before shipping.
