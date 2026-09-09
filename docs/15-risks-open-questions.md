# 15 — Risks, Constraints & Open Questions You Must Decide

## Decisions that change the architecture (answer these first)
1. **Target scope. [DECIDED]** Broad multi-architecture support is a goal: **x86/x86-64, ARM/AArch64,
   PowerPC, MIPS, and more.** The loader/disasm/emulator layers are architecture-agnostic by design (doc 02).
   Build order: x86-64 + AArch64 first for depth, then PPC/MIPS, since Ghidra/QEMU already cover them — the
   work is per-arch emulation/sanitizer/gadget wiring, not new engines. **Firmware/embedded rehosting is
   [DECIDED in scope]** as a dedicated track (doc 17.5, roadmap Phase 8).
2. **"Custom binary" meaning. [DECIDED]** Means a **custom file format wrapping a known ISA** → handled by a
   **loader plugin** + headerless-blob wizard (doc 04.6 case 1). Custom/unknown *ISA* / SLEIGH authoring
   (doc 04.6 case 2) is **optional / deprioritized**, kept as a plugin path but not a v1 requirement.
3. **Multi-binary / inter-component analysis. [DECIDED in scope]** The case model is a **component graph** —
   binaries linked by dynamic-link/dlopen/IPC/RPC/exec edges — with cross-binary callgraph, cross-boundary
   taint, whole-system detonation, and cross-component findings (doc 17). Firmware is the extreme case of this.
4. **Coverage breadth. [DECIDED]** Plan for **all practical architectures** (native + bytecode; doc 18) and
   the **entire CWE corpus** partitioned into detectable families vs an explicit out-of-scope list (doc 19).
   Both are made possible by architecture-neutral IR (detectors written once) + a live in-app capability
   matrix so coverage is always shown honestly. Breadth is delivered in waves (Tier 1 → 2 → 3 → 4), not
   all at v1 — but the design accommodates all of it from day one.
5. **AI ambition. [DECIDED — ZERO AI in the product.]** No ML, no LLM, no GPU. Every capability is
   deterministic (naming: doc 04; detection: doc 05; PoC: doc 08). Rationale: the target is a Kali VM with no
   GPU, and a low-quality small model would hurt more than help. An **optional, unshipped plugin hook for a
   local Ollama** instance is left in the plugin API for an operator who later wants naming/summary
   *suggestions* — but it is never bundled and nothing depends on it. The deterministic bug-finding stack
   (signatures + rules + taint + symbolic + fuzzing + sanitizers) is the industry standard; AI was the
   newcomer on top, not the foundation, so the impact of dropping it is contained to custom-code naming and
   summaries (an inherently human RE task).
6. **Hardware envelope. [DECIDED — Kali VM, no GPU.]** Design for ~**32 GB RAM, 4+ cores, nested
   virtualization available** (KVM inside the VM). Consequences: KVM-backed microVMs (T2) and accelerated
   system emulation (T3) are viable, not just software TCG (doc 06). Modest core count → a **few** parallel
   fuzz instances, not a farm; the resource governor (doc 02) is sized for this. No GPU means no real-time AI
   even if a model were added — reinforcing decision 5.
7. **PoC ceiling. [DECIDED — a finding is "confirmed" only when a demonstrable effect is reproduced.]** This is
   the definition of vulnerable, and it drives the confidence lifecycle (doc 05): **Confirmed** is tied to a
   reproducible artifact that produces an observable effect (a crash + sanitizer report, PC control, a leak, an
   unexpected file access). The PoC need **not** be auto-generated — it may be an input, a script, or a small
   program, authored by the tool *or* the analyst. The tool is therefore also a **PoC workbench**: author,
   capture, replay, and **re-verify** the demonstration in a clean sandbox before marking Confirmed (doc 08).
   Commitment: **L0/L1 guaranteed baseline, L2 best-effort, L3 scoped analyst-in-the-loop** (doc 08 ladder).
8. **Build vs harvest. [DECIDED — build a lean custom core, harvest engines.]** Build and own the orchestration
   spine (job queue, stage DAG, data model, GUI) so one person can understand and maintain it over a long
   horizon. **Harvest aggressively at the tool/library level** (Ghidra, angr, AFL++/LibAFL, QEMU, CASR,
   BinDiff, ROPgadget, signature DBs). **Study** open Cyber Reasoning Systems (Trail of Bits' Buttercup et al.)
   for orchestration *ideas only* — do not fork them; they are online, AI-integrated, source/patch-shaped, the
   opposite of our offline, binary-only, zero-AI posture. Rationale: solo + long horizon makes comprehension
   and ownership beat a head-start, and without AI orchestration the spine is a manageable amount of code.

## Technical risks
- **False positives** overwhelm the analyst → mitigated by the confidence pipeline (doc 05); this is the make-
  or-break design choice.
- **Auto-harnessing for library functions** is unreliable → keep human-in-the-loop; don't over-promise.
- **AEG (L3)** is frontier; even CGC auto-exploited one heap bug → scope it as a research track, not a feature.
- **The ~32% RE-agent ceiling** → the human must stay the decision-maker; design UI accordingly.
- **Sandbox escape** when detonating malicious binaries → default to strong isolation (T2/T3), no network,
  snapshot rollback (doc 06). Treat isolation bugs as security-critical.
- **Resource thrash** (Ghidra + VMs + fuzzers + LLM on one box) → the resource governor (doc 02) is essential,
  not optional.
- **Bundle staleness** on an air-gapped host → surface data-pack ages everywhere; never imply currency (doc 11).
- **Benchmark contamination** inflating perceived quality → use 2026 contamination-free sets (doc 14).

## Licensing / distribution risk
- GPL tools (QEMU, Unicorn, Qiling, GDB) are fine as **separate bundled processes**; avoid static linking that
  imposes copyleft on our code. Do a full license review before bundling any ML **model weights** or research
  code — several have non-commercial or ambiguous terms (doc 10). This can block redistribution; resolve early.

## Operational note
Offensive-security tool for authorized engagements only. (Per your instruction, no in-app authorization gate
or chain-of-custody module is planned; that's an operator-process matter, out of scope for the software.)

## Non-technical
- **Effort realism:** full scope is multi-person, multi-year. Phases 0–7 (doc 13) are the credible v1;
  8–9 are research. Right-size the team or the scope, not both optimistically.
- **Maintenance:** signatures/CVE/models rot; plan the sneakernet update cadence (doc 11) before shipping.
