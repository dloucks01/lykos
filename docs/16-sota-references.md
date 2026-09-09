# 16 — State-of-the-Art Survey (2022–2026) Driving the Design

Researched Sept 2026. Survey of the field; **not** a list of what we ship.

> **ADOPTION STANCE [decision doc 15]: the product is ZERO-AI, no GPU.** This survey is retained as
> *context and to justify the deterministic choices we made instead*. Read every "adopt" below through this
> filter:
> - **Adopted (deterministic, shipped):** Ghidra decompiler, angr, SymCC/SymQEMU, QSYM-style concolic,
>   AFL++/LibAFL (qemu/frida/CmpLog), Nyx snapshot fuzzing, QASan/RetroWrite/MTSan, CASR, Fuzzware/ES-Fuzz/
>   GDMA rehosting, ROPgadget/pwntools, BinDiff-style diffing, FID/FLIRT/zignature signatures.
> - **NOT adopted (AI/ML/GPU — reference only):** jTrans/Trex embeddings, SymLM/XFL/HexT5 neural naming,
>   LLM4Decompile/SK2Decompile/SALT4Decompile, FoC LLM crypto-ID, LATTE/VulAgent/PromptFuzz/SDLLMFuzz and all
>   LLM-directed fuzzing/symbolic, the agentic-CRS/MCP tool-bus pattern, and the LLM RE benchmarks
>   (BinMetric/CrackMeBench/REFORGE/REBENCH). Their *goals* still guide us; we reach them deterministically.
> The **DARPA AIxCC / Cyber Reasoning System** work below is studied for **orchestration ideas only** — we do
> not fork it (doc 15: build a lean core, harvest engines).

## Umbrella survey
- **SoK: AI-Augmented Binary Reversing** (arXiv 2606.17398) — the map of the whole ML-for-RE space; use
  as the taxonomy reference for which model to apply where.
- **The New Compiler Stack: Survey on Synergy of LLMs and Compilers** (arXiv 2601.02045).

## Binary code similarity (for stripped fn ID & known-vuln search)
- **jTrans** (ISSTA'22) — jump-aware transformer; +30.5% over prior SOTA, 2× recall on known-vuln search.
  Open source. *NOT adopted (ML/GPU). Deterministic substitute: BinDiff/structural diff + function hashing (doc 04.4).*
- **Trex** — hierarchical transformer over micro-traces (execution-aware embeddings).
- **StrTune** (arXiv 2411.12454) — data-dependence slicing for cross-optimization similarity.
- Caveat: **function inlining** degrades ML binary analysis (arXiv 2512.14045) — account for it in eval.

## Stripped function name / type / summary recovery
- **SymLM** (CCS'22) — context-sensitive, execution-aware function-name prediction. Open source.
- **XFL** — feature-engineered multi-label function naming.
- **HexT5** (ASE'23) — unified pre-training for name/type/summary inference over pseudo-code.
- **FoC** (arXiv 2403.18403, 2025) — LLM-based crypto-function ID in stripped binaries; +19.2% F1 over
  SymLM, +15.3% over XFL. *NOT adopted (LLM). Deterministic substitute: constant-based crypto-ID (doc 04.3).*
- **REBENCH** (arXiv 2604.27319) — fair benchmark for LLM stripped-binary type/name recovery. *Use to eval.*

## Neural decompilation (readability + recompilability of pseudo-C)
- **LLM4Decompile** (albertan017/LLM4Decompile) — DeepSeek-Coder/Llama-based; downloadable weights →
  **runs offline**. *NOT adopted (LLM/GPU). We use Ghidra's deterministic decompiler (doc 03).*
- **SK2Decompile** (arXiv 2509.22114, 2025) — two-phase skeleton→skin (structure then naming).
- **SALT4Decompile** (arXiv 2509.14646, 2025) — infers source-level abstract logic tree.
- **HELIOS / ICL4Decomp / D-LiFT** — CFG-abstraction prompting, in-context exemplars, RL quality tuning;
  +40pt compilability without retraining. Techniques to layer on the base model.

## LLM-assisted vulnerability detection & harnessing (the confidence-pipeline backbone)
- **LATTE** — LLM-driven binary taint analysis; found 37 firmware bugs, 10 CVEs, no manual taint rules.
  *NOT adopted (LLM). Deterministic substitute: curated taint source/sink/propagation rule set (doc 05).*
- **VulAgent** (arXiv 2509.11523, 2025) — hypothesis-validation multi-agent detection. *Pattern reused
  WITHOUT AI: our candidate→confirmed loop uses deterministic validators only (doc 05).*
- **VULPO** (arXiv 2511.11896) — context-aware on-policy vuln detection.
- **PromptFuzz** — LLM fuzz-driver generation, coverage-guided prompt mutation; +1.6× branch coverage,
  33 new bugs. *NOT adopted (LLM). Deterministic substitute: template-based, human-in-loop harnessing (doc 07).*
- **FuzzingBrain V2** (arXiv 2605.21779, 2025) — multi-agent discovery + reproduction end-to-end.

## Fuzzing engines & techniques
- **AFL++** — the workhorse; binary-only via **qemu-mode / frida-mode**, plus CmpLog, dictionaries.
- **LibAFL** — composable Rust fuzzing library; supports **Nyx**, frida, qemu backends. *Adopt as the
  orchestration substrate so we compose one engine instead of shelling many.*
- **Nyx / Nyx-Net** — KVM+QEMU full-system **snapshot** fuzzing; up to 300× throughput, 10× faster
  snapshot reload vs prior; source + binary-only. *Adopt for stateful/system + network targets.*
- **QSYM** — practical concolic engine for hybrid fuzzing.
- **SymCC / SymQEMU** — compilation-/emulation-based concolic execution (fast). *Adopt for hybrid mode.*

## Firmware / bare-metal rehosting (for embedded targets)
- **Fuzzware** (USENIX'22) — precise MMIO modeling for firmware fuzzing (extends Unicorn w/ NVIC + systick).
- **ES-Fuzz** (2024) — adaptive MMIO chunk modeling.
- **GDMA** (USENIX'25) — automated DMA rehosting via iterative type overlays.
- **Qiling** — cross-platform emulation framework over Unicorn (syscall/OS emulation). *Adopt for
  surgical function emulation + light rehosting.*
- **Protocol-Aware Firmware Rehosting** (CCS'25, arXiv 2509.13740) — network-stack rehosting.

## Binary-only sanitizers (memory-safety detection without source)
- **QASan** (SecDev'20) — QEMU + AddressSanitizer; arch-heterogeneous, rehosting-friendly. *Primary.*
- **RetroWrite** (Oakland'20) — static rewriting to insert ASan; low runtime overhead. *For x86-64 PIE.*
- **MTSan** (USENIX'23) — memory-tagging sanitizer for COTS binaries (AArch64 MTE-style).

## Crash triage & exploitability
- **CASR** — crash analysis, dedup, severity/exploitability scoring (gdb/casr). *Adopt.*
- **GEF/pwndbg** exploitable heuristics.

## Automatic exploit generation (frontier — scoped stretch only)
- **AEG / Mayhem** — the origins; symbolic + preconditioned search.
- **angr + rex** — CGC-era automatic exploitation.
- **MAZE** — heap-layout manipulation via Linear Diophantine "Dig & Fill".
- **ARCHEAP** — discovering heap-exploitation primitives.
- **AAHEG / DEPA** — heap primitive detection + exploit-AST strategies (fastbin/unlink).
- Reality check: even in DARPA CGC, only one heap bug was fully auto-exploited. We target crash/primitive
  demonstration, not push-button weaponization.

## Benchmarks for validating *our* detection quality
- **Juliet Test Suite** (NIST SARD) — labeled CWE cases. **LAVA-M** — injected bugs for fuzzers.
- **DARPA CGC** corpus — vulnerable binaries with known PoVs. **Magma** — real-CVE-based fuzzing benchmark.
- **ZeroDayBench** (arXiv 2603.02297) — LLM agents on unseen zero-days. **REBENCH** — stripped name/type.

---

# 2026 Frontier (most important — this is the current bar)

## The reference architecture already exists: Cyber Reasoning Systems (CRS)
**DARPA AI Cyber Challenge (AIxCC), finals Aug 2025** is the single most relevant precedent. It ran
fully-autonomous **Cyber Reasoning Systems** for ~143 hours over 53–63 real-world projects: they found
54 synthetic + **18 real, previously-unknown** vulnerabilities and auto-patched 43. Our tool is, in
effect, an **offline, offensive-focused, human-in-the-loop CRS** — so we should mirror CRS architecture.
- **SoK: DARPA's AIxCC — Competition Design, Architectures, Lessons Learned** (arXiv 2602.07666).
  *Read first; it is the field's consolidated blueprint.*
- **Team Atlanta — ATLANTIS** (1st, $4M): multi-agent orchestration mapping → exploiting → patching,
  combining LLM agents with classical fuzzing + symbolic execution.
- **Trail of Bits — Buttercup** (2nd, $3M): **open source** — study/reuse its orchestration directly.
- **Theori** (3rd). Several finalist CRSs are open-sourced post-competition; harvest their pipelines.

**Design takeaway:** the winning pattern is *hybrid* — LLM agents for hypothesis/triage/naming/harnessing,
wrapped around deterministic engines (AFL++/LibAFL fuzzing, angr/SymCC symbolic, sanitizers). Exactly the
orchestration posture in doc 02. Don't build an "LLM that finds bugs"; build a CRS that *uses* an LLM.

## 2026 RE-agent capability ceiling (set expectations honestly)
- Best LLM as of **Sept 2, 2026** fully reverse-engineers only **~32%** of a demanding realistic binary
  set ("the 32% barrier"). So automated RE assists the analyst; it does not replace them.
- **CrackMeBench** (arXiv 2605.10597), **REFORGE** (2607.07738, fn-naming), **BinMetric** (6 tasks, 20
  real projects), and a **contamination-free RE benchmark** (arXiv 2608.11469) — bundle these to track
  our own agent's real performance rather than trusting vendor claims.
- **MCP-driven RE**: the 2026 trend is LLM agents driving Ghidra/IDA *live* via Model Context Protocol to
  rename/retype/annotate in-place, with a **Quantitative Readability Score** (arXiv 2606.06838) guarding
  correctness. *NOT adopted (agentic/LLM). No tool bus ships; optional unshipped Ollama hook only (doc 15).*

## 2026 LLM-assisted fuzzing & symbolic (adopt these, not just 2024-era AFL++)
- **SDLLMFuzz** (arXiv 2604.17750) — dynamic+static, LLM structure-aware **seed generation** for
  structured inputs + static crash analysis.
- **Trace-Guided Directed Greybox Fuzzing via LLM-Predicted Call Stacks** (arXiv 2510.23101) — LLM
  predicts call stacks to steer a *directed* fuzzer at a specific candidate finding. *NOT adopted (LLM); we use classical AFLGo distance to drive
  fuzzing toward a static candidate site — this is the candidate→confirmed accelerator.*
- **ISC4DGF** (2409.14329), **DGF via LLM** (2505.03425) — LLM-driven initial corpus + reachable-seed gen.
- **PromeFuzz / PromptFuzz** — knowledge-driven LLM **harness/driver generation** at scale (doc 07).
- **Guiding Symbolic Execution with Static Analysis and LLMs** (arXiv 2604.06506) — LLM + static analysis
  prioritize symbolic paths for vuln discovery. *NOT adopted (LLM); substitute: static-analysis-guided path prioritization (doc 05/08).*

## Threat-landscape context (why this is timely, not why to over-claim)
Reporting through H1–H2 2026 shows agents chaining discovery→validation→weaponization; Anthropic's
**Claude Mythos Preview** (April 2026) demonstrated autonomous 0-day identification/exploitation across
major OSes/browsers. Capability context only — our tool stays human-in-the-loop and engagement-scoped.

## Net architectural implications for BinAnalysis (zero-AI reading)
1. Build a **lean custom orchestration core** we own (doc 02/10) with a deterministic-engine layer only —
   *study* CRS orchestration for ideas, don't fork it.
2. There is **no agent and no tool bus** in the shipped product; an optional unshipped Ollama plugin hook is
   left open (doc 15) but nothing depends on it.
3. Close the candidate→confirmed loop with **deterministic** directed greybox fuzzing (AFLGo-style distance)
   + hybrid concolic (SymCC/SymQEMU) — not blind fuzzing, not LLM guidance.
4. Bundle **Juliet/LAVA-M/Magma/CGC** to score detection quality; drop the LLM-agent RE benchmarks.
5. The tool is an analyst *force-multiplier*: deterministic naming + detection + reproduction, human as the
   decision-maker at every promotion candidate → confirmed → PoC.

---

# Deterministic SOTA we ACTUALLY adopt (zero-AI, researched Sept 2026)

This is the post-decision reading list: current, non-AI techniques for each subsystem. The takeaway from
the research is reassuring — every capability has a strong, recent deterministic line of work, and the
multi-binary/firmware case in particular is *solved deterministically* (Karonte found 46 zero-days with no ML).

## Deterministic directed greybox fuzzing (steer fuzzing at a static candidate — doc 05/07)
- **BEACON** (S&P'21) — provable path pruning: lightweight static reachability + path-condition analysis
  cuts infeasible paths to the target. *Adopt.*
- **SelectFuzz** (S&P'23) — selective exploration of only target-relevant paths; found 6 new CVEs. *Adopt.*
- **WindRanger** — data-flow fitness via taint on branch constraints. *Adopt (pairs with our taint).* 
- **AFLGopher** (arXiv 2511.10828, 2025) — feasibility-aware guidance; beats WindRanger/SelectFuzz/AFLGo.
- **Prospector** (ISSTA'24) — iterative prioritization for *large target sets* (fits "many candidates").
- **SAST-Guided Greybox Fuzzing** (TUM preprint) — drives the fuzzer from static-analysis findings. *This is
  exactly our static-candidate → directed-fuzz → confirmed loop, done without any model.*
- (Skip the ML ones: DeepGo/RL-predictive, LLM-DGF.)

## Deterministic multi-binary & firmware taint (the doc-17 foundation)
- **Karonte** (S&P'20) — **Binary Dependency Graph** + cross-binary taint propagation; **46 zero-days across
  53 firmware images, no ML.** This is our component graph (doc 17.1) validated in the literature. *Study + adopt patterns.*
- **SaTC** (USENIX'21) — shared-keyword taint linking web front-end params to back-end binary sinks.
- **BPDA** (TDSC'24, "Precise Discovery of More Taint-Style Vulnerabilities") — ~6% of SaTC's runtime, found
  21 vulns SaTC/Mango missed. *Adopt its precision/perf ideas.*
- **Mango** (USENIX'24, Gibbs et al.) — scalable taint-style discovery in binaries.
- **SysFuSS** (arXiv 2602.02243, 2026) — system-level firmware fuzzing with *selective* symbolic execution
  (deterministic hybrid) for the rehosting track (doc 17.5).

## Deterministic concolic / hybrid (candidate confirmation + PoC input — doc 05/08)
- **SymQEMU** (NDSS'21) — compilation-based symbolic execution for **binaries**, no pre-instrumentation;
  outperforms prior binary-only executors. *Primary.*
- **QSYM** (USENIX'18) — practical concolic tailored for hybrid fuzzing. *Adopt (Driller-style pairing).*
- **Fuzzolic** — fuzzing+concolic mix; **SymFusion** — hybrid LLVM-IR/binary instrumentation; **LeanSym** —
  conservative constraint debloating for scalability; **SymSAN** — faster shadow-memory concolic. *Alternatives
  to tune scalability on the Kali VM.*
- LibAFL ships a **concolic tracing** module to wire these into our fuzzing substrate.

## Deterministic stripped-function identification (doc 04)
- **BinDiff** — per-function signature from the normalized CFG (blocks/edges/calls) + **Weisfeiler-Lehman**
  graph hashing to build a unique per-function ID for matching. Fully deterministic. *Primary for corpus-diff.*
- **Binary hashing / function hashing** (River Loop) — fast exact/fuzzy function fingerprints for triage.
- **"Identifying Library Functions in Stripped Binary: Combining Function Similarity + Call Graph Features"**
  (Springer'24) — deterministic library-fn ID using callgraph context; complements pure signatures.
- **A Survey of Binary Code Fingerprinting** (ACM CSUR) — taxonomy/reference for our signature+diff stack.
- **Match & Mend** (arXiv 2510.14384, 2025) — N-day matching + local reassembly in ARM binaries; informs
  known-vuln matching and the PoC/patch angle.
- (Skip the ML ones: jTrans/Trex/VEXIR2Vec/KEENHash embeddings, BYTEWEIGHT boundary learning.)

## Net: the zero-AI stack is well-supported
Directed fuzzing (BEACON/SelectFuzz/AFLGopher/SAST-guided) + cross-binary taint (Karonte/BPDA/Mango) +
binary concolic (SymQEMU/QSYM/Fuzzolic) + graph-hashing similarity (BinDiff/Weisfeiler-Lehman) + signatures
(FID/FLIRT) + binary sanitizers (QASan/RetroWrite/MTSan) + triage (CASR) covers the whole pipeline with no
model, no GPU. AI was an accelerant on top of exactly these; we keep the base and drop the accelerant.
