# 13 — Roadmap & Milestones

Sequenced so each phase is independently useful and de-risks the next. Build the **spine** (data model + job
engine + one thin end-to-end path) before breadth. Resist starting at "auto-exploit."

## Phase 0 — Foundations (spine)
> **Detailed task breakdown: `tasks/phase-0-foundations.md`** (epics, acceptance criteria, order, exit demo).
- Core service, SQLite data model (doc 12), job/pipeline engine + result cache (doc 02), artifact store,
  plugin API skeleton, logging/event bus. Desktop shell + empty themed UI + design tokens (doc 09).
- **CRS harvest review (gate, doc 15):** license + architecture review of Trail of Bits' Buttercup and peer
  AIxCC CRSs to decide vendor-vs-reimplement for the orchestration spine — *before* finalizing the job engine.
- **Leave an optional, unshipped plugin hook** for a future local Ollama assist (doc 15) — but ship zero AI;
  nothing in the pipeline depends on it.
- **Exit:** create a case, ingest an ELF, see hashes/format/mitigations, run a trivial job, view live logs.

## Phase 1 — Static RE workspace (x86-64 ELF)
> **PHASE 1 BUILD STATUS (started):** Ghidra headless integration implemented — locator (env/bundled/PATH), Jython export script, `disassemble` stage (resource_class=cpu), `function` table (migration v3) + DAO, API (`/targets/{id}/functions`, `/functions/{id}`, disassemble via `/runs`), and a UI panel (Decompile button + function list + decompiled viewer). Ghidra is **bundled in the full offline package** (not pre-installed by the operator); absent Ghidra → the stage errors clearly and Phase-0 triage still works. Now includes **CFG (basic blocks + edges) and P-Code IR** per function (Ghidra's P-Code = our architecture-neutral IR for the CWE detectors), persisted per function (migration v4) and rendered in the UI (decompiled + disassembly/CFG + P-Code). 67 tests + 1 skipped (real-Ghidra). Now also extracts the **program call graph** (edges with call sites; external/imported callees flagged as taint sinks) and **cross-references** (string references with xref sites), persisted (migration v5, call_edge + string_ref) and served (`/targets/{id}/callgraph`, `/targets/{id}/strings`, callers/callees on function detail) + shown in the UI. 70 tests + 1 skipped. Remaining Phase 1: IR query surface for detectors, graphical CFG view. This is the reachability + sink data Phase 3 taint analysis consumes.
- Ghidra headless integration: disasm, decompile, CFG/callgraph, xrefs, strings, IR normalization (doc 03).
- RE workspace UI: synchronized disasm/decompile/CFG/hex/strings (doc 09).
- **Exit:** navigate a non-trivial binary's functions and call graph in the app.

## Phase 2 — Stripped recovery
- Deterministic naming stack (doc 04): runtime-metadata extraction (Go pclntab / C++ RTTI / DWARF),
  signature/FunctionID + libc fingerprinting, BinDiff name-transfer from a symbolized corpus, crypto-constant
  ID, behavioral tags — all with accept/reject UX. Custom-format **loader plugin** interface + headerless-blob wizard.
- **Cross-binary linking (start multi-binary, doc 17):** resolve imports↔exports across all case targets into
  one merged callgraph; render the **System Map** view (doc 09).
- **Exit:** recover functions in a stripped binary; see one call graph spanning a program + its shared libs.

## Phase 3 — Static CWE candidates + findings board
> **PHASE 3 BUILD STATUS (started):** deterministic detection engine — `finding` table with the confidence lifecycle (migration v6) + FindingDAO (upsert/merge), a detector framework + CWE catalog, and three channels: **dangerous-API sinks** (rule), **hard-coded secrets** (string), and **input->sink reachability** over the call graph (approximate taint) that promotes candidate->corroborated. `detect_cwe` stage, `/targets/{id}/findings` + `/findings/{id}` API, and a Detect button + findings list in the UI. Now includes **true intra-procedural data-flow taint** over the P-Code IR (flow-sensitive CFG fixpoint, def-use with kill-on-redefine, per-arch ABI registers) that flags sink sites whose argument registers actually carry tainted data -- more precise than call-graph reachability, and a stronger corroboration channel. Taint is now **inter-procedural**: a summary-based call-graph fixpoint pushes tainted call arguments into callees' parameters and pulls tainted returns back to callers, so a source in a caller reaching a sink deep in a callee (and source-wrapper functions) are caught. 84 tests + 1 skipped. Zero-AI. Remaining: memory/points-to precision (buffer taint via pointers), more CWE families, case-level board UI; **Confirmed** still awaits dynamic/symbolic reproduction (Phases 4/6).
- Rule + static-taint detectors over IR; CWE taxonomy engine; findings board with the state lifecycle
  (Candidate stage only for now) (doc 05/09).
- **Exit:** produce triaged CWE candidates with evidence for a known-vulnerable test binary.

## Phase 4 — Sandbox + dynamic + debugger
> **PHASE 4 BUILD STATUS (started):** tiered-isolation process sandbox (bubblewrap+netns when available, auto-fallback to rlimits-only + process-group kill), cross-arch execution via qemu-user, crash + timeout detection, a `dyn_result` table (migration v7) + DAO, the `dynamic_run` stage, and `/targets/{id}/dynresults` API + a Run(sandbox) UI control. **A reproduced crash creates a Confirmed finding** (dynamic evidence) -- the confidence lifecycle now reaches Confirmed. 90 tests + 1 skipped; live-verified (SIGSEGV crash -> Confirmed CWE-119). Remaining: integrated debugger, coverage/tracing, binary sanitizers (QASan), stronger isolation (microVM) -- and Phase 5 fuzzing to *generate* the crashing inputs.
- Tiered isolation (T1 nsjail, T2 microVM), QEMU user/system, Qiling; coverage + tracing; **QASan** sanitizer;
  integrated GDB UI (doc 06).
- **Exit:** safely detonate an untrusted binary, get coverage + a sanitizer-labeled crash, debug it live.

## Phase 5 — Harness + fuzzing (whole-program vectors)
> **PHASE 5 BUILD STATUS (started):** dependency-free black-box mutational fuzzer (seeded RNG havoc mutations + dictionary mined from the target's strings) driving the Phase-4 sandbox over whole-program vectors (stdin/argv/file). Crash dedup, crashing inputs saved as artifacts + dyn_result records, and each unique crash becomes a **Confirmed** finding with its reproducible input (L1). `fuzz` stage, enqueue via `/runs`, Fuzz button + live stats in the UI. 93 tests + 1 skipped; live-verified (fuzz -> SIGSEGV -> Confirmed CWE-119). **Minimizes** each unique crash (ddmin-style chunk removal, budget-bounded) to a tiny reproducer before saving it and building the finding/PoC. **Coverage-guided fuzzing delivered** as an optional **AFL++ qemu-mode** backend (`coverage_fuzz` stage): graceful when AFL++ is absent (locator over LYKOS_AFL/AFL_PATH/PATH, clear error, built-in black-box `fuzz` remains the zero-dependency fallback), harvests AFL's unique crashing inputs and pushes each through the same sandbox->minimize->dedup-by-signal-> Confirmed-finding pipeline; Coverage-Fuzz button + live stats in the UI; 107 tests (+2 skipped incl. the real-AFL run, skipped here since afl-fuzz is not installed). **Directed fuzzing at static candidates delivered** (`directed_fuzz` stage, zero dependencies): ranks the addressed static findings as targets (taint/reachability-corroborated dangerous sinks first), computes AFLGo-style backward callgraph distance to each, and mines a targeted dictionary + seed corpus from the string constants the near-target functions actually reference in their P-Code (resolved via each string's xref sites), biasing the shared `fuzz_campaign` toward the sink; degrades to an undirected string-mined campaign (and says so) when no static graph exists, e.g. Ghidra absent. Directed-Fuzz button + live target/dictionary readout in the UI. 116 tests (+2 skipped); live-demonstrated advantage: with 400 decoy strings and a 600-exec budget, undirected found 0 crashes while directed reproduced the token-gated crash. Remaining: LibAFL composable engine; hybrid concolic is Phase 6.
- Input-vector discovery; whole-program harness gen; seed/dictionary mining; LibAFL/AFL++ campaign with live
  dashboard; crash feed → **CASR** triage/dedup/minimize (doc 07/08).
- **Exit:** auto-harness a file/stdin target, run a campaign, get deduped minimized crashes on the board.

## Phase 6 — Confirmation loop + L0/L1 PoC
> **PHASE 6 BUILD STATUS (started):** **PoC bundle + self-verification + the POC-BACKED lifecycle state.** `build_poc` stage re-runs a crashing input in a clean sandbox to verify it, assembles a self-contained `.tar.gz` bundle (target + input + runner.sh + meta + captured stderr), and on success promotes the finding to **poc-backed** (L1). `poc` table (migration v8), `/targets/{id}/pocs` API, Build-PoC UI + downloadable bundle. 96 tests + 1 skipped; live-verified full loop fuzz->crash->verified PoC->poc-backed CWE-119. **Hybrid concolic execution delivered** (`concolic` stage) via **angr** as an optional bundled tool run in its own interpreter through a standalone driver (`symbolic/angr_driver.py`), so the core stays stdlib-only. The stage seeds angr with the fuzzer's corpus (the hybrid handoff), solves path constraints toward the statically-flagged sink sites (from `select_targets`), and emits concrete inputs; every generated input is then **replayed in the Phase-4 sandbox** so a crash becomes a Confirmed finding (detector `concolic`), a reached sink promotes the static finding to **corroborated** (a `symbolic` evidence channel), and the rest become new seeds handed back to the fuzzer. Locator over LYKOS_ANGR_PYTHON / a vendored venv / python3 (each verified by importing angr); clear failure when absent, with fuzzing as the deterministic fallback. Concolic button + live target/reached readout in the UI; driver ships in and materializes from the zipapp. 122 tests (+3 skipped incl. the real-angr run, skipped here since angr is not installed); the stubbed-solver pipeline test confirms a real token-gated overflow end-to-end. **L2 primitive PoCs delivered** (`poc_primitive` stage, zero dependencies): proves a confirmed crash yields **instruction-pointer control**, not just a fault. It detonates a De Bruijn cyclic pattern under a pure-stdlib **ptrace** register/stack-capture helper (`poc/ptrace_capture.py`, run as its own process so it never forks the threaded worker), recovers the control offset from the return-address slot the stack pointer indexes at the `ret` fault (robust to non-canonical addresses that make the PC report the ret site), then **confirms** by placing a canonical sentinel at that offset and checking the program counter loads it. On success it builds an **L2** PoC bundle (with PRIMITIVE.txt: offset, sentinel, controlled registers) and promotes the finding to poc-backed with an instruction-pointer-control evidence line; native-arch (x86-64/aarch64) only, with cross-arch/qemu targets reported unsupported rather than failing. L2 button per crash + live readout in the UI; helper ships in and materializes from the zipapp. 130 tests (+3 skipped); **live-confirmed end-to-end**: on a no-PIE/no-canary stack overflow the program counter was driven to the sentinel at offset 72. Remaining Phase 6: root-cause slicing via a debugger; SymQEMU as an alternate concolic backend; further L2 primitives (write-what-where, controlled read).
- Symbolic (angr) + hybrid (SymCC/SymQEMU) + **directed fuzzing** at candidates; promote Candidate→Confirmed;
  root-cause slicing; **L0/L1 PoC bundles** with runner + recording + self-verification (doc 05/08).
- **Cross-binary taint (doc 17.2):** propagate taint through resolved inter-binary calls so a source in A and
  a sink in B become one cross-component finding.
- **PoC ceiling [DECIDED, doc 15]:** L0/L1 (reproducer + crash + sanitizer) is the *committed* baseline here;
  L2 (control primitive) is targeted best-effort in Phase 9; L3 stays a scoped analyst-in-the-loop track.
- **Exit:** a static candidate gets dynamically confirmed and ships a verified crashing-input PoC bundle.

## Phase 7 — Reporting + polish
- HTML/PDF reports + SARIF export; case export/import; report builder UI; design-system pass; keyboard-first UX (doc 08/09).
- **Exit:** produce a shareable, reproducible report with embedded PoCs. **This is a credible v1.**

## Phase 8 — Multi-binary systems & firmware/embedded rehosting (doc 17)
Promotes the multi-binary track from "start" (Phases 2/6) to full inter-component + firmware capability.
- **Inter-component dynamic:** whole-system detonation in one isolation domain so real IPC/linking runs;
  selective emulation with stubbed components; **multi-process debugging** (follow-fork/exec, cross-process
  breakpoints); **cross-boundary blame** (crash in B ← input into A).
- **IPC/RPC modeling:** detect + model socket/pipe/shm/mq/D-Bus channels as taint sink→source pairs with
  channel contracts; boundary-driven + channel harnessing (doc 17.3/17.4).
- **Firmware/embedded rehosting:** image carving + decomposition into components; **Fuzzware** precise MMIO
  modeling; **ES-Fuzz** adaptive MMIO; **GDMA** DMA rehosting; modeled interrupts/timers (NVIC/systick);
  protocol-aware network-stack rehosting; ARM/PPC/MIPS bare-metal via the headerless loader (doc 04.6/17.5).
- **Also:** Nyx snapshot fuzzing (nested KVM); more architectures (Tier 2 → 3, doc 18); optional SLEIGH
  custom-ISA workspace (doc 04.6). (No agentic/LLM work — zero-AI, doc 15.)
- **Exit:** rehost a firmware image, run its components together, and produce a cross-component finding with a
  whole-system PoC.

## Phase 9 — Frontier (stretch, scoped)
- **L2 primitive** demonstration (controllable-byte analysis, heap-layout primitives: MAZE/AAHEG).
- **L3 exploit** synthesis (template AEG, ROP) — assisted, human-in-loop, never promised as push-button.

## Continuous (every phase)
- Run the validation harness (doc 14) to track detection/FP rates and deterministic naming coverage; don't
  let quality regress as breadth grows.

## Team & realism
This is a multi-person, multi-year effort at full scope. A small team should target **Phases 0–7** as the
real product and treat 8–9 as substantial follow-on tracks (Phase 8 multi-binary/firmware is itself large —
rehosting is a research-grade effort). An MVP demoable slice is **Phases 0,1,4,5** end-to-end on one binary
class. Multi-binary starts cheaply in Phases 2/6 (cross-binary callgraph + taint) before Phase 8's heavy
whole-system + firmware work.
