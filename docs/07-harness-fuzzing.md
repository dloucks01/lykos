# 07 — Harness Synthesis & Fuzzing Orchestration

Auto-harnessing is the hardest engineering piece (Gap E). Split it into discovery → target → environment →
seeds → instrumentation → campaign. Whole-program vectors are tractable and are the MVP; library-function
harnessing is assisted + human-in-the-loop.

## 7.1 Input-vector discovery
Find where untrusted data enters, using static taint (doc 05) + a light dynamic probe:
- **argv, stdin, env**, **files** (path from argv/config), **network sockets**, **IPC/shared mem**, ioctl.
- Classify each vector: reachability, size, structure (does it parse a format? magic bytes?).
- Output a ranked **Vector Spec** the harness builder consumes.

## 7.2 Harness generation
- **Whole-program (MVP, reliable):** wrap the real entrypoint; feed the fuzzer via file/stdin/argv. For
  file inputs, use AFL++ `@@`; for stdin, stdin mode. Minimal environment fabrication needed.
- **Library-function (advanced, human-in-the-loop):** synthesize a driver that sets up arguments/buffers/
  preconditions and calls the target function, using **deterministic templates** driven by the recovered
  prototype/types (doc 04). The tool proposes a skeleton harness (allocate buffers for pointer args, wire the
  fuzz input to the tainted parameter); the **analyst reviews and hand-tunes** it. We compile/emulate and
  validate it doesn't trivially crash on setup. No LLM — this is the honest limit: auto-harnessing library
  functions is assisted, not automatic.
- **Emulation harness (no runnable program):** drive a single function under Unicorn/Qiling with a
  synthesized state (doc 06 T0) — lets us fuzz code that can't be launched as a process.
- Persist harnesses as first-class, editable artifacts (analyst can hand-tune generated ones).

## 7.3 Seed corpus & dictionaries (cheap, high impact)
- Mine the binary for **strings, magic bytes, constants, format tokens** → dictionary + initial seeds.
- **Structure-aware seed generation from known format definitions:** where the input format is known (or an
  analyst supplies a grammar/template), generate valid structured inputs (e.g., a well-formed header) so the
  fuzzer starts past the parser. Deterministic; grammar-based, not model-generated.
- Corpus minimization (afl-cmin/tmin) and periodic distillation during the campaign.

## 7.4 Fuzzing engines & modes
- **Substrate: LibAFL** (composable Rust) so we run *one* configurable engine with pluggable backends
  instead of shelling out to many. Fall back to stock **AFL++** where it's simplest.
- **Binary-only backends:** AFL++/LibAFL **qemu-mode**, **frida-mode**, or static rewrite (**RetroWrite**).
- **Snapshot fuzzing: Nyx** (KVM+QEMU) for stateful, kernel, and network targets (up to 300× throughput; doc 16).
- **Source available (rare):** libFuzzer/AFL++ with ASan.
- **Structure-aware:** grammar/format-aware mutators for structured inputs.
- Feature set: CmpLog/RedQueen (magic-value bypass), persistent mode, parallel multi-core with shared corpus.

## 7.5 Hybrid & directed fuzzing (get past plateaus and reach candidates)
- **Hybrid concolic:** pair the fuzzer with **SymQEMU** (binary, no pre-instrumentation) or a **QSYM**-style
  engine; when coverage stalls, the symbolic side solves the hard branch and injects a new seed (Driller
  pattern). **Fuzzolic / SymFusion / LeanSym / SymSAN** are scalability-tuning alternatives (doc 16); LibAFL's
  concolic-tracing module wires them in.
- **Directed greybox fuzzing** toward a specific finding, all deterministic (doc 16): **BEACON** (provable
  path pruning), **SelectFuzz** (target-relevant path selection), **WindRanger** (data-flow fitness, pairs
  with our taint), **AFLGopher** (feasibility-aware), and **SAST-guided** fuzzing that drives directly from
  static findings — so a static candidate (doc 05) gets *confirmed* fast rather than
  waiting for blind coverage to stumble onto it. This is the key candidate→confirmed accelerator.

## 7.6 Campaign orchestration
- Managed by the job engine (doc 02): multiple parallel fuzzers + a symbolic solver + a directed instance,
  sharing one corpus, under the resource governor (don't melt the box).
- **Live metrics** to the GUI (doc 09): execs/sec, edge coverage over time, unique crashes, corpus size,
  stability, last-new-path time. Campaigns **checkpoint** and **resume** with the case.
- Auto-stop heuristics (coverage saturation, time budget) + analyst manual control.
- Every unique crash flows to triage (doc 08).
