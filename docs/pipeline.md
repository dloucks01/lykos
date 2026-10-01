# The Analysis Pipeline

---

## Static Analysis & Reverse Engineering

### Goal
Turn raw bytes into a rich, queryable, architecture-normalized program model that every downstream
analysis and the GUI read from.

### 3.1 Ingestion & loading
- **Triage first:** file type (magic), format parsing (LIEF), hashes, entropy (packing/encryption hint),
  detected packers (UPX etc. → unpack step), embedded files (binwalk-style carving for firmware),
  compiler/toolchain fingerprint, mitigations present (NX, PIE, RELRO, canary, CFI/CET).
- **Loaders (pluggable):** ELF, PE, Mach-O, raw/headerless (wizard: arch, endianness, base addr, entry,
  memory map), firmware blob (carve + map), bytecode (route to appropriate handler). See this document for custom ISAs.
- **Library identity:** detect dynamic deps; for static binaries, identify the linked libc/toolchain via
  bundled signatures (critical for stripped analysis + exploitation later).

### 3.2 Disassembly, decompilation, structure
Primary engine: **Ghidra headless** (Apache-2.0, scriptable, SLEIGH for custom arch, solid decompiler).
Secondary: **rizin/Cutter** for fast interactive disasm and a second opinion; **capstone** for quick linear
sweeps. Produce and persist:
- Instructions + basic blocks + **CFG per function** and a **program callgraph**.
- **Decompiled pseudo-C** per function (Ghidra P-Code → C).
- **Cross-references** (code/data), string table, constants, import/export tables, symbol table (if any).
- **Recovered types & signatures** where possible (Ghidra type propagation; DWARF/PDB if present).

### 3.3 Program IR (the contract for detectors)
Normalize Ghidra **P-Code** (or an equivalent lifted IR) into a stable internal IR so CWE detectors are
architecture-independent. Persist:
- SSA-ish lifted operations, per-function CFG, def-use, call sites with resolved/възможни targets.
- A queryable graph (functions, blocks, calls, data refs) — store in the case DB for fast UI + rule queries.
This IR is what the plugin API exposes. Rules should never touch raw x86 vs ARM directly.

### 3.4 Semantic enrichment
- **API/lib-call resolution:** map calls to known-dangerous functions (`strcpy`, `sprintf`, `system`,
  `memcpy`, `malloc/free`, format-string sinks) — even in stripped binaries via doc-04 recovery.
- **Data-flow / taint (static):** track from input sources (argv/env/read/recv/fread) to dangerous sinks.
  This is the backbone of static CWE candidates.
- **Constant + string intel:** magic values, format strings, hardcoded secrets/paths, crypto constants
  (S-boxes, primes) for algorithm ID.
- **Symbolic summaries (light):** for small functions, compute input→output constraints to feed doc-05.

### 3.5 Outputs consumed downstream
- Function inventory + decomp → GUI RE views + deterministic naming/typing suggestions (`gui.md`).
- IR + taint graph → CWE detectors.
- Recovered signatures + call sites → harness input-vector discovery.
- Mitigations + libc identity → PoC/exploit planning.

---

## Stripped-Binary Recovery & Custom Architectures

Stripped binaries have no symbols. Recovery is a layered pipeline of **deterministic** techniques
(decision `overview.md`). Each layer annotates the Program IR and raises analyst
confidence; the analyst accepts/rejects any suggestion. The honest boundary: these techniques name the
**plumbing** (libraries, runtime, known code) and expose dangerous calls; a binary's own **custom logic**
stays `sub_xxxx` until a human reverses it — exactly as Ghidra/IDA behave without plugins.

### 4.1 Function boundary & code discovery
- Recursive-descent + linear-sweep disassembly (Ghidra) to separate code from data.
- Compiler-idiom heuristics for function starts (prologue patterns per compiler/arch) — rule-based, not ML.
- Flag likely-inlined regions heuristically so the analyst knows boundaries are approximate.

### 4.2 Language-runtime metadata extraction (nearly free, do it first)
Many "stripped" binaries still leak names/types through runtime metadata. Deterministic extractors recover a
lot with zero inference:
- **Go**: `pclntab` embeds function names + line tables even when stripped → near-full naming.
- **C++**: RTTI, vtables, and mangled names in exception tables → class/method recovery + demangling.
- **Rust**: symbol remnants and panic strings.
- **Swift/Objective-C**: metadata sections; **.NET/Java**: managed metadata (`coverage.md` bytecode lane).
- **DWARF/PDB**: if any debug info survives, harvest it directly.
- **Exception-handling / unwind tables** (`.eh_frame`): recover precise function boundaries on any ELF.

### 4.3 Signature & known-code identification (the core naming engine)
- **Byte-signature matching:** Ghidra **Function ID (FID)**, IDA-style **FLIRT**, rizin **zignatures**. Ship
  a large bundled signature DB built by compiling common libraries (libc, OpenSSL, zlib, musl, …) across a
  matrix of compilers × versions × optimization levels × architectures (`offline-packaging.md`). Names statically-linked
  library code and, crucially, **surfaces dangerous library calls** (`strcpy`, `system`, `memcpy`) even when
  stripped/static.
- **Prototype & type archives:** once a function is identified, apply its argument/return/struct types
  (Ghidra data-type archives from library headers) and **propagate to call sites** — improves decompilation
  *and* taint.
- **libc fingerprinting:** identify the exact libc build (offset DB) — matters for exploitation.
- **Crypto-primitive ID (deterministic):** constant-based detection of S-boxes, IVs, primes, magic values →
  names AES/DES/RC4/SHA/RSA routines — pure constant/structure matching.

### 4.4 Diff-against-symbolized corpus (highest-ROI for known software)
Bundle a curated corpus of **open-source builds compiled *with* symbols**. Use **BinDiff** (open source),
**Diaphora**, or **Ghidra Version Tracking** to match a stripped target's functions against a symbolized
reference build and **transfer names/types** across. Deterministic: BinDiff derives a per-function signature
from the normalized CFG (blocks/edges/calls) and uses **Weisfeiler-Lehman graph hashing** to build a unique
per-function ID; callgraph-context features (Springer'24) further disambiguate library functions — all deterministic. For known software (a stripped build of a known OSS version), this recovers large swaths of
names, and it doubles as **known-vulnerability search**: match against the *vulnerable version* of a function
to flag "this resembles CVE-XXXX's buggy `foo`."

### 4.5 Behavioral heuristics (suggestive tags, deterministic)
Rank-and-tag unnamed functions by observable behavior:
- **String/constant references** ("%s: connection from %s", error text) hint at purpose.
- **Import/syscall usage** (a function calling `socket`/`bind`/`listen` = network setup; `open`/`read` = I/O).
- **Call-context** (wrapper around `malloc`/`memcpy`; caller/callee of a named function).
- **Calling-convention analysis** recovers arg counts/types even for unnamed functions (Ghidra, deterministic).
All surfaced as *suggestions* with provenance + a heuristic score; the analyst commits, and committing
propagates through the IR and re-runs dependent analyses.

### 4.6 Custom / unknown instruction sets
Two distinct cases:
1. **Custom file format, known ISA** → a **loader plugin** (`architecture.md`): parse headers, unwrap (decrypt/
   decompress), extract code/data, report arch/base/entry/endianness. The common "custom binary" case
   (**[DECIDED, `overview.md`]**), and straightforward.
2. **Truly custom / unknown ISA** → author a **SLEIGH processor spec** (Ghidra's processor-definition
   language): guided workspace to define registers, encodings, and semantics, with an interactive test
   harness. Assisted by opcode-frequency/entropy analysis to bootstrap. **Optional / deprioritized** — a
   plugin path, not a v1 requirement. Honest: expert, multi-day work, not automatic.

### 4.7 Deobfuscation & anti-analysis handling (deterministic)
- Detect + unpack common packers (UPX; generic entropy-triggered runtime-unpack via emulation + dump).
- Control-flow flattening / opaque predicates: **symbolic simplification** passes (Triton/miasm-style) —
  deterministic.
- Flag anti-debug/anti-VM/timing tricks for the sandbox to neutralize; log every modification.

### 4.8 Optional model hook (unshipped)
The naming stack is deterministic (decision `overview.md`). A plugin interface is left open so an operator
who later stands up a **local model** could add naming/summary *suggestions* — but nothing in the
pipeline depends on it, it is not bundled, and the tool is fully functional without it.

### Net expectation
Runtime metadata + signatures + corpus-diffing name most library/runtime/known code and demangle C++/Go;
custom application logic is left to the analyst with strong deterministic assists (types, xrefs, behavioral
tags, decompiled C). This matches how expert reverse engineers actually work.

---

## Vulnerability (CWE) Detection Engine

### Core principle: a confidence lifecycle, never a flat warning list
Every potential issue is a **Finding** that moves through states, and the UI shows the state + evidence:
```
Candidate  → Corroborated → Confirmed → PoC-backed
(one signal)  (≥2 signals)   (reproduced)  (demonstrable input/bundle)
             + confidence score at each step; analyst can accept/reject/annotate
```
This is the antidote to static-analysis false positives (`internal/01-gap-analysis.md`-B): a hypothesis→validation pipeline, but
with **deterministic** validators only (decision `overview.md`).

### The four detection channels (findings are correlated across all four in the core)
1. **Pattern / rule detectors (static, fast, noisy).** Dangerous API sinks (`strcpy`, `sprintf`, `system`,
   `memcpy`, format-string sinks, `gets`), missing bounds checks, unchecked return values, signedness,
   fixed-size stack buffers near copies. Rules run over the normalized IR so they're arch-independent.
2. **Static taint / data-flow (static, medium cost).** Propagate from input **sources** (argv/env/read/
   recv/fread/mmap) to dangerous **sinks**; a source→sink path is a candidate. Sources/sinks/propagation come
   from a **curated rule set** (dangerous-API catalog + syscall model), extensible via the plugin API.
3. **Symbolic / concolic (medium-high cost, corroborates + generates inputs).** angr / SymCC / SymQEMU
   explore paths to a candidate sink and try to satisfy the "bad" condition (e.g., index > bound). Adopt
   **static-analysis-guided path prioritization** (reachability + candidate-distance heuristics) so we don't
   path-explode. A solved input
   both corroborates the finding and seeds the PoC.
4. **Dynamic (high cost, confirms).** Run under sanitizer/emulation with the fuzzer; a
   crash/UB observation at a candidate site **confirms** it. Fuzzing can be *directed* at a candidate using
   **classical distance-based directed greybox fuzzing** (AFLGo-style: CFG/callgraph distance to the target
   site) to reach it faster — deterministic.

### Correlation & promotion (done in the core, `architecture.md`)
- Findings are keyed by (function, site, CWE-class, tainted-source). When a static candidate's site matches
  a fuzzing crash's faulting IP, or a symbolic solver satisfies its bad condition, the core **promotes** it
  and merges evidence. Same root cause seen by 3 channels = **one** high-confidence finding, not three.

### CWE taxonomy engine
- Ship the **MITRE CWE catalog offline** (dated). A finding carries: CWE ID(s), the *evidence pattern* that
  mapped to it, severity (CVSS-style vector the analyst can adjust), affected function/address, tainted
  input vector, remediation guidance, and links to the PoC bundle.
- Maintain a matrix of **which CWEs are detectable by which channel** so the UI can show coverage honestly
  (e.g., CWE-798 hardcoded creds → static/string channel; CWE-416 UAF → dynamic/sanitizer channel).

### CWE classes and their primary channel (v1 focus in **bold**)
> The full, family-by-family catalog — every in-scope CWE with channel + feasibility, plus the explicit
> out-of-scope list and firmware/hardware (CWE-1194) and managed-bytecode coverage — is **`coverage.md`**.
> The table below is the summary; `coverage.md` is the authority.
| CWE family | Examples | Primary channel |
|---|---|---|
| **Memory safety** | 119/125/787 OOB, **416 UAF**, 415 double-free, 476 NULL-deref | dynamic (QASan/RetroWrite) + symbolic |
| **Stack/heap overflow** | 121/122, 787 | fuzz + sanitizer, corroborate static |
| **Integer** | 190/191 overflow/underflow, 681 conversion | static taint + symbolic |
| **Format string** | 134 | static pattern + taint (fmt arg tainted) |
| **Command/arg injection** | 78, 88 | static taint to `system`/`exec*` |
| **Path traversal** | 22 | static taint to file APIs |
| **Uncontrolled resource** | 400, 401 leaks | dynamic + static |
| Hardcoded secrets/creds | 798, 259 | static string/entropy |
| Crypto misuse | 327/328/330 | constant + FoC crypto-ID + rules |
| Auth/logic | 306, 863 | mostly manual + rule/heuristic hints (analyst-driven) |

### Secondary pattern layer over decompiled C (cheap, deterministic)
Beyond the IR rules, run **Semgrep** or **Weggli** over Ghidra's decompiled pseudo-C as a *cheap complementary
pass*. It reliably catches the obvious class — calls to `strcpy`/`system`/`sprintf`, format-string sinks,
hardcoded-credential strings — accepted as **low precision** because decompiled C is messy (`undefined4`,
`uVar12`, gotos). It is never the backbone; the IR taint/symbolic engines are. The MITRE CWE catalog + the
**Juliet** examples are used to *author and regression-test* these rules (and the IR rules), and for
**known-vulnerable-function similarity** (BinDiff against a corpus of known-buggy functions, the stripped-recovery section.4) — not
for matching source snippets against bytes, which does not survive compilation.

### CVE fingerprint & weaponization
A distinct channel matches a target against **known CVEs** and then tries to *prove* the match, all offline:
- **Fingerprint.** Binary targets are scanned for embedded **library version banners** (OpenSSL/zlib/libpng/
  busybox/…); source projects are scanned for **dependency manifests** (`requirements.txt`,
  `package-lock.json`, `go.mod`, `Cargo.lock`) and **vendored headers** (zlib/openssl/mbedTLS/wolfSSL/
  FreeRTOS). Each identified component + version is matched against the **bundled offline CVE database**
  (OSV match index + NVD-CPE reference, `offline-packaging.md`), yielding findings that carry the component,
  version, CVE(s) and an **exploit-class hint** from the CWE of the matched CVE.
- **Corroborate (`cve_corroborate`).** A matched CVE is linked to a **demonstrated crash** when the pipeline
  has one whose class/site is consistent — turning a version match into corroborated evidence.
- **Weaponize (`cve_poc`).** For a matched CVE, a **per-CVE or CWE-class trigger** is detonated against the
  target; a **verified repro is recorded only when a real fault fires**, never on the version match alone. The
  first authored trigger is **CVE-2022-37434** (zlib `inflate` heap OOB via an oversized gzip `FEXTRA` field),
  which reproducibly aborts real **zlib 1.2.11 under ASan**.

New attack-surface coverage feeds the same findings lifecycle: **embedded config audit** (`embedded_audit`,
e.g. `FreeRTOSConfig.h`), the **integer-overflow-into-allocation** detector (`int_overflow_scan`, CWE-190,
guard-aware, source-level), and **TCP/UDP network fuzzing** of socket servers (`net_fuzz`).

### Optional model hook (unshipped)
Detection is deterministic (decision `overview.md`). The plugin API leaves a hook so an operator with a local model could
add vuln *hypotheses* as extra Candidates — but they would still require deterministic validation before
reaching Confirmed, and nothing depends on the hook.

### Output
Findings feed: the GUI findings board (`gui.md`), the report/SARIF export (`architecture.md`), and the PoC synth
stage for anything reaching Confirmed.

---

## Dynamic Analysis & Sandboxing

> **Threat model:** the target may be malicious. Dynamic analysis = detonating untrusted code. Isolation is
> the backbone, not a feature. (Gap C, `internal/01-gap-analysis.md`.)

### 6.1 Tiered isolation (choose per target/trust)
| Tier | Mechanism | Use for | Escape risk |
|---|---|---|---|
| T0 in-process emulation | Unicorn / Qiling (guest code can't issue host syscalls) | surgical single-function exec, foreign arch | very low |
| T1 process sandbox | bubblewrap / nsjail + seccomp + namespaces + rlimits | benign-ish native same-arch runs | low-med |
| T2 microVM | Firecracker / cloud-hypervisor (KVM) | untrusted native code, fast boot, snapshots | low |
| T3 full-system VM | QEMU-system (+KVM if same arch) | foreign arch, kernel/driver, firmware, max isolation | lowest |

**Default policy:** unknown/untrusted binary → **T2/T3**. Never run untrusted native code in a worker's own
address space. In-process emulation (T0) is safe *only* because emulated guest code cannot make host syscalls.

### 6.2 Containment invariants (always on)
- **No network egress** by default; optional **fake-services** mode (INetSim/FakeNet-style, bundled) when a
  target needs to "see" a network to proceed. All simulated, no real egress.
- **Filesystem:** ephemeral overlay per run; target sees a synthetic rootfs; host FS never mounted writable.
- **Resource caps:** CPU time, wall clock, memory, PID/FD counts, disk quota; hard kill on breach.
- **Snapshot/restore** between runs so state never leaks run-to-run and fuzzing can reset fast.
- **Anti-analysis handling:** detect anti-debug/anti-VM/timing checks (flagged in this document.7) and, where in
  scope, neutralize (patch checks, hide debugger) — but log every modification.

### 6.3 Execution & emulation backends
- **Native + KVM** when workstation arch == target arch (fastest).
- **QEMU user-mode** for foreign-arch userland binaries.
- **QEMU system-mode** for full OS / kernel / driver / firmware targets.
- **Qiling** for OS/syscall emulation with a fabricated environment (great for partial binaries).
- **Unicorn** for raw CPU-only emulation of a single function with a synthesized register/memory state
  (feeds harnessing, the fuzzing section).
- **Firmware/embedded + multi-binary systems:** rehost with **Fuzzware**-style precise MMIO modeling,
  **ES-Fuzz** adaptive MMIO, **GDMA** DMA rehosting (`internal/16-sota-references.md`); run multiple linked/IPC-connected components
  together in one isolation domain with multi-process debugging. **Full treatment in this document.**

### 6.4 Instrumentation, tracing, coverage
- **Coverage:** edge/block coverage via QEMU-mode or DynamoRIO/Frida — the fuel for coverage-guided fuzzing.
- **Tracing:** syscall trace, API/library-call trace, memory-access trace, and a full **execution trace**
  for time-travel/root-cause. Optionally record replayable traces (rr-style where feasible).
- **Binary sanitizers** (memory safety without source — Gap F): **QASan** (QEMU+ASan, cross-arch) as the
  default; **RetroWrite** (static ASan rewrite, low overhead) for x86-64 PIE; **MTSan** for AArch64. These
  turn silent corruption into a labeled, located, deduplicable event.
- **Taint tracking (dynamic):** DTA over QEMU/libdft-style to confirm source→sink at runtime.

### 6.5 Integrated debugger
- **GDB** (+ Python API, GEF/pwndbg-style enrichment) and/or LLDB, driven from the GUI (`gui.md`): breakpoints,
  stepping, register/memory/stack views, heap visualization, watchpoints. Attach to native (T1/T2) or via
  gdbstub to QEMU (T3) and even to Unicorn/Qiling (T0). Reverse-debugging where the backend supports it.
- The debugger is also *programmatic*: triage and PoC stages script it.

### 6.6 What dynamic analysis produces
Coverage maps, traces, crash records (signal, faulting IP, backtrace, sanitizer report), confirmed taint
paths — all correlated back to findings and stored in the case (`architecture.md`).

---

## Harness Synthesis & Fuzzing Orchestration

Auto-harnessing is the hardest engineering piece (Gap E). Split it into discovery → target → environment →
seeds → instrumentation → campaign. Whole-program vectors are tractable and are the MVP; library-function
harnessing is assisted + human-in-the-loop.

**Implemented (2026-09):** in addition to the blind + breakpoint-coverage engine, a **`libfuzzer`
stage** builds an `LLVMFuzzerTestOneInput` harness with `-fsanitize=fuzzer,address,undefined` and runs
coverage-guided libFuzzer over a source target — using an **in-tree** harness when the project ships one,
or a **synthesized** one for an entry function (analyst-named, or auto-picked: a non-static function whose
first parameter is a `char*`/`uint8_t*` — a parser). It fuzzes **libraries with no `main`** (the blind
engine cannot) and handles **C++** by declaring the target with its real signature so name mangling
resolves. Each crash is a `confirmed` finding classified from the sanitizer report (CWE + source
file:line). Source **projects** (multi-file / Makefile / CMake / autotools) build via a compiler wrapper
that forces the sanitizer flags through the project's own build; a library with no `main` links to a
shared object so it still ingests.

### 7.1 Input-vector discovery
Find where untrusted data enters, using static taint + a light dynamic probe:
- **argv, stdin, env**, **files** (path from argv/config), **network sockets**, **IPC/shared mem**, ioctl.
- Classify each vector: reachability, size, structure (does it parse a format? magic bytes?).
- Output a ranked **Vector Spec** the harness builder consumes.

### 7.2 Harness generation
- **Whole-program (MVP, reliable):** wrap the real entrypoint; feed the fuzzer via file/stdin/argv. For
  file inputs, use AFL++ `@@`; for stdin, stdin mode. Minimal environment fabrication needed.
- **Library-function (advanced, human-in-the-loop):** synthesize a driver that sets up arguments/buffers/
  preconditions and calls the target function, using **deterministic templates** driven by the recovered
  prototype/types. The tool proposes a skeleton harness (allocate buffers for pointer args, wire the
  fuzz input to the tainted parameter); the **analyst reviews and hand-tunes** it. We compile/emulate and
  validate it doesn't trivially crash on setup. This is the honest limit: auto-harnessing library
  functions is assisted, not automatic.
- **Emulation harness (no runnable program):** drive a single function under Unicorn/Qiling with a
  synthesized state (the dynamic-analysis section T0) — lets us fuzz code that can't be launched as a process.
- Persist harnesses as first-class, editable artifacts (analyst can hand-tune generated ones).

### 7.3 Seed corpus & dictionaries (cheap, high impact)
- Mine the binary for **strings, magic bytes, constants, format tokens** → dictionary + initial seeds.
- **Structure-aware seed generation from known format definitions:** where the input format is known (or an
  analyst supplies a grammar/template), generate valid structured inputs (e.g., a well-formed header) so the
  fuzzer starts past the parser. Deterministic; grammar-based, not model-generated.
- Corpus minimization (afl-cmin/tmin) and periodic distillation during the campaign.

### 7.4 Fuzzing engines & modes
- **Substrate: LibAFL** (composable Rust) so we run *one* configurable engine with pluggable backends
  instead of shelling out to many. Fall back to stock **AFL++** where it's simplest.
- **Binary-only backends:** AFL++/LibAFL **qemu-mode**, **frida-mode**, or static rewrite (**RetroWrite**).
- **Snapshot fuzzing: Nyx** (KVM+QEMU) for stateful, kernel, and network targets (up to 300× throughput; `internal/16-sota-references.md`).
- **Source available (rare):** libFuzzer/AFL++ with ASan.
- **Structure-aware:** grammar/format-aware mutators for structured inputs.
- Feature set: CmpLog/RedQueen (magic-value bypass), persistent mode, parallel multi-core with shared corpus.

### 7.5 Hybrid & directed fuzzing (get past plateaus and reach candidates)
- **Hybrid concolic:** pair the fuzzer with **SymQEMU** (binary, no pre-instrumentation) or a **QSYM**-style
  engine; when coverage stalls, the symbolic side solves the hard branch and injects a new seed (Driller
  pattern). **Fuzzolic / SymFusion / LeanSym / SymSAN** are scalability-tuning alternatives (`internal/16-sota-references.md`); LibAFL's
  concolic-tracing module wires them in.
- **Directed greybox fuzzing** toward a specific finding, all deterministic (`internal/16-sota-references.md`): **BEACON** (provable
  path pruning), **SelectFuzz** (target-relevant path selection), **WindRanger** (data-flow fitness, pairs
  with our taint), **AFLGopher** (feasibility-aware), and **SAST-guided** fuzzing that drives directly from
  static findings — so a static candidate gets *confirmed* fast rather than
  waiting for blind coverage to stumble onto it. This is the key candidate→confirmed accelerator.

### 7.6 Campaign orchestration
- Managed by the job engine (`architecture.md`): multiple parallel fuzzers + a symbolic solver + a directed instance,
  sharing one corpus, under the resource governor (don't melt the box).
- **Live metrics** to the GUI (`gui.md`): execs/sec, edge coverage over time, unique crashes, corpus size,
  stability, last-new-path time. Campaigns **checkpoint** and **resume** with the case.
- Auto-stop heuristics (coverage saturation, time budget) + analyst manual control.
- Every unique crash flows to triage.

### 7.7 Closing the coverage loop (hybrid fuzzing)
Low block coverage means the search stalled at a **guarded branch** — a magic value, a length
check — that a blind mutator cannot pass. The Autopilot closes the loop automatically:
1. **Corpus compounds across stages.** `directed_fuzz` seeds every run from the target's
   accumulated *interesting* inputs — concolic-solved inputs first, then prior crashers
   (`_prior_corpus`) — instead of restarting from string-mined tokens. Coverage carries forward.
2. **Coverage-gated concolic.** When a campaign leaves the binary under-covered (block
   coverage `< 60%`) or found nothing, concolic execution (angr / SymQEMU) **solves the branch
   constraint** for an input that takes it.
3. **Re-fuzz from the solved inputs.** A follow-up `directed_fuzz` automatically reuses concolic's
   generated inputs as seeds, so the mutator explores *around* the branch concolic just unlocked —
   reaching the code beyond it.

Measured on a magic-gated target: blind fuzzing reached **8/18 blocks, 0 crashes**; after
concolic solved the gate and the re-fuzz reseeded from it, **18/18 blocks (100%), 156 crashes**.
Both the interactive (`app/autopilot.js`) and background (`analyze/orchestrate.py`) Autopilots
run this loop; a content-addressed cache hit re-projects the recovered functions/blocks first,
so a re-analysed binary is never fuzzed blind.

---

## Crash Triage, Root Cause, PoC Synthesis & Reporting

**Implemented L3 strategies (`build_exploit`, 2026-09).** Each is confirmed by a live shell echoing a
marker, a breakpoint reached with a negative control, or the win path's observable output — never
asserted:
- `ret2win` (ISA-neutral, incl. 32-bit stack args) · `rop`/`ret2system` · `execve`-syscall ROP ·
  `srop` (one-shot + 2-stage `/bin/sh` plant) · `ret2csu`.
- `ret2libc` — no-PIE puts-leak, PIE pure-libc, and a **one-gadget** fallback (`rop.find_one_gadgets`,
  no external tool) · `canary` (leak the canary → ret2libc), with a self-contained live re-driver.
- `magic` — overwrite a magic-checked local to reach a gated flag path (no leak/gadgets, PIE-safe).
- `format` — a positional `%hhn` write-what-where over a post-sink GOT slot.
- `heap` — automated glibc heap → shell (unsorted-bin leak → tcache poison of `_IO_2_1_stdout_` →
  House of Apple 2), driven by menu op templates, with a standalone re-driver in the bundle.
- `mprotect` shellcode · `shellcode` — inject `execve("/bin/sh")` into an executable input buffer the
  target jumps to, with a **bad-char XOR encoder** (`shellcode.encode_avoiding`) for filtered input.

The PoC bundle is inspectable in the workbench (Reproduce / Payload hexdump / Technique / Files),
served by `GET /artifacts/{sha}/bundle`.

### 8.1 Crash triage
- **De-duplication:** cluster crashes by normalized stack hash / faulting-IP + call context. Thousands of
  fuzzer crashes → a handful of unique bugs. Use **CASR** (crash analysis + dedup) as the engine.
- **Minimization:** shrink each crashing input (afl-tmin) to the smallest reliable reproducer.
- **Classification:** signal type, read vs write, near-null vs wild, sanitizer verdict (heap-overflow / UAF /
  double-free / stack-overflow), and an **exploitability score** (CASR / `!exploitable`-style heuristics:
  PC control? corrupted return addr? controllable write target?).
- Attach each crash to its finding and promote the finding to **Confirmed**.

### 8.2 Root-cause analysis
- **Backward slicing / time-travel:** from the faulting instruction, walk the recorded execution trace back to the tainted input bytes and the originating bug (e.g., the missing bounds check).
- **Symbolic replay:** re-run the crashing input under angr/Triton to recover the exact constraint that
  makes it fail and to identify controllable bytes (the basis for the PoC ladder below).
- **Analyst explanation (templated):** the tool renders the slice + decompiled context + evidence into a
  structured root-cause + remediation writeup from templates (not generated prose); the analyst edits.

### 8.3 PoC ladder (define what "PoC" means — Gap H)
Each level is a **demonstrable bundle**; the tool claims only the level it actually achieved.
**Commitment [DECIDED, `overview.md`]:** L0+L1 are the guaranteed product baseline; L2 is supported best-effort and
proves impact; L3 is a scoped, analyst-in-the-loop research track, never advertised as push-button.
| Level | Demonstrates | How produced | Feasibility |
|---|---|---|---|
| **L0 Repro** | input reaches the vulnerable state | symbolic/directed input | high |
| **L1 Crash** | memory-safety crash + sanitizer report | fuzzer + sanitizer minimized input | high |
| **L2 Primitive** | control of a primitive (PC control, write-what-where, leak) | symbolic analysis of controllable bytes; heap-primitive detection (DEPA/AAHEG-style) | medium |
| **L3 Exploit** | working exploit (ROP→shell, etc.) | template-driven AEG, scoped | **frontier / stretch** |

### 8.4 PoC synthesis engine
- **Input-generating PoC (L0/L1):** the symbolic/concolic solver's satisfying input, minimized, plus the
  harness + environment needed to fire it.
- **Primitive PoC (L2):** identify controllable bytes → offsets, compute overflow offset to saved return
  address / function pointer, detect heap layout primitives (**MAZE** Dig&Fill for layout, **ARCHEAP**/
  **AAHEG** for fastbin/unlink strategies, `internal/16-sota-references.md`). Demonstrate control, e.g., set PC to a chosen value.
- **Exploit PoC (L3, scoped):** template library (ret2win, ret2libc/ROP with a bundled gadget finder like
  ROPgadget/ropper, format-string write) + pwntools-style scripting. Honest ceiling: even DARPA CGC fully
  auto-exploited only one heap bug. Provide *assisted* exploitation with analyst-in-the-loop, not push-button.
- **Bundle contents (every PoC):** input file(s), harness, environment/rootfs spec, a self-contained **runner
  script**, the expected observable (crash signature / controlled register / popped shell), a recorded
  **asciinema/video** of it firing, and the isolation tier it was validated in. Re-runnable offline, standalone.
- **Verification:** every PoC is re-executed from its bundle in a clean sandbox before it's marked valid —
  no PoC is trusted until it reproduces from scratch.

### 8.6 End-effect model — what the defect can *achieve*, and whether we proved it
A crash is the entry point, not the conclusion. Every crash finding carries a structured list of
the **end effects** an attacker can drive it toward, each with a truthful status and, when
demonstrated, the **artifact that proves it**:

| Effect | Kind | Demonstrated by | Proof |
|---|---|---|---|
| **Denial of service** | `dos` | any reproducible crash | the crashing input |
| **RCE / control-flow hijack** | `rce` | poc_primitive confirms instruction-pointer control (L2), or build_exploit lands a working exploit (L3) | the L2 primitive bundle / L3 exploit bundle |
| **Memory corruption (arbitrary write)** | `memory-corruption` | poc_primitive confirms write-what-where | the L2 bundle |
| **Information disclosure (memory leak)** | `info-disclosure` | a format-string probe leaks live memory (its bytes, incl. secrets, captured) | the leaked-bytes artifact |
| **Command / code injection** | `injection` | synthesize_injection runs an injected command | the PoC bundle |

Status is **`demonstrated`** (a PoC achieves it, with a downloadable proof) or **`potential`**
(the defect class can reach it, but it was not demonstrated — e.g. ASan aborts a source build
before control can be seized, so RCE stays potential and DoS is demonstrated). Effects only ever
**promote** across the pipeline (root_cause files the ceiling → poc_primitive/build_exploit mark
what they achieve), and the finding **headlines the most severe achievable effect** rather than
"reproduced crash". Derived deterministically from the root-cause class + confirmed primitives
(`analyze/debug/exploitability.py`); never over-claimed.

### 8.5 Reporting & export
- **Analyst report:** per-finding — CWE mapping, severity/CVSS vector, root cause, evidence trail (which
  channels fired, coverage, solved constraints), remediation, and the PoC bundle + recording. HTML + PDF,
  fully offline templating.
- **SARIF export** for interop with other tooling/pipelines.
- **Machine-readable case export** (JSON) of all findings/artifacts for archival or transfer.
- Reports embed tool + signature-DB + model versions and input hashes so results are reproducible (`architecture.md`).

---

## Multi-Binary / Inter-Component & Firmware Analysis

Real targets are rarely one binary. A vulnerability often *crosses a boundary*: attacker data enters
component A and reaches a dangerous sink in component B. This document adds cross-component analysis and the
firmware/embedded track. Both are **[DECIDED in scope]** (`overview.md`).

### 17.1 The component graph (the unifying model)
Model a case as a set of **Components** (binaries/modules/tasks) connected by typed **edges**:
| Edge type | Example | How discovered |
|---|---|---|
| **Dynamic link** | httpd → libcfg.so exported `cfg_get` | import/export tables, PLT/GOT resolution across case targets |
| **dlopen / plugin** | host loads modules at runtime | string/const refs to module paths + dynamic trace |
| **IPC** | unix/tcp socket, pipe, shared mem, message queue | matched syscall pairs (bind/connect, shmget key, mq name) |
| **RPC / message bus** | D-Bus, protobuf-over-socket | interface-name/const detection + dynamic trace |
| **File / config** | A writes, B reads a state file | taint to file APIs with matching paths |
| **exec / spawn** | A `execve`s B with argv | call-site args + process tree |
This graph is a first-class case artifact (`architecture.md`) and a GUI **System Map** view (`gui.md`): nodes are
components (arch/format/mitigations), edges are relationships, and findings can span an edge.

### 17.2 Cross-binary static analysis
- **Case-wide callgraph:** resolve each component's imports against the exports of every other component in
  the case (versioned symbol matching for stripped libs via signatures + corpus-diff, the stripped-recovery section). Produce one merged
  call graph spanning binaries, not N isolated ones.
- **Cross-binary taint:** propagate taint *through* a resolved inter-binary call (A's tainted arg →
  B's parameter → B's sink) and *across* IPC by modeling each channel as a paired **taint sink (send) →
  taint source (recv)** with a "channel contract" (what serializes across). This is how a source in A and a
  sink in B become one **cross-component finding**.
- **This is a solved deterministic problem (`internal/16-sota-references.md`):** our component graph is essentially **Karonte's
  Binary Dependency Graph** (S&P'20 -- 46 zero-days across 53 firmware images with pure static taint). Adopt
  its patterns plus **SaTC** (shared-keyword front-end/binary taint), **BPDA** (faster + more precise), and
  **Mango** (scalable taint-style discovery). Study these before building the taint engine.
- **Interface/contract inference:** for opaque IPC, infer the message schema (from serialization code /
  constants / observed traffic) so the fuzzer knows the structure to mutate.

### 17.3 Multi-binary dynamic analysis
- **Whole-system detonation:** run the entire component set together in one isolation domain (system-mode
  QEMU or a microVM, the dynamic-analysis section) so *real* IPC/linking happens; snapshot the whole system, not one process.
- **Selective emulation:** or run one component under Qiling with the others **stubbed/modeled** (fast, but
  requires channel contracts). Choose per goal.
- **Multi-process debugging:** follow-fork/exec, attach to spawned children, set breakpoints across
  processes, and correlate a crash in B back to the input that entered A (**cross-boundary blame**).

### 17.4 Multi-binary harnessing & fuzzing
- **Boundary-driven harness:** fuzz a server by driving its socket; fuzz a library by generating a caller;
  fuzz a producer→consumer pair by mutating the channel between them.
- **Blame + attribution:** record `(entry component, entry vector) → (crashing component, faulting site)` so
  a crash deep in B is traced to the reachable input in A.
- Directed fuzzing (classical CFG/callgraph distance, AFLGo-style) can steer across the merged callgraph
  toward a cross-component candidate.

### 17.5 Firmware / embedded rehosting track
A firmware image is the extreme multi-component case (bootloader + kernel + tasks + services) *and* needs
hardware it doesn't have. Rehosting = emulate it faithfully enough to execute/fuzz. Adopt (`internal/16-sota-references.md`):
- **Peripheral / MMIO modeling:** **Fuzzware** (precise MMIO models) + **ES-Fuzz** (adaptive MMIO chunks)
  so reads from unmodeled hardware don't dead-end execution.
- **DMA rehosting:** **GDMA** (iterative type overlays) for DMA-driven firmware.
- **Interrupts/timers:** Unicorn/QEMU with modeled NVIC + systick (Fuzzware approach).
- **Network stacks:** **protocol-aware rehosting** (CCS'25) for embedded network services.
- **System-level symbolic:** **SysFuSS** (2026) -- selective symbolic execution over rehosted firmware to
  reach deep states deterministically.
- **Image decomposition:** carve the image (binwalk-style), identify base address/entry, split into
  components, and feed them into the component graph (17.1). Bare-metal blobs use the headerless loader
  wizard (the stripped-recovery section.6) with the target arch (ARM/PPC/MIPS, `overview.md`).
- **Fidelity ladder:** partial (single task under Unicorn+models) → full-system (whole image under QEMU) →
  hardware-in-the-loop is **out of scope** (offline, no device farm).

### 17.6 What it produces
A merged component graph, cross-component findings with source/sink in different binaries, whole-system
crash reproductions, and firmware-task-level PoCs — all in the same case data model (`architecture.md`) and findings
lifecycle.
