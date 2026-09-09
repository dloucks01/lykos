# 04 — Stripped-Binary Recovery & Custom Architectures (Zero-AI)

Stripped binaries have no symbols. Recovery is a layered pipeline of **deterministic** techniques — no ML,
no LLM, no GPU (decision doc 15). Each layer annotates the Program IR (doc 03) and raises analyst
confidence; the analyst accepts/rejects any suggestion. The honest boundary: these techniques name the
**plumbing** (libraries, runtime, known code) and expose dangerous calls; a binary's own **custom logic**
stays `sub_xxxx` until a human reverses it — exactly as Ghidra/IDA behave without plugins.

## 4.1 Function boundary & code discovery
- Recursive-descent + linear-sweep disassembly (Ghidra) to separate code from data.
- Compiler-idiom heuristics for function starts (prologue patterns per compiler/arch) — rule-based, not ML.
- Flag likely-inlined regions heuristically so the analyst knows boundaries are approximate.

## 4.2 Language-runtime metadata extraction (nearly free, do it first)
Many "stripped" binaries still leak names/types through runtime metadata. Deterministic extractors recover a
lot with zero inference:
- **Go**: `pclntab` embeds function names + line tables even when stripped → near-full naming.
- **C++**: RTTI, vtables, and mangled names in exception tables → class/method recovery + demangling.
- **Rust**: symbol remnants and panic strings.
- **Swift/Objective-C**: metadata sections; **.NET/Java**: managed metadata (doc 18 bytecode lane).
- **DWARF/PDB**: if any debug info survives, harvest it directly.
- **Exception-handling / unwind tables** (`.eh_frame`): recover precise function boundaries on any ELF.

## 4.3 Signature & known-code identification (the core naming engine)
- **Byte-signature matching:** Ghidra **Function ID (FID)**, IDA-style **FLIRT**, rizin **zignatures**. Ship
  a large bundled signature DB built by compiling common libraries (libc, OpenSSL, zlib, musl, …) across a
  matrix of compilers × versions × optimization levels × architectures (doc 11). Names statically-linked
  library code and, crucially, **surfaces dangerous library calls** (`strcpy`, `system`, `memcpy`) even when
  stripped/static.
- **Prototype & type archives:** once a function is identified, apply its argument/return/struct types
  (Ghidra data-type archives from library headers) and **propagate to call sites** — improves decompilation
  *and* taint (doc 05).
- **libc fingerprinting:** identify the exact libc build (offset DB) — matters for exploitation (doc 08).
- **Crypto-primitive ID (deterministic):** constant-based detection of S-boxes, IVs, primes, magic values →
  names AES/DES/RC4/SHA/RSA routines. No LLM; pure constant/structure matching.

## 4.4 Diff-against-symbolized corpus (highest-ROI for known software)
Bundle a curated corpus of **open-source builds compiled *with* symbols**. Use **BinDiff** (open source),
**Diaphora**, or **Ghidra Version Tracking** to match a stripped target's functions against a symbolized
reference build and **transfer names/types** across. Deterministic: BinDiff derives a per-function signature
from the normalized CFG (blocks/edges/calls) and uses **Weisfeiler-Lehman graph hashing** to build a unique
per-function ID; callgraph-context features (Springer'24) further disambiguate library functions. No ML. For known software (a stripped build of a known OSS version), this recovers large swaths of
names, and it doubles as **known-vulnerability search**: match against the *vulnerable version* of a function
to flag "this resembles CVE-XXXX's buggy `foo`."

## 4.5 Behavioral heuristics (suggestive tags, deterministic)
Rank-and-tag unnamed functions by observable behavior:
- **String/constant references** ("%s: connection from %s", error text) hint at purpose.
- **Import/syscall usage** (a function calling `socket`/`bind`/`listen` = network setup; `open`/`read` = I/O).
- **Call-context** (wrapper around `malloc`/`memcpy`; caller/callee of a named function).
- **Calling-convention analysis** recovers arg counts/types even for unnamed functions (Ghidra, deterministic).
All surfaced as *suggestions* with provenance + a heuristic score; the analyst commits, and committing
propagates through the IR and re-runs dependent analyses.

## 4.6 Custom / unknown instruction sets
Two distinct cases:
1. **Custom file format, known ISA** → a **loader plugin** (doc 02): parse headers, unwrap (decrypt/
   decompress), extract code/data, report arch/base/entry/endianness. The common "custom binary" case
   (**[DECIDED, doc 15]**), and straightforward.
2. **Truly custom / unknown ISA** → author a **SLEIGH processor spec** (Ghidra's processor-definition
   language): guided workspace to define registers, encodings, and semantics, with an interactive test
   harness. Assisted by opcode-frequency/entropy analysis to bootstrap. **Optional / deprioritized** — a
   plugin path, not a v1 requirement. Honest: expert, multi-day work, not automatic.

## 4.7 Deobfuscation & anti-analysis handling (deterministic)
- Detect + unpack common packers (UPX; generic entropy-triggered runtime-unpack via emulation + dump).
- Control-flow flattening / opaque predicates: **symbolic simplification** passes (Triton/miasm-style) —
  deterministic, no ML.
- Flag anti-debug/anti-VM/timing tricks for the sandbox to neutralize (doc 06); log every modification.

## 4.8 Optional AI hook (unshipped)
Per decision doc 15, the shipped package contains **no AI**. A plugin interface is left open so an operator
who later stands up a **local Ollama** instance could add naming/summary *suggestions* — but nothing in the
pipeline depends on it, it is never bundled, and the tool is fully functional without it. A low-quality small
model would hurt more than help, so the default and recommended posture is zero-AI.

## Net expectation
Runtime metadata + signatures + corpus-diffing name most library/runtime/known code and demangle C++/Go;
custom application logic is left to the analyst with strong deterministic assists (types, xrefs, behavioral
tags, decompiled C). This matches how expert reverse engineers actually work.
