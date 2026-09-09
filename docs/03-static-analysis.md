# 03 — Static Analysis & Reverse Engineering

## Goal
Turn raw bytes into a rich, queryable, architecture-normalized program model that every downstream
analysis and the GUI read from.

## 3.1 Ingestion & loading
- **Triage first:** file type (magic), format parsing (LIEF), hashes, entropy (packing/encryption hint),
  detected packers (UPX etc. → unpack step), embedded files (binwalk-style carving for firmware),
  compiler/toolchain fingerprint, mitigations present (NX, PIE, RELRO, canary, CFI/CET).
- **Loaders (pluggable):** ELF, PE, Mach-O, raw/headerless (wizard: arch, endianness, base addr, entry,
  memory map), firmware blob (carve + map), bytecode (route to appropriate handler). See doc 04 for custom ISAs.
- **Library identity:** detect dynamic deps; for static binaries, identify the linked libc/toolchain via
  bundled signatures (critical for stripped analysis + exploitation later).

## 3.2 Disassembly, decompilation, structure
Primary engine: **Ghidra headless** (Apache-2.0, scriptable, SLEIGH for custom arch, solid decompiler).
Secondary: **rizin/Cutter** for fast interactive disasm and a second opinion; **capstone** for quick linear
sweeps. Produce and persist:
- Instructions + basic blocks + **CFG per function** and a **program callgraph**.
- **Decompiled pseudo-C** per function (Ghidra P-Code → C).
- **Cross-references** (code/data), string table, constants, import/export tables, symbol table (if any).
- **Recovered types & signatures** where possible (Ghidra type propagation; DWARF/PDB if present).

## 3.3 Program IR (the contract for detectors)
Normalize Ghidra **P-Code** (or an equivalent lifted IR) into a stable internal IR so CWE detectors are
architecture-independent. Persist:
- SSA-ish lifted operations, per-function CFG, def-use, call sites with resolved/възможни targets.
- A queryable graph (functions, blocks, calls, data refs) — store in the case DB for fast UI + rule queries.
This IR is what the plugin API exposes. Rules should never touch raw x86 vs ARM directly.

## 3.4 Semantic enrichment
- **API/lib-call resolution:** map calls to known-dangerous functions (`strcpy`, `sprintf`, `system`,
  `memcpy`, `malloc/free`, format-string sinks) — even in stripped binaries via doc-04 recovery.
- **Data-flow / taint (static):** track from input sources (argv/env/read/recv/fread) to dangerous sinks.
  This is the backbone of static CWE candidates (doc 05).
- **Constant + string intel:** magic values, format strings, hardcoded secrets/paths, crypto constants
  (S-boxes, primes) for algorithm ID.
- **Symbolic summaries (light):** for small functions, compute input→output constraints to feed doc-05.

## 3.5 Outputs consumed downstream
- Function inventory + decomp → GUI RE views + deterministic naming/typing suggestions (doc 04/09).
- IR + taint graph → CWE detectors (doc 05).
- Recovered signatures + call sites → harness input-vector discovery (doc 07).
- Mitigations + libc identity → PoC/exploit planning (doc 08).
