# 00 — Overview, Goals, and Honest Feasibility

## Vision
A single air-gapped Linux workstation app that takes an arbitrary binary and drives it through the full
offensive-analysis lifecycle — load → reverse engineer → detect weaknesses → confirm dynamically →
demonstrate with a PoC — inside one coherent, styled analyst workflow.

## Primary users
- **Vulnerability researcher / exploit developer** on an authorized engagement.
- **Reverse engineer** triaging unknown or custom binaries.
- **Red-team operator** who needs a demonstrable PoC to prove impact to a client.

The tool is single-operator per workstation but multi-*case*. It is not a SaaS and not multi-tenant.

## Capability tiers (set expectations honestly)
These capabilities are not equal in maturity. Be explicit internally about what is *solved engineering*
vs *frontier research*, so the roadmap does not over-promise.

| Capability | Reality | Our stance |
|---|---|---|
| Load ELF/PE/Mach-O, disassemble, decompile | Solved (Ghidra/rizin) | Orchestrate + present |
| CFG/callgraph/xref, string/const analysis | Solved | Orchestrate + present |
| Stripped-binary function recovery via signatures | Mostly solved (FLIRT/FCG/sig DBs) | Bundle DBs + ML assist |
| Static CWE pattern + taint detection | Solved but **noisy** | Orchestrate + confidence scoring |
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

## Non-goals (v1)
- Not a live malware C2/sandbox network emulator (INetSim-style) beyond what dynamic analysis needs.
- Not a source-code SAST tool (we assume binary-only, though we ingest debug info if present).
- Not multi-user collaboration server. Single workstation.
- Not a general disassembler replacement — we embed one.
- Not cloud/online CVE correlation (air-gapped); CVE/version data is bundled and clearly dated.

## Success criteria (v1)
1. Ingest a stripped x86-64 ELF and produce a navigable RE view with recovered functions.
2. Detect at least the memory-safety CWE family with dynamic confirmation.
3. Auto-propose a fuzzing harness for a file/stdin/argv input vector and run a campaign.
4. Triage crashes and emit a reproducible crashing-input PoC bundle with a written report.
5. All of the above with zero network access, from a single installer.
