# 01 — Gap Analysis: What's Missing From the Current Plan

Your goal is clear and coherent. But the phrases "analyze a binary," "even if stripped," "full dynamic
analysis," and "create a PoC" each hide several unstated decisions and several missing subsystems. This
document lists every gap I see, grouped by theme, with a recommended default so the plan stays actionable.

---

## A. Scope of "a binary" is undefined — and it drives the whole architecture

1. **Which architectures?** x86/x86-64 is easy. ARM/AArch64, MIPS, PowerPC, RISC-V, SPARC each need
   their own disassembler/emulator/gadget support. *Recommendation:* MVP = x86-64 + AArch64; design the
   loader/emulator layer arch-agnostic so more can be added.
2. **Which file formats?** ELF, PE, Mach-O, raw firmware blobs, U-Boot images, bare-metal binaries with
   no headers, bytecode (JVM/.NET/Python/Lua/WASM), packed/UPX, and *your* "custom binary" format.
   Each needs a **loader**. A headerless blob needs a base-address + entry-point + memory-map story.
   *Recommendation:* pluggable loader interface; ship ELF/PE/Mach-O + a "raw/custom" loader wizard.
3. **What does "custom binary" mean?** Two very different things:
   - a custom *file format* wrapping a known ISA → write a loader plugin.
   - a custom/unknown *instruction set* → you must author a processor spec (Ghidra SLEIGH). This is a
     specialist task and a real feature, not a checkbox. *See doc 04.*
4. **Static vs dynamic linking, and libc identity.** For stripped binaries, recognizing the exact libc
   is essential to name library calls and to build exploits. You need a bundled libc-signature DB and a
   statically-linked-libc function identifier.

## B. False positives are the core problem you haven't addressed

"Determine if it is vulnerable to any CWE" implies a yes/no. Static binary analysis produces **large
numbers of false positives**. Without a validation loop you will drown the analyst in noise. Missing:
- A **finding lifecycle**: `Candidate → Corroborated (multiple signals agree) → Confirmed (dynamic/symbolic
  reproduction) → PoC-backed`. Nothing is reported as "vulnerable" without reproduction.
- A **confidence score** and the *evidence* behind it (which analyses fired, coverage reached, constraints solved).
- **De-duplication and correlation** so the same root bug seen by three analyses is one finding.
*This is arguably the single most important addition to your plan.* See doc 05 and doc 08.

## C. Running untrusted binaries safely — completely absent from your plan

"Full dynamic analysis… execute and debug and fuzz" means **detonating untrusted, possibly malicious
code**. Your plan has no isolation story. Required additions:
- Tiered isolation: seccomp/namespaces (bubblewrap/nsjail) for cheap runs; **microVM (Firecracker/KVM)
  or full QEMU-system** for anything untrusted; snapshot/restore for fuzzing throughput.
- **Network containment** (no egress; a fake-services option if the target expects network).
- **Filesystem/resource quotas**, wall-clock kill switches, and snapshot rollback between runs.
- A policy that dynamic analysis of an *unknown* binary defaults to the strongest isolation tier.
See doc 06 — this is a backbone subsystem, not a nice-to-have.

## D. Cross-architecture / no-native-hardware execution

If the target is a different arch than the workstation, or expects peripherals/an OS it can't get, you
cannot "just run it." Missing: an **emulation strategy** — QEMU user-mode, QEMU system-mode, and
**Qiling/Unicorn** for surgical emulation of a single function with a synthesized environment. This also
unlocks fuzzing binaries that can't otherwise be launched. See doc 06/07.

## E. Harness synthesis is treated as a given — it's the hard part

"Building a harness" automatically is genuinely difficult. It decomposes into problems you haven't split out:
1. **Input-vector discovery** — where does untrusted data enter? argv, stdin, files, env, sockets, IPC,
   shared memory, cmdline of a sub-tool. Requires taint/data-flow from input syscalls.
2. **Target selection** — which function to fuzz? An entrypoint (easy) vs a deep library function that
   needs a synthesized calling context (hard).
3. **Environment synthesis** — for library-function fuzzing you must fabricate arguments, allocate/point
   buffers, and set up preconditions. This is where most auto-harnessing fails.
4. **Seed corpus + dictionary** — extract strings/constants/magic bytes from the binary to seed the fuzzer.
5. **Instrumentation choice** — source? (rare) libFuzzer/ASan. Binary-only? AFL++ qemu-mode / frida-mode /
   static rewriting (RetroWrite) / Nyx snapshot fuzzing.
*Recommendation:* MVP auto-harnesses the *whole-program* vectors (argv/stdin/file) which is tractable;
library-function harnessing is human-in-the-loop with strong assists. See doc 07.

## F. Sanitizers without source

You'll want ASan-style detection (heap overflow, UAF) but you have no source to recompile with `-fsanitize`.
Missing: binary-level memory-safety instrumentation — **QASan** (QEMU-ASan), **Valgrind/memcheck**,
**RetroWrite** (static rewriting to add ASan), or Frida-based checks. Pick per-arch capability. See doc 06.

## G. Reaching deep code / generating inputs — symbolic execution not mentioned

Fuzzing alone won't pass hard checks (magic values, checksums). You need **concolic/symbolic execution**
(angr, or a Triton-based concolic engine) to solve path constraints, and hybrid fuzzing (fuzzer + symbolic
solver, à la Driller/QSYM) to get past coverage plateaus. This is also your main **PoC-input generator**
for reaching a vulnerable state. See doc 05/08.

## H. What exactly is a "PoC"? Define the ladder.

"Create a PoC" spans a huge difficulty range. Define levels explicitly so the tool can claim honestly:
- **L0 Repro:** an input that triggers the detected condition (e.g., reaches the vulnerable line).
- **L1 Crash:** an input that crashes with a memory-safety signal + sanitizer report.
- **L2 Control:** an input that demonstrates control of a security-relevant primitive (PC control, write-what-where).
- **L3 Exploit:** a working exploit (ROP chain, shell, etc.) — **frontier / scoped stretch goal only.**
Each PoC is a *bundle*: input file(s), harness, env, a runner script, expected observable, and a recorded
trace/asciinema so it's demonstrable. See doc 08.

## I. CWE mapping needs a real engine, not a lookup

CWEs are detected by very different techniques (a format-string bug ≠ a hardcoded-credential ≠ an integer
overflow). Missing: a **taxonomy engine** that maps *evidence patterns* → CWE IDs, tracks which CWEs are
even detectable statically vs only dynamically, and attaches severity + remediation. Ship the MITRE CWE
catalog offline. See doc 05.

## J. Cross-cutting subsystems you didn't mention but must build
- **Project/case data model + persistence** (SQLite + artifact store) so long campaigns resume. Doc 12.
- **Job/pipeline orchestration** — analyses are long-running, parallel, resumable, cancellable. Doc 02.
- **Reporting/export** — HTML/PDF reports + **SARIF** export for interop with other tooling. Doc 08/12.
- **Reproducibility** — hash every input/artifact and pin tool versions so a finding re-runs identically. Doc 12.
- **Extensibility / plugin API** — custom loaders, custom CWE rules, custom detectors, Python scripting. Doc 02.
- **A benchmark/validation corpus** to measure detection rate and FP rate (Juliet, LAVA-M, CGC, real CVEs). Doc 14.
- **Air-gapped update mechanism** — signed offline update packages (sig DBs, CVE data, models). Doc 11.
- **Resource governance** — a single box running Ghidra + fuzzers + VMs will thrash; need a scheduler/quotas.

## K. The GUI is under-specified for this domain
"Highly stylized and organized" is the right instinct, but this class of tool needs specialized views most
apps don't: disassembly + decompiler panes, interactive CFG/callgraph graphs, a hex viewer, a live debugger
UI, a fuzzing dashboard (coverage/exec-speed/crashes over time), and a findings board with the confidence
lifecycle. This is IDA/Ghidra/Binary-Ninja-class UI work. See doc 09.

---

## Reframed one-line scope
> An offline analyst workstation that **orchestrates** best-in-class RE/fuzzing/symbolic tools behind one
> data model and one styled UI, turning noisy static candidates into **reproduced, PoC-backed, CWE-tagged
> findings**, while safely detonating untrusted binaries in tiered isolation.
