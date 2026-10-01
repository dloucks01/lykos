# Coverage & Validation

---

## Architecture Coverage Matrix (All Targets)

**Scope decision:** the platform aims to cover *every practical target ISA*, native and bytecode. We do this
without per-arch rewrites by standing on **architecture-neutral IR** (Ghidra P-Code and angr/VEX): CWE
detectors (`pipeline.md`) and the data model are written **once** against IR, so adding an architecture is
*wiring* (loader + disasm + emulator + sanitizer + gadget backends), never new analysis logic.

### Coverage tiers (by tooling maturity + effort, not importance)
Each architecture gets a **level per pipeline stage**. Levels:
`FULL` native-quality · `EMU` full analysis via emulation · `PART` partial/decompile-only ·
`SLEIGH` needs a processor-spec authoring effort (`pipeline.md`.6) · `N/A` handled by a different route.

#### Tier 1 — First-class (depth-first build order)
x86 (IA-32), x86-64 (AMD64), ARM (A32 + T32/Thumb, BE/LE), AArch64 (ARMv8/9).
- Every stage FULL. Native + KVM execution where workstation arch matches. RetroWrite (x86-64 & AArch64) and
  MTSan (AArch64 MTE) static sanitizers; QASan everywhere. Frida-mode + qemu-mode fuzzing. Best ROP/exploit
  support. These are the AIxCC-class targets and the MVP.

#### Tier 2 — Full analysis via emulation (strong, second wave)
MIPS (32/64, BE + LE), PowerPC (32/64, BE + LE, ELFv1/ELFv2), RISC-V (RV32/RV64 + common extensions),
SPARC (32/64).
- Disasm/decompile FULL (Ghidra SLEIGH + capstone). Execution EMU (QEMU user/system, Unicorn, Qiling).
  Sanitize EMU (QASan). Symbolic FULL/EMU (angr VEX where available, else angr P-Code engine). Fuzz EMU
  (AFL++/LibAFL qemu-mode). Gadgets: ROPgadget/ropper + pwntools support all four.

#### Tier 3 — Embedded / MCU / DSP (firmware track, `pipeline.md`.5)
Cortex-M (Thumb — Tier-1 ISA but bare-metal execution model), AVR, MSP430, Xtensa (ESP32), ARC, PIC,
8051/MCS-51, TriCore, V850/RH850, SuperH (SH-2/4), Renesas RX.
- Disasm/decompile FULL–PART (Ghidra SLEIGH ships many; a few need community modules or SLEIGH work).
  Execution = **rehosting** (Fuzzware MMIO models, ES-Fuzz, GDMA, Unicorn/Qiling), not native. Sanitizers
  limited (no MMU/ASan model) → rely on invariant/assertion + fault detection. Symbolic PART. This tier's
  hard problem is *environment fidelity*, addressed by `pipeline.md`.5, not the ISA decode.

#### Tier 4 — Legacy / rare / niche (best-effort or SLEIGH-authoring)
m68k (68000), PA-RISC, s390x (IBM Z), Alpha, IA-64 (Itanium), OpenRISC, LoongArch, CRIS, NIOS II,
Qualcomm Hexagon (QDSP6), 6502/65xx, Z80, PDP-11, WE32000, and **truly custom/unknown ISAs**.
- Decode PART where Ghidra/capstone modules exist; otherwise `SLEIGH` authoring (`pipeline.md`.6 case 2) — an
  explicit, scoped effort. Execution EMU where QEMU/Unicorn support exists, else Unicorn-via-SLEIGH or none.
  We keep these behind the plugin interface so they are additive, never blocking.

#### Bytecode / VM class — different route (not native ISA)
JVM bytecode, .NET CIL, Android Dalvik/ART, WebAssembly (WASM), eBPF, Python `.pyc`, Lua, Ruby, Erlang BEAM.
- Handled by **format-specific front-ends**, not the native disassembler: JVM→CFR/Procyon, .NET→ILSpy-class,
  Dalvik→jadx-class, WASM→Ghidra WASM/wabt, `.pyc`→decompyle, eBPF→bpftool/Ghidra. They lift to a
  higher-level IR; the CWE engine runs on that IR. Managed-memory VMs change which CWEs apply.

### Capability matrix (representative)
Columns = pipeline stages. Cells = target support level.

| Arch | Load | Disasm | Decomp | Emulate | Sanitize | Fuzz | Symbolic | Gadget/PoC |
|---|---|---|---|---|---|---|---|---|
| x86-64 | FULL | FULL | FULL | FULL(+KVM) | FULL(RetroWrite/QASan) | FULL(frida/qemu) | FULL(VEX) | FULL |
| x86 (32) | FULL | FULL | FULL | FULL | FULL(QASan) | FULL | FULL | FULL |
| ARM A32/Thumb | FULL | FULL | FULL | EMU | EMU(QASan) | FULL(frida/qemu) | FULL(VEX) | FULL |
| AArch64 | FULL | FULL | FULL | EMU(+KVM on arm host) | FULL(RetroWrite/MTSan/QASan) | FULL | FULL(VEX) | FULL |
| MIPS 32/64 | FULL | FULL | FULL | EMU | EMU(QASan) | EMU(qemu) | FULL(VEX) | FULL |
| PowerPC 32/64 | FULL | FULL | FULL | EMU | EMU(QASan) | EMU | FULL(VEX) | FULL |
| RISC-V 32/64 | FULL | FULL | FULL | EMU | EMU(QASan) | EMU | EMU(VEX/pcode) | PART |
| SPARC 32/64 | FULL | FULL | FULL | EMU | EMU | EMU | FULL(VEX) | FULL |
| s390x | FULL | FULL | PART | EMU | EMU | EMU | FULL(VEX) | PART |
| SuperH | FULL | FULL | PART | EMU | PART | EMU | PART(pcode) | PART |
| m68k | FULL | FULL | PART | EMU | PART | EMU | PART | PART |
| Cortex-M (bare-metal) | FULL | FULL | FULL | REHOST(doc17) | PART | REHOST | PART | PART |
| AVR / MSP430 / Xtensa / ARC | FULL | FULL–PART | PART | REHOST(Unicorn/Qiling) | N/A | REHOST | PART | PART |
| Hexagon / LoongArch / OpenRISC | PART | PART | PART | EMU where avail | N/A | PART | PART | N/A |
| Unknown / custom ISA | wizard | SLEIGH | SLEIGH | Unicorn-via-SLEIGH | N/A | PART | PART | N/A |
| JVM / .NET / Dalvik / WASM / eBPF | FULL | N/A(bytecode) | FULL | managed VM | lang-level | PART | PART | N/A |

### MEASURED end-to-end results (September 2026)

The matrix above is the *plan*. This one is ground truth: `examples/re-corpus/src/vuln.c`
built per architecture (`-O0 -static -fno-stack-protector`) and driven through the real
pipeline -- triage -> disassemble (Ghidra 12.1.2) -> detect_cwe -> dynamic_run -> build_poc
-> poc_primitive -- on an x86-64 host, so every non-native arch runs under qemu-user.

| label | arch | funcs | findings | corrob | taint | crash | L1 | L2 |
|---|---|---|---|---|---|---|---|---|
| aarch64 | aarch64 | 1015 | 17 | 10 | yes | SIGSEGV | yes | **yes** (off 136) |
| arm | arm | 959 | 25 | 13 | yes | SIGSEGV | yes | **yes** (off 132) |
| loongarch | loongarch | 1007 | 15 | 10 | yes | SIGSEGV | yes | **yes** (off 136) |
| m68k | m68k | 961 | 193 | 72 | yes | SIGSEGV | yes | **yes** (off 132) |
| ppc | ppc | 1231 | 175 | 93 | yes | SIGSEGV | yes | **yes** (off 156) |
| ppc64 (BE) | ppc64 | 978 | 229 | 158 | yes | SIGSEGV | yes | not confirmed |
| ppc64le | ppc64 | 1829 | 220 | 146 | yes | SIGSEGV | yes | **yes** (off 176) |
| riscv | riscv | 984 | 23 | 10 | yes | SIGSEGV | yes | **yes** (off 136) |
| s390 | s390 | 0 | 3 | 0 | no | SIGILL | yes | yes (off 176) |
| sh | sh | 969 | 200 | 120 | yes | SIGSEGV | yes | yes (off 64) |
| sparcv9 | sparcv9 | 954 | 198 | 75 | yes | SIGBUS | yes | supported, unreachable* |
| x86 (32) | x86 | 1100 | 90 | 37 | yes | SIGSEGV | yes | **yes** (off 140) |
| x86-64 | x86-64 | 1166 | 100 | 69 | yes | SIGSEGV | yes | **yes** (off 136) |

**All 13 reach a verified L1** (crash reproducer, `poc-backed` finding), and **twelve of
thirteen reach a confirmed L3** control-flow hijack -- up from one (native x86-64) before the cross-arch work. L3 uses
**ret2win**: overwrite the saved return address with a chosen function's address read from the
target's own symbol table, and prove arrival with a breakpoint. All three steps are ISA-neutral
over the qemu gdbstub; the other L3 strategies (ROP gadget search, mprotect shellcode, the PIE
info-leak) are x86-64 machine code and stay native-only.

| arch | L1 | L2 | L3 (ret2win offset) |
|---|---|---|---|
| x86-64 | yes | yes | **yes** (72) |
| x86 (32) | yes | yes | **yes** (76) |
| aarch64 | yes | yes | **yes** (72) |
| arm | yes | yes | **yes** (68) |
| ppc | yes | yes | **yes** (92) |
| ppc64 (BE) | yes | yes | **yes** (96) |
| ppc64le | yes | yes | **yes** (112) |
| riscv | yes | yes | **yes** (72) |
| loongarch | yes | yes | **yes** (72) |
| m68k | yes | yes | **yes** (68) |
| s390 | yes | yes | **yes** (176) |
| sh | yes | yes | **yes** (64) |
| sparcv9 | yes | no | no |

Reading the table:

#### Two architectures that needed more than a table row

**SuperH is the one layout that cannot be derived.** qemu-sh4 serves no target description at
all, so it is written by hand -- transcribed from qemu's SH4 gdbstub and then VERIFIED against
a live g-packet rather than trusted: 59 32-bit registers (236 bytes), with an all-'A' overflow
landing at indices 14, 16 and 17, i.e. exactly r14 (frame pointer), pc and pr (link register),
which is what that order predicts. sp is r15, the return address is pr, arguments are r4-r7.

**s390 reaches L3 despite decompiling to nothing** (Ghidra ships no SystemZ processor), which
is the clearest demonstration that the dynamic ladder does not depend on the decompiler. Two
things were in the way, both ours: its link register is `r14`, which the shared
return-address list did not contain -- that list is now per-ISA, because r14 is the link
register on s390 and ARM but an ordinary callee-saved register on PowerPC and MIPS and so
cannot be guessed globally; and `exploit_stage` recovered the control offset with
little-endian 64-bit defaults, which reads a big-endian PC backwards.

**sparcv9 is the one architecture still at L1**, for an architectural reason rather than a
gap: register windows keep the return address in `%i7` and off the stack entirely, so a
stack-buffer overflow does not corrupt control flow there at all.

#### Resolved: ppc64le yielded zero data-flow findings (callee-name decoration)

Recorded here because the cause is worth knowing. ppc64le produced **0** flagged sinks where
big-endian ppc64 produced 139, from identical source. It was not the ABI row (shared, and
working big-endian) and not endianness: it was `catalog.normalize()`.

ELFv2 -- which every little-endian ppc64 system uses -- gives each function a *global* entry
that sets up the TOC and a *local* entry 8 bytes later holding the actual body. Ghidra models
that as two functions: `main` (8 bytes, `lis r2` / `addi r2`, no calls) and `.main` (the real
184-byte, 6-block body). On the corpus binary **845 of 1829 functions and 3659 of 4828 call
targets carried the leading dot**, so `.strcpy` matched no sink, `._IO_fgets` matched no
source, and `.main` matched no entry point -- the seed landed on the 8-byte TOC stub, which
uses no parameters and reaches nothing. Big-endian ppc64 is ELFv1, has no dots, and was
unaffected, which is exactly why the matrix showed one healthy arch and one dead one.

Fixed by normalising three more decorations: a leading `.` (PowerPC local entry), Ghidra's PLT
thunk form `<hex>.plt_call.<symbol>`, and glibc's `_IO_` stdio aliases. ppc64le now reports
146 corroborated findings against big-endian's 158. The PLT-thunk part also recovered sinks on
big-endian ppc64 (`greet` calls `00000397.plt_call.strcat`, previously unmatched), so an
architecture that *looked* healthy was quietly losing findings too.

Lesson for adding an architecture: verify that recovered callee names actually match the
catalog. A silent zero here is indistinguishable from "this binary has no bugs".

### Cross-cutting per-architecture concerns (must be modeled, not assumed)
These vary by ISA and silently break analysis/PoC if hardcoded to x86:
- **Endianness** (BE vs LE; bi-endian MIPS/PPC/ARM) — affects every byte-level detector and input crafting.
- **Word size / pointer size** (16/32/64) — affects overflow math, offsets, gadget addresses.
- **Calling convention / ABI** — register-passed args (most RISC) vs stack (x86 cdecl); which register holds
  the return address (**link register** on ARM/MIPS/PPC/RISC-V vs **saved on stack** on x86). This is central
  to harness synthesis (`pipeline.md`) and to control-primitive PoCs (`pipeline.md`): "overflow to saved return address"
  is x86-specific reasoning; on LR architectures the primitive is different.
- **Instruction encoding quirks:** ARM/Thumb interworking, MIPS/SPARC **branch delay slots**, RISC-V
  compressed (C) extension, variable-length x86, PPC ELFv1 function descriptors (TOC).
- **Stack growth direction & red zones**, guard-page behavior, alignment requirements.
- **PIC/PIE, GOT/PLT layout**, relocation types — differ per ABI; needed for symbol resolution + exploitation.
- **Mitigations vary:** NX/DEP, ASLR/PIE, stack canaries, RELRO, ARM PAC/BTI, Intel CET/shadow-stack, MTE —
  detected per-target and factored into exploitability (`pipeline.md`).
- **Syscall ABI** (numbers + register mapping) per OS+arch — needed for emulation/rehosting (`pipeline.md`, `pipeline.md`).

### Backends we wire per architecture (the actual work of "adding an arch")
1. **Loader** support (usually free via ELF/PE/Mach-O; custom via plugin, `pipeline.md`.6).
2. **Disassembler/decompiler**: Ghidra SLEIGH module (+ capstone for quick sweeps). Author SLEIGH only for
   Tier-4/custom (`pipeline.md`.6).
3. **Emulator**: QEMU (user + system), Unicorn, Qiling profile; for MCUs, a rehosting profile (`pipeline.md`.5).
4. **IR lifter for symbolic**: angr VEX if supported, else angr **P-Code** engine (reuses the SLEIGH spec).
5. **Sanitizer**: QASan (any QEMU-emulable arch); RetroWrite/MTSan where available (Tier 1).
6. **Fuzzing backend**: AFL++/LibAFL qemu-mode (broad), frida-mode (Tier 1), Nyx (system-mode) for stateful.
7. **Gadget/exploit**: ROPgadget/ropper/pwntools arch profile + calling-convention model for PoC synthesis.

### Roadmap alignment (`internal/13-roadmap-milestones.md`)
- Phases 0–7 target **Tier 1** end-to-end for depth. 
- **Tier 2** breadth lands as a wave right after v1 (mostly wiring, since engines already support it).
- **Tier 3** rides the firmware track (Phase 8, `pipeline.md`.5).
- **Tier 4 / custom ISA / bytecode** are additive plugin efforts, prioritized by real engagement demand.

### MEASURED bounds + guard reasoning (September 2026)

Ground-truth fixture (`signed/s.c`): ten copy sites whose correct verdict is known from the
source — four genuinely bounded, three signed-length hazards, one guard that does not protect
the buffer, one unguarded, one constant. Built at `-O0` for all 13 architectures and scored
against that truth. `9/9` means every scored site matched.

| arch | score | what is still in the way |
|---|---|---|
| x86-64 | **9/9** | — |
| x86 (32) | **9/9** | stack-passing ABI; PIC puts a call in the guard block |
| aarch64 | **9/9** | — |
| arm (Thumb) | **9/9** | — |
| loongarch | **9/9** | — |
| m68k | **9/9** | stack-passing ABI |
| ppc | **9/9** | — |
| ppc64 (BE) | **9/9** | — |
| sh | 8/9 | a 4096 immediate comes from a PC-relative constant pool the evaluator cannot read; the site stays `unknown`, which is the correct conservative answer |
| ppc64le | 2/9 | Ghidra reports the fixture's `char[64]` as four separate 8-byte locals, so the destination SIZE is unreliable. Verdicts are `unknown` rather than wrong — see the frame-headroom rule below |
| riscv | 0/9 | Ghidra resolved one `memcpy` call edge in the whole binary; the per-site edges never reach the detector, so no site is scored at all |
| s390 | 0/9 | disassembly recovers **0 functions** (see the end-to-end table above), and there is no `ARCH_ABI` entry |
| sparcv9 | 2/9 | register windows; the recovered frame reports `frame_size=2223` |

The three failures are all upstream of the bounds pass — call-graph naming, function recovery,
and frame recovery — not guard reasoning. Where the pass cannot trust its inputs it returns
`unknown`; no architecture produces a wrong verdict.

**How the condition is read.** Out of P-Code, not off the branch mnemonic. Mnemonic tables are
an x86 fiction, and the ISAs split three ways:

* **flag registers** (x86, x86-32, aarch64, arm, m68k) — `CF`/`OF`/`SF`/`ZF` are each defined
  by an explicit comparison, then combined with boolean algebra. x86's `JA` is `!(CF|ZF)` and
  aarch64's `b.hi` is `CY & !ZR`: the same relation, different algebra, neither readable
  without evaluating it. `SF != OF` is the signed less-than; `SF` alone is sound only against
  zero, which is exactly the `n >= 0` idiom.
* **direct compare** (riscv, loongarch, sh) — no flags. The constant lives in a **register**
  and the operands are **reversed**: `li a5,0x3f; blt a5,a4` is `63 < n`.
* **condition bitfield** (ppc, ppc64) — `cmplwi` packs lt/gt/eq into `cr0` with shifts and
  `bgt` extracts one bit. The unrelated `xer_so` bit is OR'd in from a value the evaluator
  cannot see, so it tracks which bit POSITIONS are unknown instead of discarding the field.

**Frame coordinates are derived, not tabulated.** `ghidra_offset = base_offset + displacement`,
where the base's offset from the entry stack pointer is read out of the prologue. One rule,
three conventions: x86-64 `PUSH RBP; MOV RBP,RSP` gives RBP = -8; aarch64 `stp x29,x30,[sp,#-0x60]!`
gives SP = -96; loongarch `addi.d fp,sp,0x60` gives FP = 0. A per-ISA delta table got the first
two right and loongarch wrong, because its frame pointer addresses the top of the frame.

**An overflow claim must clear the whole frame.** ppc64le fragments buffers, so a copy that
exceeds the recovered variable but still fits the frame below it cannot be told apart from a
buffer the decompiler split up. Those stay `unknown`. This also removed both remaining false
positives on jhead 3.04 (`ProcessFile`, the `Comment[16001]`/`st` slot-reuse artifact).

### Honest limits
- Sanitization quality degrades off Tier 1 (no MMU/ASan for MCUs → fault-based detection only).
- Symbolic execution on obscure ISAs relies on the P-Code engine (slower, less battle-tested than VEX).
- Decompiler quality varies by SLEIGH module maturity; Tier-4 output may be disasm-grade, not clean C.
- We will publish a **live capability matrix in-app** (like the table above) so an analyst always knows the
  real support level for the target in front of them — no silent partial coverage.

---

## CWE Coverage Matrix (Comprehensive)

**Scope decision:** consider the *entire* CWE corpus, but be explicit about what is detectable in a
**compiled binary** with offensive tooling. MITRE CWE has 900+ entries; many are source-only, web-app,
design, or process weaknesses invisible in a binary. This doc partitions the corpus into **in-scope
families** (with detection strategy + channel + feasibility) and an **out-of-scope** list, so the tool
claims coverage honestly and never reports what it cannot actually see.

### How we organize coverage
- We import the MITRE CWE catalog offline (`offline-packaging.md`) and attach to each in-scope CWE: primary **channel(s)**
  (`pipeline.md`: `pattern` / `taint` / `symbolic` / `dynamic`), a **feasibility** rating, and remediation text.
- We anchor priority on the **CWE Top 25** and the **hardware view (CWE-1194)** for firmware, but coverage
  is family-based, not a fixed list — a new detector maps to whichever CWEs its evidence pattern implies.
- **Feasibility ratings:** `HIGH` reliably detectable + confirmable · `MED` detectable with some FP/FN ·
  `LOW` heuristic/assistive only · `DYN` needs execution to confirm · `MANUAL` rule/heuristic hint that
  requires analyst reverse-engineering to judge (deterministic assists only — decision `overview.md`).
- Detectors run on the architecture-neutral IR, so a family's detection logic is written once.

### Implemented native detectors (as of 2026-09)
The families below are the *planned* corpus; these are the detectors that concretely **ship today**
for native/ELF + source, each promoted to `corroborated` only when the taint or reachability channel
agrees the attacker controls the relevant argument (a bare call stays low-confidence inventory):
- **CWE-120/121/787** unbounded/stack copies (`dangerous_api` + bounds + stack-frame gate) and the
  **width-bounded scanf off-by-one** (`%16s` into a 16-byte buffer → the +1 NUL, `scanf_bounded_overflow`).
- **CWE-134** format string · **CWE-78** command execution (system/popen/exec, + Go/Rust below).
- **CWE-22** path traversal (fopen/open/openat/unlink/… with a tainted path).
- **CWE-789** uncontrolled/overflowing allocation size (malloc/calloc/realloc with a tainted size).
- **CWE-89** SQL injection (sqlite3_exec/mysql_query/PQexec/… with a tainted query).
- **CWE-822** indirect call through a function pointer in a heap object (`heap_fptr_call`).
- **CWE-327/328/330/321/798/259/377/367/693** crypto/random/temp/TOCTOU/hardening.
- **Go / Rust language-aware** (`lang_sinks`, gated on the detected source language): **CWE-78**
  (`os/exec.Command`, `std::process::Command`), **CWE-22** (`os.Open*`/`std::fs`), **CWE-89**
  (`database/sql`), **CWE-918** SSRF (`net/http`) — corroborated by call-graph reachability from an
  untrusted-input source, since the C data-flow taint does not model the Go/Rust ABI.

The taint channel propagates through x86/x86-64 **sub-registers**, so a value assembled from a
tainted buffer's bytes (a length field read as `buf[0]`, or bytes combined with shifts/ORs) stays
tainted to the sink — not only whole-word direct flows.

---

### A. Memory buffer errors (the core of binary offense)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 119 | Improper restriction of ops within bounds (class) | taint+dynamic | HIGH |
| 120 | Classic buffer overflow (unbounded copy) | pattern+taint+dynamic | HIGH |
| 121 | Stack-based buffer overflow | taint+dynamic(QASan/RetroWrite) | HIGH |
| 122 | Heap-based buffer overflow | dynamic(QASan)+symbolic | HIGH |
| 124/127 | Buffer underwrite/underread | dynamic+taint | MED |
| 125 | Out-of-bounds read | dynamic(sanitizer)+symbolic | HIGH |
| 787 | Out-of-bounds write | dynamic(sanitizer)+taint | HIGH |
| 786/788 | Access before start / past end of buffer | dynamic | MED |
| 805/806 | Buffer access with incorrect length value | taint+symbolic | MED |
| 822/823/824/825 | Untrusted/uninitialized/expired pointer deref | dynamic+symbolic | MED |
| 466 | Return of pointer outside buffer bounds | symbolic | LOW |
| 170 | Improper null termination | pattern+dynamic | MED |

### B. Lifetime / use-after-free / free errors
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 416 | Use after free | dynamic(QASan)+symbolic | HIGH(DYN) |
| 415 | Double free | dynamic(QASan) | HIGH(DYN) |
| 590 | Free of memory not on heap | dynamic+pattern | MED |
| 761/762/763 | Free of wrong/mismatched pointer | dynamic | MED |
| 401 | Missing release (memory leak) | dynamic+static | MED |
| 404/459 | Improper resource shutdown / incomplete cleanup | dynamic | MED |

### C. Uninitialized / pointer / type
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 457 | Use of uninitialized variable | dynamic(msan-style)+symbolic | MED |
| 824 | Access of uninitialized pointer | dynamic+symbolic | MED |
| 908/909 | Use of uninitialized/unset resource | dynamic | MED |
| 476 | NULL pointer dereference | symbolic+dynamic+pattern | HIGH |
| 690 | Unchecked return → NULL deref | taint+symbolic | MED |
| 843 | Type confusion (access with incompatible type) | symbolic+dynamic | MED(hard) |
| 704/588 | Incorrect type conversion / cast of struct pointer | symbolic | LOW |

### D. Numeric errors (feed overflows)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 190 | Integer overflow/wraparound | taint+symbolic | HIGH |
| 191 | Integer underflow | taint+symbolic | HIGH |
| 192/194/195/196/197 | Integer coercion / signedness / truncation / sign-extension | symbolic+pattern | MED |
| 193 | Off-by-one | symbolic+dynamic | MED |
| 128 | Wrap-around in size math | taint+symbolic | MED |
| 369 | Divide by zero | symbolic+dynamic | HIGH |
| 469 | Pointer subtraction to determine size | pattern+symbolic | LOW |
| 681 | Incorrect conversion between numeric types | symbolic | MED |

### E. Input validation → injection (native binaries)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 20 | Improper input validation (class) | taint | MED |
| 134 | Uncontrolled format string | pattern+taint | HIGH |
| 78 | OS command injection (system/exec* with tainted arg) | taint→sink | HIGH |
| 88 | Argument injection | taint→exec | MED |
| 77 | Command injection (general) | taint | MED |
| 114 | Process control (untrusted library/exec path) | taint+pattern | MED |
| 94/95 | Code injection / eval of untrusted input | taint | MED(rare in native) |
| 470 | Unsafe reflection | taint | LOW(mostly managed) |
| 502 | Deserialization of untrusted data | taint+pattern | MED(mostly managed) |

### F. Path / link / resource resolution
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 22 | Path traversal | taint→file API | HIGH |
| 23/36/40 | Relative/absolute path traversal, path equivalence | taint | MED |
| 59 | Link following (symlink) | taint+dynamic | MED |
| 73 | External control of file name/path | taint | MED |
| 41/162 | Improper path/resolution equivalence | taint | LOW |

### G. Concurrency / race conditions
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 362 | Race condition (general) | dynamic+static | MED(hard) |
| 367 | TOCTOU (time-of-check/use) | pattern(access→use pairs)+dynamic | MED |
| 364/366 | Signal handler race / race in switch | pattern+dynamic | LOW |
| 401/415 via race | double-free/UAF via race | dynamic(stress)+sanitizer | MED |
| 543/609 | Missing/incorrect synchronization | static | LOW |

### H. Resource management / DoS
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 400 | Uncontrolled resource consumption | dynamic+symbolic | MED |
| 674 | Uncontrolled recursion (stack exhaustion) | static(callgraph cycles)+dynamic | HIGH |
| 835 | Loop with unreachable exit (infinite loop) | symbolic+dynamic | MED |
| 770/771/772/775 | Missing limits / lost resource / missing release | dynamic+static | MED |
| 789 | Memory alloc with excessive size (tainted) | taint+symbolic | MED |
| 405/407 | Asymmetric resource consumption / algorithmic complexity | dynamic(fuzz timing) | LOW |

### I. Error handling / checks
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 252 | Unchecked return value | pattern(def-use of retval) | HIGH |
| 253 | Incorrect check of return value | pattern+symbolic | MED |
| 754/755 | Improper check/handling of exceptional conditions | pattern+symbolic | MED |
| 390/391 | Error condition without action / unchecked error | pattern | MED |
| 703 | Improper handling of exceptional conditions (class) | pattern | LOW |

### J. Cryptography
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 327 | Broken/risky crypto algorithm (DES/RC4/MD5…) | const-based crypto-ID | HIGH |
| 328 | Use of weak hash | const-based ID | HIGH |
| 326/327 | Inadequate encryption strength | const+pattern | MED |
| 330/331/335/338 | Insufficient randomness / weak PRNG / predictable seed | pattern(rand/srand/time)+dynamic | MED |
| 347 | Improper verification of cryptographic signature | taint+symbolic | MED |
| 780 | RSA without OAEP | const+pattern | LOW |
| 323/325 | Reuse of nonce/IV, missing crypto step | pattern+dynamic | LOW |

### K. Credentials / secrets / storage
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 798 | Hardcoded credentials | string+entropy+pattern | HIGH |
| 259/321 | Hardcoded password / cryptographic key | string+entropy+const | HIGH |
| 312/316 | Cleartext storage of sensitive info (mem/disk) | taint+dynamic | MED |
| 256 | Plaintext storage of password | pattern+taint | MED |
| 526/214 | Sensitive info in env var / process listing | pattern+dynamic | LOW |
| 200/209/532 | Info exposure / error-message / log exposure | taint+pattern | MED |

### L. Auth / authorization / privilege (mostly logic → analyst-driven)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 306 | Missing authentication for critical function | MANUAL+dynamic | LOW |
| 287/288/290/294 | Improper/auth-bypass/spoofing | MANUAL+symbolic | LOW |
| 862/863 | Missing / incorrect authorization | MANUAL | LOW |
| 250/269/271 | Execution with unnecessary privileges / improper priv mgmt | pattern(setuid/caps)+dynamic | MED |
| 732/276 | Incorrect permission assignment / default perms | pattern(chmod/umask)+dynamic | MED |
| 639/566 | Authorization bypass via user-controlled key | taint+MANUAL | LOW |

### M. Firmware / hardware (CWE-1194 view — for the embedded track, `pipeline.md`.5)
| CWE | Name | Channel | Feasibility |
|---|---|---|---|
| 1277 | Firmware not updateable / no update integrity | pattern+MANUAL | MED |
| 1329 | Reliance on hardcoded component in firmware | string+const | MED |
| 1240 | Use of a risky cryptographic primitive (hw) | const-based ID | MED |
| 1189/1191 | Improper isolation / exposed debug (JTAG/SWD) | pattern(debug regs)+MANUAL | LOW |
| 1231-1234 | Improper lock-bit / register protection | MANUAL+dynamic(rehost) | LOW |
| 1256/1300 | Info exposure through power / physical side channel | out-of-band | N/A(no HW) |
| 1326 | Missing immutable root of trust | MANUAL | LOW |
| 787/125 in firmware | classic memory bugs in firmware | rehost+fuzz+fault | MED(DYN) |

### N. Bytecode/managed-VM targets (JVM/.NET/Dalvik/WASM — the architecture-coverage matrix)
Managed memory removes most memory-safety CWEs but adds others:
- Applicable: 502 deserialization, 470 unsafe reflection, 78/88 command injection, 22 path traversal,
  327/328/798 crypto+secrets, 862/863 authz, 89/90/611 injection (when the query/parser is visible).
- Not applicable: 121/122/416/787 memory-safety (VM-managed) — do not report on pure managed bytecode.

---

### Explicitly OUT OF SCOPE for binary-only offensive analysis (do not claim)
These are real CWEs but generally invisible in a compiled binary or belong to other tool classes:
- **Web/app-layer without a visible parser:** 79 XSS, 89 SQLi, 352 CSRF, 601 open redirect, 918 SSRF,
  611 XXE — only in scope when the binary itself constructs/parses the relevant string and data is tainted.
- **Design / process / governance:** 1053, 1059, most "pillar/class" abstract entries, CWE-CATEGORY nodes,
  supply-chain-process, documentation, and configuration-of-external-systems weaknesses.
- **Source-only constructs** lost at compile time: many style/maintainability weaknesses.
- **Physical/side-channel** (power/EM/timing hardware) — needs physical instrumentation we don't have offline.
We record these as "known-not-covered" in the taxonomy engine so the UI shows *gaps*, not false silence.

### Coverage methodology & honesty
1. **Detectability, not enumeration.** We track which CWE *families* our detectors and channels actually
   cover, and at what feasibility, rather than pretending to "support 900 CWEs."
2. **Confirmed-first reporting.** For any DYN/HIGH family, a finding reaches an analyst as *Confirmed* only
   after reproduction (`pipeline.md`). LOW/MANUAL families are surfaced as clearly-labeled leads for analyst review, never as confirmed findings.
3. **Per-CWE benchmark tracking.** Detection precision/recall per family is measured on Juliet (labeled by
   CWE), LAVA-M, Magma, and CGC, and shown as a live coverage/quality dashboard in-app.
4. **Architecture independence.** Because detectors run on IR, a family's coverage holds across all
   supported architectures; only DYN confirmation depends on per-arch emulation/sanitizer availability.
5. **Extensible.** New CWE detectors register via the plugin API (`architecture.md`) mapping evidence → CWE IDs.

---

## Validation & Benchmarks (Measure Detection Quality Honestly)

A vuln tool that isn't measured drifts into confident nonsense. Build the eval harness in Phase 0 and run it
every phase (`internal/13-roadmap-milestones.md`). Measure both **detection power** (finds real bugs) and **noise** (false-positive rate).

### Bundled benchmark corpora
| Corpus | What it gives | Measures |
|---|---|---|
| **NIST Juliet** (SARD) | thousands of labeled good/bad CWE cases | per-CWE detection + FP rate (static channels) |
| **LAVA-M** | programs with many injected, labeled bugs | fuzzing/harness bug-finding recall |
| **Magma** | real CVEs re-instrumented with ground-truth triggers | realistic fuzzing + triage |
| **DARPA CGC** | vulnerable binaries with reference PoVs | end-to-end find→confirm→PoC |
| Real-CVE mini-suite | a curated set of CVEs relevant to expected targets | true end-to-end validation |

### Metrics tracked over time (regression dashboard)
- **Per-CWE:** precision / recall / F1 at each finding state (candidate vs confirmed).
- **False-positive rate** at candidate stage AND the confirmed-stage FP rate (should approach ~0 — that's the
  whole point of the confidence pipeline, `pipeline.md`).
- **Fuzzing:** time-to-first-crash, unique-bug recall on LAVA-M/Magma, coverage over time, execs/sec by mode.
- **Confirmation loop:** % of static candidates that get dynamically/symbolically confirmed; time-to-confirm
  with vs without directed fuzzing (`pipeline.md`) — prove the accelerator earns its cost.
- **PoC:** % of confirmed findings reaching L0/L1/L2; PoC re-verification success rate.
- **Naming recovery (deterministic):** % of functions named by signatures + corpus-diff + runtime metadata on
  a labeled set; measures the doc-04 stack, not any model.
- **Cost:** wall-clock + memory per stage (the box is finite; `architecture.md` governor depends on these numbers).

### Guardrails
- Account for **function inlining** degrading signature/diff matching in the eval splits.
- Keep a held-out set the rules were never tuned on.
- Gate releases on "no regression in confirmed-stage FP rate and no drop in LAVA-M/Magma recall."
