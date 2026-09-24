# 18 — Architecture Coverage Matrix (All Targets)

**Scope decision:** the platform aims to cover *every practical target ISA*, native and bytecode. We do this
without per-arch rewrites by standing on **architecture-neutral IR** (Ghidra P-Code and angr/VEX): CWE
detectors (doc 05/19) and the data model are written **once** against IR, so adding an architecture is
*wiring* (loader + disasm + emulator + sanitizer + gadget backends), never new analysis logic.

## Coverage tiers (by tooling maturity + effort, not importance)
Each architecture gets a **level per pipeline stage**. Levels:
`FULL` native-quality · `EMU` full analysis via emulation · `PART` partial/decompile-only ·
`SLEIGH` needs a processor-spec authoring effort (doc 04.6) · `N/A` handled by a different route.

### Tier 1 — First-class (depth-first build order)
x86 (IA-32), x86-64 (AMD64), ARM (A32 + T32/Thumb, BE/LE), AArch64 (ARMv8/9).
- Every stage FULL. Native + KVM execution where workstation arch matches. RetroWrite (x86-64 & AArch64) and
  MTSan (AArch64 MTE) static sanitizers; QASan everywhere. Frida-mode + qemu-mode fuzzing. Best ROP/exploit
  support. These are the AIxCC-class targets and the MVP.

### Tier 2 — Full analysis via emulation (strong, second wave)
MIPS (32/64, BE + LE), PowerPC (32/64, BE + LE, ELFv1/ELFv2), RISC-V (RV32/RV64 + common extensions),
SPARC (32/64).
- Disasm/decompile FULL (Ghidra SLEIGH + capstone). Execution EMU (QEMU user/system, Unicorn, Qiling).
  Sanitize EMU (QASan). Symbolic FULL/EMU (angr VEX where available, else angr P-Code engine). Fuzz EMU
  (AFL++/LibAFL qemu-mode). Gadgets: ROPgadget/ropper + pwntools support all four.

### Tier 3 — Embedded / MCU / DSP (firmware track, doc 17.5)
Cortex-M (Thumb — Tier-1 ISA but bare-metal execution model), AVR, MSP430, Xtensa (ESP32), ARC, PIC,
8051/MCS-51, TriCore, V850/RH850, SuperH (SH-2/4), Renesas RX.
- Disasm/decompile FULL–PART (Ghidra SLEIGH ships many; a few need community modules or SLEIGH work).
  Execution = **rehosting** (Fuzzware MMIO models, ES-Fuzz, GDMA, Unicorn/Qiling), not native. Sanitizers
  limited (no MMU/ASan model) → rely on invariant/assertion + fault detection. Symbolic PART. This tier's
  hard problem is *environment fidelity*, addressed by doc 17.5, not the ISA decode.

### Tier 4 — Legacy / rare / niche (best-effort or SLEIGH-authoring)
m68k (68000), PA-RISC, s390x (IBM Z), Alpha, IA-64 (Itanium), OpenRISC, LoongArch, CRIS, NIOS II,
Qualcomm Hexagon (QDSP6), 6502/65xx, Z80, PDP-11, WE32000, and **truly custom/unknown ISAs**.
- Decode PART where Ghidra/capstone modules exist; otherwise `SLEIGH` authoring (doc 04.6 case 2) — an
  explicit, scoped effort. Execution EMU where QEMU/Unicorn support exists, else Unicorn-via-SLEIGH or none.
  We keep these behind the plugin interface so they are additive, never blocking.

### Bytecode / VM class — different route (not native ISA)
JVM bytecode, .NET CIL, Android Dalvik/ART, WebAssembly (WASM), eBPF, Python `.pyc`, Lua, Ruby, Erlang BEAM.
- Handled by **format-specific front-ends**, not the native disassembler: JVM→CFR/Procyon, .NET→ILSpy-class,
  Dalvik→jadx-class, WASM→Ghidra WASM/wabt, `.pyc`→decompyle, eBPF→bpftool/Ghidra. They lift to a
  higher-level IR; the CWE engine runs on that IR. Managed-memory VMs change which CWEs apply (doc 19).

## Capability matrix (representative)
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

## MEASURED end-to-end results (September 2026)

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

### Two architectures that needed more than a table row

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

### Resolved: ppc64le yielded zero data-flow findings (callee-name decoration)

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

## Cross-cutting per-architecture concerns (must be modeled, not assumed)
These vary by ISA and silently break analysis/PoC if hardcoded to x86:
- **Endianness** (BE vs LE; bi-endian MIPS/PPC/ARM) — affects every byte-level detector and input crafting.
- **Word size / pointer size** (16/32/64) — affects overflow math, offsets, gadget addresses.
- **Calling convention / ABI** — register-passed args (most RISC) vs stack (x86 cdecl); which register holds
  the return address (**link register** on ARM/MIPS/PPC/RISC-V vs **saved on stack** on x86). This is central
  to harness synthesis (doc 07) and to control-primitive PoCs (doc 08): "overflow to saved return address"
  is x86-specific reasoning; on LR architectures the primitive is different.
- **Instruction encoding quirks:** ARM/Thumb interworking, MIPS/SPARC **branch delay slots**, RISC-V
  compressed (C) extension, variable-length x86, PPC ELFv1 function descriptors (TOC).
- **Stack growth direction & red zones**, guard-page behavior, alignment requirements.
- **PIC/PIE, GOT/PLT layout**, relocation types — differ per ABI; needed for symbol resolution + exploitation.
- **Mitigations vary:** NX/DEP, ASLR/PIE, stack canaries, RELRO, ARM PAC/BTI, Intel CET/shadow-stack, MTE —
  detected per-target and factored into exploitability (doc 08).
- **Syscall ABI** (numbers + register mapping) per OS+arch — needed for emulation/rehosting (doc 06/17).

## Backends we wire per architecture (the actual work of "adding an arch")
1. **Loader** support (usually free via ELF/PE/Mach-O; custom via plugin, doc 04.6).
2. **Disassembler/decompiler**: Ghidra SLEIGH module (+ capstone for quick sweeps). Author SLEIGH only for
   Tier-4/custom (doc 04.6).
3. **Emulator**: QEMU (user + system), Unicorn, Qiling profile; for MCUs, a rehosting profile (doc 17.5).
4. **IR lifter for symbolic**: angr VEX if supported, else angr **P-Code** engine (reuses the SLEIGH spec).
5. **Sanitizer**: QASan (any QEMU-emulable arch); RetroWrite/MTSan where available (Tier 1).
6. **Fuzzing backend**: AFL++/LibAFL qemu-mode (broad), frida-mode (Tier 1), Nyx (system-mode) for stateful.
7. **Gadget/exploit**: ROPgadget/ropper/pwntools arch profile + calling-convention model for PoC synthesis.

## Roadmap alignment (doc 13)
- Phases 0–7 target **Tier 1** end-to-end for depth. 
- **Tier 2** breadth lands as a wave right after v1 (mostly wiring, since engines already support it).
- **Tier 3** rides the firmware track (Phase 8, doc 17.5).
- **Tier 4 / custom ISA / bytecode** are additive plugin efforts, prioritized by real engagement demand.

## MEASURED bounds + guard reasoning (September 2026)

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

## Honest limits
- Sanitization quality degrades off Tier 1 (no MMU/ASan for MCUs → fault-based detection only).
- Symbolic execution on obscure ISAs relies on the P-Code engine (slower, less battle-tested than VEX).
- Decompiler quality varies by SLEIGH module maturity; Tier-4 output may be disasm-grade, not clean C.
- We will publish a **live capability matrix in-app** (like the table above) so an analyst always knows the
  real support level for the target in front of them — no silent partial coverage.
