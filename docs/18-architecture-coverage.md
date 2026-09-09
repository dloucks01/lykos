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

## Honest limits
- Sanitization quality degrades off Tier 1 (no MMU/ASan for MCUs → fault-based detection only).
- Symbolic execution on obscure ISAs relies on the P-Code engine (slower, less battle-tested than VEX).
- Decompiler quality varies by SLEIGH module maturity; Tier-4 output may be disasm-grade, not clean C.
- We will publish a **live capability matrix in-app** (like the table above) so an analyst always knows the
  real support level for the target in front of them — no silent partial coverage.
