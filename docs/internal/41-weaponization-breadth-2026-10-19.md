# 41 — Weaponization breadth: cross-arch ELF depth + the Windows gap (2026-10-19)

Docs [37](37-weaponization-depth-2026-10-17.md) and [38](38-technique-program-2026-10-17.md)
measured **depth on one ISA** — how far each mechanism gets on x86-64. This doc measures
**breadth**: how far the ladder gets across the *other* architectures and across the *other*
target OS (Windows/PE). It is the plan for two expansions, in priority order:

* **Part B — cross-arch ELF depth (the focus).** Push as many architectures as possible from a
  verified L1 crash to a real L3 exploit, and raise each arch's ceiling from "ret2win only" toward
  the full ladder. This is where the immediate work goes.
* **Part C/D — Windows/PE weaponization.** The single largest *capability-class* gap: PE is
  analysed but never weaponized. Sequenced second.

Every claim is tagged **[measured]** (a number from a run here), **[observed]** (read directly in
the code / a command's output this session) or **[inferred]** (reasoned, not yet measured), per
the doc-34 convention. The code citations are `file:line` at HEAD `8ab93e1`.

---

## Part A — Where weaponization stands (snapshot)

**The x86-64 ladder is deep** [observed, doc 38]: ret2win, ret2system/ROP, execve-syscall,
SROP (one-shot + 2-stage plant), ret2csu, ret2dlresolve, ret2libc (puts-leak / PIE pure-libc /
one-gadget), canary-leak→ret2libc, magic-overwrite, format-`%n`, tcache poison + House of Apple 2
/ House of Cat / setcontext-FSOP, stack pivot, mprotect+shellcode, shellcode injection with a
bad-char XOR encoder, BROP, ORW/seccomp-aware ORW, WASM indirect-call redirect. All confirmed by a
live shell / marker / breakpoint, never asserted.

**The confirmation substrate is already ISA-neutral and broad** [observed]:

* `debug/qemu_gdb.py` drives `qemu-<arch> -g` over a pure-stdlib GDB-RSP socket and reads the
  g-packet. It `supported()`s **15 architectures** — 10 hand-written register layouts
  (`_LAYOUTS`, `qemu_gdb.py:36-82`: aarch64, riscv, riscv64, arm, ppc, ppc64, s390, mips, hppa,
  sh) + 5 derived at connect from the stub's `target.xml` (`_STUB_ABI`, `qemu_gdb.py:139-151`:
  loongarch, m68k, sparcv9, x86, alpha).
* Per-ABI arg registers (`_ARG_REGS`), stack pointer (`_SP`), breakpoint kind (`_BP_KIND`) and
  the bit-0 PC mask for thumb-ish ISAs (`LSB_MASKED_PC`) are all tabulated. `_ARG_REGS` covers
  **13 of the 15** — missing **i386** and **m68k** (`qemu_gdb.py:93-109`) [observed].
* L2 is ISA-neutral: `primitive._RA_BY_ARCH` (`primitive.py:37`) is a real per-ISA
  return-address-register table across ~14 ISAs; cyclic-offset, register-window search and
  indirect-branch detection are all byte/endian/word-parameterized.

**But the L3 ladder above ret2win is x86-64-only**, and the reason is structural, not incidental:

1. **There is no L3 ABI model.** Arg registers, the return slot, stack alignment and
   `system`-calling convention are **hardcoded inline inside four near-identical per-arch
   functions** in `exploit_stage.py` [observed, agent map]. The only shared L3 datum is the amd64
   `_SIGFRAME_WORDS` for SROP. So every new arch today is ~250 lines of copy-paste, not a table
   row.
2. **Gadget discovery is hand-rolled byte decoding** (no capstone / pypcode in the decode path),
   and decoders exist only for **x86-64 (rich), aarch64, arm (ARM mode only), riscv64 (incl.
   RVC), ppc64le** (`rop.py`). There is **no** decoder for mips, ppc32/ppc64-BE, s390x, sparc,
   m68k, loongarch, sh [observed].
3. **One master gate** refuses everything else for a cross-arch target:
   `exploit_stage.py:138` — `if emulated and strategy not in ("auto","ret2win"): return
   _unsupported(... L3 strategy is x86-64 only)`. Cross-arch ret2libc/shellcode are reached only
   through `strategy=="auto"` arms that re-test `emulated and arch==…` (`exploit_stage.py:595,
   606, 617, 626, 636`) [observed].

**Net:** the plumbing can already *prove* an L3 on 15 ISAs; what's missing is the per-ISA
**gadget model + chain** and the **abstraction** that would make adding one cheap.

---

## Part B — Cross-arch ELF depth program (the focus)

> **Status (updated 2026-10-19):** M1 (the `ArchModel` abstraction) is built; ret2libc L3 now spans
> **8 arches** (x86-64/aarch64/arm32/riscv64/ppc64le + **loongarch64/s390x/ppc32-BE**) and execstack
> ret2shellcode **7 arches**. See `coverage.md` (cross-arch section) and
> `42-strategy-expansion-2026-10-19.md` for the measured outcome, including why multi-register
> syscall-ROP (#1/#3 below, NX-on) is gadget-blocked on the RISC arches.

### B.1 Ground truth as of today

Tooling columns are what is installed **on this build host** [observed, 2026-10-19]; ladder
columns are from `docs/coverage.md` [measured, Sep–Oct 2026] cross-checked against the dispatch
code [observed]. "RCE L3" = a shell/execve demonstrated, i.e. the rungs above ret2win.

| Arch | gcc here | qemu-user | gdbstub layout | arg-regs | L1 | ret2win L3 | RCE L3 (ret2libc/execve/shellcode) | Primary blocker to deeper L3 |
|---|---|---|---|---|---|---|---|---|
| x86-64 | ✓ | ✓ | derived | ✓ | ✓ | ✓ | ✓ **full ladder** | — (reference) |
| x86 (i386) | ✓ | ✓ | derived | **✗** | ✓ | ✓ | ✗ | foreign-on-x86-64 ⇒ ret2win only; no 32-bit ROP model; not in `_ARG_REGS` |
| aarch64 | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✓ ret2libc + execstack shellcode | deeper rungs (leak/SROP/heap) |
| arm32 | ✓ (hf) | ✓ | hand | ✓ | ✓ | ✓ | ✓ ret2libc + execstack shellcode | Thumb decode; deeper rungs |
| riscv64 | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✓ ret2libc | no shellcode stub; deeper rungs |
| ppc64le | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✓ ret2libc | no shellcode stub; deeper rungs |
| ppc (32, BE) | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✗ | gadget model (BE/ELFv1) |
| ppc64 (BE) | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✗ | LE-only gate (`exploit_stage.py:638`) + ELFv1 descriptors/TOC |
| s390x | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✗ | gadget model (BE, r14 link reg) |
| sh4 | ✓ | ✓ | hand | ✓ | ✓ | ✓ | ✗ | gadget model |
| loongarch64 | ✓ | ✓ | derived | ✓ | ✓ | ✓ | ✗ | gadget model |
| m68k | ✓ | ✓ | derived | **✗** | ✓ | ✓ | ✗ | not in `_ARG_REGS`; stack-arg ROP model |
| sparc64 (v9) | ✓ | ✓ | derived | ✓ | ✓ | **✗ (L1)** | ✗ | **architectural** — register windows |
| mips / mipsel / mips64(el) | **✗** | ✓ | hand (mips) | ✓ | **✗** | ✗ | ✗ | **no cross-compiler** + gadget model (delay slot, `$t9`/PIC) |
| alpha / hppa | ✗ | n/a here | derived / hand | — | — | — | — | no compiler; hppa also architectural (stack grows up) |

**Reading it.** Twelve ISAs already stand at a confirmed **L3 ret2win** (the floor), and five of
those reach a real **RCE L3**. The breadth goal is two moves: (1) raise every ret2win-only arch
toward RCE rungs that need **no planted `win()`** (execve-syscall, ret2libc, shellcode); and
(2) close the two true gaps — **MIPS** (toolchain) and **sparcv9** (architectural).

### B.2 Measurement spine first — a 2-D ceiling matrix (do this before any strategy work)

Doc 37's `tools/pipeline_conformance.py --ceiling` measures *mechanism* depth on x86-64. Extend it
to an **arch × mechanism** grid, each cell the highest rung **measured live** under qemu-user, so
the table in B.1 becomes a generated scoreboard instead of a hand-maintained claim. Concretely:

* Add cross-arch **ret2libc / execve / shellcode** conformance cases. Today the six cross-arch
  cases are **L1-only** (`want_level=1`, `tools/pipeline_conformance.py:934-986`) and the only
  cross-arch L3 coverage lives in two unit tests (`tests/test_ret2libc_cross.py`,
  `tests/test_ret2libc_arm.py`) [observed]. The ratchet cannot protect a rung it never exercises.
* Make `make arch-gate` assert **the rung each arch reached**, not just "ret2win still works," and
  fail on any regression — the same ratchet shape as the x86-64 mechanism gate.
* Record the matrix to the dashboard (`eval-history.jsonl`) so breadth is tracked over time.

This is the honest-coverage rule (doc README #4 "no silent partial coverage") applied to the one
table everyone reads.

### B.3 Build the abstraction that doesn't exist (the enabler)

The single highest-leverage change. Introduce one **`ArchModel`** (one source of truth, unifying
the three scattered tables — `primitive._RA_BY_ARCH`, `qemu_gdb._ARG_REGS/_SP`, and the four
hardcoded L3 functions):

```
ArchModel(word, endian, sp_reg, ret_slot, arg_regs[], syscall_insn, syscall_nr{execve, mprotect,
          rt_sigreturn}, align, pc_mask, sigframe_layout?, reloc{jump_slot}?)
```

Then a **table-driven ret2libc/execve chain builder** that consumes `(ArchModel, gadget_finder)`
and collapses the four bespoke `_{aarch64,arm,riscv64,ppc64}_ret2libc_exploit` functions
(`exploit_stage.py:4176, 4287, 4414, 4526`) — which are copy-pasted down to the ~70 lines of
bundle/DAO filing — into **one**. Adding an arch becomes: *register a gadget finder + add one
table row*. A per-ISA **gadget-finder interface** in `rop.py` formalizes the existing hand-written
decoders as the plug-in point.

Exit criterion: the four existing cross-arch chains pass **through the new builder** with no
behaviour change (their unit tests stay green), proving the abstraction before it carries new
arches.

### B.4 The march — strategies outward from x86-64, by value × feasibility

Ordered the way doc 38 orders x86-64 work: each item is a technique + a fixture where it is the
*only* route + a conformance case demanding the rung + a measured run, on each target arch.

**Tier 1 — table-fill (cheapest breadth, start here).**

1. **magic-value overwrite → every `supported()` arch.** It has **no intrinsic x86 dependency**
   (no gadgets, no shellcode, no syscalls, PIE-safe; confirmed by a planted marker) — it is
   native-only *purely* by its dispatch guards (`exploit_stage.py:699, 314, 376`) [observed].
   Removing those for cross-arch and routing it through the qemu capture is the smallest possible
   lift to a new L3 class on all 15 ISAs.
2. **execve-syscall ROP → cross-arch.** Conceptually the cleanest port: load the arg registers +
   a syscall gadget + `/bin/sh`, which every ISA has. What's x86-tied is enumerable — the syscall
   number (`rax=59`) and the gadget search (`_plan_execve_rop`, `exploit_stage.py:3358`;
   `rax=59`/`syscall^0xFFF` negative control at `:3385`). Reuses the B.3 builder + the tagged-
   detonation offset discovery (`_qemu_reg_offsets`, `exploit_stage.py:4394`, already generic).
   High value: **no libc symbols, NX-on**.
3. **shellcode stubs for riscv64 / ppc64(le) / mips / s390x.** `shellcode.py` today has execve +
   write-marker only for **x86-64, aarch64, arm** (and socket/dup2/egg-hunter/XOR-encoder only for
   x86-64) [observed]. The per-ISA syscall numbers are known and small to assemble (aarch64
   execve=221, arm=11; the rest are a lookup). This unblocks #4 and the mprotect chain.
4. **ret2shellcode (execstack) → riscv64 / ppc64le.** The cross-arch injection *driver*
   `_shellcode_emu_exploit` already exists for **aarch64/arm** (`exploit_stage.py:2621`); extending
   it is "add a gadget finder (`br/blr`-style redirect) + the stub from #3 + a dispatch branch,"
   mirroring `:595`. Confirmation (`_qemu_shell_detonate`) is already ISA-generic.

**Tier 2 — new per-arch gadget model, same chain template (via B.3).**

5. **ret2libc → system on the ret2win-only arches that already have layout + arg-regs:**
   **s390x, sh4, loongarch64**, then **m68k** (needs an `_ARG_REGS` entry *and* a stack-arg ROP
   model — m68k passes args on the stack). Each needs only a `find_<arch>_r2libc_gadgets` byte
   decoder; the ABI row + confirmation already exist.
6. **mprotect + shellcode → cross-arch.** Mechanical once #3+#5 land: the chain is "set 3 args,
   call mprotect (via PLT), jump to buffer." Needs the per-arch arg-loading gadgets (from #5) + a
   write-marker stub.
7. **PPC big-endian (ppc / ppc64 BE).** Remove the `endianness=="little"` gate
   (`exploit_stage.py:638`) and give `find_ppc64_r2libc_gadgets` a **BE / ELFv1** path (function
   descriptors + TOC; the LE decoder is `_ppc_words`-hardcoded LE, `rop.py:1040`). Tooling is
   present here, so this is pure implementation.

**Tier 3 — parameterize existing x86 code (unlocks PIE/ASLR targets cross-arch).**

8. **PIE / libc info-leak.** The leak→relocate→exploit loop is ISA-neutral arithmetic
   (`base = leaked - offset`); the x86 lock-in is (a) 8-byte-LE pointer harvesting with x86-64
   top-byte heuristics (`_le_pointer_words`, `leak.py:1611`; the `0x55/0x56/0x7f` masks at
   `:1621, 1641`) and (b) the x86 ROP finisher. Generalize both to `(word, endian)` + a per-ABI
   pointer-shape mask table, then reuse the Tier-2 finishers. `exploit.py:224-267` already shows
   the `word/endian`-parameterized payload-builder pattern the leak helpers should follow.
9. **format-string `%n`.** `fmt.py` is already *partly* `word/endian`-aware (`fmtstr_payload`,
   `fmt.py:30-60`); finish the `>` big-endian branch in `read_at_payload` (`:102`) and make the
   probe-marker width follow `word`. `%N$` positional offsets shift per varargs ABI but
   `find_fmt_offset` recovers them empirically. The remaining blocker is the x86-only GOT-overwrite
   *driver* (`leak.format_got_shell`), which needs a per-arch "call-this-after-sink" target like
   ret2libc.

**Tier 4 — genuinely per-ABI re-derivation (scoped research; defer).**

10. **SROP** — per-ISA `rt_sigframe`/sigcontext layout, frame size, PC/`cs` field, `rt_sigreturn`
    + `execve` numbers, and the syscall-selector register (x8/r7, not a popped rax). Table-shaped
    once built, but **every offset must be verified against the live kernel frame**
    (`_SIGFRAME_WORDS`, `rop.py:1264`, is amd64 literal).
11. **ret2dlresolve** — per-ISA relocation type (`JUMP_SLOT`=7 on x86-64, 1026 on aarch64, …),
    the ELFCLASS32/64 `r_info` split, and the `_dl_runtime_resolve` resolver ABI (aarch64/riscv
    PLT stubs don't take a pushed reloc index the way x86 PLT0 does). Least mechanical of the ROP
    family (`build_ret2dlresolve`, `rop.py:694`).
12. **heap / FSOP / House of ***— the largest single body of work. A lattice of
    **(arch × glibc-version)** `_IO_FILE`/`_IO_wide_data`/ucontext offset tables (`heap.py:168-172,
    333-337`), the per-ISA "which register holds the FILE pointer at the controlled call" micro-
    analysis, and per-ISA instruction decoders for the guard-site detectors (`heap.py:533-582` scan
    x86 `lea rip`/`jcc`). Do x86-64-glibc only until Tier 1–3 breadth is banked.

**On ret2csu:** effectively **already covered** off-x86 — the "load callee-saved regs from stack
then call" role that `__libc_csu_init` fills on x86-64 is exactly what the shipped two-gadget
ret2libc finders do on aarch64/riscv64/ppc64le. A literal csu port is low value; skip it.

### B.5 MIPS — the one toolchain gap

qemu-user (all four variants) and a hand-written `_LAYOUTS["mips"]` are present; **no MIPS
cross-compiler is installed, and MIPS is absent from every fixture builder's matrix** [observed].
So MIPS is missing from the measured ladder entirely — not even ret2win is verified.

* **Step 1 (unblocks L1→L3 ret2win immediately):** install a MIPS cross toolchain
  (`gcc-mips-linux-gnu` / `gcc-mipsel-linux-gnu` / `gcc-mips64el-linux-gnuabi64`, or the
  `MUSL_CROSS_ROOT` route the `examples/re-corpus/README.md` documents) and add MIPS rows to
  `core/lykos/eval/archgate.py` `MATRIX`, `examples/vuln-targets/fetch_build.sh`, and the
  conformance cases. qemu + layout already exist, so ret2win should light up with only fixtures.
* **Step 2 (ret2libc):** a MIPS gadget model with **branch-delay-slot** handling and the
  **`$t9`/`$ra` PIC** convention (`$t9` must hold the callee entry for PIC code) + `$a0`.

### B.6 Architectural ceilings — state them honestly, don't fake them

* **sparcv9 (L1 ceiling).** Register windows keep the return address in `%i7`, **off the stack**,
  so a *bounded* stack overflow never corrupts control flow (`archgate.py:34-44`, coverage.md).
  A deeper primitive is possible as a **research item**: corrupt a *spilled* window — overflow
  past the register-save area so an outer frame's `%i7` is restored from attacker bytes on
  `restore`/`ret`. Label it L1→L2(research), never silently absent.
* **hppa.** Return address in the frame marker, stack grows up → L1 ceiling for a bounded
  overflow. No compiler here; lowest priority.
* **i386-as-foreign.** A 32-bit x86 ELF on an x86-64 host is `emulated=True`, so it reaches only
  ret2win and cannot run the native 64-bit ladder, and it is not in `_ARG_REGS`. It deserves its
  own 32-bit ROP model (stack-arg cdecl) or a native-i386 execution path — a real gap given how
  common 32-bit targets are.

### B.7 Packaging note to verify (offline runbook)

Cross-compilers and `qemu-user` are **system packages here, not in `vendor/`** (the bundle holds
pypcode/unicorn/angr/symqemu only) [observed]. The README implies the offline bundle ships
qemu-user; confirm the toolchain `.tar.zst` actually populates `vendor/` with `qemu-<arch>` for
every target ISA, or **cross-arch dynamic analysis and all cross-arch L3 silently cannot run on an
air-gapped host** — which would violate the doc-overview "a stage that could not run says so"
rule. Fixtures are a build-time concern (not needed offline), but the runtime qemu is not.

---

## Part C — Windows / PE weaponization (second axis)

PE is **analysed but never weaponized** [observed]: `pe.py` parses headers + mitigations
(DllCharacteristics: ASLR/DEP/SEH/CFG), and PE runs under **Wine** for syscall + Win32 `+relay`
behaviour tracing (`debug/winapi.py`) and crash detection — but the entire L2/L3 ladder is
Linux-specific (qemu-gdbstub/ptrace, Linux syscalls, glibc/ELF techniques). There is **no Windows
exploitation primitive**. This is the biggest *capability-class* gap, and the `~/Desktop/Exploit_Dev`
material (the XDS course) maps it module-for-module:

| XDS module | Capability | lykos today |
|---|---|---|
| 220 / Labs 4–5 | **SEH overwrite** (nSEH/SEH + pop-pop-ret + short jump) | reads `no_seh` bit only |
| 230 | **Egghunter** (staged, tiny-buffer) | none |
| 250 / Lab 7 | **Windows shellcode** (PEB-walk → kernel32 `WinExec`/`CreateProcess`) + demonstrable effect | `shellcode.py` is Linux `execve` only |
| 260 / Labs 18–19 | **Windows ROP / DEP bypass** (VirtualProtect/VirtualAlloc chains) | ROP engine builds Linux `system`/`mprotect` only |
| 240 | **Unicode / Venetian / charset-safe encoding** | bad-char XOR only, x86 Linux |

**Proposed minimal slice (mitigations-off first, honest about Wine fidelity):** SEH-overwrite →
pop-pop-ret → egghunter (tight buffers) → Windows `WinExec` shellcode, driven by the **existing
network fuzzer** (netfuzz spawns the service, finds the port, connects), and confirmed under Wine
by a **forgery-proof marker process** via `winedbg`. Scope it as "demonstrate on classic
no-DEP/no-ASLR targets under Wine," not parity with the Linux ladder — Wine's loader/ASLR/SEH and
heap fidelity differ from real Windows.

**Explicitly out of scope:** PE backdooring (XDS 005). That is implant-making, not vulnerability
demonstration, and does not fit the "prove a defect" thesis.

## Part D — `Exploit_Dev` as a Windows validation corpus

The XDS folder's real vulnerable targets — **vulnserver, FreeFloat FTP, Kolibri, EasyChat, BigAnt,
MP3 Studio** — are **known-vulnerable programs with ground-truth offsets and documented
exploitation paths** (the lab PDFs record the crash offset and technique). Today's benchmark
corpora (Juliet/LAVA/Magma/CGC) are synthetic and Linux/source-leaning; these give a **Windows
`corpus-regression` gate** mirroring the Linux one (`tools/corpus_regression.py`), and — because
most are network services — exercise the netfuzz → PE-crash → Windows-L3 chain end to end.

Two adjacent gains the corpus also motivates:

* **Stateful / sequence network fuzzing.** netfuzz documents two real limits — forking servers
  whose parent survives, and protocols needing state (FTP `USER`/`PASS` before the vulnerable
  verb). boofuzz (in `Exploit_Dev/Resources`) is the reference model. Helps Linux daemons too.
* **Windows crash triage** — a `!exploitable`/CASR-equivalent that recognizes SEH-chain
  corruption, so a Wine crash enters the ladder the way a Linux SIGSEGV does.

---

## Part E — Sequenced program

Cross-arch depth leads (user priority); Windows follows. Each milestone ends in a **measured,
ratcheted** result, never a described one.

* **M0 — scoreboard.** B.2: the arch × mechanism ceiling matrix + cross-arch L3 conformance cases
  + arch-gate ratchet. *Exit:* the B.1 table is generated and gating.
* **M1 — abstraction.** B.3: `ArchModel` + table-driven chain builder; the 4 existing cross-arch
  chains pass through it unchanged. *Exit:* green unit tests, ≥70 fewer duplicated lines/arch.
* **M2 — Tier-1 breadth.** B.4 #1–4: magic-overwrite on all 15; execve-syscall cross-arch;
  shellcode stubs for riscv64/ppc64le/mips/s390x; execstack shellcode on riscv64/ppc64le. *Exit:*
  every ret2win-only arch gains ≥1 no-`win()` RCE rung, measured.
* **M3 — Tier-2 breadth.** B.4 #5–7: ret2libc on s390x/sh4/loongarch64/m68k; mprotect+shellcode
  cross-arch; PPC big-endian. *Exit:* RCE L3 on all non-architecturally-capped ISAs.
* **M4 — MIPS.** B.5: toolchain + fixtures (ret2win), then the MIPS gadget model (ret2libc).
* **M5 — Tier-3.** B.4 #8–9: cross-arch info-leak (PIE/ASLR) + format-`%n`.
* **M6 — sparcv9 research** (B.6 window-spill) and **i386-as-foreign** (B.6) as scoped tracks.
* **M7+ — Windows.** Part C minimal slice + Part D corpus gate; then Tier-4 heap/SROP/dlresolve
  cross-arch as long-horizon research.

## Part F — Open decisions

1. **Offline qemu (B.7)** — confirm/ship `qemu-<arch>` in the bundle, or document cross-arch
   dynamic as online-build-only. Blocks the honesty rule; decide first.
2. **Fixture provisioning** — cross-compilers aren't installable on an air-gapped box. Commit a
   minimal set of prebuilt per-arch fixtures for the gate, or ship a fixtures container? (Today
   nothing is committed; only manifests.)
3. **sparcv9** — is window-spill L2 worth the research, or do we record an honest L1 ceiling and
   move on?
4. **Windows depth** — is the Wine-confirmed, mitigations-off slice enough to claim "Windows
   RCE (demonstrated, under Wine)", or do we hold until a real-Windows execution path exists?
