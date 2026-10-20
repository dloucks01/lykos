# 42 — Strategy-expansion outcome: execstack shellcode breadth (done) + why multi-register syscall-ROP is gadget-blocked (2026-10-19)

Follows doc [41](41-weaponization-breadth-2026-10-19.md). After the cross-arch **ret2libc→`system`**
ladder reached 8 architectures (loongarch64, s390x, ppc32-BE added through the `ArchModel`
abstraction; see the `weaponize/archmodel-cross-arch` branch), two further strategy tracks were
attempted:

* **B — NX-off execstack ret2shellcode:** **DONE for every buildable arch.**
* **A — NX-on execve-syscall / mprotect via multi-register ROP:** **empirically gadget-blocked** on
  the RISC arches; recorded here with the evidence so it is not re-attempted blindly.

Every claim below is **[measured]** (a number from a run here) or **[observed]** (read in a binary /
the code).

---

## B — execstack ret2shellcode is complete

`_shellcode_emu_exploit` injects shellcode into an executable-stack overflow where a register points
at the buffer, overwrites the saved return with a jump-through-register gadget, and confirms by a
**spawned shell** under qemu-user (the guest execve is relayed to the host) or a written marker, each
with a broken-gadget negative control. It now covers:

| Arch | jump-through-reg gadget | shellcode stubs | status |
|---|---|---|---|
| x86-64 | `jmp rsp` / `jmp reg` | existing | shipped |
| aarch64 | `br/blr <Xn>` | existing | shipped |
| arm | `bx/blx <Rn>` | existing | shipped |
| riscv64 | `jr/jalr <rN>` | **new** | **[measured] L3 shell** |
| ppc64le | `mtctr rX; bctr` | **new** | **[measured] L3 shell** |
| s390x (BE) | `br %rX` | **new** | **[measured] L3 shell** |
| ppc32 (BE) | `mtctr rX; bctr` | **new** | **[measured] L3 shell** |
| mips / mipsel / mips64(el) | — | — | **blocked: no MIPS cross-compiler on this host** |

Each new stub (`execve_binsh_*` / `write_marker_*`) was verified by running its bytes **as injected
code** (an RWX buffer called through a pointer) under the matching qemu — a standalone `_start` exe
misloads on ppc as ELFv1, so injection is the correct test. Two shared-path facts this surfaced:

* **Return-address packing must be endian- and word-aware** — it was hardcoded 8-byte little-endian,
  which silently misplaced the gadget on a big-endian (s390x, ppc) or 32-bit (ppc32) saved return.
* **Link-register arches (ppc/s390) need the saved-LR offset DISCOVERED** by a tagged detonation —
  the L2 candidate recovers the fault PC, not the on-stack saved-LR slot.

mips is the only gap and it is a toolchain gap, not an engine gap: install a MIPS cross-compiler
(`gcc-mips-linux-gnu` / …) and the same recipe applies (qemu-mips and a `_LAYOUTS["mips"]` already
exist).

---

## A — multi-register syscall-ROP is gadget-blocked (not engine-blocked)

**Goal:** execve-syscall (`execve("/bin/sh",0,0)` via a raw syscall) and mprotect+shellcode on NX-on
targets, cross-arch, for cases where `system` is not linked. Both need **several argument registers
set at once** (execve: path/argv/envp + the syscall-number register; mprotect: addr/len/prot) and
then a syscall/branch.

**Why it does not generalize to the RISC arches.** The shipped cross-arch ret2libc works because it
needs control of exactly **one** argument register, via a `mov x0,xS; blr xB`-shape caller gadget
(and the loader that feeds its two callee-saved regs) — those gadgets exist. Setting three or four
registers needs **pop-style gadgets** (`ldp x0,x1,[sp..]; ret`, `pop {r0,r1,r2}` …) chained through
the stack. Those gadgets are **not present** in the binaries:

* **aarch64 (the richest-gadget arch), static glibc `vuln` fixture [measured]:** scanning every
  executable instruction, a window of 5 after each `ldp x0,x1,[sp,#imm]` for a `ret` with no
  intervening write to x0/x1 found **0** usable "set the argument registers then return" gadgets.
  There is exactly **1** `mov x8,#221; …; svc` (the libc execve syscall site) — a usable syscall
  *trigger* — but **no ROP way to set x0/x1/x2 before reaching it.** This is the well-known AArch64
  reality: the ABI/compiler does not emit `pop`-into-argument-register epilogues, so simple ROP
  pop-chains do not exist; aarch64 exploitation uses the two-gadget ret2libc (shipped) or JOP/COP.
* **ppc64-BE (ELFv1) [measured]:** **0** clean one-shot `mtctr rC; mr r3,rT; bctr` callers with both
  registers callee-saved (the 7 callee-reg `mtctr`s are all `bdnz` loop counters) — so even the
  single-arg ret2libc does not have a gadget there, let alone a multi-arg chain. (ppc32-BE *does*
  have them, which is why ppc32-BE ret2libc shipped.)

**Conclusion.** A is **gadget-blocked, not engine-blocked** — a better/general ROP engine cannot
synthesize gadgets that are not in the target. On these arches the maximal bounded control-flow
primitive is the **one-argument ret2libc→`system`**, which is already delivered on 8 architectures
and is itself arbitrary-command execution (a strictly-stronger-or-equal effect than an execve-syscall
of `/bin/sh`). execve-syscall / mprotect-ROP would be reachable only through genuine frontier AEG
(JOP/COP, stack pivots to a leaked buffer, SROP where a sigreturn exists) — a research track, scoped
exactly as `docs/overview.md` already scopes L3 ("frontier research, best-effort, scoped").

**Net:** the strongest *bounded* cross-arch weaponization is the shipped ret2libc (NX-on, 8 arches) +
execstack ret2shellcode (NX-off, 7 arches). A's syscall-ROP is not a bounded deliverable on the RISC
targets and is left as documented research.
