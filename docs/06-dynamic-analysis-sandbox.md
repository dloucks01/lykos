# 06 — Dynamic Analysis & Sandboxing

> **Threat model:** the target may be malicious. Dynamic analysis = detonating untrusted code. Isolation is
> the backbone, not a feature. (Gap C, doc 01.)

## 6.1 Tiered isolation (choose per target/trust)
| Tier | Mechanism | Use for | Escape risk |
|---|---|---|---|
| T0 in-process emulation | Unicorn / Qiling (guest code can't issue host syscalls) | surgical single-function exec, foreign arch | very low |
| T1 process sandbox | bubblewrap / nsjail + seccomp + namespaces + rlimits | benign-ish native same-arch runs | low-med |
| T2 microVM | Firecracker / cloud-hypervisor (KVM) | untrusted native code, fast boot, snapshots | low |
| T3 full-system VM | QEMU-system (+KVM if same arch) | foreign arch, kernel/driver, firmware, max isolation | lowest |

**Default policy:** unknown/untrusted binary → **T2/T3**. Never run untrusted native code in a worker's own
address space. In-process emulation (T0) is safe *only* because emulated guest code cannot make host syscalls.

## 6.2 Containment invariants (always on)
- **No network egress** by default; optional **fake-services** mode (INetSim/FakeNet-style, bundled) when a
  target needs to "see" a network to proceed. All simulated, no real egress.
- **Filesystem:** ephemeral overlay per run; target sees a synthetic rootfs; host FS never mounted writable.
- **Resource caps:** CPU time, wall clock, memory, PID/FD counts, disk quota; hard kill on breach.
- **Snapshot/restore** between runs so state never leaks run-to-run and fuzzing can reset fast (doc 07).
- **Anti-analysis handling:** detect anti-debug/anti-VM/timing checks (flagged in doc 04.7) and, where in
  scope, neutralize (patch checks, hide debugger) — but log every modification.

## 6.3 Execution & emulation backends
- **Native + KVM** when workstation arch == target arch (fastest).
- **QEMU user-mode** for foreign-arch userland binaries.
- **QEMU system-mode** for full OS / kernel / driver / firmware targets.
- **Qiling** for OS/syscall emulation with a fabricated environment (great for partial binaries).
- **Unicorn** for raw CPU-only emulation of a single function with a synthesized register/memory state
  (feeds harnessing, doc 07).
- **Firmware/embedded + multi-binary systems:** rehost with **Fuzzware**-style precise MMIO modeling,
  **ES-Fuzz** adaptive MMIO, **GDMA** DMA rehosting (doc 16); run multiple linked/IPC-connected components
  together in one isolation domain with multi-process debugging. **Full treatment in doc 17.**

## 6.4 Instrumentation, tracing, coverage
- **Coverage:** edge/block coverage via QEMU-mode or DynamoRIO/Frida — the fuel for coverage-guided fuzzing.
- **Tracing:** syscall trace, API/library-call trace, memory-access trace, and a full **execution trace**
  for time-travel/root-cause (doc 08). Optionally record replayable traces (rr-style where feasible).
- **Binary sanitizers** (memory safety without source — Gap F): **QASan** (QEMU+ASan, cross-arch) as the
  default; **RetroWrite** (static ASan rewrite, low overhead) for x86-64 PIE; **MTSan** for AArch64. These
  turn silent corruption into a labeled, located, deduplicable event.
- **Taint tracking (dynamic):** DTA over QEMU/libdft-style to confirm source→sink at runtime.

## 6.5 Integrated debugger
- **GDB** (+ Python API, GEF/pwndbg-style enrichment) and/or LLDB, driven from the GUI (doc 09): breakpoints,
  stepping, register/memory/stack views, heap visualization, watchpoints. Attach to native (T1/T2) or via
  gdbstub to QEMU (T3) and even to Unicorn/Qiling (T0). Reverse-debugging where the backend supports it.
- The debugger is also *programmatic*: triage and PoC stages script it (doc 08).

## 6.6 What dynamic analysis produces
Coverage maps, traces, crash records (signal, faulting IP, backtrace, sanitizer report), confirmed taint
paths — all correlated back to findings (doc 05) and stored in the case (doc 12).
