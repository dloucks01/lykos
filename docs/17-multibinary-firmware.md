# 17 — Multi-Binary / Inter-Component & Firmware Analysis

Real targets are rarely one binary. A vulnerability often *crosses a boundary*: attacker data enters
component A and reaches a dangerous sink in component B. This document adds cross-component analysis and the
firmware/embedded track. Both are **[DECIDED in scope]** (doc 15).

## 17.1 The component graph (the unifying model)
Model a case as a set of **Components** (binaries/modules/tasks) connected by typed **edges**:
| Edge type | Example | How discovered |
|---|---|---|
| **Dynamic link** | httpd → libcfg.so exported `cfg_get` | import/export tables, PLT/GOT resolution across case targets |
| **dlopen / plugin** | host loads modules at runtime | string/const refs to module paths + dynamic trace |
| **IPC** | unix/tcp socket, pipe, shared mem, message queue | matched syscall pairs (bind/connect, shmget key, mq name) |
| **RPC / message bus** | D-Bus, protobuf-over-socket | interface-name/const detection + dynamic trace |
| **File / config** | A writes, B reads a state file | taint to file APIs with matching paths |
| **exec / spawn** | A `execve`s B with argv | call-site args + process tree |
This graph is a first-class case artifact (doc 12) and a GUI **System Map** view (doc 09): nodes are
components (arch/format/mitigations), edges are relationships, and findings can span an edge.

## 17.2 Cross-binary static analysis
- **Case-wide callgraph:** resolve each component's imports against the exports of every other component in
  the case (versioned symbol matching for stripped libs via signatures + corpus-diff, doc 04). Produce one merged
  call graph spanning binaries, not N isolated ones.
- **Cross-binary taint (doc 05):** propagate taint *through* a resolved inter-binary call (A's tainted arg →
  B's parameter → B's sink) and *across* IPC by modeling each channel as a paired **taint sink (send) →
  taint source (recv)** with a "channel contract" (what serializes across). This is how a source in A and a
  sink in B become one **cross-component finding**.
- **This is a solved deterministic problem (doc 16), no AI:** our component graph is essentially **Karonte's
  Binary Dependency Graph** (S&P'20 -- 46 zero-days across 53 firmware images with pure static taint). Adopt
  its patterns plus **SaTC** (shared-keyword front-end/binary taint), **BPDA** (faster + more precise), and
  **Mango** (scalable taint-style discovery). Study these before building the taint engine.
- **Interface/contract inference:** for opaque IPC, infer the message schema (from serialization code /
  constants / observed traffic) so the fuzzer knows the structure to mutate (doc 07).

## 17.3 Multi-binary dynamic analysis
- **Whole-system detonation:** run the entire component set together in one isolation domain (system-mode
  QEMU or a microVM, doc 06) so *real* IPC/linking happens; snapshot the whole system, not one process.
- **Selective emulation:** or run one component under Qiling with the others **stubbed/modeled** (fast, but
  requires channel contracts). Choose per goal.
- **Multi-process debugging:** follow-fork/exec, attach to spawned children, set breakpoints across
  processes, and correlate a crash in B back to the input that entered A (**cross-boundary blame**).

## 17.4 Multi-binary harnessing & fuzzing (doc 07)
- **Boundary-driven harness:** fuzz a server by driving its socket; fuzz a library by generating a caller;
  fuzz a producer→consumer pair by mutating the channel between them.
- **Blame + attribution:** record `(entry component, entry vector) → (crashing component, faulting site)` so
  a crash deep in B is traced to the reachable input in A.
- Directed fuzzing (classical CFG/callgraph distance, AFLGo-style) can steer across the merged callgraph
  toward a cross-component candidate.

## 17.5 Firmware / embedded rehosting track
A firmware image is the extreme multi-component case (bootloader + kernel + tasks + services) *and* needs
hardware it doesn't have. Rehosting = emulate it faithfully enough to execute/fuzz. Adopt (doc 16):
- **Peripheral / MMIO modeling:** **Fuzzware** (precise MMIO models) + **ES-Fuzz** (adaptive MMIO chunks)
  so reads from unmodeled hardware don't dead-end execution.
- **DMA rehosting:** **GDMA** (iterative type overlays) for DMA-driven firmware.
- **Interrupts/timers:** Unicorn/QEMU with modeled NVIC + systick (Fuzzware approach).
- **Network stacks:** **protocol-aware rehosting** (CCS'25) for embedded network services.
- **System-level symbolic:** **SysFuSS** (2026) -- selective symbolic execution over rehosted firmware to
  reach deep states deterministically.
- **Image decomposition:** carve the image (binwalk-style), identify base address/entry, split into
  components, and feed them into the component graph (17.1). Bare-metal blobs use the headerless loader
  wizard (doc 04.6) with the target arch (ARM/PPC/MIPS, doc 15).
- **Fidelity ladder:** partial (single task under Unicorn+models) → full-system (whole image under QEMU) →
  hardware-in-the-loop is **out of scope** (air-gapped, no device farm).

## 17.6 What it produces
A merged component graph, cross-component findings with source/sink in different binaries, whole-system
crash reproductions, and firmware-task-level PoCs — all in the same case data model (doc 12) and findings
lifecycle (doc 05).
