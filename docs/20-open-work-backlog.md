# 20 — Open Work / Backlog

Running list of capabilities discussed and not-yet-fully-built, so nothing gets lost. Status
tags: **[DONE]** shipped & verified, **[WIP]** in progress this stream, **[PLANNED]** agreed
direction, not started. Everything here is deterministic / zero-AI (doc 15 §5). Roadmap phase
notes (doc 13) carry the authoritative "what shipped"; this doc is the forward queue.

## A. PoC creation beyond fuzzing (deterministic input synthesis)

Motivation: for a long time every poc-backed finding traced to a *fuzzer/concolic-produced*
crashing input; many bug classes have a **derivable** input and need no fuzzing.

- **[DONE] Directed overflow-PoC synthesis** (`synthesize_poc`): from a static CWE-121 (recovered
  stack frame → buffer size + offset), synthesize the overflow input, auto-detect the input
  channel, detonate once, build a verified L1 PoC. Feeds L2/L3 unchanged.
- **[PLANNED] Command-injection PoC synthesis** (CWE-78): for a reachable `system`/`popen`/`exec*`
  whose argument is input-derived, construct an input that injects `; id` and confirm dynamically.
- **[PLANNED] Format-string PoC synthesis** (CWE-134): for a reachable `printf(user)`, build a
  `%p…%n` payload; confirm the leak/write dynamically.
- **[PLANNED] Path-traversal PoC synthesis** (CWE-22): `../../etc/passwd` into a reachable
  `fopen(user)`; confirm the out-of-tree open.
- **[PLANNED] Secret-extraction "PoC"** (CWE-798/321): already found statically — package the
  extracted key/credential as the demonstrating artifact.

## B. Dynamic detection of classes the crash-only pipeline misses

- **[DONE] Instrumented dangerous-call monitor** (`debug_monitor`): runs under GDB with breakpoints
  on dangerous sinks, capture concrete args at runtime (copy lengths, command strings, size args)
  → dynamic evidence (a `system("…")` we watched execute; a `strcpy` of N bytes into an S-byte
  frame) without needing a segfault. See doc 08 / debug/monitor.py.
- **[DONE] Heap-error detection** (`heap_check`): an LD_PRELOAD guard-page allocator shim
  (`dynamic/heappoison.c`) catches use-after-free (CWE-416), double-free (CWE-415), heap buffer
  overflow (CWE-122) and invalid/wild free (CWE-590) at the exact access, plus opt-in leaks
  (CWE-401). These are silent corruptions that don't SIGSEGV, so fuzzing-by-crash never sees
  them. Native-arch, dynamically-linked targets; per-arch shim under qemu is future work.
- **[PLANNED] Dynamic taint tracking**: confirm a source→sink flow at runtime (we only do it
  statically now) — DTA over qemu, or a lightweight taint via the debugger.
- **[PLANNED] Syscall / behavior tracing**: trace `execve`/`connect`/`open`-for-write etc. →
  behavioral capability inventory (backdoors, anti-analysis, network beacons).

## C. Automated debugger ("find things", not just capture a crash)

- **[DONE] Dangerous-call monitor** — B.1 (the first debugger flavor); native-arch (host GDB).
- **[DONE] Heap-error detection** — B.2, shipped as the LD_PRELOAD guard-page allocator
  (`heap_check`) rather than breakpoints (more precise: faults at the offending access).
- **[PLANNED] Comparison / secret extraction**: breakpoint `strcmp`/`memcmp`/`strncmp`, dump the
  operand the program compares *our* input against → auto-recover passwords, magic bytes, license
  keys, expected tokens. Classic offensive RE; turns a crackme into an answer in one run.
- **[PLANNED] Cross-arch breakpoints**: extend the monitor/heap-tracker to emulated targets via
  `Z0` breakpoint packets over the qemu-gdbstub RSP client we already built (debug/qemu_gdb.py).
  (Monitor v1 is native-only, like root-cause.)

## C2. Execution environment

- **[PLANNED] Interactive detonation console**: a GUI panel to run the target in the sandbox
  with chosen argv/stdin/env and do live send/receive, so an analyst can reach code behind
  menus or a protocol handshake (the reachability limit the synthesizer/monitor hit). A
  recorded session becomes a seed for the fuzzer / heap-check / monitor. (One-shot detonation
  already exists as `dynamic_run`; every dynamic stage already sandbox-executes the target.)

## D. Recon / intelligence

- **[PLANNED] Embedded-library fingerprinting → offline CVE matching**: detect statically-linked
  library versions (zlib/openssl/busybox/…) from version strings/symbols and match a **vendored,
  offline** CVE DB. For static/stripped firmware this is often the fastest path to a real vuln and
  needs zero fuzzing.
- **[PLANNED] Crash exploitability rating**: a `!exploitable`/CERT-triage-style score layered on
  the existing root-cause output (near-null vs high address, write vs read, PC control, etc.).

## E. Corpus & coverage

- **[DONE] Multi-arch RE corpus** (`examples/re-corpus/`): busybox across 13 arches + PE/C++/Rust/
  stripped/static/UPX; plus `vuln_{aarch64,mipsel,mips_be,ppc}` cross-built via musl toolchains.
- **[PLANNED] More cross-arch vuln binaries**: riscv64 / s390x / arm / sparc small stack-overflow
  builds (musl cross toolchains) to keep extending the offset/L2 cross-arch matrix.
- **[PLANNED] Go / Rust deeper coverage**: currently one Rust real-world binary (ripgrep); add a Go
  binary and exercise the RE views against runtime-heavy, monomorphized code.

## F. Offset / L2 primitive hardening (delivered, kept here for context)

- **[DONE]** Static stack-frame → L2 offset corroboration + static-seeded confirmation, verified
  across x86-64 / aarch64 / mips (LE+BE) / ppc, 32- & 64-bit, stripped, both byte orders, and the
  x86 / link-register (aarch64 stp, mips $ra, ppc lr) frame conventions. 32-bit sentinel,
  endianness-aware register capture + offset search, ±word ABI slack, largest-buffer attribution.
