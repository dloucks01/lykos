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
- **[DONE] Command-injection PoC synthesis** (`synthesize_injection`) (CWE-78): for a reachable `system`/`popen`/`exec*`
  whose argument is input-derived, construct an input that injects `; id` and confirm dynamically.
- **[DONE] Format-string PoC synthesis** (`synthesize_injection`) (CWE-134): for a reachable `printf(user)`, build a
  `%p…%n` payload; confirm the leak/write dynamically.
- **[DONE] Path-traversal PoC synthesis** (`synthesize_injection`) (CWE-22): `../../etc/passwd` into a reachable
  `fopen(user)`; confirm the out-of-tree open.
- **[PLANNED] Secret-extraction "PoC"** (CWE-798/321): already found statically — package the
  extracted key/credential as the demonstrating artifact.

## B. Dynamic detection of classes the crash-only pipeline misses

- **[DONE] Instrumented dangerous-call monitor** (`debug_monitor`): runs under GDB with breakpoints
  on dangerous sinks, capture concrete args at runtime (copy lengths, command strings, size args)
  → dynamic evidence (a `system("…")` we watched execute; a `strcpy` of N bytes into an S-byte
  frame) without needing a segfault. See doc 08 / debug/monitor.py. **Windows PE branch**
  (`debug/winmonitor.py`, the Windows analog): runs the PE under Wine `+relay` and captures the
  concrete arguments at dangerous Win32 sinks — the command to CreateProcess/WinExec/ShellExecute/
  system → CWE-78, the format string to wsprintf (`%n`/`%s`) → CWE-134, the URL to
  URLDownloadToFile → CWE-494, plus the target's string-copy args (with length) as a call log.
  Attributed by the target's own thread + return-address in the exe's range (same as the PE
  behavior trace). Live-verified: `system("echo unlocked")` + the `strcpy("4242")` copies captured
  on `vuln_win64.exe` → CWE-78. Overflow verdicts on copies need the caller's PE stack-buffer size
  (not recovered yet); LoadLibrary is omitted (Wine's driver loads dominate it).
- **[DONE] Heap-error detection** (`heap_check`): an LD_PRELOAD guard-page allocator shim
  (`dynamic/heappoison.c`) catches use-after-free (CWE-416), double-free (CWE-415), heap buffer
  overflow (CWE-122) and invalid/wild free (CWE-590) at the exact access, plus opt-in leaks
  (CWE-401). These are silent corruptions that don't SIGSEGV, so fuzzing-by-crash never sees
  them. Native-arch, dynamically-linked targets; per-arch shim under qemu is future work.
- **[PLANNED] Dynamic taint tracking**: confirm a source→sink flow at runtime (we only do it
  statically now) — DTA over qemu, or a lightweight taint via the debugger.
- **[DONE] Syscall / behavior tracing** (`behavior_trace`): trace `execve`/`connect`/`open`-for-write etc. →
  behavioral capability inventory (backdoors, anti-analysis, network beacons). Native x86-64 uses
  GDB `catch syscall`; **cross-arch now runs under qemu-user's own `-strace`** (ABI-aware for any
  arch qemu supports — the gdbstub has no `catch syscall`). Same event shape / inventory / findings
  either way. Live-verified on aarch64 (`system` → `execve(/bin/sh)`). qemu-strace limit: it does
  not decode the `connect()` sockaddr, so a connection's family is inferred from the fd's prior
  `socket()` and the destination is reported undecoded (native still decodes ip:port). A
  `params.backend` override (auto|gdb|qemu) lets an analyst run a *native* target under the qemu
  backend too: the native GDB `catch syscall` can't follow a forked child's exec (glibc `system()`
  forks with `clone3` and execs in the child), so it records only the spawn; the qemu backend
  follows the child and captures the exec target. `clone3` added to the native catch set.
  **Windows PE now supported via a third backend** (`debug/winapi.py`, Wine `+relay,+module`): the
  Windows analog, capturing the target's own Win32 calls (exec / network egress / W^X / self-
  injection / anti-debug), attributed by the target's thread + return-address-in-exe-range so
  Wine's own service processes (same ImageBase) are excluded. Live-verified: `system("echo
  unlocked")` on `vuln_win64.exe` → a process-execution finding. **[PLANNED]** registry-write /
  file-I/O attribution (Wine's session init pollutes those; relay lacks the full key path). Runs both PE32+ (64-bit) and **PE32 (32-bit)** -- the latter needs the i386 WoW64 runtime (`wine32:i386`); a 32-bit PE without it is reported honestly (not "no behavior"). The wine prefix lives under `~/.cache/lykos/wineprefix` (user-owned: wine refuses to *create* a prefix under a world-writable `/tmp`), and a fresh prefix carries the WoW64 32-bit DLLs so PE32 targets run. Live-verified: `vuln_win32.exe` (i386 PE) traces the same process-execution finding.

## C. Automated debugger ("find things", not just capture a crash)

- **[DONE] Dangerous-call monitor** — B.1 (the first debugger flavor); native-arch (host GDB).
- **[DONE] Heap-error detection** — B.2, shipped as the LD_PRELOAD guard-page allocator
  (`heap_check`) rather than breakpoints (more precise: faults at the offending access).
- **[DONE] Comparison / secret extraction** (`extract_secrets`): breakpoint `strcmp`/`memcmp`/`strncmp`, dump the
  operand the program compares *our* input against → auto-recover passwords, magic bytes, license
  keys, expected tokens. Classic offensive RE; turns a crackme into an answer in one run.
- **[DONE] Cross-arch breakpoints**: the `debug_monitor` stage now runs emulated targets under the
  qemu-user gdbstub. `qemu_gdb.monitor_calls` places `Z0` breakpoints at the dangerous sinks
  (resolved from the ELF's own `.symtab` via `debug/elfsyms.py`, rebased by the runtime entry the
  stub reports), reads the arch's argument registers at each hit, and dereferences pointer args as
  C-strings over `m` memory reads -- all endianness/bit aware (`_ARG_REGS`/`_BP_KIND`,
  `breakpoints_supported`). Hits decode through the same `monitor.CATALOG` as native, yielding
  CWE-78 (executed command) and CWE-242 (`gets`) findings. Live-verified on aarch64: captured
  `system("echo unlocked")` and the `strcpy`/`strcat` copies. Limits: needs static function
  symbols (stripped/PLT-only cross-arch binaries yield no sinks); no backtrace over the stub, so
  the CWE-121 caller-buffer overflow predicate stays native-only. (Syscall/behavior tracing is now
  cross-arch too, via qemu-user `-strace` — see the behavior-tracing item above.)
- **[DONE] Analyst `sink_addrs` escape hatch**: a stripped, *statically-linked* binary loses sink
  identity entirely (no `.symtab`, and Ghidra recovers the functions only as `FUN_xxxx`), so
  name-based resolution finds nothing on either path. `debug_monitor` now accepts
  `params.sink_addrs` ({catalog-name: vaddr}, hex or int) to breakpoint sinks by address:
  cross-arch merges them into the symbol map (rebased by the runtime entry like any symbol),
  native breakpoints `*addr` via a new `run_monitor(addr_sinks=...)`. Each is decoded with that
  name's CATALOG spec. Analyst-in-the-loop (addresses come from a non-stripped twin or manual RE).
  UI: optional "sink addrs" + "monitor argv" fields by the Runtime-monitor button. Live-verified
  on a stripped static-pie aarch64: `system=0xc5c,strcpy=0x3250,strcat=0x3220` → captured
  `system("echo unlocked")` → CWE-78, on a symbol-less binary. Verified in the GUI across the
  corpus: stripped aarch64 / mipsel / mips_be / ppc (cross-arch) and stripped static x86-64
  (native). Both paths are **PIE-aware**: analyst addresses are ELF vaddrs rebased by the runtime
  load base (cross-arch: `runtime_entry − e_entry` from the gdbstub; native: `AT_ENTRY − e_entry`
  from auxv, robust even for dynamic PIE where `starti` stops in ld.so), so they hit under ASLR.
  Caveat: glibc string functions are IFUNCs, so their `nm` symbol is the resolver, not the impl —
  `system` (a normal function) is the reliable address to supply on glibc; musl builds don't
  IFUNC, so `strcpy`/`strcat` addresses work there.

## C2. Execution environment

- **[DONE] Windows PE execution substrate (Wine)**: `sandbox.run` detects a PE by image magic and runs it
  under Wine (persistent WINEPREFIX, rlimits tier, timeout, process-group kill), classifying guest
  crashes from Wine's `Unhandled exception code cXXXXXXXX` (NT status → ACCESS_VIOLATION/STACK_
  OVERFLOW/…). Routing is by magic in the shared choke point, so **`dynamic_run` and full fuzzing**
  work on PEs unchanged. Optional tool (like Ghidra/angr): absent → `unsupported-windows`, not a
  false result. Live-verified on `vuln_win64.exe`: clean run, an access-violation crash → Confirmed
  CWE-119, and a fuzz campaign that found + minimized (1100→619B) the crash. Scope so far is
  execution + crash detection + fuzzing; **[PLANNED]** the monitor / behavior_trace on PE would need
  Win32 API hooking (`WINEDEBUG=+relay` parse, or a Detours-style shim) — a separate effort. Wine is
  ~150–300ms/exec so PE fuzzing is slower than native.
- **[DONE] Interactive detonation console** (`/console` WebSocket): a GUI panel to run the target in the sandbox
  with chosen argv/stdin/env and do live send/receive, so an analyst can reach code behind
  menus or a protocol handshake (the reachability limit the synthesizer/monitor hit). A
  recorded session becomes a seed for the fuzzer / heap-check / monitor. (One-shot detonation
  already exists as `dynamic_run`; every dynamic stage already sandbox-executes the target.)

## D. Recon / intelligence

- **[DONE] Embedded-library fingerprinting → offline CVE matching** (`cve_scan`): detect statically-linked
  library versions (zlib/openssl/busybox/…) from version strings/symbols and match a **vendored,
  offline** CVE DB. For static/stripped firmware this is often the fastest path to a real vuln and
  needs zero fuzzing.
- **[DONE] Crash exploitability rating** (in `root_cause`): a `!exploitable`/CERT-triage-style score layered on
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
