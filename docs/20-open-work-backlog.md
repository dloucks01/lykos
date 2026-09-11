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
- **[DONE] Secret-extraction "PoC"** (`synthesize_secret`) (CWE-798/321): a hard-coded credential
  needs no crash and no fuzzing — it is already in the binary, so the demonstrating artifact is the
  secret itself (the deterministic analog of a crash reproducer). The stage re-runs the static
  detector's exact predicate (so dedup keys match and the existing candidate is **promoted**, not
  duplicated), locates each secret's concrete **byte offset** in the file, **verifies** it by
  re-extracting those exact bytes, and packages a self-contained PoC bundle: the binary, the
  extracted secret(s), and a **pure-stdlib offline re-extractor** (`extract.py`) any analyst can run
  to independently recover the credential from the binary alone — no execution, no fuzzing, no this
  tool. The finding is promoted to **poc-backed** with a verified `L0-secret` PoC. Safe (reads the
  file only; never runs the target) and falsifiable (the reproducer reports failure on a binary that
  lacks the secret). UI: a "Package secret PoC" button. Live-verified end-to-end: a binary with a
  planted AWS key + DB password → both candidates promoted to poc-backed, and the bundle pulled from
  the live artifact store re-extracts both secrets offline. Honest limit: it proves the credential is
  embedded and recoverable; whether it is still live on a real service is out of scope (rotate it).

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
- **[DONE] Dynamic taint tracking** (`dynamic_taint`): confirm a source→sink flow at runtime
  (marker-based, #3). Feeds a unique ASCII marker as the program's input, runs the target under
  the dangerous-call monitor (native GDB / cross-arch qemu-gdbstub, same routing as
  debug_monitor), and reports a **Confirmed** flow wherever the marker turns up in a sink's
  captured argument: input→exec (system/popen) → CWE-78, input→format (printf) → CWE-134,
  input→string-copy source → CWE-120. Not full byte-level DTA, but a sound observation of the
  flow the static taint only approximated; keyed by sink so it promotes the matching static
  finding. The monitor now also captures the copy *source* string (not just its length) for the
  match. Live-verified: cross-arch aarch64 (marker → strcpy/strcat/memcpy) and native
  command-injection (marker → strcpy → **system**, CWE-78). ELF native + cross-arch; PE taint
  is future work. UI: a "Dynamic taint" button.
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
  unlocked")` on `vuln_win64.exe` → a process-execution finding. **Registry/file behavior captured** (#2): the PE behavior trace reports autostart **persistence** (a write under a full-path CurrentVersion\Run/RunOnce/Winlogon/IFEO/AppInit_DLLs key), **file writes** (CreateFile GENERIC_WRITE) and **deletes**. Made tractable now by (a) thread+range attribution excluding Wine's service processes and (b) recovering the full key path from RegCreateKey/RegOpenKey's subkey arg + HKEY root (backslashes un-escaped). Wine's in-process session init still touches the registry, so only full-path persistence keys surface; the raw key list stays in the events artifact. Also fixed a real attribution bug: new-Wine (WoW64) maps a DYNAMICBASE PE TWICE (loader inspection + real run at 0x140000000 on another thread), so we attribute against every mapping now (also corrected the monitor/behavior trace for mingw PEs). Runs both PE32+ (64-bit) and **PE32 (32-bit)** -- the latter needs the i386 WoW64 runtime (`wine32:i386`); a 32-bit PE without it is reported honestly (not "no behavior"). The wine prefix lives under `~/.cache/lykos/wineprefix` (user-owned: wine refuses to *create* a prefix under a world-writable `/tmp`), and a fresh prefix carries the WoW64 32-bit DLLs so PE32 targets run. Live-verified: `vuln_win32.exe` (i386 PE) traces the same process-execution finding.

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
  stripped/static/UPX; plus `vuln_{aarch64,arm,mipsel,mips_be,ppc}` cross-built via musl toolchains.
- **[DONE] 32-bit ARM (armhf) deepened end-to-end** — `vuln_arm` + `vuln_arm_stripped` (ARMv7 EABI5,
  static-pie, musl cross from musl.cc; `build_corpus.sh` gained a `MUSL_CROSS_ROOT` matrix). Verified
  live across the whole pipeline: triage (arm/32/LE), Ghidra disasm + signatures/frames, detect_cwe
  (CWE-121 128-byte buffer, CWE-78 system, CWE-120, CWE-134), the cross-arch dangerous-call monitor
  (captured `system("echo unlocked")` → corroborated CWE-78), `behavior_trace` (exec `/bin/sh` via
  qemu-arm `-strace`), `synthesize_poc` (verified L1 SIGSEGV), `poc_primitive` (**verified L2
  IP-control**), and the `sink_addrs` escape hatch on the stripped twin (PIE-rebased). **Fixed a real
  ARM Thumb-interworking L2 bug**: `pop {pc}`/`bx` masks bit 0 of the loaded PC (Thumb/ARM state
  select), so the captured fault PC is `value & ~1`; when that aliases the neighbouring De Bruijn word
  (differs only in bit 0), the naive offset search pinned the return-address slot one word early and
  the marker never confirmed. `primitive_stage` now also searches `(pc | 1)` to restore the masked
  bit, and lets **confirmation** (not the raw heuristic) decide the reported offset — trying the
  dynamic offset, its Thumb-alias sibling, then the static-frame predictions, and self-correcting an
  off-by-a-word recovery. Regression-tested (`tests/test_arm.py`). General robustness win for every
  arch (a mis-recovered dynamic offset now gets a static-seeded second chance before finalizing
  unconfirmed).
- **[PLANNED] More cross-arch vuln binaries**: riscv64 / s390x / sparc small stack-overflow
  builds (musl cross toolchains) to keep extending the offset/L2 cross-arch matrix (arm/aarch64/
  mipsel/mips_be/ppc done).
- **[PLANNED] Go / Rust deeper coverage**: currently one Rust real-world binary (ripgrep); add a Go
  binary and exercise the RE views against runtime-heavy, monomorphized code.

## F. Offset / L2 primitive hardening (delivered, kept here for context)

- **[DONE]** Static stack-frame → L2 offset corroboration + static-seeded confirmation, verified
  across x86-64 / aarch64 / mips (LE+BE) / ppc, 32- & 64-bit, stripped, both byte orders, and the
  x86 / link-register (aarch64 stp, mips $ra, ppc lr) frame conventions. 32-bit sentinel,
  endianness-aware register capture + offset search, ±word ABI slack, largest-buffer attribution.

## K. Product restructuring (September 2026, from running the GUI against real code)

Driven by a walkthrough of the web GUI against jhead (real third-party source, not a program
we wrote), which produced "27 findings, 0 confirmed, 0 poc-backed" — nice information, not
actionable.

- **[DONE] A finding is a DEFECT; call sites are evidence.** One call site was one finding,
  so the count tracked compiler inlining: jhead 3.06 with distro flags gave 27 findings, the
  same program at -O0 gave 230. Migration 11 adds `finding_site`. Measured: 27 findings ->
  5 findings / 27 sites. The board gained SITES and WHERE columns; board, workbench and
  report finally agree on what a finding is.
- **[DONE] "What to do next" moved out of the GUI** into `analyze/advise.py` + a real
  endpoint (`GET /targets/<id>/advice`), so the API and CLI get the same answer. It also
  fixes what the GUI logic got wrong: it recommended `directed` whenever static findings
  existed and never mentioned coverage-guided fuzzing, but `directed` is still blind mutation
  biased toward sink addresses (~195 execs/sec, no feedback, nothing found in 505s on jhead),
  while AFL++ on the same program did ~15,000 execs/sec with edge coverage and found five
  SIGSEGV crashes in 60s.
- **[DONE] The default pipeline is dynamic-first.** `advise()` returns an ordered PLAN that
  leads with execution: fuzz -> root_cause -> build_poc -> poc_primitive, with disassemble
  and detect_cwe demoted to "explain what execution found". Static analysis is supporting
  evidence, ranked below anything demonstrated. The GUI renders it as "Plan — evidence first".
- **[DONE] CWE-120 bounds reasoning** (`detect/bounds.py`). At a copy sink it resolves the
  destination to a recovered stack variable and the length to a compile-time constant, then
  compares them. `memcpy(buf, src, sizeof buf)` and `strncpy(buf, src, sizeof buf - 1)` both
  compile to exactly that shape, so the safe idioms become provably safe and demote out of the
  headline with the arithmetic attached. A length it cannot pin stays UNKNOWN and the finding
  is left untouched — it only ever moves a verdict when it has a reason.
  It DEMOTES but never asserts an overflow, and the reason is worth keeping: C locals in
  disjoint scopes share stack slots, so a recovered frame can attribute the wrong variable and
  size to an address. jhead's ProcessFile is the worked example — the source has
  `char Comment[16001]` at RBP-0x3f50 and copies 16000 into it (safe), while Ghidra's frame
  names that exact offset `st`, a 144-byte struct stat from a sibling scope. Asserting there
  would have fabricated a critical finding in correct code. The error is asymmetric: too-small
  a recovered size invents an overflow, too-large merely misses one, and a fabricated finding
  costs the reader's trust in every other finding in the report.
- **[DONE] Dominating-guard reasoning** (`bounds.guard_bound`). `if (n < sizeof buf) memcpy(buf,
  s, n)` is the shape of nearly every real bounds check, and it leaves the length a local rather
  than a constant — 37 of jhead's 42 copy sites. The pass computes dominator sets over the
  function CFG, and for each block that dominates the copy, reads a comparison of the length's
  frame slot against a constant plus the branch that acts on it. Polarity comes from the branch
  mnemonic (x86 builds `JG` out of flag algebra, which is painful to evaluate symbolically and
  completely stable to read off the mnemonic), and from which edge actually reaches the copy —
  the guarded body is as often the fall-through (`JGE skip`) as the taken edge. The comparison
  scan is block-wide, not per-instruction: gcc emits `cmpl $64,-4(%rbp)` and
  `movl -4(%rbp),%eax; cmpl $64,%eax` about equally, and tracking only within one instruction
  missed every split form.
  `n < K` bounds at K-1, `n <= K` at K, a lower bound yields nothing, and an unreadable polarity
  returns None rather than a guess — claiming a bound that is not there would manufacture a
  "safe" verdict over a real overflow, the one error this whole channel is built to avoid. Two
  further refusals earned the same way: a comparison against 0 is a null test, not a size bound
  (reading it as one produced "at most 0 bytes reach this copy" on jhead's `DoCommand`), and a
  check that dominates but permits more than the buffer holds is SUSPECT, not SAFE — a guard
  that exists reads as careful code and can still be wrong.
  Measured on jhead 3.04: 37 unknown → 36, with the newly resolved site landing in
  `ProcessFile` on the same `Comment`/`st` slot-reuse artifact documented above (surfaced for
  review, never asserted). On a controlled fixture with known ground truth all four shapes
  resolve correctly: `n<64` → at most 63, `n<=64` → at most 64, `n<4096` into `buf[64]` →
  exceeds-recovered-size, unguarded → unknown.
- **[DONE] Signed-length hazard** (`bounds.SIGNED`, verdict `signed-length`). An upper bound
  alone is not a bound. `if (n < 64) memcpy(buf, s, n)` on an `int` admits `n = -1`, which the
  sink's `size_t` parameter takes as `0xFFFFFFFFFFFFFFFF` — the check reads as careful code and
  the copy is unbounded. `guard_bound` now returns the two halves separately, `{bound, nonneg}`,
  and a guard-derived SAFE requires both.
  `nonneg` comes from the branch mnemonic, the same authority the polarity does: `JB`/`JA` are
  unsigned and prove `0 <= n` for free, `JL`/`JG` are signed and prove nothing below. A signed
  upper bound therefore needs a *separate* dominating check, which the pass looks for via
  `_LOWER` (`n >= 0`, `n > 0`, `n == K`). `JS`/`JNS` had to be added to `_CC_TAKEN` because gcc
  -O0 compiles the `n >= 0` half of `if (n >= 0 && n < 64)` to `cmp $0,n; js skip` — the one
  idiom that fixes the hazard was the one the table could not read. A `!=` is deliberately not a
  lower bound: `-1 != 0`.
  Ordering matters — a bound that already exceeds the buffer stays SUSPECT, since that is the
  more concrete statement and does not depend on the length being negative at all. The stage
  treats `signed-length` like SUSPECT: evidence attached, never promoted, and critically never
  *demoted*, which is the actual fix. These sites previously demoted to `info` at confidence
  0.15, burying a live defect underneath its own guard.
  Validated by execution, not by reading. A 10-shape fixture compiled at `-O0` matches ground
  truth on all 10, and a driver confirms the semantics: the site this used to call `bounded`
  segfaults at `n = -1` (exit 139), while `u_lt` (unsigned) and `s_ge0` (`n >= 0 &&`) reject the
  same input and return cleanly. jhead 3.04 is unchanged at 36/4/2 — no signed hazards there,
  and no new false positives on real code.
- **[PLANNED] Signedness is read from x86 mnemonics only.** `_CC_TAKEN`/`_CC_SIGNED` are x86
  tables, so guard reasoning — and with it the signed-length check — is inert on the other 12
  supported architectures. The p-code op (`INT_SLESS` vs `INT_LESS`) carries the same fact
  ISA-independently and is the portable way in; the mnemonic tables were chosen first because
  x86 builds its conditions out of flag algebra that is painful to evaluate symbolically.
- **[PLANNED] Guard reasoning is intra-procedural and constant-only.** A length bounded by
  `sizeof buf` through a variable, by a caller's check, or by a loop induction variable still
  reads as unknown. That is most of the remaining 36.
- **[PLANNED] Frame recovery is not trustworthy enough to assert sizes.** The slot-reuse
  problem above is not a Ghidra bug, it is inherent to stack-slot sharing. Distinguishing
  "which variable lives here at THIS program point" needs liveness, not just the frame table.
- **[PLANNED] Runs list shows DONE regardless of yield.** `fuzz · 177s · DONE` found nothing;
  a wasted run looks exactly like a productive one. Needs an outcome column.
- **[PLANNED] Live Events is empty for a case with history** — the WebSocket starts at the
  current tail and nothing backfills from `/cases/<id>/events`.

## G. Static-taint channel — reach and precision

The `corroborated` state is the platform's precision lever: it is what separates
`system(argv[1])` from `system("/bin/date")`. Everything here bounds how far that lever
reaches. Measured on the bundled corpus (20 cases / 4 CWE classes, x86-64, Ghidra 12.1.2):
candidate recall 1.00 / fp_rate 0.571; corroborated recall 0.833 / fp_rate 0.214.

- **[DONE] RISC-V taint channel** — `riscv` had no `ARCH_ABI` row, so `analyze_program`
  returned empty and no RISC-V finding could ever leave `candidate`. Added the row (a0-a7 args,
  a0 return; Ghidra emits them lowercase) plus two fixes it exposed. First, `_frame_slot` only
  recognised x86's folded displacement (`INT_ADD reg:RBP const:-0x10`); RISC encodings
  materialise the constant first (`COPY const -> unique`, then `INT_ADD reg:s0 unique`), so
  spill tracking — the thing that makes the argv seed survive a prologue — was silently doing
  nothing off x86-64. `_apply` now resolves constants through single-instruction uniques.
  Second, the frame-base list was global; it is now per-arch, because R1 is the stack pointer
  on PowerPC but an *argument* register on ARM, and a shared list keys spill slots on a
  register that changes at every call (test guards the disjointness). Verified end-to-end: a
  RISC-V binary now corroborates CWE-120 across a function boundary and CWE-78 in main, both
  via `taint-dataflow`; aarch64 and 32-bit ARM confirmed too; x86-64 corpus numbers unchanged.
- **[DONE] 32-bit x86 (cdecl) taint channel** — `ARCH_ABI["x86"]["args"]` was empty because
  cdecl passes everything on the stack, so the channel was inert for the entire architecture.
  Added a stack calling convention alongside the register one: `stack_params` (the callee
  reads parameter *i* from `[EBP + 8 + 4i]` after its prologue, which the frame-slot tracker
  already resolves) and `stack_call` (the caller PUSHes right-to-left, so the most recent push
  at a CALL is argument 0). Argument taint is now an abstraction — `_arg_taints()` returns a
  per-position list from either registers or the pending push list — so `SINK_TAINT_ARGS`,
  callee-parameter propagation and the cross-binary import summary all work unchanged on a
  stack ABI. ESP-relative slot *keys* are deliberately not used: the stack pointer moves, so
  `("stack","ESP",0)` names different memory at different points; the push sequence is modelled
  explicitly instead, and cleared per call so a CALL's own return-address push is never read as
  the next call's argument 0. Verified end-to-end on a real i386 ELF: `strcpy` reached through
  a function boundary from `argv[1]`, `printf(argv[1])` and `system(argv[1])` all corroborate,
  while `strcpy(b,"constant")`, `printf("%s\n",b)` and `system("/bin/date")` correctly stay at
  `candidate`. (`gcc -m32 -nostdlib` builds a usable 32-bit ELF without multilib — the missing
  pieces were only the libc startup objects.)
- **[DONE] LoongArch, m68k and SuperH taint channels; SPARC partially.** Cross toolchains
  installed (`gcc-{m68k,sh4,sparc64,loongarch64}-linux-gnu`) so every row below is verified
  against real P-Code rather than guessed. Register names and calling conventions were taken
  from Ghidra's own `.cspec` files — note the integer argument registers sit *after* the float
  pentries in those lists, so reading the first N entries gives the wrong answer.
    * **loongarch** — a0-a7 / a0, fp+sp frame bases. Row only; same `INT_ADD reg:fp const`
      shape as RISC-V. argv and call-source flows both corroborate.
    * **m68k** — no argument registers at all (SysV m68k is stack-passing, exactly like
      cdecl), so it reuses the `stack_params`/`stack_call` model added for 32-bit x86
      unchanged: parameters at `[A6 + 8 + 4i]` after `link A6`, arguments pushed onto SP.
      Full argv support. Good evidence the stack abstraction generalises.
    * **sh** — r4-r7 / r0, r14+r15 frame. Needed real engine work: SuperH stages a scratch
      pointer instead of addressing the frame register (`mov r14,r1; add #-0x38,r1;
      mov.l r4,@(0x3c,r1)`), so `_apply` now tracks `register -> (frame base, offset)`
      aliases and resolves the slot to an R14-relative key. Without it SH produced no data
      flow whatsoever. The alias dies on any other define, so a reused scratch register cannot
      keep a stale frame identity (regression-tested).
    * **sparc / sparcv9** — PARTIAL. Call-based sources work (`getenv() -> system()`
      corroborates), but entry-point argv does not: Ghidra models `save` by spilling the whole
      register window into a synthetic memory space at computed addresses
      (`0x8000 + CWP*16*8 + n*8`) and reloading the rotated window, which redefines i0-i5 and
      wipes the seed. Closing it needs a memory model for that computed-address space, which
      is a much larger job than an ABI row. `args` (o0-o5, caller side) and `param_regs`
      (i0-i5, callee side) are split correctly and ready for when it is.
- **[WONTFIX] s390 has no taint channel because Ghidra cannot decompile it** — there is no
  SystemZ processor module in Ghidra 12.1.2 at all, so no IR is produced and an ABI row would
  be dead code. Revisit only if a SystemZ processor ships.
- **[DONE] Fixed a real ELF-parser bug found while doing the above**: `analyze/elf.py` mapped
  LoongArch to machine `0x101` (257); `EM_LOONGARCH` is **258 (0x102)**, confirmed by Ghidra's
  loader opinion file and by a real `loongarch64-linux-gnu-gcc` binary, which triaged as
  `em-258` (unknown) before the fix. Also added `EM_SPARC32PLUS` (18), which Ghidra maps and
  we did not.
- **[DONE] ppc64le zero-data-flow bug** — root-caused to `catalog.normalize()` not stripping
  PowerPC ELFv2 local-entry dots (`.main`, `.strcpy`), Ghidra PLT thunk names
  (`00000397.plt_call.strcat`) or glibc `_IO_` aliases. ppc64le went 0 -> 146 corroborated;
  big-endian ppc64 also gained from the PLT-thunk half. See doc 18.
- **[DONE] Cross-architecture L3** — `build_exploit` was gated to native x86-64; ret2win is
  ISA-neutral (overwrite the saved return address with a symbol-table address, confirm arrival
  with a breakpoint) and now runs on any architecture the gdbstub speaks for: **12 of 13**, up
  from 1. ROP/mprotect/PIE-leak remain x86-64 machine code and stay native-only. Four bugs had
  to be fixed to get there — target-aware address packing, link-register control being
  rejected as "not a ret overwrite", the LSB-alias offset candidate missing, and breakpoints
  placed at odd Thumb symbol addresses where they never fire. L3 now reads the offset L2
  already confirmed rather than re-deriving it (the local recovery lands word-1 bytes early on
  big-endian targets).
- **[DONE] L2 register layouts derived from the gdbstub** rather than hand-written — qemu
  serves a target description (`qXfer:features:read:target.xml`) listing registers in regnum
  order with widths. loongarch, m68k, sparcv9 and 32-bit x86 now need no table; L2 went from 6
  architectures to 9. sh is the exception: qemu-sh4 serves no description, so it stays
  unsupported. Future architectures need only an sp/pc name and (if register-passing) an
  argument-register list.
- **[DONE] Architecture coverage is gated** — `make arch-gate` / `lykos archgate`, also part of
  `make release`. Builds a vulnerable program per ISA with the cross toolchain, detonates it
  through the real sandbox and drives the real PoC stages, asserting the level each is expected
  to reach; an absent cross-compiler SKIPs rather than fails. Deliberately skips Ghidra —
  decompilation is the slow part and nearly every arch regression lives in the dynamic path.
  Current bar: **13 architectures, 12 at L3 and 1 at L1**, and every row below L2 must record a
  reason (a test enforces that, so the bar cannot drift down quietly). It caught a real RISC-V
  bug on its first full run: JALR clears the low bit of its target, so a fault with full IP
  control read as unconfirmed — the ARM/AArch64 Thumb masking already handled this, but the
  arch list did not include RISC-V.
- **[DONE] Verified argv seeding off x86-64** — confirmed end-to-end on riscv64, aarch64 and
  32-bit ARM. This is what surfaced the materialised-displacement bug above: the seed was
  arch-independent, but the spill tracking it depends on was not.
- **[PLANNED] Cross-arch cases in the bundled corpus.** The verification above was manual
  (`riscv64-unknown-elf-gcc` freestanding, `aarch64/arm-linux-gnueabihf-gcc -static`); nothing
  in `eval-gate` measures any arch but x86-64, so an arch regression would not trip a gate.
- **[PLANNED] CWE-120 path-insensitivity — the 3 remaining corroborated false positives.**
  `strcpy` behind `strlen() < sizeof`, `strncpy` bounded to `sizeof-1`, `memcpy` with a clamped
  length: attacker bytes genuinely reach the sink, so the taint channel is right to see a flow;
  what makes them safe is a value-range fact it does not carry. Needs bounds/value-range
  reasoning over the same P-Code (relate the copy length to the destination's recovered frame
  size). Biggest single precision win available, and the biggest piece of work here.
- **[PLANNED] CWE-798 cannot be corroborated at all** — caps corroborated recall at 0.833 (5/6).
  `hardcoded_secrets` is a string detector with no call site, so neither the reachability nor the
  data-flow channel applies. Secrets are promoted by `synthesize_secret` (straight to poc-backed)
  instead. Either give the string channel its own second-channel notion or exclude it from
  corroborated-stage scoring; today the benchmark reads as a recall gap that is really a
  structural mismatch.
- **[PLANNED] Memory model beyond constant-offset frame slots.** `_apply` now tracks
  `[BASE + const]` spills (which is what made argv usable at -O0), but heap buffers, computed
  indices and aliasing are still invisible, and a `STORE` through a non-slot address drops taint.
- **[PLANNED] `argc` is not a taint source** (deliberate — a count, not data; see
  `ENTRY_PARAM_SOURCES`). Integer-overflow and bounds classes want it; it belongs in a size/range
  channel rather than the data-flow one, where it would push taint through every `argc` guard.
- **[DONE] `correlate.reaches_source` shared one `seen` set across a depth-limited DFS** — now
  `reaches_within`, breadth-first, so every node is visited at its shortest distance. Extracted
  to module level and unit-tested, because whether the old code lost a real source depended on
  the order a Python set iterated: it never reproduced reliably, and a missed source is
  invisible (the finding just stays `candidate`).

## H. Benchmark & CI enforcement

- **[PLANNED] Ghidra in CI so `eval-gate` is enforced on push.** `.github/workflows/ci.yml` runs
  lint / typecheck / tests / packaging on 3.11 + 3.13 and installs gcc, gdb, qemu-user-static and
  bubblewrap — but not Ghidra (~1 GB), so all three detection gates run only locally. Needs a
  cached install step.
- **[PLANNED] Real benchmark corpora.** The bundled 20-case corpus is a regression tripwire, not a
  measurement. The `--juliet` and `--lava` loaders exist and are tested; wire a pinned drop in so
  recall/precision are quoted against something external.
- **[PLANNED] 32-bit ARM tests skip everywhere but a dev box** — `tests/test_arm.py` needs
  `examples/re-corpus/bin/vuln_arm`, which is gitignored and built out of band, so the freshest
  arch work has no CI coverage at all.

## I. Engine correctness (found in the September 2026 audit, unfixed)

None of these are hypothetical; each was read off the code, but none has a reproducer yet.

- **[DONE] `reap()` requeuing a job whose worker is still running it** no longer loses the
  result silently. The drop itself is unavoidable (another worker may already own the row), but
  it now emits a `job.result_discarded` warning naming the reason and the worker, and
  completion is guarded by claim identity so a stale worker cannot overwrite the new owner's
  job. Regression-tested both ways.
- **[DONE] `JobQueue._emit` fired `on_event` before `COMMIT`** — callbacks are now queued and
  delivered only after the transaction commits, and dropped on rollback, so a consumer can
  never observe an event the database does not contain.
- **[DONE] `enqueue()` cache/dedup check-then-insert race** — the lookup and the insert that
  depends on it now run under one `BEGIN IMMEDIATE`. Tested with six concurrent enqueues of the
  same cache key producing exactly one row.
- **[DONE] Temp-directory leak per request** — `_upload_target`, `_import_case` and
  `_get_case_export` now use `TemporaryDirectory`, which also cleans up on the error paths an
  explicit `unlink` never reached.
- **[PLANNED] Stage input parameters are inconsistent and fail silently.** `dynamic_run`
  reads its input from `params["input_b64"]`; `build_poc` and `poc_primitive` read
  `params["input_sha"]`. Passing the wrong one is not an error -- `dynamic_run` simply runs
  the target with NO input and records a clean exit, which is indistinguishable from a
  genuine no-crash result. This is reachable straight from the HTTP API, which forwards
  `params` verbatim. Either accept both spellings or reject an unknown input key.
- **[DONE] `api/server.py:_create_run` elif chain** replaced by two dispatch tables (imports
  stay lazy, since stages pull in heavy optional backends). A test resolves every entry and
  asserts the tables and the engine registry name exactly the same 29 stages in both
  directions, so a stage can no longer be runnable-but-unreachable or vice versa. An unknown
  stage now returns 400 listing the valid names; it used to be enqueued as a run no worker
  could ever execute, sitting queued forever instead of reporting the typo.
- **[DONE] `sandbox.run()` re-implemented `classify_rc()` inline** — now calls it; the two
  copies had already drifted.

## J. Product-security posture (accepted risk — recorded, not scheduled)

Decision (September 2026): single operator, single workstation, so these are **accepted**, not
planned. Recorded because the threat model would change the moment a second person runs the UI,
analyses a sample someone else supplied, or the API binds anything but loopback.

- Upload filename is used unsanitised as a path (`api/server.py` `_upload_target` +
  `api/multipart.py`), giving arbitrary file write/delete via `X-Filename: ../..`. Demonstrated.
- No authentication and no `Origin`/`Host` check on the HTTP API or either WebSocket. WebSockets
  are not subject to CORS, so any page the operator visits can drive `/console` (which spawns the
  target under a PTY) or export a case. `--http` also accepts a non-loopback bind.
- `esc()` in `api/static/index.html` escapes `& < >` but not quotes, and is used inside
  double-quoted attributes carrying decompiler output (`title="${esc(f.signature)}"`, callee
  names); `f.addr`/`f.id`/`s.addr` are interpolated unescaped. A crafted symbol name in an
  analysed binary is stored XSS in the operator's UI — which, combined with the item above, is
  the hostile-sample-to-workstation chain the README's threat model assumes.
- `casestore._safe_extract` uses a string-prefix containment check and ignores symlink members;
  `extractall` runs without `filter="data"`. Python 3.14's default filter blocks both, but the
  project supports 3.11+, where it does not.
- Sandbox: `--ro-bind / /` exposes the whole host filesystem to the detonated binary, the full
  environment is inherited (`env=None`), and when bubblewrap is missing or fails `run()` silently
  drops to `rlimits-only` — native execution with network access. Wine targets get no bwrap.
- `sandbox._spawn` uses `preexec_fn` from threaded workers (`ThreadingHTTPServer` + thread pool),
  which CPython documents as unsafe.
