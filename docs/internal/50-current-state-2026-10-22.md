# Current state — what lykos does today (2026-10-22)

> **Update 2026-10-24 (doc 51):** the large-binary items below are addressed — size-tiered,
> checkpointed rizin recovery (≥16 MB) keeps a real function list + call graph under a deadline;
> taint ranks top-N reachable functions instead of returning zero above 6000; mmap replaces the
> whole-file reads. PE exports + TLS callbacks are now parsed. The rest of this doc stands.

The single "what is true now" internal reference. The dated planning/strategy/audit series that
preceded this (docs 01–46) is **archived** under `archive/`; this doc supersedes it as the start
point, and the forward plan for the gaps named here is `49-next-build-vision`. When this doc and the
code disagree, the code wins (`./lykos doctor` + the test suite are ground truth).

lykos ingests a binary (ELF / PE / Mach-O / firmware / JAR) or a C/C++ source tree, recovers its
structure, detects CWE-class defects (static taint + bounds + detectors, CVE fingerprinting),
fuzzes/emulates to reproduce, and drives each crash up the ladder **L0 detected → L1 crash → L2
primitive → L3 working exploit**, offline. Core is stdlib-only; heavy engines are vendored under
`vendor/`. The three capability axes below were surveyed against the code on 2026-10-22.

## Architecture coverage across the L0→L3 chain

The emulation/confirmation substrate is genuinely multi-arch (qemu-user + a per-ISA gdbstub register
layer). **Deep L3 synthesis — ROP-chain algebra, info-leak/ASLR defeat, heap-to-shell, advanced
shellcode, format-`%n`, SROP/BROP — is x86-64 only.** Non-x86 L3 is (a) a shared cross-arch
**ret2libc** driver (`poc/archmodel.py` `MODELS` + `drive_cross_ret2libc`) for 8 named ISAs, and (b)
an ISA-neutral **ret2win** redirect for anything qemu can single-step.

| Arch | Max L | Where it stops |
|---|---|---|
| **x86-64** | **L3 (full)** | Every technique. The only arch with ROP-chain synth, leak-based ASLR defeat, heap/FSOP, SROP, dlresolve, format-`%n`, BROP. |
| aarch64, arm, riscv64, ppc64le, ppc32, s390x | **L3 (synth)** | ret2libc + NX-off ret2shellcode. No leak/ROP-chain algebra → confined to **no-PIE / fixed-address** targets. |
| loongarch64, sh4 | **L3 (partial)** | ret2libc **only** — no shellcode stub (`shellcode.py`, ret2shellcode table). |
| mips / mipsel / mips64 | **L2; L3 only via ret2win** | Full L1/L2 gdbstub capture, but **no gadget decoder / no ret2libc** (`rop.py`). The clearest "infra present, synthesis missing" case. |
| hppa, sparcv9, alpha, m68k | **L2; L3 only via ret2win** | L1/L2 register capture only; no synthesis. |
| x86 (32) | L1/L2 capture | L3 recipes gate on x86-64/amd64; 32-bit x86 doesn't hit them. |
| xtensa, microblaze, or1k, sparc | **L1 only** | Run under qemu-user for crash repro; no gdbstub layout → no L2/L3. |

L1 crash-repro runs under **qemu-user for ~22 arches**; the fault-PC + register capture that powers
L1-detail and the L2 primitive is the **15 arches** in `debug/qemu_gdb.supported()`. The x86-centric
bottlenecks (what the next build must abstract for more arches to pass ret2libc): `poc/rop.py` (gadget
vocabulary + all chain builders), `poc/exploit_stage.py` (~30 x86-64-gated recipes + scattered
if/elif dispatch), `poc/leak.py` (the entire ASLR-defeat engine), `poc/shellcode.py` (advanced
stubs), `poc/heap.py`+`chain_primitive.py` (glibc tcache/FSOP). Already clean/table-driven:
`archmodel.py`, `qemu_gdb.py`, `native_re.py` (SLEIGH), `dynamic/sandbox.py`.

## Windows / PE depth

A PE is first-class **through triage, static analysis, disassembly, and dynamic execution under Wine
(L1)** — then falls off a cliff at L2/L3.

- **Static (deep, stdlib):** `analyze/pe.py` parses headers, arch/bits, sections + per-section
  entropy, **imports with named symbols**, toolchain hint, and **mitigations: ASLR / DEP / SafeSEH /
  CFG** (the Windows equivalents of the ELF NX/PIE/CANARY set). **Not** extracted yet: exports (field
  exists, never populated → triage reports exports=0), TLS callbacks, resources, relocations,
  debug/.pdata. A **.NET** PE is split off (`analyze/dotnet.py`) and capped at L1 by design.
- **Dynamic (L1 reached):** runs under Wine (`dynamic/sandbox.py` `_wine`/`_is_pe`/wineprefix);
  `wine_exception()` parses Wine stderr into NT statuses incl. **SEH-frame corruption** →
  `synthesize_poc` reproduces a PE overflow as a **verified L1 crash**. Purpose-built Win32 dynamic
  detectors: `debug/winapi.py` (behavior) + `debug/winmonitor.py` (dangerous sinks: WinExec/
  CreateProcess/VirtualProtect/WriteProcessMemory/wsprintf/… → CWE-78/134/494).
- **The wall (L2/L3):** `capabilities.py` does **not** refuse `poc_primitive`/`build_exploit` for PE
  (PE declares `ip_control=True` in `substrate.py:83`), so a PE is *offered* L3 but structurally
  produces nothing: (1) **L2** RIP-confirmation is host-native ptrace (`poc/ptrace_capture.py`) and
  cannot follow Win64 state through wineserver; (2) **L3** `build_exploit` is entirely ELF symbol
  tables + System V AMD64 ABI + Linux shellcode — **no Win64 ABI (rcx/rdx/r8/r9 + shadow space), no
  SEH-overwrite, no WinExec/VirtualProtect/LoadLibrary gadget synthesis.** *(2026-10-27: static
  **Win32 dangerous-API detection now exists** — `detect/detectors.py windows_dangerous_imports`
  reads the PE import table and flags the high-signal sinks (WinExec / ShellExecute / CreateProcess /
  wsprintf / lstrcpy / URLDownloadToFile / msvcrt copies), the static twin of the dynamic winmonitor
  set, because rizin leaves a PE's IAT thunks unnamed so the call-graph `dangerous_api` missed them.
  The L2/L3 weaponizer wall above is unchanged.)*
- **Large PE:** additionally loses the coverage/directed-fuzz depth lane — AFL can't instrument a PE
  and Wine runs **~1 exec/s** (`substrate.py:83/372`); depth collapses to static + concolic.

**Current max for a PE, one line:** parsed statically (incl. Windows mitigations) + disassembled +
Wine-executed to a verified **L1** crash; **no L2/L3** (no Wine-aware RIP capture, no Windows
weaponizer).

## Large binaries (100 MB+)

The declared **large (≥40 MB) / huge (≥90 MB)** modes (`orchestrate.py:1605`) are mostly **advisory**
— they scale the default budget (`max(900, min(21600, 900+mb*120))`, so 100 MB → ~12,900 s) and emit
a note; **no lane is dropped by size** (additive, by design). The real ceiling is algorithmic, not
byte-gated:

- **~24 MB** — whole-program `aaa` (`native_re.py:562`, run **ungated by size**) stops finishing in a
  normal budget → function/call-graph recovery degrades to **strings-only**. "Gate `aaa` by size, use
  `aa`+`aac`" is roadmap, not built.
- **~90–136 MB** — `aaa` RSS reaches ~3.5 GB; an `RLIMIT_AS` cap (80% of free RAM, floor 1 GB, ceil
  24 GB, `native_re.py:110`) kills rizin → **graceful truncation to strings-only** (never a silent
  clean 0 — the cut is reported at `disassemble.py:173`).
- **Taint hard-drop:** `detect/taint.py` returns **zero** inter-procedural dataflow above `_MAX_FUNCS
  = 6000` functions (`:750/:813`) — a 100 MB binary far exceeds it (counted/reported, capability
  lost). Ranked top-N instead of hard-drop is roadmap.
- **Concolic:** angr whole-image load OOM/stalls on 90 MB+ (softened, not eliminated).
- **Whole-file reads** (`native_re.py:551/902`, `disassemble.py:203`) add the full file to RSS.
- **Large PE** assumes-ELF for its primary (execution-based) depth and collapses to static + concolic.

**Scaling bottleneck files:** `native_re.py` (ungated `aaa`, full-file reads, mem cap),
`detect/taint.py` (hard caps), `disassemble.py` (stage wrapper/timeouts), `orchestrate.py` (advisory
mode/budget), `budget.py`+`substrate.py` (recover-phase starves `aaa`; PE=Wine 1 exec/s).

## The honesty posture (unchanged, and verified)

Above every ceiling the degradation is **reported, never silent**: a truncated disassembly emits a
`partial/truncated` note and keeps strings-keyed detectors; taint caps are counted in an `oversized`
list; the engine-health table and "what this run did" panel say why each engine ran/skipped. A broken
run is not read as a clean negative. This is the property the next-build work (doc 49) must preserve.

## The current active docs
- `47-timed-engagement-reliability-roadmap` — open-items tracker (fuzz-robustness, auto-invocation, …).
- `48-codebase-audit-2026-10-22` — the latest whole-codebase audit + prioritized follow-ups.
- `49-next-build-vision-2026-10-22` — the forward plan (code/GUI/report overhaul + the arch/Windows/
  scale capability track that targets the gaps above).
- `archive/` — the dated 01–46 planning/strategy/audit history (kept, not current).
