# 24 — Modernization Plan (2026 SOTA refresh)

**Researched 2026-09-21.** A fresh state-of-the-art sweep prompted by two new product asks, plus a
hard look at the shipped package size and the Ghidra dependency. This doc **proposes changes to
decisions recorded in doc 15** (binary-only scope; Ghidra-primary; zero-AI) and a phased plan to act
on them. Nothing here is DECIDED yet — each proposed decision is marked and needs sign-off before it
moves into doc 15.

Cross-refs: doc 00 (scope/non-goals), doc 08 (PoC ladder), doc 10 (tech stack), doc 15 (decisions),
doc 16 (SOTA survey), doc 23 (air-gap runbook).

---

## 1. The two asks that drove this

1. **"Give the user a PoC and a path to exploit a found vulnerability, given source code *or* a
   binary."** Today the tool is **binary-only** (doc 00 non-goal: "not a source-code SAST tool"). The
   source case does not exist in the code. This is the single highest-leverage gap.
2. **"See if there are better tools; can we just get rid of Ghidra; where can we do better and what
   are we missing."** The shipped bundle is 3.3 GB packed / ~11.6 GB unpacked. Ghidra drags in a JDK.

The rest of this doc answers both, grounded in a four-thread SOTA sweep (RE-without-Ghidra;
automatic exploit generation; source-code vuln+PoC; offline/no-GPU LLM assistance).

---

## 2. Package-size reality (measured, not guessed)

From the actual 20260917 bundle, uncompressed sizes by component:

| Component | Uncompressed | Why it is bundled |
|---|---|---|
| Cross/native compilers (`cc1plus` + per-arch sysroots) | ~5–7 GB | Building arch-gate / eval **test fixtures** for ~11 ISAs |
| Ghidra framework + decompiler | ~0.82 GB | Decompiler / analyzer |
| JDK 25 | ~0.33 GB | **Only** present because Ghidra needs a JVM |
| Wine | ~0.60 GB | PE (Windows) execution |
| qemu-user | ~0.46 GB | Cross-arch execution |
| angr venv | ~0.50 GB | Concolic |

**Key finding: the cross-compiler matrix, not Ghidra, is the dominant cost**, and most of the heavy
weight (compilers, Wine, JDK) serves the *test/eval/gate* infrastructure and PE support — not the
analyst's core "analyze a target" path. So "the package is huge" and "drop Ghidra" are related but
separate levers, and the compilers are the bigger one. The run-in-place `vendor/` layout (doc 23)
already lets us split the bundle into a lean core plus optional add-ons without any install step.

---

## 3. SOTA sweep summary (2026-09)

Full per-tool detail and source URLs are in §8. The four load-bearing conclusions:

**A. Ghidra without the JVM is a solved swap.** The Ghidra decompiler is C++ (only the framework is
Java). **rizin + rz-ghidra** ships the *same* SLEIGH/P-Code engine with no JDK at ~60–80 MB
(LGPLv3), plus loading, auto-analysis, xrefs, CFG/callgraph, and FLIRT function ID (`sigdb`, at parity
with Ghidra FID and able to read Hex-Rays sigs). What is genuinely lost is Ghidra's Java
**auto-analysis quality** on stripped/optimized/obfuscated binaries, plus BSim and type archives — and
that upstream analysis, not the decompiler, is what makes hard-binary output better. Binary Ninja is
excellent offline but proprietary/paid: wrong fit for a freely-redistributable bundle.

**B. The source path collapses to "sanitizer build + coverage-guided fuzzer = PoC."** A crashing
input under an ASan/UBSan/MSan build *is* the PoC: reproducible, bug-class-labeled, source-line
accurate. No lifting, no emulation, no decompiler. The whole stack (clang sanitizers, AFL++/libFuzzer,
UTopia/OSS-Fuzz-Gen harnessing, Weggli/Joern targeting, SymCC/KLEE gate-breaking, afl-tmin, CASR) is
FOSS and runs air-gapped on CPU. Only license caveat: CodeQL is commercial-licensed — prefer
Joern/Weggli/clang-analyzer.

**C. Exploit paths: L0–L2 automatable offline; L3 mostly analyst-gated.** `angr + angrop + pwntools +
one_gadget + libc-database` gives L0–L1 for free and auto-*finishes* chains (ROP/SROP/ret2dlresolve/
ret2csu, libc offset math, gadget selection) **once a control primitive exists and mitigations are
modest.** The creative front half — finding an info-leak to beat ASLR/PIE, defeating canaries/CFI,
non-trivial heap — is not automated. Ground truth to surface in the UI: in DARPA CGC exactly **one**
heap bug was ever fully auto-exploited, and **AIxCC 2025 scored PoV = crash+sanitizer, i.e. our L1,
not L3.**

**D. Zero-AI core is right; one narrow, fenced door is worth opening.** Headline 2025-2026 results
(AIxCC winners, Big Sleep, XBOW) need frontier cloud models + datacenter fuzzing, verified by classical
engines; autonomous RE still sits at a ~32% ceiling on clean binaries and collapses on stripped ones —
unreproducible air-gapped/no-GPU. Excluding *autonomous AI discovery* stays correct. But a small local
model earns its keep in three verifier-gated roles (harness/seed gen, decompiler-output renaming,
triage narration), and only with a modest GPU.

---

## 4. Proposed decisions (need sign-off; would amend doc 15)

| # | Proposed decision | Amends |
|---|---|---|
| D-24.1 | **rizin + rz-ghidra becomes the default decompiler/analyzer;** full Ghidra + JDK becomes an *optional heavy profile* for hard binaries, not bundled in the lean core. | doc 10 (Ghidra "primary") |
| D-24.2 | **Split the toolchain bundle** into a lean core (~0.5–1 GB) + optional add-ons (full Ghidra+JDK, cross-compiler matrix, Wine). Core is what a fresh analyst needs; add-ons are opt-in. | doc 11/23 |
| D-24.3 | **Add a source-code analysis path** (sanitizer build + fuzz → sanitizer-confirmed PoC). Changes the doc 00 "binary-only" non-goal to "binary-first, source-capable." | doc 00 non-goal |
| D-24.4 | **Ship a deterministic exploit-path "finish-the-chain" backend** (angrop/pwntools/one_gadget/libc-database) driven from L2 detection, and **reframe the ladder UI** to advertise reliable auto L0–L2, auto L3 only for low-mitigation stack bugs, analyst-gated L3 otherwise. | doc 08 |
| D-24.5 | **Permit an optional, off-by-default, verifier-gated local-LLM helper** in exactly three roles (§Phase 4). Core stays reproducible with it disabled; no LLM output is ever a "finding." | doc 15 zero-AI |

---

## 5. Phased plan

Ordered by leverage-per-risk. Each phase is independently shippable.

### Phase 1 — Lean RE stack, drop the JVM  *(size + dependency win, low risk)*
- Wire **rizin + rz-ghidra** behind the existing `disassemble`/`decompile` stage; keep the stage
  interface so full Ghidra remains a swappable heavy profile (`LYKOS_GHIDRA` still honored).
- Replace Ghidra FID with **rizin FLIRT + sigdb** for stripped-function ID; verify the rz-ghidra
  SLEIGH set covers every architecture we claim (doc 18).
- Split `vendor/` into **core** (rizin+rz-ghidra, angr, AFL++, qemu-user for supported guests, bwrap,
  gdb, CASR, pwntools/ROPgadget/one_gadget/libc-database, a sanitizer-capable clang) and **add-ons**
  (full Ghidra+JDK, cross-compilers, Wine). `doctor` reports which profile is present.
- **Exit criteria:** core bundle ≤ ~1 GB packed; decompile output diffed full-Ghidra vs rz-ghidra on a
  representative corpus with the analysis-quality delta measured and documented; all arch tests pass on
  the rz-ghidra SLEIGH set or the arch is explicitly moved to the heavy profile.

#### Phase 1 prototype — built and measured 2026-09-21
A working native backend landed as `core/lykos/analyze/native_re.py`, wired behind the disassemble
stage via `LYKOS_DECOMPILER = native | ghidra | auto` (`auto` prefers Ghidra when present, else native).
Findings from building it:
- **The load-bearing gap the survey missed: the memory-safety detectors (`bounds`/`taint`/`detect`)
  parse Ghidra *P-Code*, which rizin/radare2 do not emit.** A decompiler-only swap would keep
  decompilation but break taint/bounds. The bridge is **pypcode** — a Python binding to Ghidra's own
  SLEIGH lifter (no JVM) — which emits real Ghidra P-Code per instruction. The backend formats it into
  the exact detector string form (`INT_SUB reg:RSP:8 const:0x8:8 -> reg:RSP:8`, `STORE`, `CALL`), so
  the detectors run unchanged. This makes **rizin/rz-ghidra + pypcode** (not rizin alone) the real
  Phase-1 target.
- **Proven end to end:** `tests/test_native_backend.py` compiles a strcpy overflow, runs
  ingest → native disassemble → `detect_cwe`, and confirms the pipeline recovers functions with P-Code,
  the `char[16]` stack buffer, and lands the memory-safety finding — no Ghidra, no JVM.
- **Measured footprint:** radare2 ~34 MB + pypcode ~28 MB ≈ **62 MB** (≈ 80 MB with rz-ghidra on Kali),
  versus **~1150 MB** for Ghidra + JDK — a ~15× cut, JVM removed. Confirms the size thesis with real
  numbers.
- **Known gaps (deferred, honest):** the backend must clean rizin symbol decorations to Ghidra's form
  (`sym.imp.strcpy` → `strcpy`, external) for the detectors to match — done. Decompiled-C quality
  depends on the Ghidra decompiler plugin: **rz-ghidra (Kali package) is the target**; the prototype
  falls back to radare2's built-in `pdc` where `pdg` is absent, and note **r2ghidra does not build
  against radare2 6.0.7** (API drift) — another reason the bundle should ship the rizin twin. Auto-
  analysis quality on stripped/optimized binaries remains the genuine full-Ghidra advantage (§3.A).

#### Phase 1 — shipped 2026-09-21 (D-24.1). ONE build, Ghidra replaced, every other capability kept
Design correction after the first cut: the goal is **replace heavy tools with lighter equivalents that
do the same job, not delete capabilities to save space.** So there is no lean/heavy split and no profile
flag — a single air-gap bundle carries every capability, with exactly one swap:
- **Ghidra → rizin/rz-ghidra + pypcode.** rizin does loading/analysis/decompile; pypcode (Ghidra's
  SLEIGH lifter as a Python module, no JVM) emits the P-Code the detectors parse. `auto` now prefers
  native (`disassemble._select_backend`); `LYKOS_DECOMPILER=ghidra` still works if Ghidra is installed
  separately. Ghidra is no longer in the bundle (its `apt` is empty; it is a doctor-reported optional).
- **Everything else stays.** Wine (PE dynamic execution), the cross-compiler matrix (arch-gate
  fixtures), the JVM (Java-target execution), qemu-user, gdb, AFL++, angr/Unicorn, etc. are all still
  pulled — they have no lighter equivalent, so removing them would be deleting capability, which we do
  not do. `apt_packages()` is a single list (26 debs) = everything except `ghidra`.
- **rizin/rz-ghidra** arrive via apt into the toolchain tree (on the wrapper PATH). **pypcode** is
  vendored with `pip install --target vendor/pysite` (proven: 33 MB, imports in-place); `vendorenv`
  puts `vendor/pysite` on `sys.path` + `PYTHONPATH`, `setup.sh` places it, so the native backend
  imports pypcode with nothing installed.
- **Net size effect:** the one honest saving is dropping the Ghidra framework (~820 MB extracted / a few
  hundred MB packed); the bundle stays large because its capabilities (11-arch cross-compilers, Wine,
  the JVM, all the engines) are large and irreplaceable. Re-cut with `make toolchain-bundle`.
- **A real "same job, less space" idea for later (not yet done):** the cross-compilers exist only to
  *build* per-arch test fixtures; shipping the **prebuilt fixtures** instead would drop ~5–7 GB with no
  capability lost. That is an eval/arch-gate change, tracked separately.

### Phase 2 — Source-code path  *(the big capability unlock)*
- New ingest mode: accept a source tree + build command (or detect one). Produce a **clang
  ASan+UBSan+LSan** primary build and a separate **MSan** build; `TSan` only when concurrency matters.
- **Harnessing:** **UTopia** (synthesize drivers from existing unit tests, deterministic) first;
  fall back to templates; optional LLM draft in Phase 4.
- **Fuzz:** AFL++ LTO + CMPLOG (or libFuzzer when a driver exists); add **libprotobuf-mutator** /
  **Nautilus** for structured inputs.
- **Target + gate-break:** Weggli/Joern/clang-analyzer locate a candidate line (leads, ~70% FP on
  adversarial suites — never reported as a bug); **SymCC** hybrid-assist or **KLEE** on a sliced
  function solves the blocking branch and hands the input back to the fuzzer.
- **Confirm:** sanitizer-caught crash = **L1 PoC**; `afl-tmin` minimize; CASR triage/dedup. Bundle =
  sanitizer trace + minimized input + reproducer command (fits the doc 08 bundle format).
- **Exit criteria:** given a known-vulnerable source project, produce a minimized, sanitizer-confirmed
  crashing-input PoC end-to-end offline; source findings flow through the same confidence lifecycle and
  report/SARIF export as binary findings.

### Phase 3 — Exploit-path automation + honest ladder  *(depth on L2/L3)*
- Deterministic **finish-the-chain backend**: from an L2 primitive (offset to saved-return/fn-ptr,
  controllable bytes), drive angrop + pwntools to assemble ROP/SROP/ret2dlresolve/ret2csu; resolve
  libc via libc-database; select one_gadget with constraint checking. Add **Zeratool** for the easy
  tail (fmt-string, ret2win, straightforward ret2libc).
- **Heap:** automate primitive *discovery* and *layout* (port ideas from ARCHEAP/DEPA/MAZE, use AAHEG's
  AST-strategy pattern for tcache/safe-linking-aware chains) but **gate the final chain to the
  analyst.** Keep how2heap as the offline technique corpus.
- **Ladder UI:** label reachable levels honestly; mark leak-discovery, canary/CFI, and non-trivial
  heap as human-gated steps. Never advertise push-button L3.
- **Exit criteria:** on a low-mitigation stack-overflow corpus, auto-produce a working L3 exploit
  bundle that re-runs from scratch in the sandbox; on hardened/heap targets, produce the L2 primitive +
  a clearly-labeled analyst-gated next step.

**Delivered 2026-09-23** (validated against an HTB pwn set — vuln/scanner/da/sick_rop/auth-or-out/
tictactoe):
- **Multi-channel input auto-retry** — the autopilot ranks the target's input channels (stdin/arg/
  file, from its imports) and retries across them on no-crash instead of a single stdin guess.
  Measured: ncompress 0 → 26 crashes + an L2 primitive, fully automatic.
- **Menu / interactive-protocol seeds** (`fuzz/menu.py`) — synthesise multi-step navigation seeds
  from the numbered menu a binary prints, so coverage/directed fuzzing starts INSIDE the state
  machine (add/modify/print loops, auth gates). auth-or-out's 1–5 Author menu → 39 seeds.
- **SROP synthesis** (`poc/rop.py` + `_plan_srop`) — a byte-exact amd64 sigreturn frame + syscall/
  pop-rax/writable detection + execve chain for static/no-PIE targets, with precise boundary
  reporting when a piece is missing (sick_rop's no-writable variant). Unconfirmed stays *potential*.
- **Flag-printer ret2win** — an `open()`+print() "cat flag" backdoor is a recognised win target now,
  not only `system`/`execve` callers.
- **Canary leak-chain** — a canary-preserving overflow builder (`exploit.build_canary_overflow`)
  plus, when a canary-hardened target is hit with no leak, the exact leak-chain recipe + params.
- **Custom-allocator heap-primitive discovery** (`dynamic/heaptrace.py` + the `heap_trace` stage) —
  the LD_PRELOAD guard (`heap_check`) only sees libc; a target with its OWN allocator
  (`ta_alloc`/`ta_free`, an arena pool, `operator new`) was invisible. `heap_trace` identifies the
  allocator pair from local symbols, drives create-then-double-act menu op-sequences, and traces the
  pointer lifecycle by ptrace to discover a **double-free (CWE-415)**, a **use-after-free (CWE-416)**
  and a **heap overflow (CWE-122)** allocator-agnostically, filing
  it `corroborated` + an aaheg `Vuln{double_free|uaf|heap_overflow}` lead. UAF and double-free use a
  hardware watchpoint on the freed chunk's data; the overflow detector arms a **write-only** watchpoint
  on the qword just past each live chunk's end (paired from the alloc-entry `rdi`=size and the
  alloc-return `rax`=ptr) and reports a write there from any non-allocator code (usually libc
  `strcpy`/`memcpy` driven by the program). Validated end-to-end on synthetic custom-allocator
  double-free / UAF / overflow binaries.
- **Menu-semantic sequence inference** (`fuzz/menu.py`) — the generic `(option, size, data)` op-
  sequence never allocates against a rich add flow (auth-or-out's add reads Name, Surname, Age,
  Note-size, Note), so `heap_trace` saw nothing. `crawl_menu` now DRIVES the live sandboxed process
  one prompt at a time, classifying each prompt as an index / number / string (`classify_prompt`)
  and learning every option's ordered field template; `menu_op_sequences` composes correctly-typed
  double-free / UAF / overflow sequences from it (falling back to the generic shapes when no
  allocator flow is found). Validated: it learns auth-or-out's add as `[str,str,num,num,str]` and
  each id-taking option as `[idx]`.
- **Out-of-bounds array-index discovery** (`dynamic/oob_index.py` + the `oob_index` stage) — the
  auth-or-out class: a fixed-size global object table (`authors[10]`) selected by a user id whose
  bound check is missing / off-by-one. It arms read/write **guard** watchpoints on the words just
  before and after each fixed-size global array (from the ELF symbol size), then drives every
  index-taking menu option with boundary indices (0, capacity, capacity+1). A guard access from
  program code proves the index escaped the array, filing **CWE-129** (Improper validation of array
  index) `corroborated`. Reuses the heaptrace ptrace helper in a new static-watch mode. Validated
  end-to-end: cracks auth-or-out in ~12 s — option 2 (Modify) with index 0 reaches `authors[-1]`
  (id validated only against `> 10`, never `== 0`), a downstream arbitrary read/write.
- **Primitive chaining → demonstrated control-flow hijack** (`poc/chain_primitive.py` + the
  `chain_primitive` stage) — the `heap_trace` (double-free/UAF/overflow) and `oob_index` (CWE-129)
  Findings previously reached no exploit builder (dead-end leads). This stage consumes them: when
  the target has a reachable win function (`exploit.find_win`), it drives the primitive's menu
  option to overwrite an adjacent CODE pointer with the win address, triggers the use, and CONFIRMS
  control reached the win under the ptrace debugger with the same **negative-control** causation
  proof `build_exploit` uses (a hijack that also fires without the overwrite is rejected). On
  success it files an **L3 `verified`** poc ("Control-flow hijack (demonstrated)"); otherwise it
  emits the concrete `aaheg` technique + target **recipe** as L2 guidance. The live-confirm path is
  non-PIE (a PIE win address needs a runtime leak, which stays analyst-gated). Reuses `make_capture`
  / `exploit.reached`. Validated end-to-end through BOTH the harness and the web UI: heap overflow
  (CWE-122) on a custom allocator → option 2 overwrites the neighbour chunk's callback at +24 with
  `win` → option 3 calls it → L3 confirmed; the verdict-first UI escalates its headline from DoS to
  "Control-flow hijack". On auth-or-out the OOB-index primitive files an L2 recipe (no reachable
  win; the real exploit is leak-based).

- **Symbol-free allocator discovery** (`heap_discover._libc_plt_pair` + heaptrace PLT mode) — a
  STRIPPED menu-driven heap service has no named allocator, but it still calls libc. When
  `identify_allocator` finds no named pair and a menu is present, `heap_trace` now traces the
  `malloc`/`free` **PLT stubs** (resolved from the DYNAMIC symbols, which survive stripping): at the
  stub entry it captures the size (`rdi`) and one-shot-breakpoints the caller's return address
  (`[rsp]`) to read the returned pointer (`rax`), then applies the same double-free / UAF logic
  (libc's own metadata writes make the end-of-chunk overflow watch unreliable, so PLT mode reports
  only double-free + UAF — heap_check's guard pages already cover libc overflow). Also fixed:
  `detect_menu` now strips a leading table border (`| [1] Allocate |` boxed menus), and `menu._fill`
  sizes a data string to its preceding size field so a `read(fd, buf, size)` allocator does not
  under-read and desync the sequence. Validated end-to-end on a fully STRIPPED line-based libc
  double-free target → CWE-415 found with no symbols; chain files the L2 tcache recipe.

- **Fixed-width input-protocol inference** (`heap_discover._read_width` + a fixed-width mode across
  `menu.crawl_menu` / `_fill` / `menu_op_sequences`) — a target that reads scalars with
  `read(0, buf, W)` (not fgets/scanf) consumes exactly W bytes per field regardless of newlines, so
  a line-based `value\n` driver under-reads and desyncs every later field. `_read_width` recovers W
  from the constant `mov edx, imm` lengths before `read@plt` calls (when no line reader is present);
  the crawl and the op-sequences then pad each scalar to W bytes and send a data buffer raw. Proven
  end-to-end on a fully STRIPPED `read(0,buf,4)` libc double-free target → CWE-415 found. (On the
  real dreamdiary1 the driver now correctly reaches allocate + free, but that target's Delete NULLs
  its pointer slot, so it is double-free-safe — the finding is a correct negative, and its actual
  bug is an edit-path issue outside this detector.)
- **Symbol-free OOB array-table discovery** (`oob_index._array_candidates_symfree` /
  `_candidates_from_disasm`) — a STRIPPED binary has no OBJECT symbols, so the fixed-size global
  arrays are recovered from the DISASSEMBLY: an indexed data access `[reg*scale + 0xDISP]` whose
  DISP falls in `.data`/`.bss` is an array base with `scale` as its element stride. The element
  count is not in the binary, so the capacity is estimated from the gap to the next global base —
  but the **before-guard** (`base - stride`) is exact and catches the dominant underflow case
  (auth-or-out class) regardless. The boundary set now also drives index `-1` (a direct negative
  index, not only the `id-1` shape). Native non-PIE (a PIE base is RIP-relative). Validated
  end-to-end on a STRIPPED global-pointer-table target → CWE-129 found with no symbols
  (`data_<addr>[-1]` reached from program code). `oob_index` also now infers the fixed-width input
  width and threads it through the crawl + probes, like `heap_trace`.

Known gaps / next: bad_grades (a stripped counted STACK overflow) reaches L1 via the fuzzer but
stalls (no win); its bug is a stack array, not a global table. **PIE symbol-free** array/allocator
recovery (RIP-relative bases). Also: the full angrop/pwntools finish-the-chain backend, live
tcache-poison driving off the heap primitives (currently an L2 recipe), leaked-canary/PIE
auto-confirmation (unblocks the chainer on PIE targets and auth-or-out), and the SROP 2-stage/leak
variant for the no-writable case (sick_rop).

### Phase 4 — Optional, fenced local-LLM helper  *(only worthwhile with a modest GPU)*
- Off by default. Three roles only, each **verifier-gated**: (1) fuzz harness/seed/dictionary
  generation (fuzzer is the oracle), (2) decompiler-output renaming via **LLM4Decompile-Ref** on
  rizin/Ghidra pseudocode (ground-truth disasm untouched), (3) crash-triage root-cause narration
  (advisory; clustering stays classical).
- **Hard rules:** results identical with the helper disabled; **no LLM output is ever a "finding"**;
  greedy decoding; pinned model SHA + quant + seed logged with results; weights vendored into the
  air-gap bundle with pinned hashes + recorded license.
- **Models/hardware:** Qwen2.5-Coder (Apache-2.0) 14B on a 12–16 GB GPU is the useful sweet spot;
  LLM4Decompile-9B-v2 for refinement. CPU-only caps at a marginal 7B — treat 14B+ as batch-only.
  **Avoid Codestral (non-commercial license).**
- **Exit criteria:** the helper can be enabled/disabled per case; a run with it disabled reproduces
  byte-identically; every accepted suggestion has a recorded deterministic confirmation.

---

## 6. Smaller items worth queuing

- **Directed greybox fuzzing** (SAST-guided / BEACON / SelectFuzz / AFLGopher) to close
  candidate→confirmed deterministically — already in doc 16 "adopt"; pairs with Phase 2 targeting.
- **Structure-aware / grammar fuzzing** as a first-class option for parsers (big recall win).
- **N-day / known-vuln matching** (BinDiff / Weisfeiler-Lehman hashing / Match&Mend) for the "is this
  a known CVE" angle, complementing the bundled CVE fingerprint DB.
- **Snapshot fuzzing (Nyx)** for stateful/firmware/network targets — needs KVM (bare-metal Kali).

---

## 6b. Workbench UI rework — shipped 2026-09-21

The old GUI was one 160 KB `index.html` with a single inline `<script>`: every view, every
fetch, and all state braided together. It worked, but a change anywhere risked the whole page,
and getting to a PoC meant driving 25 stages by hand across tabbed panels. The rework keeps
that page as `classic.html` (still linked, still guarded by its harnesses) and replaces the
default UI with a small, results-first single-page app built on the fewest-clicks goal.

**Architecture.** Preact + htm, loaded as vendored ES modules through an import map — no build
step, no toolchain, nothing to install, consistent with the air-gapped posture. Files:

- `static/index.html` — shell: import map (`preact`, `preact/hooks`, `htm` → vendored files),
  styles, and the `#root` mount. No application logic.
- `static/app/api.js` — the entire REST contract as one client; a route change is edited once.
- `static/app/autopilot.js` — the orchestrator (below). Pure logic, no DOM, no Preact.
- `static/app/util.js` — the finding-ranking rules (the results-first promise) and formatting.
- `static/app/components.js` — pure presentational components (drop zone, finding card, log).
- `static/app/app.js` — state + wiring + mount.
- `server.py` — a new, traversal-safe static-asset route serves `/app/*` and `/vendor/*` with
  correct media types (the old server served only the one HTML file).

**Autopilot — one click, every applicable capability, a proof-of-concept.** Drop one or more
binaries, click once. The client asks `GET /targets/<id>/advice` (recommended plan + the command
line read off the binary) AND `GET /targets/<id>/capabilities` (what is possible at all), then
runs the full applicable pipeline per target, gated on availability and each stage guarded:

- **Recover:** disassemble, detect CWE, CVE scan.
- **Search:** the recommended dynamic backend (coverage/black-box fuzz), runtime dangerous-call
  monitor, heap-guard check, directed fuzzing, boundary fuzzing, and a concolic fallback.
- **Prove (on a crash):** root-cause, build PoC (L1), IP-control primitive (L2), exploit (L3),
  multi-process fork/exec debugging — each handed the crashing input's sha.
- **Enrich:** behaviour trace, dynamic taint, secret extraction, injection/secret PoC synthesis,
  and static PoC synthesis when nothing crashed.

Each completed stage reports WHAT it found, not just that it finished (`GET /runs/<id>/output`
exposes the stage result; the log renders e.g. "Directed fuzzing — 11 new crashing inputs",
"Root-cause — SIGSEGV → stack-return-overwrite (CWE-121) → EXPLOITABLE 90/100"). Capabilities
that cannot apply to this target are listed with the server's reason, so "deep" is honest about
its gaps. With several binaries in one case, the per-target runs are followed by the case-level
cross-binary analyses (link case, IPC model, cross-binary taint, whole-system model). Results are
shown demonstrated-first across the whole case: a PoC-backed finding leads with its downloadable
bundle and exploit steps; candidates rank below.

The crash-input threading matters: the PoC-ladder stages (`root_cause`, `build_poc`,
`poc_primitive`, `multi_debug`) require `params.input_sha`; without it they reject the run and no
bundle is produced. Autopilot captures the first crashing input's sha and threads it through.

**Tests.** `tests/js/gui_modules.js` (ranking, REST contract, the capability-driven pipeline and
the multi-target case orchestration against a scripted server), `gui_render.js` (real Preact + htm
rendering the components via an ESM loader hook — no browser, no npm), and `gui_static.js`
(import-map wiring + `node --check` on every module). The five classic harnesses were repointed at
`classic.html`. `make gui` runs all eight; they also run under pytest, skipping only when node is
absent. The `.gitignore` `vendor/` rule was anchored to the repo root so the web UI's vendored
Preact/htm runtime ships in the air-gap package (an unanchored rule dropped it and shipped a blank
page); a packaging guard now reads git's own view to keep it shippable.

**Validated in-browser** (Chrome automation, 2026-09-21): the SPA mounts with no console errors;
drag-drop upload triages correctly; one-click Autopilot drives the full pipeline live; a crashing
target reaches a PoC-backed finding with a verified, downloadable L2 bundle. A UI race that read a
target before its async triage finished (showing file type "unknown") was fixed by waiting on the
triage run. Remaining known gap: decompiled-C source text (rz-ghidra `pdg` wiring); the decompile
stage recovers functions and the call graph, which the P-Code detectors use, but emits no C text.

**Verdict-first re-layout (2026-09-23).** Running the workbench against a multi-binary HTB set made
the information architecture problem obvious: the case view was a long linear scroll — target info,
pipeline log, console, coverage — with the Results (findings) at the very bottom, so the *answer*
(worst demonstrated effect, and whether it is proven) was buried under the *process*. Re-arranged
verdict-first: a per-target VerdictStrip + VerdictCard lead the view (headline effect + an L1▸L2▸L3
ladder meter + proof links, or "no crash reproduced — N findings, M% covered"); target detail and
ranked findings follow; the pipeline/console/coverage collapse into one "Analysis" drawer that is
open while running and collapsed once a run finishes. Front-end only; the API already returned
effects-with-status and PoC levels.

---

## 7. Honest ceilings (surface these in the product, not just the docs)

- Static findings are **leads, not bugs** (~70% false-positive on adversarial suites). The tool proves
  or refutes them dynamically; it never reports an unconfirmed static hit as a vulnerability.
- **L1 (crash + sanitizer) and L2 (primitive) are the reliable auto deliverables.** L3 is the
  exception: automatable only for low-mitigation stack bugs; analyst-in-the-loop for info-leak
  discovery, canaries, CFI, Full RELRO, and non-trivial heap.
- Autonomous RE/exploitation by a *local* model on this hardware is marginal; the LLM helper is an
  ergonomic convenience layer, never a source of truth.

## 8. Non-goals — reaffirmed and changed

- **Changed:** binary-only → **binary-first, source-capable** (D-24.3).
- **Changed:** zero-AI-everywhere → **deterministic, reproducible core + optional fenced LLM helper**
  (D-24.5). The core still produces identical results with AI disabled.
- **Reaffirmed:** no autonomous AI vuln discovery; no cloud/online dependency; single-workstation,
  air-gapped, no mandatory GPU; harvest engines, own the orchestration.

---

## 9. References (2026 sweep)

**RE without Ghidra:** rz-ghidra https://github.com/rizinorg/rz-ghidra ·
rizin https://rizin.re/ · sigdb https://github.com/rizinorg/sigdb ·
decompiler benchmarks: DecompileBench https://arxiv.org/abs/2505.11340 ,
Decompile-Bench https://arxiv.org/pdf/2505.12668 · Binary Ninja offline/license
https://docs.binary.ninja/about/license.html

**Automatic exploit generation:** angrop https://github.com/angr/angrop ·
Zeratool https://github.com/ChrisTheCoolHut/Zeratool ·
pwntools ROP https://docs.pwntools.com/en/stable/rop.html ·
ARCHEAP https://hacking.kaist.ac.kr/pubs/2020/yun:archeap.pdf ·
MAZE https://www.usenix.org/system/files/sec21fall-wang-yan.pdf ·
AAHEG https://www.mdpi.com/2073-8994/15/12/2197 ·
SAEG (stateful, 2024) https://yinqian.org/papers/ESORICS24b.pdf

**Source-code vuln + PoC:** LibAFL https://www.s3.eurecom.fr/docs/ccs22_fioraldi.pdf ·
UTopia https://gts3.org/assets/papers/2023/jeong:utopia.pdf ·
PromeFuzz https://dl.acm.org/doi/10.1145/3719027.3765222 ·
Weggli https://github.com/weggli-rs/weggli · Cooddy https://github.com/program-analysis-team/cooddy ·
KLEE https://klee-se.org/publications/ · ColorGo (directed concolic) https://arxiv.org/pdf/2505.21130 ·
static-analysis FP study https://arxiv.org/pdf/2506.10322

**AIxCC 2025 + offline LLM:** SoK AIxCC https://arxiv.org/abs/2602.07666 ·
ATLANTIS (winner) https://arxiv.org/abs/2509.14589 ·
Buttercup (open source) https://github.com/trailofbits/buttercup ·
DARPA results https://www.darpa.mil/news/2025/aixcc-results ·
Big Sleep https://projectzero.google/2024/10/from-naptime-to-big-sleep.html ·
ZeroDayBench https://arxiv.org/abs/2603.02297 ·
SRE-Bench "~32% barrier" https://d-central.tech/llm-binary-reverse-engineering-32-percent/ ·
LLM4Decompile https://github.com/albertan017/LLM4Decompile ·
local-model VRAM https://willitrunai.com/blog/qwen-2-5-coder-14b-vram-requirements
