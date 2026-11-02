# CWE coverage ledger — detect → mechanism → level

The mission: for **every** finding/PoC class lykos can narrow to, a quick, directed, specialized
mechanism that drives the narrowed candidate all the way to **L3** — **no large blind fuzzing**,
**no honest-ceiling escape**. Every gap category below (A detect-only, B dormant-mechanism, C
level-gap) must reach L3. A ceiling is lykos's limit to overcome, not a property of the target: if
a class is not at L3 yet, this ledger names the mechanism to build, never calls it blocked.

This ledger tracks every class so coverage stays comprehensive rather than cherry-picked. It is
maintained by hand; the `detect`/`mechanism` columns are grounded in the detectors
(`analyze/fingerprint`, `source_sinks`, `srctaint`, `cpg_scan`) and the escalators
(`analyze/poc/*`), and `demo` is the best level actually reached on a real benchmark target
(`bench/recall`), not a claim.

Levels: **L0** candidate/recipe only · **L1** reproduced crash · **L2** primitive (controlled
read/write/IP) · **L3** validated PoC with **demonstrated impact**. L3 is class-specific but always
means a working, validated demonstration, never a candidate:
- memory corruption → control-flow hijack (ROP/shell) or a validated disclosure (ASLR defeat);
- injection → the payload executes / escapes (command run, path escaped, query altered);
- resource / loop / alloc (400/770/789/835/674/409) → a demonstrated denial of service (hang/OOM);
- uninit / disclosure / leak (457/200/401) → secret or pointer bytes exfiltrated under a control;
- race (362) → the TOCTOU window won to a concrete effect (overwrite / privilege);
- secrets (798/321) → the extracted credential/key used against the thing it protects;
- divide-by-zero / assertion / null (369/617/476) → the fault reached and the process downed, plus
  the attacker-reachability proof that makes the downing a usable DoS (not merely L1).

## Status note (2026-11-02): detector breadth vs. demonstration

A survey of the implementation corrected a systematic error in earlier editions of this ledger: the
classes it marked "**no detector — add**" / "**no mechanism**" are, with few exceptions, **already
implemented** — they were simply never exercised by one of the six bench targets, which is a
property of the *bench corpus*, not of the platform. Grounded pointers:

- **CWE-457** uninitialised read → `compile_source_msan` + the `mem_oracle` stage.
- **CWE-362** data race → `compile_source_tsan` + `tsan_detonate` (driven from the coverage path).
- **CWE-401** memory leak → `compile_source_lsan` + `dos` (L1/L2/L3 by growth ratio).
- **CWE-835/674** loop / recursion → `fuzz._verify_hang` + `dos` + `rootcause` recursion mapping.
- **CWE-369 / 476** divide-by-zero / NULL-deref → `rootcause` signal mapping (SIGFPE/SEGV).
- **CWE-409** compression bomb → `cve_triggers` + `dos`.
- **CWE-798/321/242** secrets → `embedded_audit` + `extract_secrets` + `secret_stage`.
- **CWE-918/611/643/776** SSRF/XXE/XPath/XML → `detect/detectors.py` SSRF sinks + `injection`.

So the honest remaining work is **demonstration** (give each implemented class a target that
exercises it — the bench corpus lacks div-by-zero, race, leak, SSRF, … targets) and a few genuine
capability frontiers (the TTPs below). The rows marked **IMPLEMENTED** name the module and say
"undemonstrated on the current bench" rather than falsely claiming the detector is missing.

New this session (all demonstrated / validated): **CWE-125 jhead GPS → L3** disclosure
(`jpeg_overread`), the **unzip ASan build fix** that puts CWE-121 `zip_overflow` L1 in-pipeline, and
the **sanitizer-exit detection fix** (an ASan error that exits without a signal now counts).

## Capability frontiers (TTPs) — built this cycle, with the honest remainders named

The five frontiers the earlier editions named are now built; what remains on each is a narrower,
named next technique (a ceiling is lykos's to overcome, never a target property):

- **int-overflow → undersized-alloc → heap-OOB chain (CWE-190→122)** — BUILT. The CWE-190 detector
  now catches the dominant `var * literal` shape (`malloc(n*16)`), the scanf family is a strong
  input reader (so a scanf-sourced size is attacker-controlled, not hygiene), and a CWE-190 lead is
  admitted into `chain_primitive` and routed to the heap-overflow engine (whose `menu.alloc_primers`
  already drives the 32-bit wrap thresholds that undersize the allocation). Validated end-to-end: a
  scanf-sourced `malloc(count*16)` files a high CWE-190 + a source recipe + a chain recipe, and the
  bug reaches a poc-backed control-flow hijack. Honest remainder: L3 via the CWE-190 path on a PIE
  target needs an in-band ASLR leak (the live-hijack path is non-PIE); the deterministic, no-fuzz
  ASan confirmation of the undersizing overflow (independent of win/leak) is the next refinement.
- **tcache poisoning → L3 for double/invalid free (CWE-415/590/762)** — the tcache-poison /
  fastbin-dup engine already reaches L3 for 415/416; CWE-590/762 (invalid / mismatched free) are now
  routed into it (admitted as leads, mapped to the double_free vclass) and moved to the rce ceiling.
- **Go/Rust injection probes (CWE-78)** — BUILT. argv-direct exec payloads (`echo <marker>`), the
  `posix_spawn` libc sink, and the Go/Rust managed sink + stdin-channel vocabularies; the
  forgery-proof marker oracle is unchanged, so a non-injectable managed target still never confirms.
- **format-string-on-PIE** — the fgets/read-loop leak-channel detection is built (a sink reached ≥2×
  via a proven caller-loop now gets the two-stage plan). Honest remainder: the sweep-speed half —
  pinning the %hhn write slot from recovered cross-function frame geometry to shrink the k-sweep.
- **Win64 weaponiser + WoW64** — the single-call Win64 ROP → WinExec/system L3 is joined by a
  COMPOSED multi-register chain (`rop_solver.solve_reg_chain` over `_pe_exec_segments`), so a PE
  lacking the exact `pop rcx; ret` gadget but with a clean multi-insn setter now reaches L3, and a
  multi-argument sink can be driven. Honest remainder: the 32-bit WoW64 lane (stdcall stack args,
  32-bit SEH overwrite) and leak-based ROP under Wine's fixed addresses (unverifiable there).

## Memory corruption (high-leverage: overflow → ROP / disclosure)

| CWE | name | detect | mechanism | demo | gap → next mechanism |
|-----|------|:--:|:--:|:--:|------|
| 121 | stack buffer overflow | ✓ | synthesize_poc, x64frame, rop_solver, **zip_overflow (ZIP)** | **L2** (ncompress) + **L1 (unzip, in-pipeline)** | zip_overflow: a valid ZIP whose central-dir `compression_method`≥1000 overflows `methbuf[8]` at unzip list.c:342 (CVE-2014-9913), reproduced via format-aware placement behind the ZIP parser, no fuzzing. Validated standalone AND in-pipeline against a real ASan unzip (method 999 safe, 1000→WRITE size 5, 61453→WRITE size 6, all at list_files). **The build gap is FIXED** (source_project `_b_make`, commit 340e508): the make builder now tries `all`/`generic` when the default target builds nothing, drops the CFLAGS override that clobbered unzip's `-I.`, and retries through a `-std=gnu89` wrapper that clears unzip's K&R `gmtime` conflicting-types hard error — so unzip builds as ASan ELFs (unzip/unzipsfx/funzip). The stage's L1 gate also no longer requires a signal (commit c7d9ebc): an ASan error that EXITS code 1 is still a confirmed overflow. Honest L1 for this bug (1–2 byte ASCII overrun, too small for the saved return addr). L2→L3 ROP needs a control-grade overflow; the class reaches L3 via rop_solver on a target that overwrites the saved frame. |
| 787 | out-of-bounds write | ✓ | oob_construct, chain_primitive | **L2** (ncompress) | PIE-indexed write needs a leak first; wire the leak→write chain |
| 125 | out-of-bounds read | ✓ | palette_overread (GIF), **jpeg_overread (JPEG)**, chain_primitive._oob_read_disclose | **L1+L3 (giflib) + L1+L3 (jhead JPEG)** | GIF palette over-read: L1 in the real pipeline (gif2rgb.c:294, CVE-2016-3977) + L3 disclosure oracle (CWE-200). jpeg_overread: three documented jhead EXIF over-reads reproduced via format-aware JPEG placement, no fuzzing (CVE-2020-26208 memcmp past a 2-byte APP1; CVE-2018-6612 Get32u(ExifSection+12); CVE-2020-6625 ProcessGpsInfo gpsinfo.c:138) — L1. **The GPS over-read now reaches L3**: `gps_disclose`/`confirm_gps_disclosure` build a complete JPEG whose GPS latitude declares one component but whose sub-IFD is followed by two rationals jhead's fixed three-component loop reads and PRINTS as the coordinate; varying only those past-the-field bytes (declared degrees fixed) makes the printed coordinate a forgery-proof function of OOB memory (CWE-200 disclosure). md4c's is a 1-byte over-read hidden by parser slack → honest L1. Next: PNG/BMP palette |
| 122 | heap buffer overflow | ✓ | heap, heap_groom | — | drive narrowed heap-overflow candidate to groom→hijack |
| 119/788/126/127/124 | bounds errors | ✓ | (shared w/ 787/125) | L2 (ncompress 119) | fold into 787/125 mechanisms |
| 416 | use-after-free | ✓ | heap, aaheg | ? | prove on a real UAF target (none in bench yet) |
| 415/590/762 | double/invalid free | ✓ | heap, aaheg, **chain_primitive (tcache-poison/fastbin-dup)** | L3 (415/416) | CWE-590/762 (invalid/mismatched free) now ROUTED into the double_free tcache-poison/fastbin-dup engine that already reaches L3 for 415/416 (admitted as leads, mapped to the double_free vclass, moved to the rce ceiling) |
| 476 | NULL deref | ✓ | rootcause (SEGV→CWE-476) | — | **IMPLEMENTED** (rootcause.py maps SEGV/null-deref→CWE-476; a reached fault files L1). Honest DoS ceiling unless the pointer is controllable. Undemonstrated on the current bench |
| 824/822 | uninit/untrusted pointer | ✓ | chain_primitive | — | drive to controlled deref |
| 457 | uninitialized read | ✓ | MSan build + mem_oracle | — | **IMPLEMENTED** (compile_source_msan + `mem_oracle` detonates the corpus on the MSan build → CWE-457/200). Undemonstrated on the current bench (also listed in the logic/hygiene table) |

## Numeric / allocation

| CWE | name | detect | mechanism | demo | gap → next mechanism |
|-----|------|:--:|:--:|:--:|------|
| 190 | integer overflow | ✓ | overflow_recipe, source_recipe, **chain_primitive (heap_overflow)** | **L2 recipe + fuzz-confirmed hijack** | CHAIN WIRED: detector now catches `var*literal` (`malloc(n*16)`) + scanf-sourced sizes are strong; a CWE-190 lead is admitted into chain_primitive and routed to the heap-overflow engine (alloc_primers wrap thresholds undersize the allocation). L3 via this path on PIE needs an in-band ASLR leak; a deterministic ASan confirmation of the undersizing overflow is the next refinement |
| 191 | integer underflow | ✓ | – | — | fold into the 190 chain |
| 131 | wrong buffer-size calc | ✓ | oob_recipe | — | → 787/122 |
| 369 | divide by zero | ✓ | rootcause (SIGFPE→CWE-369) | — | **IMPLEMENTED** (rootcause.py maps SIGFPE→CWE-369; a reached fault files L1). Honest DoS ceiling. Undemonstrated on the current bench (no div-by-zero target) |
| 789/770/400 | alloc/resource exhaustion | ✓/– | dos | — | → L1 DoS demonstration |
| 835/674 | infinite loop / deep recursion | ✓ | dos (hang-verify), rootcause (recursion) | — | **IMPLEMENTED** (fuzz `_verify_hang` differential + dos non-termination + rootcause.py recursion/stack-exhaustion → CWE-674); → L1 DoS. Undemonstrated on the current bench |
| 409 | compression bomb | ✓ | dos, cve_triggers | — | **IMPLEMENTED** (cve_triggers + dos amplification/ratio). Undemonstrated on the current bench |

## Injection (reaches L3 today)

| CWE | name | detect | mechanism | demo | gap → next mechanism |
|-----|------|:--:|:--:|:--:|------|
| 78 | OS command injection | ✓ | inject_stage, filename_inject | **L3** (jhead) | solid; Go/Rust probes are the only known gap |
| 134 | format string | ✓ | fmt, fmt_recipe | **L3** (giflib unlisted) | solid |
| 22 | path traversal | ✓ | inject_stage | **L3** (giflib unlisted) | **reach** on unzip (7 high candidates, 0 demo) — needs mode/input |
| 94/77 | code/command injection | ✓/– | injection | — | prove on a real target |
| 89 | SQL injection | ✓ | injection | — | prove on a real target |
| 918/611/643/776 | SSRF / XXE / XPath / XML bomb | ✓ | detectors (SSRF sinks), injection, dos | — | **IMPLEMENTED** (detectors.py flags http.Get/Post→CWE-918 SSRF sinks; injection/inject_stage cover XXE/XPath/XML-bomb). Web/service-shaped → no offline bench target issues the request/parse, so undemonstrated here |
| 79/116 | XSS / encoding | ✓ | – | — | web-shaped; no offline mechanism (low priority for a native/air-gap engagement) |

## Logic / hygiene / secrets (also to L3 — demonstrated impact, not a candidate)

| CWE | name | detect | mechanism | demo | gap → next mechanism (to L3) |
|-----|------|:--:|:--:|:--:|------|
| 617 | reachable assertion | ✓ | (crash) | **L1** (md4c) | L3 = reach it from attacker input + prove the process-down is a usable DoS |
| 252 | unchecked return value | ✓ | – | — | drive the unchecked error path to its memory-safety consequence (NULL/OOB) → L3 |
| 693/1188/20 | protection failure / unsafe init / input-val | ✓ | – | — | reach the weakened path and demonstrate the concrete bypass it enables → L3 |
| 203 | observable discrepancy | ✓ | – | — | time the oracle under control and recover a secret bit-by-bit (demonstrated) → L3 |
| 798/321/242 | hardcoded creds / key / dangerous fn | ✓ | embedded_audit, extract_secrets, secret_stage | — | **IMPLEMENTED** (embedded_audit + extract_secrets detect; secret_stage synthesises). Undemonstrated on the current bench (no embedded secret). L3 = use the extracted secret against what it guards |
| 457 | uninitialised read | ✓ | MSan build + mem_oracle | — | **IMPLEMENTED** (compile_source_msan + the `mem_oracle` stage detonates the corpus on the MSan build → CWE-457/200). Undemonstrated on the current bench |
| 362 | race condition | ✓ | TSan build + tsan_detonate | — | **IMPLEMENTED** (compile_source_tsan + `tsan_detonate`, driven from the coverage/fuzz path, files CWE-362). Needs a concurrent/racy target to demonstrate; none on the current bench |
| 401 | memory leak | ✓ | LSan build + dos | — | **IMPLEMENTED** (compile_source_lsan + dos escalates CWE-401 at L1/L2/L3 via the growth ratio). Undemonstrated on the current bench |
| 200 | information exposure | ✓ | leak, chain_primitive, **jpeg_overread (GPS)** | **L3 (jhead JPEG GPS disclosure)** | GPS over-read → printed-coordinate numeric disclosure proven forgery-proof on jhead (CVE-2020-6625). Also reached generically via leak/chain_primitive (exfiltrate secret/pointer bytes under a control) |

## Cross-cutting enablers (unblock MANY classes at once)

1. **Format-aware trigger placement** — embed the trigger (overlong field / out-of-range index /
   oversized count) into a *valid* container field, so a directed stage reaches a sink behind a
   parser. Instances landed: `palette_overread` (GIF/CWE-125, over-read→disclosure),
   `zip_overflow` (ZIP/CWE-121, central-dir `compression_method`→stack overflow, CVE-2014-9913,
   now firing IN-PIPELINE after the unzip build fix), and `jpeg_overread` (JPEG/CWE-125, jhead EXIF
   over-reads at L1 and the **GPS coordinate at L3** — `gps_disclose`/`confirm_gps_disclosure`).
   All confirmed against a real ASan build reaching the exact sink, no fuzzing. Generalize next to
   PNG / BMP and to the CWE-787/190 shapes. This is what unblocks the reach-behind-parser misses on
   jhead/giflib/unzip that `synthesize_poc` (raw blob) cannot.
2. **Smart-first scheduling** — directed/synthesis stages run first with guaranteed budget; blind
   fuzzing becomes a small, last, narrowed top-up. Measured need: unzip's `synthesize_poc` ran
   "out of time" after ~300s of `coverage_fuzz`+`directed_fuzz`+`fuzz`.

## Build order (comprehensive — every class reaches its best level, no class is special)

The goal is full-matrix coverage, not one favoured family. Order by how many classes each step
unblocks, then sweep the remainder exhaustively:

1. **Enabler — format-aware trigger placement** (#1): lifts the reach ceiling for *every*
   format-parsed sink at once (125, 121, 787, 190, 122, …), so it comes first for coverage, not
   because overflows are special.
2. **Enabler — smart-first scheduling** (#2): lets *every* directed stage run before blind fuzzing
   starves it.
3. **Close the detect-only orphans (A)** — each class we narrow to but cannot drive at all: give
   each a mechanism to its honest level (20, 79, 116, 127, 191, 203, 252, 369, 693, 824, 1188).
4. **Add detectors for the dormant mechanisms (B)** — each escalator with no feeder: wire one
   (94, 242, 321, 362, 401, 409, 457, 590, 611, 643, 674, 762, 776, 789, 798, 835, 918).
5. **Lift the level gaps (C)** to L3 where the class admits it — memory-corruption disclosure/ROP
   chains, injection reach — and record an honest ceiling where it does not.

Nothing is dropped: a class with only an honest ceiling (logic/hygiene/timing) still gets a tracked
candidate/recipe, never silence.
