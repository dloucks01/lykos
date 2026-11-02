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

## Memory corruption (high-leverage: overflow → ROP / disclosure)

| CWE | name | detect | mechanism | demo | gap → next mechanism |
|-----|------|:--:|:--:|:--:|------|
| 121 | stack buffer overflow | ✓ | synthesize_poc, x64frame, rop_solver, **zip_overflow (ZIP)** | **L2** (ncompress) + **L1 standalone (unzip); in-pipeline BLOCKED by a build gap** | zip_overflow: a valid ZIP whose central-dir `compression_method`≥1000 overflows `methbuf[8]` at unzip list.c:342 (CVE-2014-9913), reproduced via format-aware placement behind the ZIP parser, no fuzzing. **Validated standalone** against a real ASan unzip (method 999 safe, 1000→WRITE size 5, 61453→WRITE size 6, all at list_files). **In-pipeline it does NOT fire**: lykos analyses the STALE pre-built non-ASan `unzip` from the source tree (byte-identical sha), because unzip's ASan build fails three ways — the default make target is `help` (builds nothing), `_b_loose` dies on unzip's multiple `main()`s (funzip/unzipstb/gbloffs/…), and `make all`→`generic` hits a gmtime/localtime K&R conflicting-types hard error under gcc 14. The 1–2 byte ASCII overrun is invisible without ASan, so a plain build can't reveal it. Honest L1 for this bug anyway (too small for the saved return addr). **Actionable fix (3-part build-robustness task for source_project `_b_make`):** try `make all`/`generic` when the default yields no ELF; link multiple-main trees per-program; work around the K&R gmtime redecl (patch or a `-fgnu89-inline`/C89 path). This would unblock the WHOLE unzip benchmark (currently 0/11), not just this stage. L2→L3 ROP needs a control-grade overflow; the class reaches L3 via rop_solver on a target that overwrites the saved frame. |
| 787 | out-of-bounds write | ✓ | oob_construct, chain_primitive | **L2** (ncompress) | PIE-indexed write needs a leak first; wire the leak→write chain |
| 125 | out-of-bounds read | ✓ | palette_overread (GIF), **jpeg_overread (JPEG)**, chain_primitive._oob_read_disclose | **L1+L3 (giflib, pipeline) + L1 wired (jhead JPEG)** | GIF palette over-read: L1 in the real pipeline (gif2rgb.c:294, CVE-2016-3977) + L3 disclosure oracle (CWE-200). jpeg_overread: three documented jhead EXIF over-reads reproduced via format-aware JPEG placement, no fuzzing (CVE-2020-26208 memcmp past a 2-byte APP1; CVE-2018-6612 Get32u(ExifSection+12); CVE-2020-6625 ProcessGpsInfo gpsinfo.c:138) — honest L1 (internal reads, not disclosed). jhead's L3 instance is the GPS coordinate the over-read feeds into the printed summary (ProcessGpsInfo→ImageInfo.GpsLat): a numeric disclosure oracle over a complete JPEG is the named next step. md4c's is a 1-byte over-read hidden by parser slack → honest L1. Next: PNG/BMP palette |
| 122 | heap buffer overflow | ✓ | heap, heap_groom | — | drive narrowed heap-overflow candidate to groom→hijack |
| 119/788/126/127/124 | bounds errors | ✓ | (shared w/ 787/125) | L2 (ncompress 119) | fold into 787/125 mechanisms |
| 416 | use-after-free | ✓ | heap, aaheg | ? | prove on a real UAF target (none in bench yet) |
| 415/590/762 | double/invalid free | ✓/– | heap, aaheg | — | detector for 590/762; tcache-poison → L3 |
| 476 | NULL deref | ✓ | (crash) | — | reproduce → L1 (honest ceiling unless controllable) |
| 824/822 | uninit/untrusted pointer | ✓ | chain_primitive | — | drive to controlled deref |
| 457 | uninitialized read | – | (MSan build) | — | **no detector** — add; → L1/disclosure |

## Numeric / allocation

| CWE | name | detect | mechanism | demo | gap → next mechanism |
|-----|------|:--:|:--:|:--:|------|
| 190 | integer overflow | ✓ | overflow_recipe | ? | int-overflow → undersized alloc → heap OOB chain to L3 |
| 191 | integer underflow | ✓ | – | — | **no mechanism** — fold into 190 chain |
| 131 | wrong buffer-size calc | ✓ | oob_recipe | — | → 787/122 |
| 369 | divide by zero | ✓ | – | — | **no mechanism** — reproduce → L1 |
| 789/770/400 | alloc/resource exhaustion | ✓/– | dos | — | → L1 DoS demonstration |
| 835/674 | infinite loop / deep recursion | – | dos | — | **no detector** — add; → L1 DoS |
| 409 | compression bomb | – | dos | — | **no detector** — add |

## Injection (reaches L3 today)

| CWE | name | detect | mechanism | demo | gap → next mechanism |
|-----|------|:--:|:--:|:--:|------|
| 78 | OS command injection | ✓ | inject_stage, filename_inject | **L3** (jhead) | solid; Go/Rust probes are the only known gap |
| 134 | format string | ✓ | fmt, fmt_recipe | **L3** (giflib unlisted) | solid |
| 22 | path traversal | ✓ | inject_stage | **L3** (giflib unlisted) | **reach** on unzip (7 high candidates, 0 demo) — needs mode/input |
| 94/77 | code/command injection | ✓/– | injection | — | prove on a real target |
| 89 | SQL injection | ✓ | injection | — | prove on a real target |
| 918/611/643/776 | SSRF / XXE / XPath / XML bomb | – | injection, dos | — | **no detector** — add |
| 79/116 | XSS / encoding | ✓ | – | — | **no mechanism** (web-shaped; low priority offline) |

## Logic / hygiene / secrets (also to L3 — demonstrated impact, not a candidate)

| CWE | name | detect | mechanism | demo | gap → next mechanism (to L3) |
|-----|------|:--:|:--:|:--:|------|
| 617 | reachable assertion | ✓ | (crash) | **L1** (md4c) | L3 = reach it from attacker input + prove the process-down is a usable DoS |
| 252 | unchecked return value | ✓ | – | — | drive the unchecked error path to its memory-safety consequence (NULL/OOB) → L3 |
| 693/1188/20 | protection failure / unsafe init / input-val | ✓ | – | — | reach the weakened path and demonstrate the concrete bypass it enables → L3 |
| 203 | observable discrepancy | ✓ | – | — | time the oracle under control and recover a secret bit-by-bit (demonstrated) → L3 |
| 798/321/242 | hardcoded creds / key / dangerous fn | – | secret_stage | — | **no detector** — add; L3 = use the extracted secret against what it guards |
| 362 | race condition | – | (TSan build) | — | **no detector** — add; L3 = win the TOCTOU window to a concrete effect |
| 401 | memory leak | – | (LSan build) | — | **no detector** — add; L3 = demonstrate growth to allocation failure (DoS) |
| 200 | information exposure | ✓ | leak, chain_primitive | — | L3 disclosure (shared w/ 125): exfiltrate secret/pointer bytes under a control |

## Cross-cutting enablers (unblock MANY classes at once)

1. **Format-aware trigger placement** — embed the trigger (overlong field / out-of-range index /
   oversized count) into a *valid* container field, so a directed stage reaches a sink behind a
   parser. Instances landed: `palette_overread` (GIF/CWE-125, over-read→disclosure) and
   `zip_overflow` (ZIP/CWE-121, central-dir `compression_method`→stack overflow, CVE-2014-9913).
   Both confirmed against a real ASan build reaching the exact sink, no fuzzing. Generalize next to
   JPEG (jhead EXIF/GPS over-reads) / PNG / BMP and to the CWE-787/190 shapes. This is what unblocks
   the reach-behind-parser misses on jhead/giflib/unzip that `synthesize_poc` (raw blob) cannot.
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
