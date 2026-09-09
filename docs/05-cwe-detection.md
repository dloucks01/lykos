# 05 — Vulnerability (CWE) Detection Engine

## Core principle: a confidence lifecycle, never a flat warning list
Every potential issue is a **Finding** that moves through states, and the UI shows the state + evidence:
```
Candidate  → Corroborated → Confirmed → PoC-backed
(one signal)  (≥2 signals)   (reproduced)  (demonstrable input/bundle)
             + confidence score at each step; analyst can accept/reject/annotate
```
This is the antidote to static-analysis false positives (doc 01-B): a hypothesis→validation pipeline, but
with **deterministic** validators only — no AI in the loop (decision doc 15).

## The four detection channels (findings are correlated across all four in the core)
1. **Pattern / rule detectors (static, fast, noisy).** Dangerous API sinks (`strcpy`, `sprintf`, `system`,
   `memcpy`, format-string sinks, `gets`), missing bounds checks, unchecked return values, signedness,
   fixed-size stack buffers near copies. Rules run over the normalized IR so they're arch-independent.
2. **Static taint / data-flow (static, medium cost).** Propagate from input **sources** (argv/env/read/
   recv/fread/mmap) to dangerous **sinks**; a source→sink path is a candidate. Sources/sinks/propagation come
   from a **curated rule set** (dangerous-API catalog + syscall model), extensible via the plugin API — no LLM.
3. **Symbolic / concolic (medium-high cost, corroborates + generates inputs).** angr / SymCC / SymQEMU
   explore paths to a candidate sink and try to satisfy the "bad" condition (e.g., index > bound). Adopt
   **static-analysis-guided path prioritization** (reachability + candidate-distance heuristics) so we don't
   path-explode. A solved input
   both corroborates the finding and seeds the PoC (doc 08).
4. **Dynamic (high cost, confirms).** Run under sanitizer/emulation (doc 06) with the fuzzer (doc 07); a
   crash/UB observation at a candidate site **confirms** it. Fuzzing can be *directed* at a candidate using
   **classical distance-based directed greybox fuzzing** (AFLGo-style: CFG/callgraph distance to the target
   site) to reach it faster — deterministic, no ML.

## Correlation & promotion (done in the core, doc 02)
- Findings are keyed by (function, site, CWE-class, tainted-source). When a static candidate's site matches
  a fuzzing crash's faulting IP, or a symbolic solver satisfies its bad condition, the core **promotes** it
  and merges evidence. Same root cause seen by 3 channels = **one** high-confidence finding, not three.

## CWE taxonomy engine
- Ship the **MITRE CWE catalog offline** (dated). A finding carries: CWE ID(s), the *evidence pattern* that
  mapped to it, severity (CVSS-style vector the analyst can adjust), affected function/address, tainted
  input vector, remediation guidance, and links to the PoC bundle.
- Maintain a matrix of **which CWEs are detectable by which channel** so the UI can show coverage honestly
  (e.g., CWE-798 hardcoded creds → static/string channel; CWE-416 UAF → dynamic/sanitizer channel).

## CWE classes and their primary channel (v1 focus in **bold**)
> The full, family-by-family catalog — every in-scope CWE with channel + feasibility, plus the explicit
> out-of-scope list and firmware/hardware (CWE-1194) and managed-bytecode coverage — is **doc 19**.
> The table below is the summary; doc 19 is the authority.
| CWE family | Examples | Primary channel |
|---|---|---|
| **Memory safety** | 119/125/787 OOB, **416 UAF**, 415 double-free, 476 NULL-deref | dynamic (QASan/RetroWrite) + symbolic |
| **Stack/heap overflow** | 121/122, 787 | fuzz + sanitizer, corroborate static |
| **Integer** | 190/191 overflow/underflow, 681 conversion | static taint + symbolic |
| **Format string** | 134 | static pattern + taint (fmt arg tainted) |
| **Command/arg injection** | 78, 88 | static taint to `system`/`exec*` |
| **Path traversal** | 22 | static taint to file APIs |
| **Uncontrolled resource** | 400, 401 leaks | dynamic + static |
| Hardcoded secrets/creds | 798, 259 | static string/entropy |
| Crypto misuse | 327/328/330 | constant + FoC crypto-ID + rules |
| Auth/logic | 306, 863 | mostly manual + rule/heuristic hints (analyst-driven) |

## Secondary pattern layer over decompiled C (cheap, deterministic)
Beyond the IR rules, run **Semgrep** or **Weggli** over Ghidra's decompiled pseudo-C as a *cheap complementary
pass*. It reliably catches the obvious class — calls to `strcpy`/`system`/`sprintf`, format-string sinks,
hardcoded-credential strings — accepted as **low precision** because decompiled C is messy (`undefined4`,
`uVar12`, gotos). It is never the backbone; the IR taint/symbolic engines are. The MITRE CWE catalog + the
**Juliet** examples are used to *author and regression-test* these rules (and the IR rules), and for
**known-vulnerable-function similarity** (BinDiff against a corpus of known-buggy functions, doc 04.4) — not
for matching source snippets against bytes, which does not survive compilation.

## Optional AI hook (unshipped)
No AI ships (decision doc 15). The plugin API leaves a hook so an operator with a local Ollama instance could
add vuln *hypotheses* as extra Candidates — but they would still require deterministic validation before
reaching Confirmed, and nothing depends on the hook.

## Output
Findings feed: the GUI findings board (doc 09), the report/SARIF export (doc 08/12), and the PoC synth
stage (doc 08) for anything reaching Confirmed.
