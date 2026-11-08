# 63 — Binary finding resolution: the binary counterpart of the source rework (2026-11-06)

Operator question: the source tree needed a ground-up rework (doc 60: reach + taint + triage wired
into engine stages so every finding gets a disposition). Do binaries need the same?

**Answer: yes, the same connective layer -- not a rewrite.** The binary pieces exist (P-Code IR,
call graph, libscope, taint, block tracer, guard-page / QASan oracles, hypothesis loop). What was
missing is what connects a filed finding to a verdict. Measured on gif2rgb (giflib 5.1.4, stripped):
22 unresolved findings (7 "need a PoC", 17 leads); nothing had checked whether ANY execution reached
their sites.

## Built (2026-11-05/06)

| piece | what it does | commit |
|---|---|---|
| `analyze/resolve_stage.py` (`finding_resolve`) | every unresolved finding: replay kept inputs under the block tracer (reached?), replay the site-reaching ones under the guard-page heap oracle + QASan attributed to the finding's own function, 3/3 (fires? -> confirmed + a crash row the prove loop takes), else a measured verdict: reached-did-not-fire / function-entered-site-cold / not-reached / unmapped. Verdicts never lower a state. Prove phase, before the prove loop. | 9cad507 |
| `fuzz/corpus_keep.py` | each campaign keeps its corpus (AFL queue, sandbox fuzzer) -- they were discarded at campaign end | 9cad507 |
| invocation variety | for sites nothing reached, kept inputs replay under every flag the binary documents (usage line, option string, --help), input pinned last | 1d27009 |
| argument-length probe | a site reached through a flag's VALUE gets long values in that slot; differential and attributed (a smashed return faults on the function's own `ret`) | 1d27009 |
| GUI | each finding shows its verdict (Proof cards, leads, detail Resolution panel) | 237f249 |

## Precision bugs the resolution exposed (fixed)
- `dangerous_api` and `stack_frame` flagged EVERY `sscanf` as an unbounded `%s` whenever any string
  in the image had one; gif2rgb's option parser calls `sscanf(arg, "%d", &n)` -- a "medium" CWE-120
  and a HIGH CWE-121 that were both false. Both now read the format at the call site (1d27009).
- `invocation.discover` ignored a usage line the program PRINTS (giflib builds it at runtime), so
  no flags were known (1d27009).
- `oob_index` filed the watchpoint's RUNTIME pc on a PIE (0x55555555cdd9), so the finding mapped to
  no function (9cad507).
- FP-review replay delivered PoC inputs over stdin without the guard-page oracle: proven findings
  read "did not reproduce 0/5" (394a368).
- exploitability treated a mitigation stored as "off" as enabled (5a1f774).

## gif2rgb after the resolver (con-case, pre-rerun)
1 fired at its site (the QASan over-read; same defect as the proven L2), 7 reached but quiet,
2 function entered / site cold, 10 not reached under 65 inputs incl. 4 documented invocations,
2 unmapped (an old oob_index row; the path-traversal recipe).

## Next (the remaining foundation)
1. **One address model.** Runtime / link-time / decompiler coordinates are converted ad hoc per
   stage; two of today's bugs were this class. One module (`analyze/addr.py`) every stage uses.
2. **Execution-evidence index.** Per kept input: its block coverage, once, reused by the resolver,
   the reach-gated fuzz scheduler and the hypothesis loop's seeding (today each recomputes or
   cannot).
3. **Directed solve for "site cold" / "reached, quiet"**: the resolver hands its reaching input as
   the seed; aim the hypothesis loop at that block (it reaches program code since 3e0e41e).
4. **Static reach for "not reached"**: decide whether the function is reachable from an input
   source at all (taint_reach) so an unreachable lead is said to be unreachable, not merely untried.
