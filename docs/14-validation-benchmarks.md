# 14 — Validation & Benchmarks (Measure Detection Quality Honestly)

A vuln tool that isn't measured drifts into confident nonsense. Build the eval harness in Phase 0 and run it
every phase (doc 13). Measure both **detection power** (finds real bugs) and **noise** (false-positive rate).

## Bundled benchmark corpora
| Corpus | What it gives | Measures |
|---|---|---|
| **NIST Juliet** (SARD) | thousands of labeled good/bad CWE cases | per-CWE detection + FP rate (static channels) |
| **LAVA-M** | programs with many injected, labeled bugs | fuzzing/harness bug-finding recall |
| **Magma** | real CVEs re-instrumented with ground-truth triggers | realistic fuzzing + triage |
| **DARPA CGC** | vulnerable binaries with reference PoVs | end-to-end find→confirm→PoC |
| Real-CVE mini-suite | a curated set of CVEs relevant to expected targets | true end-to-end validation |

## Metrics tracked over time (regression dashboard)
- **Per-CWE:** precision / recall / F1 at each finding state (candidate vs confirmed).
- **False-positive rate** at candidate stage AND the confirmed-stage FP rate (should approach ~0 — that's the
  whole point of the confidence pipeline, doc 05).
- **Fuzzing:** time-to-first-crash, unique-bug recall on LAVA-M/Magma, coverage over time, execs/sec by mode.
- **Confirmation loop:** % of static candidates that get dynamically/symbolically confirmed; time-to-confirm
  with vs without directed fuzzing (doc 07) — prove the accelerator earns its cost.
- **PoC:** % of confirmed findings reaching L0/L1/L2; PoC re-verification success rate.
- **Naming recovery (deterministic):** % of functions named by signatures + corpus-diff + runtime metadata on
  a labeled set; measures the doc-04 stack, not any model.
- **Cost:** wall-clock + memory per stage (the box is finite; doc 02 governor depends on these numbers).

## Guardrails
- Account for **function inlining** degrading signature/diff matching in the eval splits.
- Keep a held-out set the rules were never tuned on.
- Gate releases on "no regression in confirmed-stage FP rate and no drop in LAVA-M/Magma recall."
