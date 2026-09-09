# 12 — Data Model, Persistence & Reproducibility

## Case-centric model
Everything lives under a **Case** (one engagement/target set). A case is self-contained and portable
(export/import as a directory or archive) so it can move between air-gapped hosts.

```
Case
 ├─ Binaries (Target)        one or more analyzed files
 ├─ ComponentGraph           inter-binary edges: link/dlopen/IPC/RPC/exec (doc 17)
 ├─ AnalysisRuns (jobs)      pipeline stage executions (doc 02)
 ├─ Functions / IR           recovered program model (doc 03/04)
 ├─ Findings                 with state lifecycle + evidence (doc 05)
 ├─ Harnesses                generated/edited (doc 07)
 ├─ FuzzCampaigns + Crashes  metrics, corpus refs, crash records (doc 07/08)
 ├─ PoCBundles               inputs, runner, recording, verification (doc 08)
 ├─ Reports                  HTML/PDF/SARIF exports (doc 08)
 └─ Provenance               tool/model/pack versions, input hashes
```

## Storage
- **SQLite** for structured data (cases, targets, functions, findings, jobs, crashes, poc metadata).
- **DuckDB** (optional) for heavy analytical queries over large trace/coverage tables.
- **Vector index** (FAISS/hnswlib) for function embeddings (doc 04).
- **Content-addressed artifact store:** every artifact (binary, corpus, crash input, trace, model output,
  recording) stored by hash; DB rows reference hashes. Dedup + integrity for free.

## Key entities (illustrative fields)
- **Target (Component):** hashes (md5/sha256/sha1), arch, format, size, mitigations, libc-id, entropy, imports/exports.
- **ComponentEdge:** src→dst component, type (link/dlopen/ipc/rpc/file/exec), channel contract, evidence refs (doc 17).
- **Finding** may be **cross-component:** source_site in one component, sink_site in another.
- **Finding:** id, cwe_ids[], state (Candidate/Corroborated/Confirmed/PoC-backed), confidence, severity/CVSS,
  function, address/site, tainted_vector, evidence[] (channel + artifact refs), analyst_notes, dedup_key.
- **AnalysisRun (job):** stage, inputs[] (by hash), params, tool+version, status, started/ended, outputs[],
  cache_key = hash(stage, input-hashes, params, tool-version) → **result caching** + resumability (doc 02).
- **Crash:** signal, faulting_ip, backtrace_hash (dedup), sanitizer_verdict, exploitability, minimized_input ref.
- **PoCBundle:** level (L0–L3), input refs, harness ref, env spec, runner script, expected_observable,
  recording ref, verified_bool + verification_run ref, isolation_tier.

## Reproducibility (not "chain of custody" — engineering reproducibility)
- Hash every input and artifact; pin every tool/model/pack **version** into each run and report.
- A finding records exactly *how* it was produced so re-running yields the same result — critical when
  bundles are stale (doc 11) and when a colleague on another air-gapped host must reproduce a PoC.
- Deterministic seeds where engines allow; record RNG seeds for fuzz/symbolic runs.

## Logging & audit
- Structured event log (job lifecycle, analysis runs, sandbox detonations, PoC verifications). Local only.
- Deterministic pipeline → every result is reproducible from its recorded inputs/params/tool-versions.
