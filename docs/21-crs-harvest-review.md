# 21 — CRS Harvest-Review Memo (Template)

**Deliverable of Phase 0 task P0.8.2** (`tasks/phase-0-foundations.md`). This is a **template to fill in
during the time-boxed review**; complete the `‹fill›` fields and the decision matrix, then treat the
"Decisions" section as the authoritative input to the Phase 0 job-engine design (P0.3).

> **Fill-in convention:** `‹fill›` = complete during review · `[?]` = verify, do not assume ·
> ratings use **H/M/L** unless noted.

| Field | Value |
|---|---|
| Reviewer | ‹fill› |
| Dates (time-box) | ‹start› → ‹end›  (budget: ~3–5 days, per P0.8) |
| Status | Draft / In-review / **Decided** |
| Drives | Phase 0 P0.3 (job/orchestration engine) design |

---

## 1. Purpose & the single question this memo answers
Decision doc 15 committed us to **build a lean custom orchestration core and harvest at the tool/library
level**, studying open Cyber Reasoning Systems for *ideas*, not forking them. This review makes that concrete:

> **For each part of our orchestration spine, do we (a) reuse a CRS component as-is, (b) adapt/port it,
> (c) take the design idea and reimplement, or (d) build clean with no reference?**

Scope is deliberately narrow: **orchestration only** — job/task model, scheduling, resource management,
tool coordination, corpus/artifact flow. NOT their AI layers (we are zero-AI), NOT their web/cloud infra.

## 2. Orientation reading (do first)
- **SoK: DARPA's AIxCC — Competition Design, Architectures, Lessons Learned** (arXiv 2602.07666) — the
  consolidated blueprint; read before touching any repo. Key takeaways for us: ‹fill›
- Each candidate's own writeup/blog + README. Notes: ‹fill›

## 3. Candidate systems
Locate the released repositories (verify URLs/licenses before use).

| System | Team / place | Repo `[?]` | License `[?]` | Reviewed? |
|---|---|---|---|---|
| **Buttercup** | Trail of Bits · 2nd | `github.com/trailofbits/buttercup` `[?]` | ‹fill› | ☐ |
| **ATLANTIS** | Team Atlanta · 1st | ‹fill› `[?]` | ‹fill› | ☐ |
| **Theori CRS** | Theori · 3rd | ‹fill› `[?]` | ‹fill› | ☐ |
| ‹other released finalist› | ‹fill› | ‹fill› | ‹fill› | ☐ |

> **Bias note for the whole review:** these systems are **online, LLM-integrated, source-and-coverage
> oriented, patch-focused** (OSS-Fuzz-style, source usually available). Ours is **offline, zero-AI,
> binary-only, offensive-PoC oriented, single Kali VM.** Expect *partial* fit; grade every component
> against *our* posture, not against how good it is in its own context.

## 4. Evaluation rubric (score each candidate)
Fill one block per reviewed system.

### System: ‹name›
| Dimension | Rating | Notes |
|---|---|---|
| License fit (offline redistribution, no copyleft trap) | ‹H/M/L› | ‹fill› |
| Offline-ability (how much assumes network / cloud / OSS-Fuzz / package fetch) | ‹H/M/L› | ‹fill› |
| **AI-decoupling cost** (how baked-in is the LLM; can orchestration run with it removed) | ‹H/M/L› | ‹fill› |
| **Binary-only fit** (do they need source / compiler instrumentation we won't have) | ‹H/M/L› | ‹fill› |
| Orchestration quality (task model, scheduling, resource mgmt, resume, cancellation) | ‹H/M/L› | ‹fill› |
| Component modularity (can a piece be lifted cleanly) | ‹H/M/L› | ‹fill› |
| Language/stack fit (Python/Rust vs theirs) | ‹H/M/L› | ‹fill› |
| Dependency weight (fits ~32 GB VM; no k8s/cloud sprawl) | ‹H/M/L› | ‹fill› |
| Maintainability for a solo dev (readability, docs, test coverage) | ‹H/M/L› | ‹fill› |
| **Overall harvest value to us** | ‹H/M/L› | ‹fill› |

*(Duplicate the block for each additional system.)*

## 5. Component-by-component decision matrix  ← the core output
Map their orchestration components to **our** modules (doc 02 + Phase 0). For each, pick a decision and
justify. `Decision ∈ {Reuse-as-is · Adapt/port · Ideas-only · Reimplement · N/A}`.

| Our module (doc ref) | Best source system | Decision | Rationale | Effort | License note |
|---|---|---|---|---|---|
| Job queue / task model (P0.3.1) | ‹fill› | ‹fill› | ‹fill› | ‹S/M/L› | ‹fill› |
| Scheduler + resource governor (P0.3.2, doc 02) | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Stage/DAG model (Phase 1, doc 02) | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Result caching / idempotence (P0.3.3) | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Tool adapters — Ghidra headless | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Tool adapters — AFL++/LibAFL | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Tool adapters — angr / SymQEMU | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Tool adapters — sanitizers (QASan) / CASR triage | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Corpus / seed management | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Crash dedup / triage flow | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Artifact storage & provenance (P0.4, doc 12) | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |
| Finding correlation / lifecycle (doc 05) | ‹fill› | ‹fill› | ‹fill› | ‹fill› | ‹fill› |

**Default expectation** (to be confirmed/overturned by the review): **Ideas-only for orchestration**
(job model, scheduling, coordination patterns) and **Adapt/port for tool adapters** where a clean, permissively
licensed wrapper exists and matches our arch/target. **Reimplement** anything welded to the LLM layer, to an
online service, or to a source/coverage-build workflow we can't satisfy.

## 6. Patterns worth stealing (design ideas)
Concrete orchestration ideas to carry into P0.3, with why: ‹fill›
- e.g. task granularity, backpressure, budget allocation across fuzz/symbolic, artifact schema, crash-dedup key.

## 7. Anti-patterns / do NOT inherit
Things that are right for a CRS but wrong for us (offline, zero-AI, solo, binary-only): ‹fill›
- e.g. cloud/k8s assumptions, LLM-in-the-loop scheduling, OSS-Fuzz source-build coupling, telemetry/phone-home,
  heavyweight message brokers.

## 8. Licensing review (blocking)
Per component we intend to reuse/adapt: license, copyleft implications, and whether it can ship in an
offline bundle as a separate process vs linked. Resolve before any code is copied.
| Component | System | License | Ship as | Verdict |
|---|---|---|---|---|
| ‹fill› | ‹fill› | ‹fill› | separate process / port / vendored | ✅/⚠️/❌ |

## 9. Decisions (authoritative — feeds P0.3)
State the final calls in plain sentences so the job-engine design can start:
1. Orchestration core: ‹Reimplement lean / adapt from ‹X›› because ‹fill›.
2. Reuse-as-is components: ‹list or "none"›.
3. Adapt/port components: ‹list› from ‹system›.
4. Ideas adopted (no code): ‹list›.
5. Explicitly built clean: ‹list›.

## 10. Risks & open questions
- ‹fill› (e.g., a tempting component has an incompatible license; a wrapper assumes source builds; etc.)

## 11. Sign-off
Reviewer: ‹fill› · Date decided: ‹fill› · P0.3 design may proceed: ☐ yes ☐ blocked by ‹fill›
