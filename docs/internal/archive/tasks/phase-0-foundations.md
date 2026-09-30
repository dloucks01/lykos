# Phase 0 — Foundations (the Spine) · Task Breakdown

Expands roadmap Phase 0 (doc 13) into concrete, solo-developer tasks. **Goal:** build the spine plus one
thin vertical slice that proves the whole plumbing end-to-end, so every later phase plugs into a working
skeleton. Zero-AI, air-gapped, Kali VM (~32 GB RAM, 4+ cores, nested virt), per decisions in doc 15.

## Phase 0 status (implemented)
P0.1 data model · P0.2 API · P0.3 job engine · P0.4 artifact store (in casestore) · P0.5 ingest/triage ·
P0.6 events · P0.7 UI (web; Tauri wrap deferred) · P0.10 packaging (zipapp) · P0.11 CI — **DONE, 61 tests + offline verify green.**
Partial: P0.0 (Makefile/ruff in place; no git init) · P0.8 (harvest memo is a template, doc 21) ·
P0.9 (stage registry is the plugin seam; formal plugin loader + Ollama hook are stubs). The exit-demo flow
runs offline via `packaging/verify.sh` (equivalent to `tests/phase0_exit_demo.py`, which needs httpx/websockets).

## Exit criteria (Definition of Done for Phase 0)
A clean, offline Kali VM can install and launch the app, and an operator can:
1. **Create a case** and see it persisted.
2. **Ingest an ELF** (also accept PE/Mach-O), stored content-addressed.
3. See its **hashes, format, architecture/endianness/bits, sections, imports, and mitigations**
   (NX, PIE, RELRO, stack canary, FORTIFY) in the UI.
4. **Run a job** (the ingest/triage stage) and watch **live logs + progress** stream in the UI.
5. Re-running the same job hits the **result cache** (no recompute).
All with **no network access**.

## Explicitly NOT in Phase 0 (guard against scope creep)
- No Ghidra/disassembly/decompilation (Phase 1). No CWE detection, fuzzing, symbolic, sandbox, PoC.
- No full pipeline DAG (single-stage runner is enough; DAG lands in Phase 1).
- No multi-arch emulation, no signatures/naming, no reporting.
- No AI anything (a plugin *hook* stub only; nothing wired).

## Effort legend
`S` ≤1 day · `M` 2–4 days · `L` 1–2 weeks · `XL` >2 weeks. Estimates are rough, solo, calendar-ish.

---

## Tech baseline to lock on day one
- **Backend:** Python 3.12, **FastAPI** over a **Unix domain socket / loopback only** (never a public bind).
- **DB:** SQLite (WAL mode) via SQLAlchemy or raw `sqlite3` + a tiny migration runner.
- **Parsing:** **LIEF** for ELF/PE/Mach-O + hashing from stdlib.
- **Frontend:** **Tauri** (Rust shell) + React + TypeScript, reusing the design tokens from the console
  prototype (`prototype/console.html`) so the look is coherent from day one.
- **Transport:** REST for commands + **WebSocket** for the event stream.
- **Packaging:** target an offline Podman image or Nix closure; Phase 0 only needs a rough self-contained
  launch, not the final installer (doc 11).

### Repo layout (deliverable of P0.0)
```
binanalysis/
  core/lykos/
    api/         FastAPI app, routers, WS endpoint
    db/          schema, migrations, models, DAO
    jobs/        queue, worker pool, scheduler, result cache
    artifacts/   content-addressed store
    events/      pub/sub bus + persistence
    plugins/     registry + typed hook stubs
    workers/     stage implementations (ingest_triage first)
    config/      settings, paths, logging
  ui/            Tauri + React
  tasks/         this file, future phases
  tests/         pytest + golden sample binaries
  packaging/     offline build scripts (rough in P0)
```

---

## Epics & tasks

### P0.0 — Project setup & tooling  (M)
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.0.1 | Repo skeleton + layout above | `git init`, dirs, `pyproject.toml`, `ui/` scaffold | tree matches; `pip install -e core` works offline | — |
| P0.0.2 | Pin & vendor deps for offline | local wheel cache / vendored deps; Rust/npm offline cache | fresh VM builds with no network | P0.0.1 |
| P0.0.3 | Dev tooling | `ruff`+`mypy`+`pytest`; `make` targets (`run`, `test`, `lint`, `bundle`) | `make test` green on empty suite | P0.0.1 |
| P0.0.4 | Config & paths | `config/` with case-store root, socket path, log config | app reads config; no hardcoded paths | P0.0.1 |

### P0.1 — Data model & persistence  (M)
Minimal subset of doc 12. Tables: `case`, `target`, `analysis_run`, `artifact`, `run_artifact`, `event`.
> **Ticket-level breakdown: `tasks/phase-0-P0.1-data-model-tickets.md`** (DM-00…DM-20, authoritative schema, DoD).
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.1.1 | Schema + migration runner | SQL schema (below) + forward migrations | `lykos db init` creates DB (WAL) | P0.0 |
| P0.1.2 | DAO layer | typed CRUD for each table | unit tests round-trip each entity | P0.1.1 |
| P0.1.3 | Content-hash helpers | sha256/md5/sha1 utilities, canonical param hashing | golden hashes match `sha256sum` | P0.0 |

Phase-0 schema (illustrative):
```
case(id PK, name, notes, engagement_ref NULL, created_at)
target(id PK, case_id FK, filename, sha256, md5, sha1, size,
       format, arch, bits, endianness, mitigations_json, entropy, ingested_at)
artifact(id PK, case_id FK, sha256 UNIQUE-per-store, kind, rel_path, size, meta_json, created_at)
analysis_run(id PK, case_id FK, target_id FK, stage, status,        -- queued|running|done|error|cancelled
             params_json, tool, tool_version, cache_key, error,
             started_at, ended_at)
run_artifact(run_id FK, artifact_id FK, role)                       -- input|output
event(id PK, case_id FK, run_id FK NULL, ts, level, type, payload_json)  -- append-only
```

### P0.2 — Core service & API skeleton  (M)
> **P0.2/P0.6 BUILD STATUS (implemented):** stdlib HTTP server on a unix socket + hand-rolled RFC-6455
> event WebSocket (`core/lykos/api/`); `lykos serve` live-verified with curl. No FastAPI/uvicorn
> dep. 58 tests green. Event bus = the persisted `event` table tailed by the WS (P0.6).
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.2.1 | FastAPI app on Unix socket | service boots, `GET /health` | curl over socket returns ok; no TCP bind | P0.0 |
| P0.2.2 | Case + target routers | `POST/GET /cases`, `POST /cases/{id}/targets`, `GET /targets/{id}` | create case → ingest target → fetch triage | P0.1, P0.5 |
| P0.2.3 | Run router | `POST /runs` (enqueue stage), `GET /runs/{id}` | enqueue returns run id; status transitions visible | P0.3 |
| P0.2.4 | Structured logging | JSON logs → file + event table | logs correlate by case_id/run_id | P0.6 |

### P0.3 — Job/queue engine (minimal) & result cache  (L)
Single-stage runner now; full DAG in Phase 1. **Informed by the P0.8 harvest memo.**
> **Ticket-level breakdown: `tasks/phase-0-P0.3-job-engine-tickets.md`** (JE-00…JE-30, build order, DoD).
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.3.1 | SQLite-backed job queue | enqueue/claim/complete `analysis_run` rows | survives restart; no double-claim | P0.1 |
| P0.3.2 | Worker pool + concurrency governor | process/thread pool, semaphore by resource class | N-worker cap honored; 1 stuck job ≠ frozen UI | P0.3.1 |
| P0.3.3 | Result cache | `cache_key = hash(stage, sorted(input_hashes), canonical(params), tool_version)`; lookup-before-run | re-run identical job → cache hit, no recompute | P0.1.3, P0.3.1 |
| P0.3.4 | Cancellation + status | cooperative cancel flag; status lifecycle | cancel a running job → `cancelled`, worker freed | P0.3.2 |
| P0.3.5 | Stage registry | map `stage name → callable(ctx)`; `ingest_triage` registered | new stage added in <20 LOC | P0.9 |

### P0.4 — Content-addressed artifact store  (S–M)
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.4.1 | Store API | `put(bytes|path)->sha256`, `get(sha256)`, dedup, `sha256/xx/xxxx…` layout | same content stored once; integrity verified on read | P0.1 |
| P0.4.2 | Run I/O wiring | runs record input/output artifacts via `run_artifact` | ingest run’s triage JSON retrievable by hash | P0.4.1, P0.3 |

### P0.5 — First analyzer: ingest & triage worker  (L)  ← the vertical slice
Deterministic, LIEF-based. No disassembly.
> **Ticket-level breakdown: `tasks/phase-0-P0.5-ingest-triage-tickets.md`** (IT-00…IT-23, triage schema, DoD).
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.5.1 | Ingest | copy target into artifact store, compute md5/sha1/sha256, size | target row + stored blob | P0.4 |
| P0.5.2 | Format/arch parse | LIEF: format (ELF/PE/Mach-O), arch, bits, endianness, sections, imports | fields correct on golden samples across 3 arches | P0.5.1 |
| P0.5.3 | Mitigations | NX (GNU_STACK), PIE (ET_DYN+flag), RELRO (GNU_RELRO+BIND_NOW), canary (`__stack_chk_fail`), FORTIFY (`*_chk`) | matches `checksec` on golden set | P0.5.2 |
| P0.5.4 | Entropy + packer hint | section entropy; UPX/high-entropy flag | UPX sample flagged; normal binary not | P0.5.2 |
| P0.5.5 | Emit triage artifact + events | triage JSON → store; progress/log events on the bus | UI shows result + streamed log (P0.7) | P0.5.3, P0.6 |

### P0.6 — Event bus & live streaming  (M)
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.6.1 | In-process pub/sub | topic-per-case bus; workers publish progress/log/metric | subscriber receives worker events | P0.0 |
| P0.6.2 | Persist events | append to `event` table | events survive restart; queryable by case/run | P0.1 |
| P0.6.3 | WebSocket fan-out | `WS /events?case_id=` streams live | UI log panel updates in real time | P0.6.1, P0.2.1 |

### P0.7 — Desktop shell + UI skeleton + design system  (L)
> **P0.7 BUILD STATUS (implemented, with deviation):** functional operator-console **web UI** (`core/lykos/api/static/index.html`) served by the server over a **loopback TCP bind** and wired to the live REST + WebSocket API — case list/create, target upload, targets table with mitigation chips, triage-detail panel, runs list, live event log, light/dark. Reuses the console prototype's tokens; offline system fonts (no Google Fonts). **DEVIATION:** not yet wrapped in a **Tauri** desktop shell (no npm/cargo toolchain here) — Tauri packaging of this same page is a thin later step. 60 tests green; live-verified.
Reuse the console prototype’s tokens/components.
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.7.1 | Tauri + React scaffold, offline | app window loads local UI, talks to socket | launches on Kali VM, no network | P0.0.2 |
| P0.7.2 | Port design tokens | color/type/space tokens + base components from `prototype/console.html`; light+dark | matches prototype look; theme toggle works | P0.7.1 |
| P0.7.3 | Case list + create | list cases, create-case dialog | create → appears in list | P0.2.2 |
| P0.7.4 | Case dashboard | targets table (hashes/format/arch/mitigations), run controls, **live log panel** (WS) | ingest a file → row + streamed log appear | P0.5, P0.6.3 |
| P0.7.5 | Ingest flow | pick/drop a file → enqueue ingest_triage | end-to-end from UI | P0.2.3, P0.5 |

### P0.8 — CRS harvest review (GATE, time-boxed)  (M)  ← run early, in parallel
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.8.1 | Study Buttercup + 1–2 AIxCC OSS CRSs | reading notes | orchestration patterns understood | — |
| P0.8.2 | Vendor-vs-reimplement memo | `docs/internal/21-crs-harvest-review.md`: what to reuse vs build, license notes | decisions feed P0.3 design | P0.8.1 |
> Gate: **finish P0.8.2 before finalizing the P0.3 job-engine design** (scaffolding P0.3.1 may start earlier).

### P0.9 — Plugin API skeleton  (S–M)
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.9.1 | Registry + typed hook stubs | `register_loader`, `register_stage`, `register_detector` (stub), `register_report_section` (stub) | importing a plugin registers it | P0.3.5 |
| P0.9.2 | Prove the pattern | the ELF loader + ingest_triage stage registered *through* the API | core has no hardcoded stage list | P0.9.1, P0.5 |
| P0.9.3 | Unshipped AI hook stub | documented no-op hook for a future local Ollama assist | present, disabled, nothing depends on it | P0.9.1 |

### P0.10 — Offline packaging smoke test  (M)
> **P0.10/P0.11 BUILD STATUS (implemented):** `packaging/build.sh` builds a **single-file zipapp** (`dist/lykos.pyz`, ~124K, stdlib-only so it builds with no network); `packaging/verify.sh` runs it end-to-end offline (serves UI + triages a binary), verified under `unshare -rn` (network namespace). `make ci` = ruff lint (clean) + mypy (optional) + 61 pytest green. Tauri wrap of the UI still deferred.
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.10.1 | Self-contained bundle (rough) | script producing an offline-installable bundle | builds with no network | P0.0.2 |
| P0.10.2 | Clean-VM launch | run on a fresh Kali VM, network disabled | app launches + exit demo passes | all |

### P0.11 — Tests & local CI  (M, continuous)
| ID | Task | Deliverable | Accept | Dep |
|----|------|-------------|--------|-----|
| P0.11.1 | Golden sample corpus | small ELF/PE/Mach-O set (x86-64, AArch64, PPC) + expected triage JSON | committed, license-clean | P0.5 |
| P0.11.2 | Unit + API tests | pytest for DAO, cache, store, triage; headless API test | `make test` green | P0.5, P0.2 |
| P0.11.3 | Local CI target | `make ci` (lint+type+test), runnable offline | one command, deterministic | P0.0.3 |

---

## Critical path & suggested order
```
P0.0 ─► P0.1 ─► P0.2.1 ─► P0.6 ─► P0.4 ─► P0.3 ─► P0.5 ─► P0.9 ─► P0.7 ─► P0.11 ─► P0.10 (exit demo)
                                     ▲
P0.8 (harvest memo, in parallel from day 1) ──► informs P0.3 design
```
Rough Phase-0 envelope for a solo dev: **~6–9 weeks**, dominated by P0.3 (job engine), P0.5 (triage), and
P0.7 (UI). P0.8 runs alongside and must land before P0.3’s design is frozen.

## Exit demo script (proves Phase 0)
> **Automated harness: `tests/phase0_exit_demo.py`** (+ `tests/phase0_exit_demo.sh` runner). Asserts every
> criterion below over the unix socket; exits non-zero on any failure. The steps below are the human-readable
> version of what the harness checks.
1. Fresh Kali VM, **network off**. Install the bundle (P0.10). Launch.
2. UI: **create case** “demo-001”.
3. **Ingest** a stripped AArch64 ELF (drag-drop).
4. Watch the **live log** stream the ingest_triage stage.
5. See the target row: sha256, `ELF · AArch64 · 64-bit · little-endian`, sections/imports count,
   mitigations (`NX RELRO(partial)` etc.), entropy.
6. **Re-run** ingest_triage → **cache hit**, no recompute, instant.
7. Confirm the triage JSON is retrievable from the artifact store by hash.

## Phase-0 risks
- **Over-building the job engine.** Keep it single-stage + cache; resist DAG/distributed until Phase 1.
- **UI/backend transport friction** on Tauri offline — spike P0.7.1 early to de-risk.
- **LIEF edge cases** (odd/packed/foreign binaries) — bound triage to “best-effort, report what’s parseable,”
  never crash the worker.
- **Harvest memo scope drift** — time-box P0.8 to a fixed budget; its output is a decision, not code.

## Hand-off to Phase 1
Phase 1 (doc 13) adds Ghidra headless: disasm, decompile, CFG/callgraph, IR normalization, and the
synchronized RE workspace — each as a new **stage** registered through the plugin API (P0.9) and a new
**view** on the P0.7 shell. The spine does not change; capability plugs in.
