# Phase 0 · P0.1 Data Model & Persistence — Ticket-Level Breakdown

Expands epic **P0.1** (`tasks/phase-0-foundations.md`) into implementation-ready tickets. This is the
foundation both the **job engine (P0.3)** and the **ingest/triage worker (P0.5)** build on, so it is the
**authoritative Phase 0 schema**. Air-gapped, single Kali VM, zero-AI. SQLite (WAL), no external DB.

> **Boundary with the job engine:** this epic ships the **migration framework + base tables + DAO +
> hashing**. The queue-specific columns on `analysis_run` (lease, heartbeat, attempts, priority, cancel,
> resource_class) are added by a *later migration authored under **JE-00*** using this framework — not
> duplicated here. The base `analysis_run` (DM-07) is written to be extended.


> **BUILD STATUS (implemented):** all DM tickets done — `core/lykos/` + `tests/` (20 passing).
> DB access = raw sqlite3 + dataclass DAOs (DM-00); UUID PKs + sha256 artifact identity (DM-01).

## Effort legend
`S` ≤½ day · `M` ~1 day · `L` 2–3 days.

---

## A. Decisions to lock first (blocking)
| Ticket | Title | Deliverable / Recommendation | Dep | Eff |
|---|---|---|---|---|
| **DM-00** | DB access approach | **Recommend raw `sqlite3` + typed dataclass DAOs** (no ORM): lean, zero extra deps, full SQL control, air-gap-friendly, easy to reason about solo. Record decision + rationale | — | S |
| **DM-01** | ID & key strategy | **Recommend text `UUIDv4` PKs** for `case`/`target`/`analysis_run`/`event` (portable, collision-free on case export/import/merge — doc 12) and **`sha256` as artifact identity**. Record decision | — | S |

## B. DB framework & lifecycle
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **DM-02** | Migration runner | numbered **forward-only** migrations + `schema_version` table; each migration in its own transaction; `lykos db init` / `db upgrade`; idempotent; fails safe (rollback on error) | DM-00 | M |
| **DM-03** | Connection factory + pragmas | WAL, `foreign_keys=ON`, `busy_timeout`, `synchronous=NORMAL`, sane cache/mmap; **per-process connections** (each worker opens its own); documented single-writer discipline | DM-00 | S |

## C. Base schema (authoritative DDL below)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **DM-04** | `case` table | migration + round-trip test | DM-02 | S |
| **DM-05** | `target` table | migration incl. denormalized triage fields consumed by P0.5 (arch/bits/endianness/mitigations_json/…) | DM-02 | S |
| **DM-06** | `artifact` table | content-addressed; `sha256` unique per store; kind + meta_json | DM-02 | S |
| **DM-07** | `analysis_run` table (base) | base columns only; **built to be extended by JE-00**; status enum documented | DM-02 | S |
| **DM-08** | `run_artifact` join | (run_id, artifact_id, role∈{input,output}); composite PK | DM-02 | S |
| **DM-09** | `event` table | append-only; `(case_id, id)` + `(run_id, id)` indexes for the live log panel | DM-02 | S |
| **DM-10** | Constraints & index pass | FKs (with sensible `ON DELETE`), unique constraints, base indexes; one migration | DM-04…DM-09 | S |

### Authoritative Phase 0 schema (DDL, illustrative)
```sql
CREATE TABLE schema_version(version INTEGER NOT NULL, applied_at INTEGER NOT NULL);

CREATE TABLE "case"(
  id TEXT PRIMARY KEY,                 -- uuid4
  name TEXT NOT NULL,
  notes TEXT,
  engagement_ref TEXT,                 -- optional label; no auth gate (doc 15)
  created_at INTEGER NOT NULL);

CREATE TABLE target(
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  sha256 TEXT NOT NULL, md5 TEXT, sha1 TEXT, size INTEGER,
  file_type TEXT,                      -- elf|pe|macho|raw|other
  arch TEXT, bits INTEGER, endianness TEXT,
  linking TEXT, stripped INTEGER,      -- denormalized triage subset (P0.5)
  mitigations_json TEXT, entropy REAL,
  ingested_at INTEGER NOT NULL,
  UNIQUE(case_id, sha256));            -- per-case dedup (IT-05)

CREATE TABLE artifact(
  sha256 TEXT PRIMARY KEY,             -- content identity
  case_id TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                  -- target-blob|triage-json|log|…
  rel_path TEXT NOT NULL,              -- location in the content store (P0.4)
  size INTEGER, meta_json TEXT,
  created_at INTEGER NOT NULL);

CREATE TABLE analysis_run(            -- BASE; JE-00 adds queue columns
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  target_id TEXT REFERENCES target(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  status TEXT NOT NULL,                -- queued|running|done|error|cancelled
  params_json TEXT, tool TEXT, tool_version TEXT,
  cache_key TEXT, error TEXT,
  started_at INTEGER, ended_at INTEGER, created_at INTEGER NOT NULL);

CREATE TABLE run_artifact(
  run_id TEXT NOT NULL REFERENCES analysis_run(id) ON DELETE CASCADE,
  artifact_sha256 TEXT NOT NULL REFERENCES artifact(sha256),
  role TEXT NOT NULL,                  -- input|output
  PRIMARY KEY(run_id, artifact_sha256, role));

CREATE TABLE event(
  id INTEGER PRIMARY KEY AUTOINCREMENT,   -- monotonic for the log stream
  case_id TEXT REFERENCES "case"(id) ON DELETE CASCADE,
  run_id TEXT REFERENCES analysis_run(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL, level TEXT NOT NULL, type TEXT NOT NULL,
  payload_json TEXT);

CREATE INDEX ix_run_case ON analysis_run(case_id, status);
CREATE INDEX ix_run_cache ON analysis_run(cache_key);
CREATE INDEX ix_event_case ON event(case_id, id);
CREATE INDEX ix_event_run ON event(run_id, id);
CREATE INDEX ix_target_case ON target(case_id);
```

## D. DAO / repository layer
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **DM-11** | Base repository util | execute/query helpers, row→dataclass mapping, JSON-column (de)serialization, tx context manager | DM-03 | M |
| **DM-12** | Case + Target DAO | CRUD; list targets by case; **upsert target by (case,sha256)** (IT-05) | DM-11, DM-04/05 | S |
| **DM-13** | AnalysisRun DAO | create, fetch, status update, list by case/target (base CRUD; queue claim logic lives in JE-03) | DM-11, DM-07 | S |
| **DM-14** | Artifact + RunArtifact DAO | register artifact (idempotent by sha256), link role, fetch by sha256 / by run | DM-11, DM-06/08 | S |
| **DM-15** | Event DAO | append; query by case/run with **cursor pagination** (for the UI log panel + WS backfill) | DM-11, DM-09 | S |

## E. Shared primitives (feed P0.4 store & JE cache)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **DM-16** | Content hashing | streaming md5/sha1/sha256 for files+bytes; golden hashes match `sha256sum` | DM-00 | S |
| **DM-17** | Canonical JSON + param hashing | stable canonical serialization (sorted keys, normalized types) — **the same primitive JE-15/16 and P0.5 IT-20 depend on**; determinism tests | DM-16 | S |

## F. Integrity, portability & tests
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **DM-18** | Case directory & portability | a case = a directory (`case.db` + content-store subtree); define layout; export/import as a single archive (doc 12); round-trip preserves all rows+artifacts | DM-02, P0.4 | M |
| **DM-19** | Schema/DAO test suite | fresh-DB migrate-up; round-trip every entity; FK cascade behavior; JSON-column integrity; busy_timeout under a concurrent writer | DM-11…DM-17 | M |
| **DM-20** | Fixtures & factories | builders for case/target/run/artifact/event used across all Phase-0 tests | DM-11 | S |

---

## Build order (within the epic)
```
DM-00 ─► DM-01 ─► DM-02 ─► DM-03 ─► DM-04…DM-09 ─► DM-10
DM-16 ─► DM-17            (parallel; needed by P0.4 store & JE cache)
DM-11 ─► DM-12/13/14/15   (DAOs, after framework + schema)
DM-18 (needs P0.4)  ·  DM-19/DM-20 continuously, gate before epic close
```
**Internal milestones:**
1. **M-1 (DB boots):** DM-00…DM-03 — `db init` creates a WAL DB with pragmas; migration runner works.
2. **M-2 (schema in):** DM-04…DM-10 — all six tables + indexes/FKs migrate cleanly on a fresh DB.
3. **M-3 (DAOs):** DM-11…DM-15 — every entity has typed CRUD with round-trip tests.
4. **M-4 (primitives):** DM-16/DM-17 — hashing + canonical serialization other epics import.
5. **M-5 (portable + proven):** DM-18…DM-20 — case export/import round-trips; test suite green.

## Definition of Done (P0.1)
- `lykos db init` / `db upgrade` create and forward-migrate a WAL SQLite DB with `foreign_keys=ON`,
  transactionally, idempotently.
- All six base tables exist with FKs, unique constraints, and the listed indexes; `analysis_run` is
  cleanly extensible (JE-00 adds queue columns with no rework).
- Typed DAOs round-trip every entity; **target upsert by (case, sha256)** and **event cursor pagination** work.
- Content-hashing and canonical-JSON primitives exist and are deterministic (imported by P0.4 and JE-15/16).
- A case exports/imports as a single archive with all rows and artifacts intact.

## Notes & guardrails
- **No ORM, no external DB** — SQLite only, per the air-gapped/lean posture. Keep migrations plain SQL.
- **Single-writer discipline:** SQLite tolerates many readers + one writer; the queue's claim path (JE-03)
  is the hot writer — keep write transactions short. `busy_timeout` handles contention on the 4-core VM.
- **JSON columns** (`mitigations_json`, `params_json`, `meta_json`, `payload_json`) stay opaque blobs at the
  DB layer; validation lives in the producing code (e.g., triage schema IT-00), not in SQL.
- **Timestamps live on rows, not inside cached artifacts** — reinforces the determinism the result cache
  (JE-16) and triage output (IT-20) rely on.
- Reserve `20` as an unused doc number; task files live under `tasks/`, design docs under `docs/`.
