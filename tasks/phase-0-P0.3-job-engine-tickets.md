# Phase 0 · P0.3 Job Engine — Ticket-Level Breakdown

Expands epic **P0.3** (`tasks/phase-0-foundations.md`) into implementation-ready tickets. Context: Python
core, **SQLite-backed queue (no external broker)**, **multiprocessing worker pool** (a crashing native tool
must not take the service down), single Kali VM (4+ cores, ~32 GB, nested virt), zero-AI. Single-stage now;
the full pipeline DAG is Phase 1 — but the stage registry + context are built here so Phase 1 just adds stages.


> **BUILD STATUS (implemented):** JE-00..JE-08, JE-15..JE-25, JE-27..JE-30 done — `core/lykos/jobs/` + `core/lykos/db` (schema v2). 38 tests green (states, queue incl. concurrent no-double-claim, worker pool).
> **Deferred (honest):** JE-09 true *process* isolation uses threads for now (Phase-0 stages are Python; native-tool crash isolation lands with Phase 1 tools). JE-26 registers the real `ingest_triage` stage in **P0.5**. Concurrent-writer safety validated via BEGIN IMMEDIATE + busy_timeout in the no-double-claim test.

## Effort legend
`S` ≤½ day · `M` ~1 day · `L` 2–3 days. Ticket-level, so most are S/M.

## Schema deltas to P0.1 (`analysis_run`)
The queue needs columns beyond the P0.1 sketch. **Ticket JE-00** adds them:
```
+ claimed_by       TEXT     -- worker id holding the lease (NULL when queued)
+ lease_expires_at INTEGER  -- epoch; reaper requeues past this if still 'running'
+ heartbeat_at     INTEGER
+ attempts         INTEGER DEFAULT 0
+ max_attempts     INTEGER DEFAULT 1
+ priority         INTEGER DEFAULT 100   -- lower = sooner
+ resource_class   TEXT     -- e.g. quick|cpu|io|vm
+ cancel_requested INTEGER DEFAULT 0
-- cache_key already present in P0.1
Indexes: (status, resource_class, priority, id), (cache_key), (lease_expires_at)
```

---

## A. Job queue (from P0.3.1)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **JE-00** | Schema delta migration | migration adds columns+indexes above; `db upgrade` idempotent | P0.1 | S |
| **JE-01** | Status state machine | `JobStatus` enum + `can_transition(a,b)`; illegal transitions raise; unit-tested | JE-00 | S |
| **JE-02** | Enqueue API | `enqueue(case,target,stage,params,priority,resource_class)->run_id`; row `queued`; computes cache_key (JE-15); **dedupes** an identical `queued`/`running` job (returns existing id) | JE-01, JE-15 | M |
| **JE-03** | Atomic claim | single `UPDATE…WHERE status='queued' AND resource_class IN(…) …RETURNING` (SQLite RETURNING) sets `running`,`claimed_by`,`started_at`,`lease_expires_at`; **no double-claim** under concurrent workers | JE-01 | M |
| **JE-04** | Lease + reaper | `heartbeat(run_id)` extends lease; background **reaper** requeues `running` jobs past `lease_expires_at` (attempts++ / terminal per policy) | JE-03, JE-06 | M |
| **JE-05** | Complete / fail | `complete(run_id,outputs)`, `fail(run_id,err)` — idempotent; **guard**: refuse to complete a `cancelled`/expired job | JE-01 | S |
| **JE-06** | Retry policy | `attempts`/`max_attempts` + backoff; classify retryable vs terminal errors; requeue or `error` | JE-05 | S |
| **JE-07** | Boot crash-recovery | on service start, orphaned `running` jobs (no live worker) → requeue/`error` per policy | JE-04 | S |
| **JE-08** | Ordering & priority | deterministic claim order by `(priority, id)`; FIFO within priority | JE-03 | S |

## B. Worker pool + concurrency governor (from P0.3.2)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **JE-09** | Worker process model | `multiprocessing` workers loop claim→run→complete; a segfaulting stage kills **only** that worker | JE-03, JE-25 | M |
| **JE-10** | Supervisor + respawn | parent supervises workers; dead worker respawned; its lease expires → reaper (JE-04) | JE-09 | M |
| **JE-11** | Resource classes & caps | classes `quick|cpu|io|vm` with per-class concurrency caps from config; claim respects remaining class capacity | JE-03, JE-30 | M |
| **JE-12** | Admission / memory guard | global in-flight cap + coarse RAM budget check before starting heavy (`vm`/`cpu`) jobs on the 32 GB VM | JE-11 | M |
| **JE-13** | Graceful shutdown | SIGTERM: stop claiming, let in-flight finish within grace, then cancel; persist state; clean worker exit | JE-09, JE-19 | S |
| **JE-14** | Hung-worker detection | supervisor tracks worker heartbeats; no-heartbeat worker killed+respawned | JE-10 | S |

## C. Result cache (from P0.3.3)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **JE-15** | Canonical param serialization | stable canonical JSON (sorted keys, normalized numeric/bool/null); determinism unit tests | — | S |
| **JE-16** | Cache-key function | pure `cache_key = sha256(stage ‖ sorted(input_artifact_hashes) ‖ canonical_params ‖ tool_version)`; golden tests | JE-15 | S |
| **JE-17** | Lookup-before-run | claim/enqueue path finds a prior `done` run with same `cache_key`; **short-circuit**: link its outputs, emit `job.cachehit`, mark `done` without running | JE-16, JE-05, JE-27 | M |
| **JE-18** | Store + invalidation | persist `cache_key`+output refs on completion; `force` flag bypasses cache; changing `tool_version` misses (by construction) | JE-16 | S |

## D. Cancellation + status lifecycle (from P0.3.4)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **JE-19** | Cooperative cancel token | `cancel(run_id)` sets `cancel_requested`; ctx exposes `should_cancel()`; stage polls it; job ends `cancelled` | JE-01 | S |
| **JE-20** | Subprocess cancel helper | ctx-provided managed-subprocess wrapper that runs native tools in a **process group** and kills the group on cancel/timeout (readies Phase 1+ tools) | JE-19, JE-24 | M |
| **JE-21** | Wall-clock / resource timeout | per-stage timeout (config default); breach → cancel + `error(timeout)`; frees the worker | JE-19, JE-30 | S |
| **JE-22** | Transition events | every status change validated (JE-01) + emitted on the bus (P0.6) with correlation ids | JE-01, JE-27 | S |

## E. Stage registry & job context (from P0.3.5)
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **JE-23** | Stage registry | `register_stage(name, fn, resource_class, default_params, tool, tool_version)`; lookup/list; **core has no hardcoded stage list** (wires to plugin API P0.9) | P0.9.1 | S |
| **JE-24** | Job context object | typed `ctx`: `params`, input artifacts, artifact-store `put/get` (P0.4), event/log emitter (P0.6), `should_cancel()`, scratch workdir, `tool_version` | P0.4, P0.6 | M |
| **JE-25** | Stage runner | resolve stage fn → build ctx → run → capture outputs/metrics → exceptions map to `fail`; enforce timeout (JE-21) | JE-23, JE-24, JE-05 | M |
| **JE-26** | Register `ingest_triage` | the P0.5 worker registered as the first real stage through JE-23 (proves the pattern; overlaps P0.9.2) | JE-23, P0.5 | S |

## F. Cross-cutting / quality
| Ticket | Title | Deliverable / Accept | Dep | Eff |
|---|---|---|---|---|
| **JE-27** | Event schema | standard events `job.{queued,started,progress,log,cachehit,done,error,cancelled}` with `case_id`/`run_id`/`ts` | P0.6 | S |
| **JE-28** | Metrics/observability | counters (by status/stage) + per-stage timings; queryable via API for the dashboard | JE-22 | S |
| **JE-29** | Concurrency & fault test suite | fake **fast**, **slow/hanging**, and **crashing** stages drive: no-double-claim, lease reclaim on worker death, cancel mid-run, timeout, cache hit, graceful shutdown, boot recovery | most of A–E | L |
| **JE-30** | Config surface | worker count (default ≈ cores−1), per-class caps, lease TTL, heartbeat interval, timeouts, retry policy, cache on/off — with Kali-VM defaults | JE-00 | S |

---

## Build order (within the epic)
```
JE-00 ─► JE-01 ─► JE-15 ─► JE-16 ─► JE-02 ─► JE-03 ─► JE-05 ─► JE-08
                                                   └─► JE-04 ─► JE-06 ─► JE-07
JE-23 ─► JE-24 ─► JE-25 ─► JE-26           (stage layer, parallel after P0.4/P0.6 ready)
JE-27 ─► JE-22 ─► JE-19 ─► JE-21 ─► JE-20  (lifecycle + cancel)
JE-09 ─► JE-10 ─► JE-11 ─► JE-12 ─► JE-13/JE-14   (pool + governor)
JE-17 ─► JE-18                              (cache short-circuit, once claim+complete exist)
JE-30 alongside · JE-28 after JE-22 · JE-29 continuously, hard-gate before epic close
```
**Internal milestones:**
1. **M-A (queue works):** JE-00…JE-08 + JE-15/16 — enqueue, atomically claim, complete, retry, recover.
2. **M-B (stages run):** JE-23…JE-26 + JE-24 ctx — a registered stage executes in a worker.
3. **M-C (pool + governor):** JE-09…JE-14 — N isolated workers under per-class caps.
4. **M-D (lifecycle + cache):** JE-17…JE-22, JE-27 — cancel/timeout/events + cache short-circuit.
5. **M-E (hardened):** JE-28…JE-30 — config, metrics, full fault-test suite green.

## Definition of Done (P0.3)
- Enqueue → atomically claim → run a registered stage in an isolated worker → complete, with **no
  double-claim** under concurrency and **automatic reclaim** when a worker dies mid-job.
- **Cache hit** on identical re-run (no recompute) + `force` bypass.
- **Cancel** and **timeout** end a running job cleanly and free the worker; native subprocesses are killed.
- Per-class concurrency caps + memory admission honored on the 4-core/32 GB VM.
- Graceful shutdown and boot crash-recovery both leave the queue consistent.
- Every transition emits a bus event; JE-29 fault suite green in `make ci`.

## Notes & guardrails
- **Keep it SQLite-only.** No Redis/RabbitMQ/Celery — the whole point is an air-gapped, single-box,
  broker-free spine. `RETURNING` + a single-writer WAL connection for claims is enough at this scale.
- **Isolation via processes, not threads,** because Phase 1+ stages shell out to native tools that can crash.
- **Do not build the DAG here.** Single stage per run; Phase 1 composes stages. The registry + ctx are the
  only forward-looking pieces built now.
- Feed **JE-11's class model** and **JE-16's cache key** from the CRS harvest memo (doc 21) if it surfaces a
  better task/resource model — otherwise these defaults stand.
