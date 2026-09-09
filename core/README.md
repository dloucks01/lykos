# lykos — core

Air-gapped binary vulnerability analysis platform, core backend. Phase 0 in progress.
Zero external dependencies in the data-model core (stdlib `sqlite3` only); `pytest` for dev.

## Quickstart
```bash
# run the data-model test suite (no install needed)
python3 -m pytest tests/ -q

# or install editable, then use the CLI entrypoint
pip install -e core
lykos db init --case-store /path/to/case
lykos db version --case-store /path/to/case
```
Without installing, the CLI runs as `PYTHONPATH=core python3 -m lykos db init --case-store DIR`.

## Layout (implemented so far)
```
core/lykos/
  db/connection.py    WAL + pragmas, per-process connections, transaction()   (DM-03)
  db/migrations.py    forward-only numbered migrations, txn-safe DDL           (DM-02)
  db/schema.py        authoritative Phase-0 schema (6 tables + indexes)        (DM-04..10)
  db/models.py        typed dataclasses                                        (DM-00)
  db/repository.py    JSON/bool helpers, BaseDAO                               (DM-11)
  db/dao.py           Case/Target/Artifact/RunArtifact/AnalysisRun/Event DAOs  (DM-12..15)
  hashing.py          content hashing + canonical JSON + cache-key             (DM-16/17)
  casestore.py        case dir + content-addressed store + export/import       (DM-18)
  jobs/states.py      run status state machine                                 (JE-01)
  jobs/queue.py       SQLite queue: enqueue/dedup/claim/lease/reap/cache        (JE-02..08,17)
  jobs/context.py     stage context: events, cancel/timeout, artifacts, subproc (JE-19..24)
  jobs/registry.py    stage registry + StageDef                                (JE-23,25)
  jobs/worker.py      thread worker pool + governor + reaper + metrics         (JE-09..14,28)
  jobs/config.py      Kali-VM defaults                                         (JE-30)
  analyze/filetype.py magic-based file-type detection                          (IT-04)
  analyze/elf.py      pure-stdlib ELF parser (arch/mitigations/imports/...)    (IT-06..12)
  analyze/triage.py   triage record schema + builder + validator              (IT-00,16,17,20)
  analyze/ingest.py   ingest helper + registered `ingest_triage` stage         (IT-01/03/18, JE-26)
  api/server.py       unix-socket HTTP API + serve()                           (P0.2)
  api/ws.py           RFC-6455 server WebSocket (event stream)                 (P0.6)
  api/multipart.py    minimal multipart upload parser                          (P0.2)
  api/static/index.html  operator-console web UI (vanilla, offline)            (P0.7)
  analyze/ghidra.py   Ghidra locator + headless runner + result parser         (Phase 1)
  analyze/ghidra_scripts/ExportAnalysis.py  Jython export (functions + decomp)  (Phase 1)
  analyze/disassemble.py  `disassemble` stage (Ghidra headless)                (Phase 1)
  cli.py              `lykos db init|upgrade|version|serve`                (DM-02, P0.2)
tests/                migrations, DAO, hashing, casestore + fixtures/factories (DM-19/20)
```

## Status
- Data-model epic (P0.1 / DM-00..DM-20): **implemented.**
- Job-engine epic (P0.3 / JE-00..JE-30): **implemented** (threads now; process isolation deferred).
- Ingest/triage worker (P0.5 / IT-00..IT-22): **implemented** — first real stage; ELF parser is
  pure stdlib (LIEF deferred for PE/Mach-O). Cross-checked against file(1)/readelf.
- API + event stream (P0.2 / P0.6): **implemented** — stdlib unix-socket HTTP + RFC-6455 WebSocket,
  no FastAPI/uvicorn. `lykos serve` live-verified with curl (`/bin/ls` -> triage).
- UI shell (P0.7): **implemented** — functional web console served over a loopback bind, wired to the
  live API + WebSocket (Tauri desktop wrap deferred). Reuses the prototype's design tokens, offline fonts.
- Packaging (P0.10): **implemented** — `make bundle` builds `dist/lykos.pyz` (single-file zipapp,
  stdlib-only, offline); `make verify` runs it end-to-end offline (verified under a network namespace).
- CI (P0.11): **implemented** — `make ci` = ruff lint + mypy(optional) + pytest.
- **Phase 1 started:** Ghidra headless integration — `disassemble` stage, `function` table, functions API,
  and a Decompile/functions/decompiled-code UI panel. **Ghidra ships in the full bundle** (not pre-installed);
  if absent, the stage errors clearly and triage still works.
- Phase 1 now extracts **CFG (blocks+edges) + P-Code IR** per function (migration v4), served via the
  functions API and shown in the UI (decompiled / disassembly+CFG / P-Code). P-Code is the neutral IR the
  Phase-3 CWE detectors will run on.
- Phase 1 also extracts the **program call graph** (call edges + sites; external callees flagged as sinks)
  and **cross-references** (strings + xref sites), persisted (migration v5) and served via
  `/targets/{id}/callgraph` and `/targets/{id}/strings`, with callers/callees on function detail. This is
  the reachability + taint-sink data the Phase-3 CWE detectors need.
- **Phase 3 started — CWE detection engine (deterministic):** `finding` table + confidence lifecycle,
  detectors (dangerous-API rule, hard-coded secrets, call-graph input->sink reachability that promotes
  candidate->corroborated), the `detect_cwe` stage, findings API, and a Detect button + findings list in
  the UI. Findings reach **Confirmed** only via dynamic/symbolic reproduction (Phases 4/6), not statically.
- Detection now includes **true data-flow taint** over P-Code (flow-sensitive, def-use, per-arch ABI
  registers): it flags sink sites whose argument registers carry tainted data, a precise corroboration
  channel above call-graph reachability. Limits: intra-procedural, register-granularity (no memory model).
- Taint is now **inter-procedural** (summary-based call-graph fixpoint: tainted args into callees, tainted
  returns back to callers), catching source-in-caller -> sink-in-callee and source-wrapper functions.
- **Phase 4 started -- dynamic analysis:** tiered-isolation sandbox (bubblewrap+netns, auto-fallback to
  rlimits), cross-arch via qemu-user, crash/timeout detection, the `dynamic_run` stage, dynresults API, and
  a Run(sandbox) UI. **A reproduced crash promotes a finding to Confirmed** -- the lifecycle's payoff.
- **90 tests green (+1 skipped: real Ghidra).** Live-verified: a SIGSEGV crash yields a Confirmed CWE-119.
- **Phase 5 started -- fuzzing:** dependency-free black-box mutational fuzzer (havoc + strings dictionary)
  drives the sandbox over stdin/argv/file; unique crashes become **Confirmed** findings with reproducible
  inputs. `fuzz` stage + Fuzz UI button with live stats.
- **93 tests green (+1 skipped: real Ghidra).** Live-verified: fuzzing a target auto-confirms a CWE-119.
- **Phase 6 started -- demonstrable PoCs:** `build_poc` verifies a crashing input in a clean sandbox and
  builds a self-contained `.tar.gz` (target+input+runner+meta+stderr); a verified PoC promotes the finding
  to **poc-backed** (top of the lifecycle). PoC list + downloadable bundle in the UI.
- Detection coverage widened: added **weak-crypto** (CWE-327/328), **insecure-PRNG** (CWE-330),
  **insecure-temp-file** (CWE-377), and a **hardening** detector (missing NX/canary/PIE/RELRO -> CWE-693),
  all deterministic over the call graph + strings + mitigations.
- Fuzzing now **minimizes** each unique crash (ddmin-style, budget-bounded) to a tiny reproducer before it
  becomes a finding/PoC bundle.
- **104 tests green (+1 skipped: real Ghidra).** Live-verified end-to-end: fuzz -> crash -> verified PoC ->
  poc-backed CWE-119 with a downloadable bundle.
- Deferred: symbolic/concolic (angr/SymQEMU) to reach unreached candidates, coverage-guided/directed
  fuzzing, crash minimization, L2 primitive PoCs, debugger/sanitizers, microVM isolation; Tauri wrap.

## Ghidra (Phase 1)
The operator does NOT install Ghidra separately — the full offline bundle includes it (Apache-2.0). The
locator checks `LYKOS_GHIDRA` / `GHIDRA_INSTALL_DIR`, a bundled `vendor/ghidra`, then PATH. For dev,
point it at an existing install: `export LYKOS_GHIDRA=/opt/ghidra_11.x`.

## Run the service
```bash
PYTHONPATH=core python3 -m lykos serve --socket /tmp/b.sock --case-store /tmp/cs --workers 2
curl -s --unix-socket /tmp/b.sock http://localhost/health
curl -s --unix-socket /tmp/b.sock -F file=@/bin/ls http://localhost/cases/$CID/targets

# with the UI (open the URL in a browser):
PYTHONPATH=core python3 -m lykos serve --http 127.0.0.1:8787 --case-store /tmp/cs --workers 2
# then browse to http://127.0.0.1:8787
```
