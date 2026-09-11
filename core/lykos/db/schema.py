"""DM-04..DM-10 — Authoritative Phase 0 schema.

The initial migration creates all six base tables + indexes/FKs (tickets DM-04..DM-10).
`analysis_run` is intentionally written to be EXTENDED by a later migration authored under
the job-engine epic (JE-00: lease/heartbeat/attempts/priority/cancel/resource_class).
Keep this list append-only; never edit a shipped migration — add a new one.
"""
from __future__ import annotations

from .migrations import Migration

_INITIAL = r"""
CREATE TABLE "case"(
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  notes          TEXT,
  engagement_ref TEXT,
  created_at     INTEGER NOT NULL
);

CREATE TABLE target(
  id            TEXT PRIMARY KEY,
  case_id       TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  filename      TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  md5           TEXT,
  sha1          TEXT,
  size          INTEGER,
  file_type     TEXT,
  arch          TEXT,
  bits          INTEGER,
  endianness    TEXT,
  linking       TEXT,
  stripped      INTEGER,
  mitigations_json TEXT,
  entropy       REAL,
  ingested_at   INTEGER NOT NULL,
  UNIQUE(case_id, sha256)
);

CREATE TABLE artifact(
  sha256     TEXT PRIMARY KEY,
  case_id    TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  rel_path   TEXT NOT NULL,
  size       INTEGER,
  meta_json  TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE analysis_run(
  id           TEXT PRIMARY KEY,
  case_id      TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  target_id    TEXT REFERENCES target(id) ON DELETE CASCADE,
  stage        TEXT NOT NULL,
  status       TEXT NOT NULL,
  params_json  TEXT,
  tool         TEXT,
  tool_version TEXT,
  cache_key    TEXT,
  error        TEXT,
  started_at   INTEGER,
  ended_at     INTEGER,
  created_at   INTEGER NOT NULL
);

CREATE TABLE run_artifact(
  run_id          TEXT NOT NULL REFERENCES analysis_run(id) ON DELETE CASCADE,
  artifact_sha256 TEXT NOT NULL REFERENCES artifact(sha256),
  role            TEXT NOT NULL,
  PRIMARY KEY(run_id, artifact_sha256, role)
);

CREATE TABLE event(
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id      TEXT REFERENCES "case"(id) ON DELETE CASCADE,
  run_id       TEXT REFERENCES analysis_run(id) ON DELETE CASCADE,
  ts           INTEGER NOT NULL,
  level        TEXT NOT NULL,
  type         TEXT NOT NULL,
  payload_json TEXT
);

CREATE INDEX ix_run_case   ON analysis_run(case_id, status);
CREATE INDEX ix_run_cache  ON analysis_run(cache_key);
CREATE INDEX ix_target_case ON target(case_id);
CREATE INDEX ix_event_case ON event(case_id, id);
CREATE INDEX ix_event_run  ON event(run_id, id);
"""

# JE-00 — queue columns on analysis_run (job-engine epic extends the base table).
_QUEUE_COLUMNS = r"""
ALTER TABLE analysis_run ADD COLUMN claimed_by       TEXT;
ALTER TABLE analysis_run ADD COLUMN lease_expires_at INTEGER;
ALTER TABLE analysis_run ADD COLUMN heartbeat_at     INTEGER;
ALTER TABLE analysis_run ADD COLUMN attempts         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_run ADD COLUMN max_attempts     INTEGER NOT NULL DEFAULT 1;
ALTER TABLE analysis_run ADD COLUMN priority         INTEGER NOT NULL DEFAULT 100;
ALTER TABLE analysis_run ADD COLUMN resource_class   TEXT    NOT NULL DEFAULT 'quick';
ALTER TABLE analysis_run ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;
CREATE INDEX ix_run_claim ON analysis_run(status, resource_class, priority, id);
CREATE INDEX ix_run_lease ON analysis_run(lease_expires_at);
"""

# Phase 1 — recovered functions (Ghidra output persisted for the RE views).
_FUNCTIONS = r"""
CREATE TABLE function(
  id          TEXT PRIMARY KEY,
  target_id   TEXT NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  addr        TEXT NOT NULL,
  name        TEXT,
  size        INTEGER,
  decompiled  TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX ix_function_target ON function(target_id);
"""

# Phase 1 — per-function CFG + P-Code IR (Ghidra lifts every arch to P-Code = our neutral IR).
_FUNCTION_IR = r"""
ALTER TABLE function ADD COLUMN blocks  INTEGER;
ALTER TABLE function ADD COLUMN edges   INTEGER;
ALTER TABLE function ADD COLUMN ir_json TEXT;
"""

# Phase 1 — program call graph + cross-references (reachability + taint sinks for Phase 3).
_CALLGRAPH_XREFS = r"""
CREATE TABLE call_edge(
  id         TEXT PRIMARY KEY,
  target_id  TEXT NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  src_addr   TEXT,          -- calling function entry
  site_addr  TEXT,          -- call instruction address
  dst_addr   TEXT,          -- callee entry (may be null / thunk)
  dst_name   TEXT,          -- callee name (e.g. strcpy)
  external   INTEGER,       -- 1 if callee is imported/external (a potential sink)
  created_at INTEGER NOT NULL
);
CREATE INDEX ix_calledge_target ON call_edge(target_id);
CREATE INDEX ix_calledge_src    ON call_edge(target_id, src_addr);
CREATE INDEX ix_calledge_dst    ON call_edge(target_id, dst_addr);
CREATE INDEX ix_calledge_name   ON call_edge(target_id, dst_name);

CREATE TABLE string_ref(
  id         TEXT PRIMARY KEY,
  target_id  TEXT NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  addr       TEXT NOT NULL,
  value      TEXT,
  xrefs_json TEXT,          -- list of referencing site addresses
  created_at INTEGER NOT NULL
);
CREATE INDEX ix_stringref_target ON string_ref(target_id);
"""

# Phase 3 — CWE findings with the confidence lifecycle
# (candidate -> corroborated -> confirmed -> poc-backed).
_FINDINGS = r"""
CREATE TABLE finding(
  id            TEXT PRIMARY KEY,
  target_id     TEXT NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  case_id       TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  cwe           TEXT,
  title         TEXT,
  severity      TEXT,           -- info|low|medium|high|critical
  state         TEXT,           -- candidate|corroborated|confirmed|poc-backed
  confidence    REAL,
  function_addr TEXT,
  site_addr     TEXT,
  detector      TEXT,
  dedup_key     TEXT NOT NULL,
  evidence_json TEXT,           -- [{channel, detail}]
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  UNIQUE(target_id, dedup_key)
);
CREATE INDEX ix_finding_target ON finding(target_id, state);
CREATE INDEX ix_finding_case   ON finding(case_id, state);
"""

# Phase 4 — dynamic execution results (crash/timeout records from the sandbox).
_DYN_RESULTS = r"""
CREATE TABLE dyn_result(
  id          TEXT PRIMARY KEY,
  target_id   TEXT NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  case_id     TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  run_id      TEXT,
  input_sha   TEXT,
  input_mode  TEXT,
  argv        TEXT,
  exit_code   INTEGER,
  signal      INTEGER,
  signal_name TEXT,
  crashed     INTEGER,
  timed_out   INTEGER,
  isolation   TEXT,
  duration_ms INTEGER,
  stdout_sha  TEXT,
  stderr_sha  TEXT,
  note        TEXT,
  created_at  INTEGER NOT NULL
);
CREATE INDEX ix_dynresult_target ON dyn_result(target_id);
"""

MIGRATIONS = [
    Migration(version=1, name="initial_schema", sql=_INITIAL),
    Migration(version=2, name="job_queue_columns", sql=_QUEUE_COLUMNS),
    Migration(version=3, name="functions", sql=_FUNCTIONS),
    Migration(version=4, name="function_cfg_ir", sql=_FUNCTION_IR),
    Migration(version=5, name="callgraph_xrefs", sql=_CALLGRAPH_XREFS),
    Migration(version=6, name="findings", sql=_FINDINGS),
    Migration(version=7, name="dyn_results", sql=_DYN_RESULTS),
    Migration(version=8, name="pocs", sql=r"""
CREATE TABLE poc(
  id         TEXT PRIMARY KEY,
  target_id  TEXT NOT NULL REFERENCES target(id) ON DELETE CASCADE,
  case_id    TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  finding_id TEXT,
  level      TEXT,             -- L0 (reproducer) | L1 (crash) | L2 (primitive)
  verified   INTEGER,
  signal_name TEXT,
  input_sha  TEXT,
  bundle_sha TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX ix_poc_target ON poc(target_id);
"""),
    Migration(version=9, name="component_edges", sql=r"""
-- Phase 8 (doc 17.1): the component graph. Case-level edges between targets discovered
-- by resolving imports<->exports (and, later, IPC/exec/file relationships).
CREATE TABLE component_edge(
  id          TEXT PRIMARY KEY,
  case_id     TEXT NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  src_target  TEXT NOT NULL,      -- importer / caller component (A)
  dst_target  TEXT NOT NULL,      -- exporter / callee component (B)
  kind        TEXT,               -- dynamic-link | dlopen | ipc | exec | file
  symbol      TEXT,               -- resolved symbol / channel key (nullable)
  detail      TEXT,
  created_at  INTEGER NOT NULL,
  UNIQUE(case_id, src_target, dst_target, kind, symbol)
);
CREATE INDEX ix_component_edge_case ON component_edge(case_id);
"""),
    Migration(version=10, name="function_signature_frame", sql=r"""
-- Phase 1 deepening: decompiler-recovered prototype + stack-frame layout.
-- signature is light (shown in the function list); frame_json (params + stack variables
-- with offsets/sizes/buffer flags + frame geometry) is heavy, hydrated on the full view.
ALTER TABLE function ADD COLUMN signature  TEXT;
ALTER TABLE function ADD COLUMN frame_json TEXT;
"""),
    Migration(version=11, name="finding_sites", sql=r"""
-- A finding is a DEFECT, not a call site. Before this, one dangerous call site was one
-- finding row, so a binary's finding count tracked compiler inlining rather than risk:
-- jhead 3.06 built with distro flags produced 27 findings and the SAME PROGRAM at -O0
-- produced 230, because -O0 does not inline memcpy. Sites are now evidence hanging off the
-- defect, which is also how the Workbench already presented them ("x12 sites") while the
-- findings board showed 12 separate rows of identical text.
CREATE TABLE finding_site(
  id            TEXT PRIMARY KEY,
  finding_id    TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  function_addr TEXT,
  site_addr     TEXT,
  detail        TEXT,
  created_at    INTEGER NOT NULL,
  UNIQUE(finding_id, function_addr, site_addr)
);
CREATE INDEX ix_finding_site ON finding_site(finding_id);
"""),
    Migration(version=12, name="finding_verdicts", sql=r"""
-- A finding's state is the STRONGEST thing any channel currently says about it -- not the
-- strongest thing any channel has EVER said. The old merge took the higher state/severity/
-- confidence and kept it forever, which is right for promotion (that is how a finding climbs
-- candidate -> corroborated -> confirmed -> poc-backed when channels agree) and wrong for
-- everything else: a channel could never revise its own verdict downward.
--
-- That silently discarded every demotion. `enqueue_detect` forces by default -- "re-detect
-- after re-analysis should re-run rather than cache-hit" -- so detect re-running is the
-- designed path, and the bounds channel's "provably bounded, demote to info" was computed and
-- thrown away on every one of those runs. gzip 1.3.5's guarded strcpy demotes correctly on a
-- fresh case and stays high on a re-run of the same one.
--
-- Each channel now records its own verdict and the finding is the maximum over them, so a
-- channel can lower ITS OWN contribution without being able to lower anyone else's. A weak
-- late channel still cannot undo a crash-proven promotion.
CREATE TABLE finding_verdict(
  finding_id  TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  channel     TEXT NOT NULL,
  run_id      TEXT,
  state       TEXT NOT NULL,
  severity    TEXT NOT NULL,
  confidence  REAL NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY(finding_id, channel)
);
CREATE INDEX ix_finding_verdict ON finding_verdict(finding_id);

-- Seed from what already exists, or the first upsert after this migration would recompute a
-- finding from ONE channel and drop the standing verdicts of every channel that has not
-- re-run yet.
INSERT INTO finding_verdict(finding_id, channel, run_id, state, severity, confidence,
                            updated_at)
  SELECT id, COALESCE(detector, 'legacy'), NULL, state, severity, confidence, updated_at
    FROM finding;
"""),
    Migration(version=13, name="finding_site_verdicts", sql=r"""
-- A finding is a defect and its sites are the places it occurs -- but every verdict the
-- analysis computes is about ONE PLACE. bounds proves a particular copy bounded, a dominating
-- guard bounds a particular index, crash attribution proves a particular instruction. All of
-- that was being written as prose into `detail` and then collapsed to a single badge on the
-- finding.
--
-- The cost was overclaiming. jhead's poc-backed CWE-125 has 99 sites and exactly ONE of them
-- is proven -- the instruction the crash landed on -- yet all 99 carried the identical detail
-- string, so nothing in the data said which. A 99-site finding with one proven site rendered
-- exactly like one with 99.
--
-- Sites now carry their own state and verdict, so they can be ranked within the finding and
-- the finding can say "1 of 99 proven" instead of a flat badge.
ALTER TABLE finding_site ADD COLUMN state TEXT;
ALTER TABLE finding_site ADD COLUMN confidence REAL;
ALTER TABLE finding_site ADD COLUMN verdict TEXT;
"""),
]
