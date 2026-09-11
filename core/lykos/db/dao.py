"""DM-12..DM-15 — Typed DAOs for each entity.

Each DAO takes a connection. IDs/timestamps are assigned here if absent. JSON and bool
columns are (de)serialized via repository helpers.
"""
from __future__ import annotations

import sqlite3
import time
from collections.abc import Sequence
from typing import Any, Optional

from ..hashing import new_id
from .connection import transaction
from .models import (
    ARTIFACT_ROLES,
    FINDING_STATES,
    RUN_STATUSES,
    SEVERITIES,
    AnalysisRun,
    Artifact,
    CallEdge,
    Case,
    ComponentEdge,
    DynResult,
    Event,
    Finding,
    Function,
    Poc,
    RunArtifact,
    StringRef,
    Target,
)
from .repository import BaseDAO, as_bool, as_flag, as_int_bool, dumps, loads

_TABLE_CASE = '"case"'  # reserved word — must be quoted everywhere


def _now() -> int:
    return int(time.time())


# --------------------------------------------------------------------------- Case (DM-12)
class CaseDAO(BaseDAO):
    def create(self, name: str, notes: Optional[str] = None,
               engagement_ref: Optional[str] = None) -> Case:
        c = Case(id=new_id(), name=name, created_at=_now(), notes=notes,
                 engagement_ref=engagement_ref)
        self.conn.execute(
            f'INSERT INTO {_TABLE_CASE}(id,name,notes,engagement_ref,created_at) '
            "VALUES(?,?,?,?,?)",
            (c.id, c.name, c.notes, c.engagement_ref, c.created_at),
        )
        return c

    def get(self, case_id: str) -> Optional[Case]:
        r = self.conn.execute(f'SELECT * FROM {_TABLE_CASE} WHERE id=?', (case_id,)).fetchone()
        return self._row(r) if r else None

    def list(self) -> list[Case]:
        rows = self.conn.execute(f'SELECT * FROM {_TABLE_CASE} ORDER BY created_at DESC').fetchall()
        return [self._row(r) for r in rows]

    def delete(self, case_id: str) -> None:
        self.conn.execute(f'DELETE FROM {_TABLE_CASE} WHERE id=?', (case_id,))

    @staticmethod
    def _row(r: sqlite3.Row) -> Case:
        return Case(id=r["id"], name=r["name"], created_at=r["created_at"],
                    notes=r["notes"], engagement_ref=r["engagement_ref"])


# ------------------------------------------------------------------------- Target (DM-12)
class TargetDAO(BaseDAO):
    def upsert(self, case_id: str, filename: str, sha256: str, **fields: Any) -> Target:
        """Insert, or return the existing target for (case_id, sha256), updating fields.

        Implements per-case dedup by content hash (IT-05).
        """
        existing = self.get_by_hash(case_id, sha256)
        if existing:
            if fields:
                self._update_fields(existing.id, fields)
                return self.get(existing.id)  # type: ignore[return-value]
            return existing
        t = Target(id=new_id(), case_id=case_id, filename=filename, sha256=sha256,
                   ingested_at=_now(), **fields)
        self.conn.execute(
            "INSERT INTO target(id,case_id,filename,sha256,md5,sha1,size,file_type,"
            "arch,bits,endianness,linking,stripped,mitigations_json,entropy,ingested_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (t.id, t.case_id, t.filename, t.sha256, t.md5, t.sha1, t.size, t.file_type,
             t.arch, t.bits, t.endianness, t.linking, as_int_bool(t.stripped),
             dumps(t.mitigations), t.entropy, t.ingested_at),
        )
        return t

    def _update_fields(self, target_id: str, fields: dict[str, Any]) -> None:
        cols, vals = [], []
        for k, v in fields.items():
            if k == "stripped":
                v = as_int_bool(v)
            elif k == "mitigations":
                k, v = "mitigations_json", dumps(v)
            cols.append(f"{k}=?")
            vals.append(v)
        if not cols:
            return
        vals.append(target_id)
        self.conn.execute(f"UPDATE target SET {','.join(cols)} WHERE id=?", vals)

    def update_triage(self, target_id: str, **fields: Any) -> None:
        self._update_fields(target_id, fields)

    def delete(self, target_id: str) -> bool:
        """Remove a target and everything derived from it, atomically.

        Row cascades (ON DELETE CASCADE) take out its functions, call edges, string refs,
        findings, dyn results, PoCs, runs, run-artifact links, and run events. Component
        edges reference targets by plain id (no FK), so any edge touching this target is
        deleted explicitly here -- keeping the System Map consistent. Content-addressed
        artifact blobs are shared/dedup'd and are intentionally left in the store.
        """
        if self.get(target_id) is None:
            return False
        with transaction(self.conn):
            self.conn.execute(
                "DELETE FROM component_edge WHERE src_target=? OR dst_target=?",
                (target_id, target_id))
            self.conn.execute("DELETE FROM target WHERE id=?", (target_id,))
        return True

    def get(self, target_id: str) -> Optional[Target]:
        r = self.conn.execute("SELECT * FROM target WHERE id=?", (target_id,)).fetchone()
        return self._row(r) if r else None

    def get_by_hash(self, case_id: str, sha256: str) -> Optional[Target]:
        r = self.conn.execute("SELECT * FROM target WHERE case_id=? AND sha256=?",
                              (case_id, sha256)).fetchone()
        return self._row(r) if r else None

    def list_by_case(self, case_id: str) -> list[Target]:
        rows = self.conn.execute(
            "SELECT * FROM target WHERE case_id=? ORDER BY ingested_at DESC", (case_id,)
        ).fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(r: sqlite3.Row) -> Target:
        return Target(
            id=r["id"], case_id=r["case_id"], filename=r["filename"], sha256=r["sha256"],
            ingested_at=r["ingested_at"], md5=r["md5"], sha1=r["sha1"], size=r["size"],
            file_type=r["file_type"], arch=r["arch"], bits=r["bits"],
            endianness=r["endianness"], linking=r["linking"], stripped=as_bool(r["stripped"]),
            mitigations=loads(r["mitigations_json"]), entropy=r["entropy"],
        )


# ----------------------------------------------------------------------- Artifact (DM-14)
class ArtifactDAO(BaseDAO):
    def register(self, sha256: str, case_id: str, kind: str, rel_path: str,
                 size: Optional[int] = None, meta: Optional[dict] = None) -> Artifact:
        """Idempotent by sha256 (content identity)."""
        a = Artifact(sha256=sha256, case_id=case_id, kind=kind, rel_path=rel_path,
                     created_at=_now(), size=size, meta=meta)
        self.conn.execute(
            "INSERT INTO artifact(sha256,case_id,kind,rel_path,size,meta_json,created_at) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(sha256) DO NOTHING",
            (a.sha256, a.case_id, a.kind, a.rel_path, a.size, dumps(a.meta), a.created_at),
        )
        return self.get(sha256)  # type: ignore[return-value]

    def get(self, sha256: str) -> Optional[Artifact]:
        r = self.conn.execute("SELECT * FROM artifact WHERE sha256=?", (sha256,)).fetchone()
        return self._row(r) if r else None

    def list_by_case(self, case_id: str) -> list[Artifact]:
        rows = self.conn.execute("SELECT * FROM artifact WHERE case_id=?", (case_id,)).fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(r: sqlite3.Row) -> Artifact:
        return Artifact(sha256=r["sha256"], case_id=r["case_id"], kind=r["kind"],
                        rel_path=r["rel_path"], created_at=r["created_at"], size=r["size"],
                        meta=loads(r["meta_json"]))


# -------------------------------------------------------------------- RunArtifact (DM-14)
class RunArtifactDAO(BaseDAO):
    def link(self, run_id: str, artifact_sha256: str, role: str) -> RunArtifact:
        if role not in ARTIFACT_ROLES:
            raise ValueError(f"invalid role {role!r}; expected one of {sorted(ARTIFACT_ROLES)}")
        self.conn.execute(
            "INSERT INTO run_artifact(run_id,artifact_sha256,role) VALUES(?,?,?) "
            "ON CONFLICT(run_id,artifact_sha256,role) DO NOTHING",
            (run_id, artifact_sha256, role),
        )
        return RunArtifact(run_id=run_id, artifact_sha256=artifact_sha256, role=role)

    def list_by_run(self, run_id: str) -> list[RunArtifact]:
        rows = self.conn.execute("SELECT * FROM run_artifact WHERE run_id=?", (run_id,)).fetchall()
        return [RunArtifact(run_id=r["run_id"], artifact_sha256=r["artifact_sha256"],
                            role=r["role"]) for r in rows]


# --------------------------------------------------------------------- AnalysisRun (DM-13)
class AnalysisRunDAO(BaseDAO):
    def create(self, case_id: str, stage: str, *, target_id: Optional[str] = None,
               status: str = "queued", params: Optional[dict] = None,
               tool: Optional[str] = None, tool_version: Optional[str] = None,
               cache_key: Optional[str] = None, priority: int = 100,
               resource_class: str = "quick", max_attempts: int = 1) -> AnalysisRun:
        if status not in RUN_STATUSES:
            raise ValueError(f"invalid status {status!r}")
        run = AnalysisRun(id=new_id(), case_id=case_id, stage=stage, status=status,
                          created_at=_now(), target_id=target_id, params=params or {},
                          tool=tool, tool_version=tool_version, cache_key=cache_key,
                          priority=priority, resource_class=resource_class,
                          max_attempts=max_attempts)
        self.conn.execute(
            "INSERT INTO analysis_run(id,case_id,target_id,stage,status,params_json,"
            "tool,tool_version,cache_key,error,started_at,ended_at,created_at,"
            "priority,resource_class,max_attempts) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run.id, run.case_id, run.target_id, run.stage, run.status, dumps(run.params),
             run.tool, run.tool_version, run.cache_key, None, None, None, run.created_at,
             run.priority, run.resource_class, run.max_attempts),
        )
        return run

    def set_status(self, run_id: str, status: str, *, error: Optional[str] = None,
                   started_at: Optional[int] = None, ended_at: Optional[int] = None) -> None:
        if status not in RUN_STATUSES:
            raise ValueError(f"invalid status {status!r}")
        self.conn.execute(
            "UPDATE analysis_run SET status=?, error=COALESCE(?,error), "
            "started_at=COALESCE(?,started_at), ended_at=COALESCE(?,ended_at) WHERE id=?",
            (status, error, started_at, ended_at, run_id),
        )

    def get(self, run_id: str) -> Optional[AnalysisRun]:
        r = self.conn.execute("SELECT * FROM analysis_run WHERE id=?", (run_id,)).fetchone()
        return self._row(r) if r else None

    def list_by_case(self, case_id: str) -> list[AnalysisRun]:
        rows = self.conn.execute(
            "SELECT * FROM analysis_run WHERE case_id=? ORDER BY created_at DESC", (case_id,)
        ).fetchall()
        return [self._row(r) for r in rows]

    def find_cached(self, cache_key: str) -> Optional[AnalysisRun]:
        """A prior successful run with this cache key (for the result cache, JE-17)."""
        r = self.conn.execute(
            "SELECT * FROM analysis_run WHERE cache_key=? AND status='done' "
            "ORDER BY ended_at DESC LIMIT 1", (cache_key,)
        ).fetchone()
        return self._row(r) if r else None

    @staticmethod
    def _row(r: sqlite3.Row) -> AnalysisRun:
        return AnalysisRun(
            id=r["id"], case_id=r["case_id"], stage=r["stage"], status=r["status"],
            created_at=r["created_at"], target_id=r["target_id"],
            params=loads(r["params_json"]) or {}, tool=r["tool"],
            tool_version=r["tool_version"], cache_key=r["cache_key"], error=r["error"],
            started_at=r["started_at"], ended_at=r["ended_at"],
            claimed_by=r["claimed_by"], lease_expires_at=r["lease_expires_at"],
            heartbeat_at=r["heartbeat_at"], attempts=r["attempts"],
            max_attempts=r["max_attempts"], priority=r["priority"],
            resource_class=r["resource_class"], cancel_requested=bool(r["cancel_requested"]),
        )


# --------------------------------------------------------------------------- Event (DM-15)
class EventDAO(BaseDAO):
    def append(self, type: str, level: str = "info", *, case_id: Optional[str] = None,
               run_id: Optional[str] = None, payload: Optional[dict] = None,
               ts: Optional[int] = None) -> Event:
        ev = Event(case_id=case_id, run_id=run_id, ts=ts or _now(), level=level,
                   type=type, payload=payload)
        cur = self.conn.execute(
            "INSERT INTO event(case_id,run_id,ts,level,type,payload_json) VALUES(?,?,?,?,?,?)",
            (ev.case_id, ev.run_id, ev.ts, ev.level, ev.type, dumps(ev.payload)),
        )
        if cur.lastrowid is None:                  # AUTOINCREMENT always assigns one
            raise RuntimeError("event insert produced no rowid")
        ev.id = int(cur.lastrowid)
        return ev

    def list(self, *, case_id: Optional[str] = None, run_id: Optional[str] = None,
             after_id: int = 0, limit: int = 100) -> list[Event]:
        """Cursor pagination by monotonic id (feeds the UI log panel + WS backfill)."""
        clauses: list[str] = ["id > ?"]
        params: list[Any] = [after_id]
        if case_id is not None:
            clauses.append("case_id = ?"); params.append(case_id)
        if run_id is not None:
            clauses.append("run_id = ?"); params.append(run_id)
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM event WHERE {' AND '.join(clauses)} ORDER BY id ASC LIMIT ?",
            params,
        ).fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(r: sqlite3.Row) -> Event:
        return Event(id=r["id"], case_id=r["case_id"], run_id=r["run_id"], ts=r["ts"],
                     level=r["level"], type=r["type"], payload=loads(r["payload_json"]))


# --------------------------------------------------------------------- Function (Phase 1)
def _frame_blob(f: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Fold the decompiler-recovered prototype details + stack frame into one blob:
    frame geometry + vars, plus params / calling_convention / thunk / varargs."""
    if not f.get("frame") and not f.get("params"):
        return None
    blob = dict(f.get("frame") or {})
    blob["params"] = f.get("params") or []
    blob["calling_convention"] = f.get("calling_convention") or ""
    blob["thunk"] = bool(f.get("thunk"))
    blob["varargs"] = bool(f.get("varargs"))
    return blob


class FunctionDAO(BaseDAO):
    def replace_for_target(self, target_id: str, funcs: list[dict]) -> int:
        """Replace the target's function set (re-disassembly overwrites).

        Each func dict may carry: addr, name, size, decompiled, blocks, edges, `cfg`
        (the per-function CFG + P-Code IR, stored as ir_json), `signature`, and the
        stack-frame layout (params + calling_convention + thunk/varargs + frame geometry
        + `frame`.vars), collected into frame_json.
        """
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("DELETE FROM function WHERE target_id=?", (target_id,))
            now = _now()
            for f in funcs:
                self.conn.execute(
                    "INSERT INTO function(id,target_id,addr,name,size,decompiled,"
                    "blocks,edges,ir_json,signature,frame_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (new_id(), target_id, f.get("addr", ""), f.get("name"), f.get("size"),
                     f.get("decompiled"), f.get("blocks"), f.get("edges"),
                     dumps(f.get("cfg")), f.get("signature"), dumps(_frame_blob(f)), now))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return len(funcs)

    def list_by_target(self, target_id: str) -> list[Function]:
        rows = self.conn.execute(
            "SELECT id,target_id,addr,name,size,blocks,edges,signature,created_at "
            "FROM function WHERE target_id=? ORDER BY addr", (target_id,)
        ).fetchall()
        return [Function(id=r["id"], target_id=r["target_id"], addr=r["addr"],
                         created_at=r["created_at"], name=r["name"], size=r["size"],
                         blocks=r["blocks"], edges=r["edges"], signature=r["signature"])
                for r in rows]

    def get(self, func_id: str) -> Optional[Function]:
        r = self.conn.execute("SELECT * FROM function WHERE id=?", (func_id,)).fetchone()
        if not r:
            return None
        return Function(id=r["id"], target_id=r["target_id"], addr=r["addr"],
                        created_at=r["created_at"], name=r["name"], size=r["size"],
                        decompiled=r["decompiled"], blocks=r["blocks"], edges=r["edges"],
                        signature=r["signature"], frame=loads(r["frame_json"]),
                        ir=loads(r["ir_json"]))

    def count_by_target(self, target_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM function WHERE target_id=?",
                              (target_id,)).fetchone()
        return int(r["c"])


# ------------------------------------------------------------------- CallEdge (Phase 1)
class CallEdgeDAO(BaseDAO):
    def replace_for_target(self, target_id: str, edges: list[dict]) -> int:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("DELETE FROM call_edge WHERE target_id=?", (target_id,))
            now = _now()
            for e in edges:
                self.conn.execute(
                    "INSERT INTO call_edge(id,target_id,src_addr,site_addr,dst_addr,"
                    "dst_name,external,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (new_id(), target_id, e.get("src_addr"), e.get("site_addr"),
                     e.get("dst_addr"), e.get("dst_name"), as_int_bool(e.get("external")), now))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return len(edges)

    def list_by_target(self, target_id: str) -> list[CallEdge]:
        rows = self.conn.execute(
            "SELECT * FROM call_edge WHERE target_id=? ORDER BY src_addr, site_addr",
            (target_id,)).fetchall()
        return [self._row(r) for r in rows]

    def callees_of(self, target_id: str, src_addr: str) -> list[CallEdge]:
        rows = self.conn.execute(
            "SELECT * FROM call_edge WHERE target_id=? AND src_addr=? ORDER BY site_addr",
            (target_id, src_addr)).fetchall()
        return [self._row(r) for r in rows]

    def callers_of(self, target_id: str, dst_addr: str) -> list[CallEdge]:
        rows = self.conn.execute(
            "SELECT * FROM call_edge WHERE target_id=? AND dst_addr=? ORDER BY src_addr",
            (target_id, dst_addr)).fetchall()
        return [self._row(r) for r in rows]

    def calls_to_name(self, target_id: str, dst_name: str) -> list[CallEdge]:
        """Call sites to a named callee (e.g. dangerous-API sinks like strcpy)."""
        rows = self.conn.execute(
            "SELECT * FROM call_edge WHERE target_id=? AND dst_name=?",
            (target_id, dst_name)).fetchall()
        return [self._row(r) for r in rows]

    def count_by_target(self, target_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM call_edge WHERE target_id=?",
                              (target_id,)).fetchone()
        return int(r["c"])

    @staticmethod
    def _row(r: sqlite3.Row) -> CallEdge:
        return CallEdge(id=r["id"], target_id=r["target_id"], created_at=r["created_at"],
                        src_addr=r["src_addr"], site_addr=r["site_addr"],
                        dst_addr=r["dst_addr"], dst_name=r["dst_name"],
                        external=as_bool(r["external"]))


# ------------------------------------------------------------------ StringRef (Phase 1)
class StringDAO(BaseDAO):
    def replace_for_target(self, target_id: str, strings: list[dict]) -> int:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("DELETE FROM string_ref WHERE target_id=?", (target_id,))
            now = _now()
            for s in strings:
                self.conn.execute(
                    "INSERT INTO string_ref(id,target_id,addr,value,xrefs_json,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (new_id(), target_id, s.get("addr", ""), s.get("value"),
                     dumps(s.get("xrefs")), now))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return len(strings)

    def list_by_target(self, target_id: str, limit: int = 2000) -> list[StringRef]:
        rows = self.conn.execute(
            "SELECT * FROM string_ref WHERE target_id=? ORDER BY addr LIMIT ?",
            (target_id, limit)).fetchall()
        return [StringRef(id=r["id"], target_id=r["target_id"], addr=r["addr"],
                          created_at=r["created_at"], value=r["value"],
                          xrefs=loads(r["xrefs_json"])) for r in rows]

    def count_by_target(self, target_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM string_ref WHERE target_id=?",
                              (target_id,)).fetchone()
        return int(r["c"])


# -------------------------------------------------------------------- Finding (Phase 3)
def _rank(seq: Sequence[str], val: Optional[str], default: int = 0) -> int:
    try:
        return seq.index(val)
    except ValueError:
        return default


class FindingDAO(BaseDAO):
    def upsert(self, target_id: str, case_id: str, c: dict) -> None:
        """Insert a candidate, or MERGE into the existing finding with the same dedup_key.

        Merge = union of evidence, and take the *higher* state/severity/confidence. This is
        how the confidence lifecycle advances when multiple channels agree (doc 05).

        A finding is a DEFECT; each occurrence is recorded as a SITE against it (see the
        finding_site migration). `function_addr`/`site_addr` on the finding row stay as the
        first site seen, so existing consumers keep working.
        """
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            now = _now()
            key = c["dedup_key"]
            row = self.conn.execute(
                "SELECT * FROM finding WHERE target_id=? AND dedup_key=?",
                (target_id, key)).fetchone()
            ev_new = c.get("evidence", []) or []
            if row:
                evidence = loads(row["evidence_json"]) or []
                seen = {(e.get("channel"), e.get("detail")) for e in evidence}
                for e in ev_new:
                    if (e.get("channel"), e.get("detail")) not in seen:
                        evidence.append(e)
                state = FINDING_STATES[max(_rank(FINDING_STATES, row["state"]),
                                           _rank(FINDING_STATES, c.get("state", "candidate")))]
                severity = SEVERITIES[max(_rank(SEVERITIES, row["severity"]),
                                          _rank(SEVERITIES, c.get("severity", "info")))]
                confidence = max(row["confidence"] or 0.0, c.get("confidence", 0.0))
                self.conn.execute(
                    "UPDATE finding SET state=?, severity=?, confidence=?, evidence_json=?, "
                    "detector=?, updated_at=? WHERE id=?",
                    (state, severity, confidence, dumps(evidence), c.get("detector"),
                     now, row["id"]))
            else:
                self.conn.execute(
                    "INSERT INTO finding(id,target_id,case_id,cwe,title,severity,state,"
                    "confidence,function_addr,site_addr,detector,dedup_key,evidence_json,"
                    "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (new_id(), target_id, case_id, c.get("cwe"), c.get("title"),
                     c.get("severity", "info"), c.get("state", "candidate"),
                     c.get("confidence", 0.0), c.get("function_addr"), c.get("site_addr"),
                     c.get("detector"), key, dumps(ev_new), now, now))
            fid = self.conn.execute(
                "SELECT id FROM finding WHERE target_id=? AND dedup_key=?",
                (target_id, key)).fetchone()["id"]
            if c.get("function_addr") or c.get("site_addr"):
                self.conn.execute(
                    "INSERT OR IGNORE INTO finding_site(id,finding_id,function_addr,"
                    "site_addr,detail,created_at) VALUES(?,?,?,?,?,?)",
                    (new_id(), fid, c.get("function_addr"), c.get("site_addr"),
                     c.get("site_detail"), now))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise

    def sites(self, finding_id: str) -> list[dict]:
        """Every place this defect occurs, oldest first."""
        rows = self.conn.execute(
            "SELECT function_addr, site_addr, detail FROM finding_site "
            "WHERE finding_id=? ORDER BY created_at, rowid", (finding_id,)).fetchall()
        return [{"function_addr": r["function_addr"], "site_addr": r["site_addr"],
                 "detail": r["detail"]} for r in rows]

    def site_counts(self, target_id: str) -> dict:
        """finding id -> number of recorded sites, for the whole target in one query."""
        rows = self.conn.execute(
            "SELECT f.id AS fid, COUNT(s.id) AS n FROM finding f "
            "LEFT JOIN finding_site s ON s.finding_id = f.id "
            "WHERE f.target_id=? GROUP BY f.id", (target_id,)).fetchall()
        return {r["fid"]: int(r["n"]) for r in rows}

    def list_by_target(self, target_id: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM finding WHERE target_id=? ORDER BY confidence DESC, severity DESC",
            (target_id,)).fetchall()
        return [self._row(r) for r in rows]

    def list_by_case(self, case_id: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM finding WHERE case_id=? ORDER BY confidence DESC", (case_id,)
        ).fetchall()
        return [self._row(r) for r in rows]

    def get(self, finding_id: str) -> Optional[Finding]:
        r = self.conn.execute("SELECT * FROM finding WHERE id=?", (finding_id,)).fetchone()
        return self._row(r) if r else None

    def id_for_dedup(self, target_id: str, dedup_key: str) -> Optional[str]:
        r = self.conn.execute("SELECT id FROM finding WHERE target_id=? AND dedup_key=?",
                              (target_id, dedup_key)).fetchone()
        return r["id"] if r else None

    def counts_by_state(self, target_id: str) -> dict:
        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS c FROM finding WHERE target_id=? GROUP BY state",
            (target_id,)).fetchall()
        return {r["state"]: int(r["c"]) for r in rows}

    def count_by_target(self, target_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM finding WHERE target_id=?",
                              (target_id,)).fetchone()
        return int(r["c"])

    @staticmethod
    def _row(r: sqlite3.Row) -> Finding:
        return Finding(id=r["id"], target_id=r["target_id"], case_id=r["case_id"],
                       dedup_key=r["dedup_key"], created_at=r["created_at"],
                       updated_at=r["updated_at"], cwe=r["cwe"], title=r["title"],
                       severity=r["severity"], state=r["state"], confidence=r["confidence"],
                       function_addr=r["function_addr"], site_addr=r["site_addr"],
                       detector=r["detector"], evidence=loads(r["evidence_json"]) or [])


# ------------------------------------------------------------------ DynResult (Phase 4)
class DynResultDAO(BaseDAO):
    def insert(self, target_id: str, case_id: str, *, run_id: Optional[str] = None,
               input_sha: Optional[str] = None,
               input_mode: Optional[str] = None, argv: Optional[list] = None,
               exit_code: Optional[int] = None, signal: Optional[int] = None,
               signal_name: Optional[str] = None, crashed: bool = False,
               timed_out: bool = False, isolation: Optional[str] = None,
               duration_ms: Optional[int] = None, stdout_sha: Optional[str] = None,
               stderr_sha: Optional[str] = None, note: Optional[str] = None) -> str:
        rid = new_id()
        self.conn.execute(
            "INSERT INTO dyn_result(id,target_id,case_id,run_id,input_sha,input_mode,argv,"
            "exit_code,signal,signal_name,crashed,timed_out,isolation,duration_ms,"
            "stdout_sha,stderr_sha,note,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, target_id, case_id, run_id, input_sha, input_mode, dumps(argv),
             exit_code, signal, signal_name, as_int_bool(crashed), as_int_bool(timed_out),
             isolation, duration_ms, stdout_sha, stderr_sha, note, _now()))
        return rid

    def list_by_target(self, target_id: str) -> list[DynResult]:
        rows = self.conn.execute(
            "SELECT * FROM dyn_result WHERE target_id=? ORDER BY created_at DESC",
            (target_id,)).fetchall()
        return [self._row(r) for r in rows]

    def count_by_target(self, target_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM dyn_result WHERE target_id=?",
                              (target_id,)).fetchone()
        return int(r["c"])

    @staticmethod
    def _row(r: sqlite3.Row) -> DynResult:
        return DynResult(id=r["id"], target_id=r["target_id"], case_id=r["case_id"],
                         created_at=r["created_at"], run_id=r["run_id"],
                         input_sha=r["input_sha"], input_mode=r["input_mode"],
                         argv=loads(r["argv"]), exit_code=r["exit_code"], signal=r["signal"],
                         signal_name=r["signal_name"], crashed=as_flag(r["crashed"]),
                         timed_out=as_flag(r["timed_out"]), isolation=r["isolation"],
                         duration_ms=r["duration_ms"], stdout_sha=r["stdout_sha"],
                         stderr_sha=r["stderr_sha"], note=r["note"])


# ------------------------------------------------------------------------ Poc (Phase 6)
class PocDAO(BaseDAO):
    def insert(self, target_id: str, case_id: str, *, finding_id: Optional[str] = None,
               level: Optional[str] = None, verified: bool = False,
               signal_name: Optional[str] = None, input_sha: Optional[str] = None,
               bundle_sha: Optional[str] = None) -> str:
        rid = new_id()
        self.conn.execute(
            "INSERT INTO poc(id,target_id,case_id,finding_id,level,verified,signal_name,"
            "input_sha,bundle_sha,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, target_id, case_id, finding_id, level, as_int_bool(verified),
             signal_name, input_sha, bundle_sha, _now()))
        return rid

    def set_finding(self, poc_id: str, finding_id: str) -> None:
        self.conn.execute("UPDATE poc SET finding_id=? WHERE id=?", (finding_id, poc_id))
        self.conn.commit()

    def list_by_target(self, target_id: str) -> list[Poc]:
        rows = self.conn.execute(
            "SELECT * FROM poc WHERE target_id=? ORDER BY created_at DESC", (target_id,)
        ).fetchall()
        return [self._row(r) for r in rows]

    def count_by_target(self, target_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM poc WHERE target_id=?",
                              (target_id,)).fetchone()
        return int(r["c"])

    @staticmethod
    def _row(r: sqlite3.Row) -> Poc:
        return Poc(id=r["id"], target_id=r["target_id"], case_id=r["case_id"],
                   created_at=r["created_at"], finding_id=r["finding_id"], level=r["level"],
                   verified=as_flag(r["verified"]), signal_name=r["signal_name"],
                   input_sha=r["input_sha"], bundle_sha=r["bundle_sha"])


# ------------------------------------------------------------ ComponentEdge (Phase 8)
class ComponentEdgeDAO(BaseDAO):
    def upsert(self, case_id: str, src_target: str, dst_target: str, *, kind: str,
               symbol: Optional[str] = None, detail: Optional[str] = None) -> None:
        """Insert an edge, or update its detail if the (case,src,dst,kind,symbol) exists."""
        self.conn.execute(
            "INSERT INTO component_edge(id,case_id,src_target,dst_target,kind,symbol,"
            "detail,created_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(case_id,src_target,dst_target,kind,symbol) "
            "DO UPDATE SET detail=excluded.detail",
            (new_id(), case_id, src_target, dst_target, kind, symbol, detail, _now()))

    def list_by_case(self, case_id: str) -> list[ComponentEdge]:
        rows = self.conn.execute(
            "SELECT * FROM component_edge WHERE case_id=? ORDER BY kind, symbol", (case_id,)
        ).fetchall()
        return [self._row(r) for r in rows]

    def clear_case(self, case_id: str, kind: Optional[str] = None) -> None:
        if kind:
            self.conn.execute("DELETE FROM component_edge WHERE case_id=? AND kind=?",
                              (case_id, kind))
        else:
            self.conn.execute("DELETE FROM component_edge WHERE case_id=?", (case_id,))

    def count_by_case(self, case_id: str) -> int:
        r = self.conn.execute("SELECT COUNT(*) AS c FROM component_edge WHERE case_id=?",
                              (case_id,)).fetchone()
        return int(r["c"])

    @staticmethod
    def _row(r: sqlite3.Row) -> ComponentEdge:
        return ComponentEdge(id=r["id"], case_id=r["case_id"], src_target=r["src_target"],
                             dst_target=r["dst_target"], created_at=r["created_at"],
                             kind=r["kind"], symbol=r["symbol"], detail=r["detail"])
