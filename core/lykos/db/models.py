"""Typed dataclass models for the Phase 0 entities (DM-00 decision: no ORM).

JSON columns are exposed as dicts here; the DAO layer (de)serializes them. Booleans
(e.g. Target.stripped) are stored as 0/1 in SQLite and mapped here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Run status lifecycle (base set; the job engine's state machine JE-01 governs transitions).
RUN_STATUSES = frozenset({"queued", "running", "done", "error", "cancelled"})
ARTIFACT_ROLES = frozenset({"input", "output"})

# Finding confidence lifecycle + severity (ordered low->high for merge/ranking).
FINDING_STATES = ["candidate", "corroborated", "confirmed", "poc-backed"]
SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Case:
    id: str
    name: str
    created_at: int
    notes: Optional[str] = None
    engagement_ref: Optional[str] = None


@dataclass
class Target:
    id: str
    case_id: str
    filename: str
    sha256: str
    ingested_at: int
    md5: Optional[str] = None
    sha1: Optional[str] = None
    size: Optional[int] = None
    file_type: Optional[str] = None
    arch: Optional[str] = None
    bits: Optional[int] = None
    endianness: Optional[str] = None
    linking: Optional[str] = None
    stripped: Optional[bool] = None
    mitigations: Optional[dict[str, Any]] = None
    entropy: Optional[float] = None
    # {path-relative-to-binary: content-sha256} for companion files the target needs to RUN
    # (a bundled loader / libc / data file). None for an ordinary standalone binary.
    deps: Optional[dict[str, str]] = None


@dataclass
class Artifact:
    sha256: str
    case_id: str
    kind: str
    rel_path: str
    created_at: int
    size: Optional[int] = None
    meta: Optional[dict[str, Any]] = None


@dataclass
class AnalysisRun:
    id: str
    case_id: str
    stage: str
    status: str
    created_at: int
    target_id: Optional[str] = None
    params: dict[str, Any] = field(default_factory=dict)
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    cache_key: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[int] = None
    ended_at: Optional[int] = None
    # queue columns (JE-00)
    claimed_by: Optional[str] = None
    lease_expires_at: Optional[int] = None
    heartbeat_at: Optional[int] = None
    attempts: int = 0
    max_attempts: int = 1
    priority: int = 100
    resource_class: str = "quick"
    cancel_requested: bool = False


@dataclass
class RunArtifact:
    run_id: str
    artifact_sha256: str
    role: str


@dataclass
class Function:
    id: str
    target_id: str
    addr: str
    created_at: int
    name: Optional[str] = None
    size: Optional[int] = None
    decompiled: Optional[str] = None
    blocks: Optional[int] = None          # CFG basic-block count
    edges: Optional[int] = None           # CFG edge count
    signature: Optional[str] = None       # recovered prototype (light: shown in the list)
    # frame: {frame_size, local_size, param_size, ret_offset,
    #         calling_convention, thunk, varargs, params:[{name,type,size}],
    #         vars:[{name, offset, size, type, is_buffer}]}  (heavy: full view only)
    frame: Optional[dict[str, Any]] = None
    # IR: {"blocks": [{addr, instructions:[{addr, text, pcode:[...]}], succ:[...]}]}
    ir: Optional[dict[str, Any]] = None


@dataclass
class CallEdge:
    id: str
    target_id: str
    created_at: int
    src_addr: Optional[str] = None
    site_addr: Optional[str] = None
    dst_addr: Optional[str] = None
    dst_name: Optional[str] = None
    external: Optional[bool] = None


@dataclass
class StringRef:
    id: str
    target_id: str
    addr: str
    created_at: int
    value: Optional[str] = None
    xrefs: Optional[list] = None


@dataclass
class Finding:
    id: str
    target_id: str
    case_id: str
    dedup_key: str
    created_at: int
    updated_at: int
    cwe: Optional[str] = None
    title: Optional[str] = None
    severity: str = "info"
    state: str = "candidate"
    confidence: float = 0.0
    function_addr: Optional[str] = None
    site_addr: Optional[str] = None
    detector: Optional[str] = None
    evidence: list = field(default_factory=list)


@dataclass
class DynResult:
    id: str
    target_id: str
    case_id: str
    created_at: int
    run_id: Optional[str] = None
    input_sha: Optional[str] = None
    input_mode: Optional[str] = None
    argv: Optional[list] = None
    exit_code: Optional[int] = None
    signal: Optional[int] = None
    signal_name: Optional[str] = None
    crashed: bool = False
    timed_out: bool = False
    isolation: Optional[str] = None
    duration_ms: Optional[int] = None
    stdout_sha: Optional[str] = None
    stderr_sha: Optional[str] = None
    note: Optional[str] = None
    # Image-relative address of the faulting instruction, when the run was traced. Two crashes
    # at different addresses are different defects however alike their signals look.
    fault_pc: Optional[int] = None
    # Sanitizer-defect discriminator (ASan class + source) for a SIGABRT crash, so two distinct
    # sanitizer defects that both abort don't collapse to one signal-only bucket.
    defect_key: Optional[str] = None


@dataclass
class Poc:
    id: str
    target_id: str
    case_id: str
    created_at: int
    finding_id: Optional[str] = None
    level: Optional[str] = None
    verified: bool = False
    signal_name: Optional[str] = None
    input_sha: Optional[str] = None
    bundle_sha: Optional[str] = None


@dataclass
class ComponentEdge:
    id: str
    case_id: str
    src_target: str
    dst_target: str
    created_at: int
    kind: Optional[str] = None
    symbol: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class Event:
    case_id: Optional[str]
    run_id: Optional[str]
    ts: int
    level: str
    type: str
    payload: Optional[dict[str, Any]] = None
    id: Optional[int] = None  # assigned by autoincrement on insert
