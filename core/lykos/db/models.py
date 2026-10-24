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

#: CWE classes where a working reproducer PROVES exploitable impact, so a severity the first
#: pattern detector guessed must not hold the finding down. This is the floor's real condition:
#: jhead's proven out-of-bounds read carried the `low` its pattern detector assigned, and the
#: one finding in the report with a verified PoC was badged below unproven advisories.
#:
#: Conditioning on STATE alone was too wide. A managed runtime's exception tables
#: (jvm/pyc/dotnet.EXCEPTION_CWE) deliberately rank an uncaught `FileNotFoundException` or
#: `IllegalStateException` at info/low -- a program that validates its input by throwing is
#: doing the right thing, and 42 of those 91 mappings say so in as many words -- yet every one
#: of them reproduces easily and so was promoted to `high`, burying the findings that matter.
#: That is the exact outcome those tables were written to avoid.
MEMORY_CORRUPTION_CWES = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
    "CWE-129", "CWE-131", "CWE-134", "CWE-190", "CWE-191", "CWE-193", "CWE-415", "CWE-416",
    "CWE-476", "CWE-590", "CWE-680", "CWE-761", "CWE-787", "CWE-788", "CWE-822", "CWE-823",
    "CWE-824", "CWE-825",
})

#: A NARROWER question, and the reason it is a second set: which of root_cause's classes are
#: specific enough to KEEP over a confirmed primitive's own label.
#:
#: `primitive_stage` relabels a reproduced crash once it has confirmed what the input can do
#: (instruction-pointer control, an arbitrary write, a controlled read) but defers to
#: root_cause's CWE where that is already a memory-corruption class, because root_cause read
#: the sanitizer/debugger report and is usually more precise. Reusing the severity-floor set
#: above for that silently widened the keep-list by seven classes, and two of them are the
#: exact mislabelling the deferral exists to prevent:
#:
#:   * CWE-476 (null-pointer dereference) -- measured on a service carved out of a SquashFS
#:     image: a stack smash left a NEAR-NULL return address, root_cause read the fault as a null
#:     deref, and a confirmed IP hijack at a known stack offset went out carrying a DoS-grade
#:     weakness id. A null deref CONTRADICTS a confirmed hijack; it must be replaced, not kept.
#:   * CWE-129 (improper index validation) names the input flaw, not the access, so it loses the
#:     one thing the primitive established.
#:   * CWE-131/134/190/191/680 are likewise CAUSES (a bad size calculation, a format string, an
#:     integer wrap) rather than the corruption the primitive has just demonstrated.
#:
#: They stay in the severity floor above, where the question is only "does a reproducer prove
#: impact for this family" -- and a reproduced null deref or integer wrap does.
OUTRANKS_PRIMITIVE_CWES = frozenset({
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127",
    "CWE-193", "CWE-415", "CWE-416", "CWE-590", "CWE-761", "CWE-787", "CWE-788", "CWE-822",
    "CWE-823", "CWE-824", "CWE-825",
})

#: Detectors that merely SPOT something in the image -- no execution, nothing demonstrated.
#: Everything that decides "has this been proven?" filters on this, so it is kept here beside
#: the states and severities rather than copied into each consumer.
#:
#: It used to be `{dangerous_api, detect_cwe, cwe_scan, source_sink_scan}` in two places, where
#: three of the four are STAGE names and can never match a finding's `detector` column -- so
#: the filter whose whole job is "detected is not demonstrated" enforced it for one detector
#: out of fourteen. Names below are the ones the detectors actually file under.
#:
#: Deliberately NOT listed, and each for a reason: `secret_poc` demonstrates by re-extracting
#: the credential (the extractability IS the defect, which is why it needs no crash);
#: `firmware_carve` and `unpack` report a structural fact about a container rather than a
#: candidate site; `cross_binary_taint` and `ipc_taint` were left out because this audit did
#: not establish whether they execute, and counting a demonstration as static would HIDE real
#: evidence -- the costlier mistake of the two.
STATIC_DETECTORS = frozenset({
    # detect/ -- pattern, frame and taint analysis over recovered code
    "dangerous_api", "stack_frame", "hardcoded_secrets", "weak_crypto", "weak_random",
    "insecure_tmp", "toctou", "toctou_race", "hardening", "tainted_deref",
    "int_overflow_check", "int_overflow_alloc", "scanf_bounded_overflow", "heap_fptr_call",
    "lang_sinks", "scriptscan", "pyc_scan",
    # detect/ -- the logic/auth detectors and static CWE-129, re-derived by detect/stage on every
    # run (its `_STATIC_DETECTORS`), so static by construction
    "unchecked_privdrop", "world_writable_perms", "privilege_drop_order", "format_string",
    "array_index",
    # detect/jvmdetect -- the constant pool, read directly
    "jvm_sink", "jvm_crypto", "jvm_tls",
    # fingerprint/ -- version matching and source/config scanning
    "cve_fingerprint", "cve_source", "embedded_config", "int_overflow", "uaf", "source_sink",
    # source pattern matching
    "weggli",
})


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
    # producing toolchain / source language (go, rust, c++, gcc, clang, ...), from triage.
    toolchain_hint: Optional[str] = None


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
