"""Assemble a plain-dict report model from a case's stored data.

One model feeds every exporter (HTML/PDF/SARIF/JSON) so the formats never drift. The
model is JSON-serializable and self-contained: it embeds the reproducibility metadata
(tool + engine versions, input hashes) the report must carry (doc 08 §8.5, doc 12).
"""
from __future__ import annotations

import time
from typing import Any, Optional

from .. import __version__ as _lykos_version
from ..analyze.detect import catalog
from ..db.dao import (
    AnalysisRunDAO,
    DynResultDAO,
    FindingDAO,
    PocDAO,
    TargetDAO,
)
from ..db.models import FINDING_STATES, SEVERITIES

# Findings at or above this state are included by default (the "reportable" set:
# everything that cleared pure candidate). Callers can widen or narrow it.
DEFAULT_MIN_STATE = "candidate"

_MAX_EMBED_BUNDLE = 8 * 1024 * 1024   # cap ONE self-embedded PoC bundle at 8 MiB
# ...and the whole report at this, because the per-bundle cap says nothing about how many
# there are. A PoC bundle carries the target binary so it can reproduce standalone, which is
# the point of it -- 660 KB of a 694 KB jhead report was one bundle. Ten PoCs on that target
# would have produced a 7 MB page that a browser has to base64-decode before it renders.
_MAX_EMBED_TOTAL = 4 * 1024 * 1024


def _rank(order: list[str], value: Optional[str]) -> int:
    try:
        return order.index(value) if value else 0
    except ValueError:
        return 0


def _iso(ts: Optional[int]) -> Optional[str]:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _runtime(t) -> dict:
    """What this target RUNS ON, and what that means for the evidence in the report.

    A 47 KB report over a case holding a jar mentioned "Java" zero times and printed
    `Arch: jvm/64 big` -- placeholder fields from triage rendered as though they described a
    processor. A reader could not tell that a finding came from a managed runtime, nor why no
    L2/L3 appears for it, and "no exploit was produced" reads as a gap rather than as the
    runtime's own guarantee.
    """
    from ..analyze import capabilities as capmod
    ftype = (t.file_type or "").lower()
    if ftype in ("jar", "class"):
        return {
            "substrate": "jvm",
            "label": "Java (JVM)" + (" — JAR" if ftype == "jar" else " — class file"),
            "describes_cpu": False,
            "ceiling": "L1",
            "ceiling_why": (
                "The JVM checks every array access and owns the instruction pointer, so a "
                "defect surfaces as an uncaught exception that terminates the process -- "
                "denial of service -- and cannot be escalated to control-flow hijack. L1 (a "
                "verified, reproducible fault) is the ceiling this runtime supports; the "
                "absence of an L2 or L3 result is the runtime's guarantee, not a gap in the "
                "analysis."),
            "unavailable": capmod.unavailable_summary(t),
        }
    if ftype == "pe":
        return {"substrate": "windows", "label": "Windows PE", "describes_cpu": True,
                "ceiling": "L3", "ceiling_why": "",
                "unavailable": capmod.unavailable_summary(t)}
    return {"substrate": "native", "label": "Native machine code", "describes_cpu": True,
            "ceiling": "L3", "ceiling_why": "",
            "unavailable": capmod.unavailable_summary(t)}


def build_report(
    store,
    case_id: str,
    *,
    min_severity: Optional[str] = None,
    min_state: str = DEFAULT_MIN_STATE,
    states: Optional[list[str]] = None,
    finding_ids: Optional[list[str]] = None,
    embed_pocs: bool = False,
) -> dict[str, Any]:
    """Build the report model for one case.

    Filtering (all optional, AND-combined):
      * min_severity  -- drop findings below this severity
      * min_state     -- drop findings below this confidence state
      * states        -- keep only findings whose state is in this explicit set
      * finding_ids   -- keep only these findings (report-builder selection)
    `embed_pocs` base64-embeds each PoC bundle into the model so an HTML/JSON report
    is fully self-contained (bounded by _MAX_EMBED_BUNDLE per bundle).
    """
    conn = store.conn
    case = store.cases.get(case_id)
    if not case:
        raise KeyError(f"no case {case_id!r}")

    tdao = TargetDAO(conn)
    fdao = FindingDAO(conn)
    pdao = PocDAO(conn)
    ddao = DynResultDAO(conn)
    rdao = AnalysisRunDAO(conn)

    sel_ids = set(finding_ids) if finding_ids is not None else None
    sev_floor = _rank(SEVERITIES, min_severity) if min_severity else 0
    state_floor = _rank(FINDING_STATES, min_state)
    state_set = set(states) if states else None

    targets_out: list[dict] = []
    tot_findings = 0
    by_state: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    poc_levels: dict[str, int] = {}

    for t in tdao.list_by_case(case_id):
        pocs = pdao.list_by_target(t.id)
        pocs_by_finding: dict[str, list] = {}
        for p in pocs:
            pocs_by_finding.setdefault(p.finding_id or "", []).append(p)
        crashes = ddao.list_by_target(t.id)
        crash_by_input: dict[str, Any] = {}
        for d in crashes:
            if d.input_sha and d.input_sha not in crash_by_input:
                crash_by_input[d.input_sha] = d

        findings_out: list[dict] = []

        # one embed per distinct bundle, and a budget for the whole report

        embedded: set = set()

        budget = {"left": _MAX_EMBED_TOTAL}
        for f in fdao.list_by_target(t.id):
            if sel_ids is not None and f.id not in sel_ids:
                continue
            if _rank(SEVERITIES, f.severity) < sev_floor:
                continue
            if _rank(FINDING_STATES, f.state) < state_floor:
                continue
            if state_set is not None and f.state not in state_set:
                continue

            f_pocs = []
            f_crashes = []
            for p in pocs_by_finding.get(f.id, []):
                pd = {
                    "id": p.id, "level": p.level, "verified": p.verified,
                    "signal": p.signal_name, "input_sha": p.input_sha,
                    "bundle_sha": p.bundle_sha, "created_at": _iso(p.created_at),
                }
                if p.bundle_sha:
                    # Where to get it, in every mode. With embedding off the report showed a
                    # bare hash and nothing to do about it -- which is the same dead end as a
                    # bundle that was too large to embed.
                    pd["bundle_href"] = f"/artifacts/{p.bundle_sha}"
                if embed_pocs and p.bundle_sha:
                    # Each distinct bundle is embedded ONCE. Several findings can be backed by
                    # the same PoC -- jhead's crash backs two -- and embedding per finding
                    # duplicates the target binary for no gain.
                    if p.bundle_sha in embedded:
                        pd["bundle_same_as"] = p.bundle_sha
                    else:
                        b64 = _embed(store, p.bundle_sha, budget)
                        if b64:
                            pd["bundle_b64"] = b64
                            embedded.add(p.bundle_sha)
                            budget["left"] -= len(b64)

                f_pocs.append(pd)
                d = crash_by_input.get(p.input_sha)
                if d:
                    f_crashes.append(_crash_dict(d))

            findings_out.append({
                "id": f.id, "cwe": f.cwe, "cwe_name": catalog.name(f.cwe) if f.cwe else None,
                "title": f.title, "severity": f.severity, "state": f.state,
                "confidence": round(f.confidence or 0.0, 3),
                "function_addr": f.function_addr, "site_addr": f.site_addr,
                "detector": f.detector, "evidence": f.evidence or [],
                "pocs": f_pocs, "crashes": f_crashes,
                "created_at": _iso(f.created_at), "updated_at": _iso(f.updated_at),
            })
            tot_findings += 1
            by_state[f.state] = by_state.get(f.state, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            for p in f_pocs:
                if p.get("verified") and p.get("level"):
                    poc_levels[p["level"]] = poc_levels.get(p["level"], 0) + 1

        if findings_out or finding_ids is None:
            targets_out.append({
                "id": t.id, "filename": t.filename, "sha256": t.sha256, "md5": t.md5,
                "sha1": t.sha1, "size": t.size, "file_type": t.file_type, "arch": t.arch,
                "bits": t.bits, "endianness": t.endianness, "linking": t.linking,
                "stripped": t.stripped, "mitigations": t.mitigations or {},
                "runtime": _runtime(t),
                "entropy": t.entropy, "ingested_at": _iso(t.ingested_at),
                "findings": findings_out,
            })

    engines = _engines(rdao, case_id)

    return {
        "schema": "lykos.report/1",
        "generated_at": _iso(int(time.time())),
        "tool": {"name": "lykos", "version": _lykos_version},
        "engines": engines,
        "case": {
            "id": case.id, "name": case.name, "notes": case.notes,
            "engagement_ref": case.engagement_ref, "created_at": _iso(case.created_at),
        },
        "filters": {
            "min_severity": min_severity, "min_state": min_state,
            "states": sorted(state_set) if state_set else None,
            "finding_ids": sorted(sel_ids) if sel_ids is not None else None,
        },
        "summary": {
            "targets": len(targets_out),
            "findings": tot_findings,
            "by_state": {s: by_state.get(s, 0) for s in FINDING_STATES if by_state.get(s)},
            "by_severity": {s: by_severity.get(s, 0)
                            for s in reversed(SEVERITIES) if by_severity.get(s)},
            "confirmed": by_state.get("confirmed", 0) + by_state.get("poc-backed", 0),
            "poc_backed": by_state.get("poc-backed", 0),
            "poc_levels": poc_levels,
        },
        "targets": targets_out,
    }


def _crash_dict(d) -> dict:
    return {
        "id": d.id, "signal": d.signal_name, "exit_code": d.exit_code,
        "input_mode": d.input_mode, "input_sha": d.input_sha,
        "isolation": d.isolation, "duration_ms": d.duration_ms,
        "timed_out": d.timed_out, "note": d.note,
    }


def _engines(rdao, case_id: str) -> list[dict]:
    """Distinct (tool, version) pairs actually used in this case -- reproducibility."""
    seen: dict[tuple, dict] = {}
    for r in rdao.list_by_case(case_id):
        if r.tool:
            seen.setdefault((r.tool, r.tool_version), {
                "tool": r.tool, "version": r.tool_version,
            })
    return sorted(seen.values(), key=lambda e: (e["tool"], e["version"] or ""))


def _embed(store, sha: str, budget: Optional[dict] = None) -> Optional[str]:
    import base64
    try:
        if not store.content.exists(sha):
            return None
        data = store.content.get_bytes(sha)
    except OSError:
        return None
    if len(data) > _MAX_EMBED_BUNDLE:
        return None
    b64 = base64.b64encode(data).decode("ascii")
    if budget is not None and len(b64) > budget.get("left", 0):
        return None
    return b64
