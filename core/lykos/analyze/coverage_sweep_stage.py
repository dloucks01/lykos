"""`coverage_sweep` stage -- wires the auditable CWE catalog + line-complete function sweep into the
pipeline, so a real run PROVES "every function examined, every CWE accounted for" instead of a
reviewer taking it on faith.

It resolves the case's source tree, runs `cwe_sweep.sweep_source` (every function x every static
pattern) and `cwe_catalog.completeness` (every named CWE has a declared method), and:
  * persists the full ledger as the stage's metrics (files parsed/skipped, functions examined,
    per-CWE candidate-site counts, catalog method breakdown) -- the report reads this;
  * files a finding ONLY for a genuine HOLE -- a source file that failed to parse (not one that was
    deliberately excluded as test/vendored), or a CWE named in lykos but missing from the catalog.
    A clean run files nothing: completeness is proven by SILENCE, and any regression surfaces as a
    tracked finding.

Pure/quick (string work only); it discovers candidate SITES and coverage HOLES, never confirms a
bug -- the confirmation ladder does that. stdlib + the catalog/sweep modules only.
"""
from __future__ import annotations

import io
import tarfile

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from . import cwe_sweep, cwe_catalog

try:
    from ..cwe import CWE_NAMES
except Exception:                                        # noqa: BLE001
    CWE_NAMES = {}

COVERAGE_STAGE = "coverage_sweep"
TOOL = "lykos.coverage"
TOOL_VERSION = "1"


def _source_root(ctx, target):
    """Extract the case's archived source tree (same approach as grounding_stage), or None."""
    proj = source_project_for(ctx.conn, target)
    if proj is None:
        return None
    root = ctx.scratch() / "coverage-src"
    if not root.exists():
        root.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(fileobj=io.BytesIO(ctx.content.path(proj.sha256).read_bytes()),
                              mode="r:gz") as tf:
                for mem in tf.getmembers():
                    if mem.isfile() and not mem.name.startswith("/") and ".." not in mem.name:
                        tf.extract(mem, root)
        except Exception:                                # noqa: BLE001
            return None
    return root


def coverage_sweep_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("coverage_sweep requires a target_id")
    root = _source_root(ctx, target)
    if root is None:
        return {"metrics": {"coverage_sweep": "no source project (binary target)"}}

    named = list(CWE_NAMES.keys())
    led = cwe_sweep.sweep_source(str(root), named_cwes=named)
    fd = FindingDAO(ctx.conn)

    # genuine holes: files skipped for a BAD reason (read/parse error), not deliberate exclusions.
    bad = [(p, r) for p, r in led.files_skipped if "excluded" not in r]
    for path, reason in bad[:200]:
        fd.upsert(target.id, target.case_id, {
            "cwe": "COVERAGE", "title": f"Coverage hole: source file not analyzed ({reason})",
            "severity": "low", "state": "candidate", "detector": "coverage_sweep",
            "dedup_key": f"coverage-hole:{path}", "stage": COVERAGE_STAGE,
            "evidence": [{"channel": "coverage", "detail": f"{path}: {reason}"}]})

    # catalog gaps: a CWE lykos names but the auditable catalog has no entry for.
    cat = led.catalog or {}
    for cwe in cat.get("missing", []):
        fd.upsert(target.id, target.case_id, {
            "cwe": cwe, "title": f"Catalog gap: {cwe} has no detection method declared",
            "severity": "low", "state": "candidate", "detector": "coverage_sweep",
            "dedup_key": f"catalog-gap:{cwe}", "stage": COVERAGE_STAGE,
            "evidence": [{"channel": "coverage", "detail": f"{cwe} named in lykos but absent from cwe_catalog"}]})

    bm = cat.get("by_method", {})
    return {"metrics": {
        "files_total": led.files_total,
        "files_parsed": led.files_parsed,
        "files_skipped": len(led.files_skipped),
        "coverage_holes": len(bad),
        "functions_examined": led.functions_examined,
        "static_detectors_run": len(cwe_sweep._static_cwes()),
        "catalog_entries": cat.get("total_catalog", len(cwe_catalog.CATALOG)),
        "cwes_named": len(named),
        "cwes_missing_from_catalog": len(cat.get("missing", [])),
        "catalog_methods": {k: len(v) for k, v in bm.items()},
        "candidate_sites_per_cwe": dict(sorted(led.per_cwe.items(), key=lambda kv: -kv[1])),
    }}


register_stage(COVERAGE_STAGE, coverage_sweep_stage, resource_class="quick",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=300)


def enqueue_coverage_sweep(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, COVERAGE_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="quick", force=force)
