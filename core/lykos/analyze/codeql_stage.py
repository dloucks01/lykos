"""`codeql` stage (F3, doc 60) -- CodeQL as the engine's CPG / interprocedural-dataflow backbone.

CodeQL is installed, air-gapped and non-AI; it gives precise interprocedural source->sink dataflow
(the taint our `srctaint` lite cannot) and a mature per-CWE query library. This stage makes its
results first-class findings in the case, carrying their dataflow path, instead of a hand-run on the
side. It is defensive: a missing `codeql` binary, an unbuildable DB, or a failed analysis degrade to
a skipped result, never a pipeline failure.

Flow: locate the source tree -> reuse a cached DB (keyed by the source sha) or build one best-effort
(autobuild, bounded) -> run the installed cpp security-extended suite -> ingest SARIF as findings.
The deterministic, always-tested core is `ingest_sarif`; the build/analyze steps are best-effort.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from ..db.dao import FindingDAO, TargetDAO
from ..jobs.registry import register_stage
from .source_lookup import source_project_for
from .grounding_stage import _source_root

_log = logging.getLogger(__name__)
CODEQL_STAGE = "codeql"
TOOL = "lykos.codeql"
TOOL_VERSION = "1"

#: SARIF rule.properties "problem.severity" / security-severity -> finding severity.
_SEV = {"error": "high", "warning": "medium", "recommendation": "low", "note": "low"}


def codeql_available() -> "str | None":
    return shutil.which("codeql")


def _rule_cwe(rule: dict) -> "str | None":
    for t in (rule.get("properties", {}) or {}).get("tags", []) or []:
        if "external/cwe/cwe-" in t:
            n = t.rsplit("-", 1)[-1]
            if n.isdigit():
                return f"CWE-{int(n)}"
    return None


def ingest_sarif(sarif_path: str, fdao, target, *, root: str = "") -> int:
    """Parse a CodeQL SARIF file and upsert each result as a finding (detector 'codeql'), carrying
    its rule, location and the dataflow path (codeFlows) in evidence. Deterministic + pure-ish (DB
    writes only). Returns the number of findings filed."""
    with open(sarif_path, "r", errors="ignore") as fh:
        sar = json.load(fh)
    n = 0
    for run in sar.get("runs", []):
        rules = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or ""
            rule = rules.get(rid, {})
            cwe = _rule_cwe(rule) or "CWE-000"
            msg = (res.get("message", {}) or {}).get("text", rid)
            sev = _SEV.get((rule.get("properties", {}) or {}).get("problem.severity", ""), "medium")
            loc = ""
            try:
                p = res["locations"][0]["physicalLocation"]
                uri = p["artifactLocation"]["uri"]
                line = p.get("region", {}).get("startLine", "")
                loc = f"{uri.split(root)[-1] if root else uri}:{line}"
            except Exception:                            # noqa: BLE001
                pass
            ev = [{"channel": "codeql", "detail": f"{rid} @ {loc}: {msg[:200]}"}]
            # the interprocedural dataflow path (source -> ... -> sink), CodeQL's key value-add.
            for cf in res.get("codeFlows", []) or []:
                steps = []
                for tf in cf.get("threadFlows", []) or []:
                    for st in tf.get("locations", []) or []:
                        t = (st.get("location", {}).get("message", {}) or {}).get("text")
                        pl = st.get("location", {}).get("physicalLocation", {})
                        ln = pl.get("region", {}).get("startLine", "")
                        u = pl.get("artifactLocation", {}).get("uri", "")
                        if u:
                            steps.append(f"{u.split('/')[-1]}:{ln}{(' '+t) if t else ''}")
                if steps:
                    ev.append({"channel": "codeql-dataflow", "detail": " -> ".join(steps[:12])})
            fdao.upsert(target.id, target.case_id, {
                "cwe": cwe, "title": f"[codeql] {rid}", "detector": "codeql",
                "severity": sev, "state": "candidate", "stage": CODEQL_STAGE,
                "dedup_key": f"codeql:{rid}:{loc}", "evidence": ev})
            n += 1
    return n


def _build_db(root: str, db: str, *, timeout: int = 1500) -> bool:
    """Best-effort CodeQL DB build via autobuild. True on success. Never raises."""
    try:
        r = subprocess.run(["codeql", "database", "create", db, "--language=cpp",
                            "--source-root", root, "--build-mode=autobuild", "--overwrite"],
                           capture_output=True, text=True, timeout=timeout)
        ok = r.returncode == 0 or os.path.isfile(os.path.join(db, "codeql-database.yml"))
        if not ok:
            # finalize a partial extraction so queries can still run on what compiled.
            subprocess.run(["codeql", "database", "finalize", db], capture_output=True,
                           text=True, timeout=300)
            ok = os.path.isfile(os.path.join(db, "codeql-database.yml"))
        return ok
    except Exception:                                    # noqa: BLE001
        _log.debug("codeql db build failed", exc_info=True)
        return False


def _suite() -> "str | None":
    import glob
    for pat in (os.path.expanduser("~/.codeql/packages/codeql/cpp-queries/*/codeql-suites/cpp-security-extended.qls"),
                "/opt/codeql/qlpacks/codeql/cpp-queries/*/codeql-suites/cpp-security-extended.qls"):
        hits = glob.glob(pat)
        if hits:
            return sorted(hits)[-1]
    return None


def codeql_stage(ctx) -> dict:
    target = TargetDAO(ctx.conn).get(ctx.target_id) if ctx.target_id else None
    if target is None:
        raise ValueError("codeql requires a target_id")
    if not codeql_available():
        return {"metrics": {"codeql": "skipped (codeql not installed)"}}
    if source_project_for(ctx.conn, target) is None:
        return {"metrics": {"codeql": "skipped (not a source project)"}}
    root = _source_root(ctx, target)
    if root is None:
        return {"metrics": {"codeql": "skipped (source tree unavailable)"}}
    root = str(root)
    db = str(ctx.scratch() / "codeql-db")
    sarif = str(ctx.scratch() / "codeql.sarif")
    reused = os.path.isfile(os.path.join(db, "codeql-database.yml"))
    if not reused and not _build_db(root, db):
        return {"metrics": {"codeql": "skipped (DB build failed/unbuildable)"}}
    suite = _suite()
    if not suite:
        return {"metrics": {"codeql": "skipped (no cpp query suite installed)"}}
    # run the installed suite PLUS lykos' custom per-CWE queries for the FreeRDP classes (gap 2):
    # wire->divisor and wire->unbounded-alloc, which model the interprocedural flows the default
    # suite does not. Passed as additional query specs; a custom-query failure must not sink the run.
    custom = os.path.join(os.path.dirname(__file__), "codeql_queries")
    specs = [suite] + ([custom] if os.path.isdir(custom) else [])
    try:
        r = subprocess.run(["codeql", "database", "analyze", db, *specs,
                            "--additional-packs", os.path.expanduser("~/.codeql/packages"),
                            "--format=sarifv2.1.0", "--output", sarif, "--threads=4"],
                           capture_output=True, text=True, timeout=1800)
        if r.returncode != 0 or not os.path.isfile(sarif):
            # retry with the suite alone (a custom query may not compile on this CodeQL version).
            r = subprocess.run(["codeql", "database", "analyze", db, suite,
                                "--format=sarifv2.1.0", "--output", sarif, "--threads=4"],
                               capture_output=True, text=True, timeout=1800)
            if r.returncode != 0 or not os.path.isfile(sarif):
                return {"metrics": {"codeql": f"skipped (analyze failed: {r.stderr[-120:]})"}}
    except Exception as e:                               # noqa: BLE001
        return {"metrics": {"codeql": f"skipped (analyze error: {e})"}}
    n = ingest_sarif(sarif, FindingDAO(ctx.conn), target, root=root.rstrip("/") + "/")
    return {"metrics": {"codeql_findings": n, "db_reused": reused, "suite": os.path.basename(suite),
                        "custom_queries": len([q for q in os.listdir(custom) if q.endswith(".ql")]) if os.path.isdir(custom) else 0}}


register_stage(CODEQL_STAGE, codeql_stage, resource_class="heavy",
               tool=TOOL, tool_version=TOOL_VERSION, timeout=3600)


def enqueue_codeql(queue, target, *, force: bool = True):
    return queue.enqueue(target.case_id, CODEQL_STAGE, target_id=target.id,
                         input_hashes=[target.sha256], tool=TOOL, tool_version=TOOL_VERSION,
                         resource_class="heavy", force=force)
