"""The COVERAGE LEDGER -- the measurement that turns "are we at 100%?" into a number and a worklist.

Full coverage is an asymptote (undecidable in general), so the honest substitute is an account of
the gap along three axes, each with the GAPS surfaced as a to-do list:

  * CHECK coverage (axis B -- vuln classes): of the analysis checks lykos HAS, which ran on this case
    and which did not (and why), with the weakness classes each check covers. This answers "did we
    run every class of check we are capable of?" -- a check that never ran is a class never looked for.
  * WEAPONIZATION coverage (axis C): of the findings, how many reached a verified PoC or at least a
    corroborated recipe, and which are still bare candidates -- the weaponization worklist. The bar is
    "every finding gets a verified PoC OR a corroborated recipe", never "every finding reaches L3"
    (not soundly achievable); the ledger measures against that honest bar.
  * CODE coverage (axis A): per target, how much of the recovered code the search exercised, so a
    thin dynamic result is read as "little code reached" rather than "clean". The precise
    uncovered-function worklist deepens as harness synthesis / per-function symbolic execution land.

Pure and read-only: it reads the case's runs, findings and coverage and derives the ledger; it never
runs anything. stdlib-only.
"""
from __future__ import annotations

from typing import Any, Optional

from ..db.dao import AnalysisRunDAO, CallEdgeDAO, FindingDAO, FunctionDAO, TargetDAO

#: The analysis CHECKS lykos can perform, each tagged with the weakness classes it covers and its
#: kind. The stage NAMES are the registry's (a test pins that every name here still exists), so the
#: ledger's "what we can check" inventory cannot silently drift from the real pipeline. `classes` is
#: ["*"] for a general crash finder (it can surface any memory-safety class), [] for a stage that
#: confirms or weaponizes rather than discovers a class.
_CHECKS: list[dict] = [
    # ---- static discovery (source) ----
    {"stage": "source_sink_scan", "label": "Tainted sinks (command / format-string injection)",
     "classes": ["CWE-78", "CWE-134"], "kind": "static"},
    {"stage": "int_overflow_scan", "label": "Integer-overflow allocations",
     "classes": ["CWE-190"], "kind": "static"},
    {"stage": "uaf_scan", "label": "Use-after-free / double-free (source)",
     "classes": ["CWE-416", "CWE-415"], "kind": "static"},
    {"stage": "source_cve_scan", "label": "Dependency CVEs (known-vulnerable versions)",
     "classes": ["CWE-1395"], "kind": "static"},
    {"stage": "embedded_audit", "label": "Hardcoded secrets / embedded config",
     "classes": ["CWE-798"], "kind": "static"},
    {"stage": "weggli_scan", "label": "Weggli structural patterns", "classes": ["*"],
     "kind": "static"},
    {"stage": "variant_scan", "label": "Variant scan (patterns of a seed bug)", "classes": ["*"],
     "kind": "static"},
    # ---- static discovery (binary) ----
    {"stage": "detect_cwe", "label": "Binary static detectors",
     "classes": ["CWE-121", "CWE-122", "CWE-787", "CWE-125", "CWE-476", "CWE-134", "CWE-190",
                 "CWE-129"], "kind": "static"},
    {"stage": "oob_index", "label": "Out-of-bounds array index", "classes": ["CWE-125", "CWE-787"],
     "kind": "static"},
    {"stage": "cve_scan", "label": "Known-CVE fingerprint (binary)", "classes": ["CWE-1395"],
     "kind": "static"},
    # ---- dynamic oracles ----
    {"stage": "libfuzzer", "label": "In-process libFuzzer (ASan + UBSan)",
     "classes": ["CWE-121", "CWE-122", "CWE-416", "CWE-787", "CWE-125"], "kind": "dynamic"},
    {"stage": "heap_trace", "label": "Heap use-after-free / double-free trace",
     "classes": ["CWE-416", "CWE-415"], "kind": "dynamic"},
    {"stage": "heap_check", "label": "Heap guard-page overflow check",
     "classes": ["CWE-122", "CWE-787"], "kind": "dynamic"},
    {"stage": "mem_oracle", "label": "Uninitialised-memory oracle (MSan)", "classes": ["CWE-457"],
     "kind": "dynamic"},
    {"stage": "fuzz", "label": "Black-box fuzzing", "classes": ["*"], "kind": "dynamic"},
    {"stage": "coverage_fuzz", "label": "Coverage-guided fuzzing", "classes": ["*"],
     "kind": "dynamic"},
    {"stage": "directed_fuzz", "label": "Directed fuzzing", "classes": ["*"], "kind": "dynamic"},
    {"stage": "net_fuzz", "label": "Network-channel fuzzing", "classes": ["*"], "kind": "dynamic"},
    {"stage": "env_fuzz", "label": "Environment-channel fuzzing", "classes": ["*"],
     "kind": "dynamic"},
    {"stage": "boundary_fuzz", "label": "IPC-boundary fuzzing", "classes": ["*"], "kind": "dynamic"},
    {"stage": "concolic", "label": "Concolic / symbolic execution", "classes": ["*"],
     "kind": "dynamic"},
    {"stage": "dynamic_taint", "label": "Dynamic taint tracking", "classes": ["*"], "kind": "dynamic"},
    {"stage": "uc_symbolic", "label": "Under-constrained symbolic exec (undriven code)",
     "classes": ["CWE-94"], "kind": "dynamic"},
    # ---- confirmation ----
    {"stage": "source_confirm", "label": "Source confirmation ladder (template/concolic/smart-fuzz)",
     "classes": [], "kind": "confirm"},
    {"stage": "root_cause", "label": "Crash root-cause classification", "classes": [],
     "kind": "confirm"},
    # ---- weaponization ----
    {"stage": "chain_primitive", "label": "Primitive chaining", "classes": [], "kind": "weaponize"},
    {"stage": "build_exploit", "label": "Exploit synthesis (L3)", "classes": [], "kind": "weaponize"},
    {"stage": "synthesize_poc", "label": "Static PoC synthesis", "classes": [], "kind": "weaponize"},
    {"stage": "synthesize_injection", "label": "Injection-probe synthesis", "classes": [],
     "kind": "weaponize"},
    {"stage": "cve_poc", "label": "CVE weaponization", "classes": [], "kind": "weaponize"},
]

#: states that count a finding as WEAPONIZED (a verified PoC, or a corroborated recipe / primitive).
_WEAPONIZED_STATES = ("corroborated", "confirmed", "poc-backed")


def _run_status(runs: list) -> str:
    """Whether a stage's CHECK was performed, from its runs: done (completed), partial (it started
    and ran but the budget cut it short -- `cancelled`/`timeout` after starting, which still means
    the check was attempted and may have filed findings), errored, or not_run. A stage the autopilot
    budget reclaims is marked `cancelled` even after it did its work and emitted findings, so
    done-only would falsely report that class as never looked for."""
    if not runs:
        return "not_run"
    statuses = {r.status for r in runs}
    if "done" in statuses:
        return "done"
    # cancelled/timeout AFTER starting = the check ran but did not finish cleanly
    if any(r.status in ("cancelled", "timeout") and r.started_at for r in runs):
        return "partial"
    if statuses & {"error"}:
        return "errored"
    return "pending"


def build_ledger(store, case_id: str) -> dict[str, Any]:
    """The coverage ledger for a case: check coverage (classes), weaponization coverage, code
    coverage, and a combined gaps worklist. Read-only."""
    conn = store.conn
    runs = AnalysisRunDAO(conn).list_by_case(case_id)
    runs_by_stage: dict[str, list] = {}
    for r in runs:
        runs_by_stage.setdefault(r.stage, []).append(r)

    # ---- axis B: CHECK / class coverage ----
    checks: list[dict] = []
    classes_checked: set = set()
    for c in _CHECKS:
        status = _run_status(runs_by_stage.get(c["stage"]) or [])
        ran = status in ("done", "partial")                 # the check was performed (done or budget-cut)
        if ran:
            classes_checked.update(x for x in c["classes"] if x != "*")
        checks.append({**c, "status": status, "ran": ran})
    checks_ran = sum(1 for c in checks if c["ran"])
    not_run = [{"stage": c["stage"], "label": c["label"], "status": c["status"],
                "classes": c["classes"]} for c in checks if not c["ran"]]

    # ---- axis C: WEAPONIZATION coverage ----
    fdao = FindingDAO(conn)
    tdao = TargetDAO(conn)
    fndao = FunctionDAO(conn)
    all_findings: list = []
    code: list[dict] = []
    for t in tdao.list_by_case(case_id):
        all_findings += fdao.list_by_target(t.id)
        # ---- axis A: CODE coverage (best-effort, per target) ----
        try:
            nfns = len(fndao.list_by_target(t.id))
        except Exception:                                    # noqa: BLE001
            nfns = 0
        cov = _target_block_coverage(store, case_id, t.id)
        entry = {"target": t.filename, "functions_recovered": nfns,
                 "block_pct": cov.get("pct") if cov else None,
                 "blocks_hit": cov.get("blocks_hit") if cov else None,
                 "blocks_known": cov.get("blocks_known") if cov else None}
        # the UNDRIVEN-function worklist (axis A): recovered functions with no static call path from a
        # harness entry -- code no driver reaches, the worklist for harness synthesis.
        und = _undriven_functions(conn, t.id)
        if und:
            entry["undriven"] = und
        code.append(entry)

    by_state: dict[str, int] = {}
    for f in all_findings:
        by_state[f.state] = by_state.get(f.state, 0) + 1
    weaponized = sum(1 for f in all_findings if (f.state or "candidate") in _WEAPONIZED_STATES)
    total_f = len(all_findings)
    unweaponized = [{"id": f.id, "cwe": f.cwe, "title": f.title, "detector": f.detector}
                    for f in all_findings if (f.state or "candidate") not in _WEAPONIZED_STATES]

    # ---- combined GAPS worklist ----
    gaps: list[str] = []
    if not_run:
        gaps.append(f"{len(not_run)} analysis check(s) did not run on this case "
                    f"(classes never looked for): "
                    + ", ".join(c["label"] for c in not_run[:6])
                    + (" …" if len(not_run) > 6 else ""))
    if unweaponized:
        gaps.append(f"{len(unweaponized)} finding(s) are bare candidates with no verified PoC and no "
                    f"corroborated recipe — the weaponization worklist")
    dark = [c for c in code if (c["block_pct"] in (None, 0) and c["functions_recovered"])]
    if dark:
        gaps.append(f"{len(dark)} target(s) have little or no measured code coverage — much of their "
                    f"code was not exercised")
    # the worst-driven target: a harness that statically reaches only a small fraction of recovered
    # functions is exercising a sliver of the code -- the "reach all code" gap, directional.
    driven = [(c.get("undriven") or {}).get("pct") for c in code if (c.get("undriven") or {}).get("total")]
    driven = [p for p in driven if p is not None]
    if driven and min(driven) < 50:
        gaps.append(f"a harness statically reaches as little as {min(driven):g}% of a target's "
                    f"recovered functions — most code is undriven and needs additional drivers "
                    f"(harness-synthesis worklist)")

    return {
        "schema": "lykos.coverage-ledger/1",
        "checks": {"total": len(checks), "ran": checks_ran, "items": checks, "not_run": not_run,
                   "classes_checked": sorted(classes_checked)},
        "weaponization": {"findings": total_f, "weaponized": weaponized,
                          "pct": round(100.0 * weaponized / total_f, 1) if total_f else None,
                          "by_state": by_state, "unweaponized": unweaponized[:200]},
        "code": code,
        "gaps": gaps,
    }


def _undriven_functions(conn, target_id: str) -> Optional[dict]:
    """How much of the recovered code a harness statically DRIVES: the count of functions reachable
    from a harness entry (LLVMFuzzer* / main) over the call graph, vs the total recovered. The
    remainder is undriven -- code no harness exercises, which fuzzing that harness can never reach.
    Sound and directional: the recovered call graph does not model indirect/virtual calls (so it may
    under-count reachable), and `total` includes statically-linked libraries, so the figure is the
    HONEST 'fraction of recovered functions a harness reaches', not a clean project worklist -- the
    precise, source-attributed worklist is the harness-synthesis step's job. None when there is no
    identifiable harness entry or no call graph."""
    fns = FunctionDAO(conn).list_by_target(target_id)
    if not fns:
        return None
    by_addr = {f.addr: f for f in fns if f.addr}
    entries = {f.addr for f in fns if (f.name or "").startswith("LLVMFuzzer") and f.addr}
    if not entries:
        entries = {f.addr for f in fns if (f.name or "") == "main" and f.addr}
    if not entries:
        return None
    adj: dict = {}
    for e in CallEdgeDAO(conn).list_by_target(target_id):
        if e.src_addr and e.dst_addr:
            adj.setdefault(e.src_addr, set()).add(e.dst_addr)
    seen: set = set()
    stack = list(entries)
    while stack:
        a = stack.pop()
        if a in seen:
            continue
        seen.add(a)
        stack.extend(d for d in adj.get(a, ()) if d not in seen)
    reachable = len(seen & set(by_addr))
    total = len(by_addr)
    return {"total": total, "reachable": reachable, "count": max(0, total - reachable),
            "pct": round(100.0 * reachable / total, 1) if total else None}


def _target_block_coverage(store, case_id: str, target_id: str) -> Optional[dict]:
    """Best block coverage for a target, reused from the report model's logic (one source of truth)."""
    try:
        from ..report.model import _best_coverage
        runs = [r for r in AnalysisRunDAO(store.conn).list_by_case(case_id) if r.target_id == target_id]
        cov = _best_coverage(store, runs)
        return cov if cov and cov.get("kind") == "block" else None
    except Exception:                                        # noqa: BLE001
        return None
