"""Assemble a plain-dict report model from a case's stored data.

One model feeds every exporter (HTML/PDF/SARIF/JSON) so the formats never drift. The
model is JSON-serializable and self-contained: it embeds the reproducibility metadata
(tool + engine versions, input hashes) the report must carry (doc 08 §8.5, doc 12).
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

from .. import __version__ as _lykos_version
from .. import observe
from ..analyze.detect import catalog
from ..db.dao import (
    AnalysisRunDAO,
    CallEdgeDAO,
    DynResultDAO,
    FindingDAO,
    PocDAO,
    TargetDAO,
)
from ..analyze.confirm_ladder import attack_surface as _attack_surface
from ..analyze.confirm_ladder import finding_analysis as _finding_analysis
from ..analyze.confirm_ladder import finding_exploitability as _finding_exploitability
from ..analyze.confirm_ladder import finding_verification as _finding_verification
from ..analyze.confirm_ladder import prove_out_plan as _prove_out_plan
from ..analyze.reachability import reachability_steps as _reachability_steps
from ..analyze.stages import label_for as _stage_label_report
from . import figures as _figures
from ..db.models import FINDING_STATES, SEVERITIES
from ..jobs.registry import cached_output_json

_log = logging.getLogger(__name__)


def _best_coverage(store, runs) -> Optional[dict]:
    """The best fuzzing coverage this target reached, read from its fuzz runs' summaries. Included in
    the report so "0 crashes" can be read against how much of the binary was actually exercised.

    Block coverage (percent of recovered code) is the richer figure, but ONLY when blocks were
    actually hit: a directed campaign against a target that cannot be block-traced natively
    (a kernel, a .so, a cross-architecture binary) records blocks_hit=0 and reports 0%. That 0% used
    to override a coverage-guided AFL/qemu campaign that DID exercise the target -- so the UI showed
    "0% cov" next to 12k execs and looked broken. So block wins only with blocks_hit>0; otherwise the
    edge count (AFL's bitmap) is shown, which is the honest measure of what the campaign reached."""
    best_block = None
    best_edge = None
    for r in runs:
        if r.status != "done" or not (r.stage or "").endswith("fuzz"):
            continue
        try:
            out = cached_output_json(store, r.id)
        except Exception:
            observe.absorbed(_log, "keeping the default")
            out = None
        cov = (out or {}).get("coverage") if isinstance(out, dict) else None
        if not cov:
            continue
        if cov.get("kind") == "block" and cov.get("blocks_known"):
            pct, hit = cov.get("pct"), cov.get("blocks_hit") or 0
            if pct is not None and hit > 0 and (best_block is None or pct > best_block["pct"]):
                best_block = {"kind": "block", "pct": pct, "blocks_hit": hit,
                              "blocks_known": cov.get("blocks_known")}
        elif cov.get("kind") == "edge":
            edges = cov.get("edges_found") or 0
            if edges and (best_edge is None or edges > (best_edge.get("edges") or 0)):
                best_edge = {"kind": "edge", "edges": edges}
    return best_block or best_edge


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


#: Evidence channels whose `detail` is STRUCTURED (a JSON blob), not prose. Every surface that
#: renders evidence prints `detail` verbatim, so one of these reached a reader as raw JSON --
#: measured in a SARIF message, where it lands in a GitHub code-scanning alert, and the same in
#: the HTML and PDF. The data is kept, parsed, under its own key; only the prose stays in the
#: line a reader sees.
_STRUCTURED_EVIDENCE = frozenset({"effects", "patch-diff-map"})


def _split_evidence(ev: list) -> tuple:
    """(prose evidence, parsed structured evidence by channel)."""
    prose, structured = [], {}
    for e in ev or []:
        ch = e.get("channel")
        if ch in _STRUCTURED_EVIDENCE:
            try:
                structured[ch] = json.loads(e.get("detail") or "null")
            except (ValueError, TypeError):
                structured[ch] = None
            continue
        prose.append(e)
    return prose, structured


def _sentence(text: Optional[str]) -> str:
    """A reason phrase as a sentence -- these are composed for inline use elsewhere."""
    t = (text or "").strip()
    return (t[0].upper() + t[1:]) if t else ""


def _ceiling_why(submod, ftype: str, sub) -> str:
    """Why the ladder stops where it does, phrased for a REPORT reader.

    `substrate.no_ip_control_reason` states the mechanism, which is what a tooltip in the
    workbench needs. A report has a different reader: someone deciding whether the missing L2/L3
    is a limit of the target or a hole in the analysis. So the mechanism is kept and the
    consequence spelled out, which is the whole reason this field exists.
    """
    why = _sentence(submod.no_ip_control_reason(ftype))
    if not why:
        return ""
    if sub.runtime:
        return why + (" The absence of an L2 or L3 result is the runtime's guarantee, not a gap "
                      "in the analysis.")
    if sub.backend is None:
        return why + (" Nothing was executed, so no level is claimed at all -- that is a limit "
                      "of this host, not a statement about the target.")
    return why


def _runtime(t) -> dict:
    """What this target RUNS ON, and what that means for the evidence in the report.

    A 47 KB report over a case holding a jar mentioned "Java" zero times and printed
    `Arch: jvm/64 big` -- placeholder fields from triage rendered as though they described a
    processor. A reader could not tell that a finding came from a managed runtime, nor why no
    L2/L3 appears for it, and "no exploit was produced" reads as a gap rather than as the
    runtime's own guarantee.

    Derived from `analyze.substrate` rather than a jar/class/pe list kept here, because that
    list reproduced the very bug above for every format added after it: .pyc, .wasm and a .NET
    assembly all fell through to "Native machine code" with `describes_cpu` true and an L3
    ceiling, so the report rendered `Arch: cpython` / `Arch: cil` as a processor and implied an
    exploit had been possible but was not produced. A Mach-O and a raw blob claimed L3 on an
    image nothing here can execute.
    """
    from ..analyze import capabilities as capmod
    from ..analyze import substrate as submod
    ftype = (t.file_type or "").lower()
    sub = submod.of(ftype)
    out = {"substrate": sub.backend or "none",
           "label": _SUBSTRATE_LABELS.get(ftype, "Native machine code"),
           # Only a machine-code image has an `arch` that names a PROCESSOR. For a managed
           # target triage puts the runtime there ("jvm", "cpython", "cil"), which must not be
           # presented as hardware.
           "describes_cpu": bool(sub.machine_code),
           "ceiling": "L3" if sub.ip_control else "L1",
           "ceiling_why": _ceiling_why(submod, ftype, sub),
           "unavailable": capmod.unavailable_summary(t)}
    if sub.backend is None:
        # Nothing here executes it, so even L1 -- a verified, reproducible fault -- is out of
        # reach, and saying "L1" would promise a reproducer the platform cannot build.
        out["ceiling"] = "L0"
    return out


#: Reader-facing names. Absent means "Native machine code", which is right for an ELF.
_SUBSTRATE_LABELS = {
    "jar": "Java (JVM) — JAR", "class": "Java (JVM) — class file",
    "pe": "Windows PE", "dotnet": ".NET assembly (CIL)",
    "pyc": "CPython bytecode", "wasm": "WebAssembly module",
    "macho": "Mach-O (macOS/iOS)", "firmware": "Bare-metal firmware image",
    "raw": "Raw blob", "other": "Not an executable image",
}


#: Operator curation statuses (written by `api.curation`), in report order. The OPERATOR's
#: judgement, kept strictly beside the tool's evidence: it never changes a finding's state, severity
#: or L-level. A false positive is DEMOTED (listed separately), never dropped.
CURATION_STATUSES = ("true_positive", "needs_review", "false_positive")
CURATION_LABEL = {"false_positive": "False positive (operator)",
                  "true_positive": "True positive (operator)",
                  "needs_review": "Needs review (operator)"}

#: Engine-health verdicts (`analyze.fuzz.health.summarize`), worst first, plus `unrecorded` for a
#: target the autopilot never produced a health record for. Used to roll targets up to one case verdict.
_HEALTH_ORDER = ("none", "degraded", "unrecorded", "idle", "ok")
#: Per-engine statuses that mean the engine could not do its job (a FIX-THIS signal).
_ENGINE_BAD = ("failed", "error")
_ENGINE_WEAK = ("noprogress", "starved", "stalled")


def _ts_iso(v) -> Optional[str]:
    """An epoch int, or an already-ISO string, as ISO-8601 (curation stores epoch seconds)."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return _iso(int(v))
    return v if isinstance(v, str) and v else None


def _norm_curation(c) -> Optional[dict]:
    """A curation entry in the report's shape, or None. Tolerant of partial/foreign input: an
    unknown status is kept verbatim (never silently mapped to a known one) but carries no label."""
    if not isinstance(c, dict):
        return None
    status = c.get("status") or None
    note = (c.get("note") or "").strip() if isinstance(c.get("note"), str) else ""
    if status is None and not note:
        return None
    return {"status": status, "label": CURATION_LABEL.get(status) if status else None,
            "note": note, "updated_at": _ts_iso(c.get("updated_at") or c.get("at"))}


def _load_curation(store, case_id: str) -> dict:
    """{finding_id: curation} for the case, from the API's event-sourced curation store.

    Reuses `api.curation.current_for_case` so "latest event wins, a cleared verdict is gone" has
    one definition. If that module is unavailable the same fold is done here over the
    `finding.curation` events, so a report never silently drops the operator's triage."""
    try:
        from ..api import curation as _cur
        return dict(_cur.current_for_case(store.conn, case_id) or {})
    except Exception:                                    # noqa: BLE001 -- fall back to the raw fold
        observe.absorbed(_log, "folding curation events directly")
    out: dict = {}
    try:
        from ..db.dao import EventDAO
        for p in EventDAO(store.conn).payloads_of_type("finding.curation", case_id=case_id):
            fid = p.get("finding_id")
            if not fid:
                continue
            if not p.get("status") and not (p.get("note") or "").strip():
                out.pop(fid, None)
            else:
                out[fid] = {"status": p.get("status"), "note": p.get("note") or "",
                            "updated_at": p.get("at")}
    except Exception:                                    # noqa: BLE001 -- the report must render
        observe.absorbed(_log, "reporting without curation")
    return out


def best_verified_level(f: dict) -> str:
    """The highest L-level a VERIFIED PoC of this finding reached, '' if none.

    The one definition every renderer uses for a finding's demonstrated rung. An unverified PoC
    (built, but its reproducer did not re-fire) does not demonstrate anything, so it never sets
    the level a verdict or headline claims -- the summary's `poc_levels` already counted only
    verified PoCs while the HTML verdict counted any, so the two disagreed about the same case."""
    best = ""
    for p in f.get("pocs") or []:
        lvl = p.get("level") or ""
        if p.get("verified") and lvl and lvl > best:
            best = lvl
    return best


def best_unverified_level(f: dict) -> str:
    """The highest L-level any PoC was BUILT at, verified or not ('' if none)."""
    best = ""
    for p in f.get("pocs") or []:
        lvl = p.get("level") or ""
        if lvl and lvl > best:
            best = lvl
    return best


def engine_health(execution: dict) -> dict:
    """The run's dynamic-engine health for one target, normalised for every renderer.

    Read from the scorecard's `fuzz_health` (`analyze.fuzz.health.summarize`, the same verdict the
    CLI and web GUI show). A target with no record is `unrecorded` -- NOT `ok`: absent evidence that
    anything executed must never read as a clean dynamic pass."""
    fh = (execution or {}).get("fuzz_health")
    if not isinstance(fh, dict) or not fh:
        return {"verdict": "unrecorded", "recorded": False, "engines": [],
                "note": ("No engine-health record for this target: the autopilot never "
                         "finished a pass over it, so this report cannot claim that any dynamic "
                         "engine executed it."),
                "failed": [], "weak": [], "declined": [], "no_gain": [], "ran": []}
    engines = [e for e in (fh.get("engines") or []) if isinstance(e, dict)]

    def _names(statuses):
        return [e.get("engine") for e in engines if e.get("status") in statuses]
    return {"verdict": fh.get("verdict") or "unrecorded", "recorded": True,
            "note": fh.get("note") or "", "engines": engines,
            "failed": _names(_ENGINE_BAD), "weak": _names(_ENGINE_WEAK),
            "declined": _names(("declined",)), "no_gain": _names(("no_gain",)),
            "ran": [e.get("engine") for e in engines
                    if e.get("status") == "ok" and (e.get("execs") or 0) > 0]}


def target_verdict(t: dict) -> dict:
    """A one-line verdict for a target: the strongest DEMONSTRATED outcome, framed so a static-only
    or never-executed result can never read as a clean binary. Shared by HTML, PDF and SARIF.

    Only a verified PoC sets the level. With no level, the dynamic-engine health decides how the
    absence reads: "no defects demonstrated" is printed only when an engine really executed the
    target; otherwise the verdict says why nothing could escalate past L0."""
    findings = t.get("findings") or []
    ex = t.get("execution") or {}
    eh = t.get("engine_health") or engine_health(ex)
    sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    best_lvl, built_lvl, worst_sev = "", "", None
    for f in findings:
        lvl = best_verified_level(f)
        if lvl > best_lvl:
            best_lvl = lvl
        ulvl = best_unverified_level(f)
        if ulvl > built_lvl:
            built_lvl = ulvl
        s = f.get("severity")
        if s and (worst_sev is None or sev_order.get(s, 0) > sev_order.get(worst_sev, 0)):
            worst_sev = s
    base = ex.get("baseline")
    never_ran = base is not None and not base.get("ran")
    hv = eh.get("verdict")
    nothing_executed = never_ran or hv == "none" or (
        hv == "unrecorded" and not ex.get("executions_recorded")
        and not ex.get("executions_attempted"))
    gate_closed = bool((ex.get("runtime_env") or {}).get("gate_closed"))
    out = {"level": best_lvl, "built_level": built_lvl if built_lvl > best_lvl else "",
           "engine_health": hv, "nothing_executed": bool(nothing_executed),
           "gate_closed": gate_closed}
    if best_lvl == "L3":
        out.update(label="Exploited — working exploit demonstrated (L3)", tone="critical")
    elif best_lvl == "L2":
        out.update(label="Exploitation primitive established (L2)", tone="high")
    elif best_lvl == "L1":
        out.update(label="Reproduced crash — verified reproducer (L1)", tone="high")
    elif findings:
        lab = f"Static findings only — {len(findings)} not yet demonstrated dynamically"
        if nothing_executed:
            lab += ("; no dynamic engine executed the target, so nothing could escalate past L0 "
                    "(a tooling outcome, not evidence the findings are false)")
        elif gate_closed:
            lab += ("; the target never got past its startup gate (a config, data dir or env var "
                    "that could not be supplied), so dynamic analysis measured only that exit")
        elif hv == "degraded":
            lab += "; dynamic analysis was degraded (see engine health)"
        out.update(label=lab, tone=worst_sev or "medium")
    elif never_ran:
        out.update(label="Inconclusive — the target never executed (see execution gaps)",
                   tone="medium")
    elif nothing_executed:
        out.update(label=("Inconclusive — no dynamic engine executed the target; static review "
                          "only, not a clean result"), tone="medium")
    elif gate_closed:
        out.update(label=("Inconclusive — the target never got past its startup gate (it needs a "
                          "config, data dir or env var that could not be supplied); not a clean "
                          "result"), tone="medium")
    elif hv == "degraded":
        out.update(label=("No defects demonstrated — but dynamic analysis was degraded (an "
                          "engine failed; see engine health)"), tone="medium")
    elif hv == "idle":
        out.update(label=("No defects demonstrated — fuzzing executed the target but reached "
                          "nothing beyond its seeds"), tone="low")
    else:
        out.update(label="No defects demonstrated", tone="info")
    if gate_closed and nothing_executed and not best_lvl:
        out["label"] += ("; the target also stops at a startup gate (a config, data dir or env "
                         "var that could not be supplied)")
    if out["built_level"]:
        out["label"] += (f" (a PoC was built at {out['built_level']} but did not verify, so "
                         f"that level is not claimed)")
    return out


def has_execution_gaps(t: dict) -> bool:
    """True when part of the analysis never executed or failed -- the condition under which "no
    findings" must NOT be read as clean. One definition, so HTML and PDF cannot disagree."""
    ex = t.get("execution") or {}
    base = ex.get("baseline")
    eh = t.get("engine_health") or engine_health(ex)
    return bool(ex.get("did_not_run_count") or ex.get("failed_stages")
                or ex.get("stages_skipped_for_budget")
                or (base is not None and not base.get("ran"))
                or eh.get("verdict") in ("none", "degraded") or eh.get("failed")
                or (ex.get("runtime_env") or {}).get("gate_closed"))


def _call_graph_svg(call_edges, findings_out: list[dict]) -> Optional[str]:
    """A per-target call-graph figure (doc 49 Theme 4), focused on the worst located finding's
    function when there is one, so the report draws the same graph the GUI's Code tab does. None
    when the target has no recovered call edges. Best-effort -- a figure never fails the report."""
    try:
        edges = [{"src_addr": e.src_addr, "dst_addr": e.dst_addr, "dst_name": e.dst_name}
                 for e in call_edges]
        focus = next((f.get("function_addr") for f in findings_out if f.get("function_addr")), None)
        return _figures.call_graph_svg(edges, focus_addr=focus)
    except Exception:                               # noqa: BLE001
        observe.absorbed(_log, "call-graph figure skipped")
        return None


def _engagement_map_svg(targets_out: list[dict], *, findings: int, highest_level: str,
                        poc_backed: int, confirmed: int) -> Optional[str]:
    """The case's engagement map (doc 49 Theme 2a): the analysis path recover → detect → search →
    prove → report, each phase showing what it produced and whether it was reached. Derived honestly
    from the case totals -- an unreached phase is drawn muted, never implied done."""
    nt = len(targets_out)
    executed = sum(1 for t in targets_out if not (t.get("verdict") or {}).get("nothing_executed"))
    best_cov = None
    for t in targets_out:
        fc = t.get("fuzz_coverage") or {}
        if fc.get("pct") is not None:
            best_cov = fc["pct"] if best_cov is None else max(best_cov, fc["pct"])
    phases = [
        {"label": "Recover", "detail": f"{nt} target" + ("" if nt == 1 else "s"), "reached": nt > 0},
        {"label": "Detect", "detail": f"{findings} finding" + ("" if findings == 1 else "s"),
         "reached": findings > 0},
        {"label": "Search",
         "detail": (f"{best_cov}% covered" if best_cov is not None
                    else (f"{executed}/{nt} executed" if nt else "—")),
         "reached": executed > 0},
        {"label": "Prove", "detail": (f"{highest_level}, {poc_backed} PoC" if highest_level
                                      else "no PoC"), "reached": bool(highest_level)},
        {"label": "Report", "detail": f"{confirmed} confirmed", "reached": True},
    ]
    try:
        return _figures.engagement_map_svg(phases)
    except Exception:                               # noqa: BLE001
        observe.absorbed(_log, "engagement map skipped")
        return None


def _patch_diff_map_svg(findings_out: list[dict]) -> Optional[str]:
    """The per-target patch-diff map (doc 49 Theme 4, figure 5): the changed functions this build's
    patch_diff leads name, ranked by moved score. Built from the structured patch-diff data on the
    findings (never by parsing prose). None when the target has no patch_diff leads."""
    rows = [f["patch_diff"] for f in findings_out if f.get("patch_diff")]
    try:
        return _figures.patch_diff_map_svg(rows)
    except Exception:                               # noqa: BLE001
        observe.absorbed(_log, "patch-diff figure skipped")
        return None


def _provenance_chain_svg(f: dict) -> Optional[str]:
    """The finding's provenance as a chain (doc 49 Theme 4, figure 6): how it was established, left
    to right -- the stage that found it -> the detector -> the corroborating evidence -> the rung it
    reached. Drawn from the finding model ONLY (authoritative); nothing is inferred."""
    steps: list[dict] = []
    if f.get("stage_label"):
        steps.append({"label": f["stage_label"], "sub": "found by", "tone": "source"})
    if f.get("detector"):
        steps.append({"label": f["detector"], "sub": "detector"})
    ev = f.get("evidence") or []
    if ev:
        steps.append({"label": f"{len(ev)} signal" + ("" if len(ev) == 1 else "s"),
                      "sub": "evidence"})
    if f.get("level"):
        steps.append({"label": f["level"], "sub": "verified rung", "tone": "sink"})
    elif f.get("state"):
        steps.append({"label": f["state"], "sub": "confidence", "tone": "sink"})
    if len(steps) < 2:
        return None                                 # a single pill is not a chain worth drawing
    try:
        return _figures.chain_svg(steps, title="How this finding was established")
    except Exception:                               # noqa: BLE001
        observe.absorbed(_log, "provenance figure skipped")
        return None


def _reachability_path_svg(call_edges, f: dict) -> Optional[str]:
    """The source-reachability path (doc 49 Theme 4, figure 2) as an SVG, labelled "reachability,
    not verified dataflow" so it never overstates what was proven."""
    steps = _reachability_steps(call_edges, f)
    if not steps:
        return None
    try:
        return _figures.chain_svg(
            steps, title="Reachable from an input source",
            caption="shortest call path from a function that reads external input "
                    "(reachability, not verified dataflow)")
    except Exception:                               # noqa: BLE001
        observe.absorbed(_log, "reachability figure skipped")
        return None


def _coverage_figure(targets_out: list[dict]) -> Optional[str]:
    """The case-level coverage figure (doc 49 Theme 4): one bar per binary, from the per-target
    fuzz coverage the model already computes. None when no target reached measurable coverage."""
    rows = []
    for t in targets_out:
        fc = t.get("fuzz_coverage")
        if fc and fc.get("pct") is not None:
            detail = (f"{fc.get('edges')} edges" if fc.get("kind") == "edge"
                      else (f"{fc.get('hit')}/{fc.get('known')} blocks" if fc.get("known") else ""))
            rows.append({"name": t["filename"], "pct": fc["pct"], "detail": detail})
    try:
        return _figures.coverage_bars_svg(rows)
    except Exception:                               # noqa: BLE001
        observe.absorbed(_log, "coverage figure skipped")
        return None


#: a source location `path.ext:line` inside a finding's evidence detail.
_SRC_LOC_RE = re.compile(r"([\w./+\-]+\.(?:c|cc|cpp|cxx|h|hpp|hh|cs|go|rs|py|java|js|ts)):(\d+)")


def _finding_src_loc(f: dict):
    """(relpath, line) for a finding whose evidence carries a source location; else None."""
    for e in f.get("evidence") or []:
        m = _SRC_LOC_RE.search(str(e.get("detail") or ""))
        if m:
            return m.group(1), int(m.group(2))
    return None


def _match_src_member(members: list, path: str):
    """A tar member whose name is, or ends with, `path` (the tree is archived under a top dir)."""
    if path in members:
        return path
    suf = "/" + path
    return next((m for m in members if m.endswith(suf)), None)


def _snippet(lines: list, ln: int, path: str, ctx: int) -> Optional[dict]:
    n = len(lines)
    if ln < 1 or ln > n:
        return None
    lo, hi = max(1, ln - ctx), min(n, ln + ctx)
    return {"file": path, "line": ln,
            "rows": [{"n": i, "text": lines[i - 1], "hit": i == ln} for i in range(lo, hi + 1)]}


def _attach_source_snippets(store, target, findings_out: list, *, ctx: int = 4, cap: int = 120):
    """Attach the vulnerable SOURCE lines around each finding's site, read ONCE from the archived
    source tree, so the report shows the code -- not just a file:line. Best-effort: a tree that
    cannot be read, or a file/line that cannot be located, simply yields no snippet (never raised)."""
    want: dict = {}
    for f in findings_out:
        loc = _finding_src_loc(f)
        if loc:
            want.setdefault(loc[0], []).append((f, loc[1]))
    if not want:
        return
    try:
        from ..analyze.source_lookup import source_project_for
        proj = source_project_for(store.conn, target)
        if proj is None:
            return
        import io
        import tarfile
        raw = store.content.path(proj.sha256).read_bytes()
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    except Exception:                                    # noqa: BLE001 -- snippets are advisory
        observe.absorbed(_log, "source tree unavailable for snippets")
        return
    try:
        infos = {m.name: m for m in tf.getmembers() if m.isfile()}
        names = list(infos)
        done = 0
        for path, flist in want.items():
            if done >= cap:
                break
            mem = _match_src_member(names, path)
            if not mem:
                continue
            try:
                text = tf.extractfile(infos[mem]).read().decode("utf-8", "replace")
            except Exception:                            # noqa: BLE001
                continue
            lines = text.splitlines()
            for f, ln in flist:
                if done >= cap:
                    break
                snip = _snippet(lines, ln, path, ctx)
                if snip:
                    f["source_snippet"] = snip
                    done += 1
    finally:
        tf.close()


def build_report(
    store,
    case_id: str,
    *,
    min_severity: Optional[str] = None,
    min_state: str = DEFAULT_MIN_STATE,
    states: Optional[list[str]] = None,
    finding_ids: Optional[list[str]] = None,
    embed_pocs: bool = False,
    curation: Optional[dict] = None,
) -> dict[str, Any]:
    """Build the report model for one case.

    Filtering (all optional, AND-combined):
      * min_severity  -- drop findings below this severity
      * min_state     -- drop findings below this confidence state
      * states        -- keep only findings whose state is in this explicit set
      * finding_ids   -- keep only these findings (report-builder selection)
    An UNKNOWN severity/state raises ValueError: it used to rank as the lowest value, so a typo
    like `min_state=confirmd` silently widened the report to every candidate.
    `embed_pocs` base64-embeds each PoC bundle into the model so an HTML/JSON report
    is fully self-contained (bounded by _MAX_EMBED_BUNDLE per bundle).
    `curation` is an optional {finding_id: {status, note, updated_at}} map of operator verdicts;
    when None it is read from the case's curation store. Curation never filters a finding out.
    """
    if min_severity and min_severity not in SEVERITIES:
        raise ValueError(f"unknown severity {min_severity!r} (one of {SEVERITIES})")
    if min_state and min_state not in FINDING_STATES:
        raise ValueError(f"unknown finding state {min_state!r} (one of {FINDING_STATES})")
    bad_states = [s for s in (states or []) if s not in FINDING_STATES]
    if bad_states:
        raise ValueError(f"unknown finding state(s) {bad_states} (one of {FINDING_STATES})")
    conn = store.conn
    case = store.cases.get(case_id)
    if not case:
        raise KeyError(f"no case {case_id!r}")
    cur_map = curation if curation is not None else _load_curation(store, case_id)
    cur_counts: dict[str, int] = {}

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

    all_runs = rdao.list_by_case(case_id)
    # False-positive review verdicts (replay determinism), keyed by the input they reviewed,
    # keeping the latest for each -- so the report carries "verified 5/5" / "flaky 2/5".
    verdicts: dict[str, dict] = {}
    for a in store.artifacts.list_by_case(case_id):
        if a.kind != "replay-verdict":
            continue
        m = a.meta or {}
        ish = m.get("input_sha")
        if ish and (ish not in verdicts or (a.created_at or 0) > verdicts[ish].get("_at", 0)):
            verdicts[ish] = {"runs": m.get("runs"), "crashed": m.get("crashed"),
                             "signal": m.get("signal"), "deterministic": m.get("deterministic"),
                             "_at": a.created_at or 0}

    # one embed per distinct bundle, and a byte budget for the WHOLE report -- both must span
    # every target, or an N-target case can emit up to N x the cap and re-embed a bundle shared
    # across targets (the browser-choking blowup the cap exists to prevent).
    embedded: set = set()
    budget = {"left": _MAX_EMBED_TOTAL}
    for t in tdao.list_by_case(case_id):
        _target_runs = [r for r in all_runs if r.target_id == t.id]
        pocs = pdao.list_by_target(t.id)
        pocs_by_finding: dict[str, list] = {}
        for p in pocs:
            pocs_by_finding.setdefault(p.finding_id or "", []).append(p)
        crashes = ddao.list_by_target(t.id)
        # R2: an execution that NEVER HAPPENED is evidence, and the report had no way to say so.
        # Every substrate returns a sentinel isolation for it (jvm-missing, python-missing,
        # dotnet-missing, unsupported-arch, wine-launch-failed, .../not-runnable), and all of it
        # died at this boundary: a target nothing could run produced an empty crash list, which
        # is byte-identical in the report to a target that ran cleanly and had no defect. That is
        # the one confusion this whole platform is built to avoid, surviving into the deliverable.
        from ..analyze.dynamic import sandbox as _sb
        _notrun = [d for d in crashes if _sb.did_not_run(d.isolation)]
        execution = {
            "executions_recorded": len(crashes),
            "did_not_run": [{"isolation": d.isolation, "mode": d.input_mode,
                             "reason": d.note or ""} for d in _notrun[:8]],
            "did_not_run_count": len(_notrun),
        }
        # R3: a stage that ERRORED is not a stage that found nothing. `_engines` lists the tools
        # used for reproducibility and discarded run status entirely, so afl-fuzz aborting with
        # zero executions still read as "AFL++ was used".
        execution["failed_stages"] = sorted({
            r.stage for r in _target_runs if r.status in ("error", "timeout") and r.stage})
        # R7: the SCORECARD -- what the run actually did to this target, which is the only thing
        # that makes "no findings" readable. Measured: one stock binary completed the pipeline
        # with 2,756 executions and no crash (a real clean result) while another executed ZERO
        # times because a stage upstream spent the budget, and the two reports were identical.
        execution.update(_scorecard(store, case_id, t.id))
        # The actionable "why" behind a thin dynamic result -- missing shared library, a target that
        # needs a config/args, a campaign that never reached the parser. Carried into the report so
        # a blocked run is never mistaken for a clean one.
        execution["diagnostics"] = _diagnostics(store, case_id, t.id)
        # What the target needed to START, and whether it got it. A startup gate nothing could
        # open means every dynamic result for this target measured that early exit.
        _renv = _runtime_env_state(store, case_id, t.id)
        if _renv:
            execution["runtime_env"] = _renv
            if _renv["gate_closed"]:
                execution["diagnostics"].append({"stage": "runtime_env", "note": _GATE_NOTE})
        crash_by_input: dict[str, Any] = {}
        for d in crashes:
            if d.input_sha and d.input_sha not in crash_by_input:
                crash_by_input[d.input_sha] = d

        findings_out: list[dict] = []

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
                    "provenance": getattr(p, "provenance", None),
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

            # The review verdict for this finding: the replay result of any of its inputs.
            fv = None
            for p in f_pocs:
                if p.get("input_sha") in verdicts:
                    v = verdicts[p["input_sha"]]
                    fv = {k: v[k] for k in ("runs", "crashed", "signal", "deterministic")}
                    break

            _ev_prose, _ev_struct = _split_evidence(f.evidence or [])
            _cur = _norm_curation((cur_map or {}).get(f.id))
            if _cur and _cur.get("status"):
                cur_counts[_cur["status"]] = cur_counts.get(_cur["status"], 0) + 1
            findings_out.append({
                "id": f.id, "cwe": f.cwe, "cwe_name": catalog.name(f.cwe) if f.cwe else None,
                "cwe_desc": catalog.describe(f.cwe) if f.cwe else None,
                "title": f.title, "severity": f.severity, "state": f.state,
                "confidence": round(f.confidence or 0.0, 3),
                "function_addr": f.function_addr, "site_addr": f.site_addr,
                "detector": f.detector, "evidence": _ev_prose,
                # The tool's own dedup identity. The SAME logical source bug is filed once per
                # target that compiles the file, sharing this key -- so it is also the cross-target
                # cluster key (see `summary.distinct` + `target_span`, set after the target loop).
                "dedup_key": f.dedup_key,
                # The pipeline stage that discovered this finding (doc 49 Themes 1a/2b), so the
                # report's provenance reads the same chain the GUI does. None when unknown.
                "stage": f.stage, "stage_label": _stage_label_report(f.stage),
                # Parsed, under its own key, so a renderer can present the effect LIST instead
                # of the blob and nothing has to re-parse a string.
                "effects": _ev_struct.get("effects") or [],
                # Structured patch-diff facts (doc 49 Theme 4, figure 5), when this is a patch_diff
                # lead -- the moved score, block/insn deltas, callee churn. None otherwise.
                "patch_diff": _ev_struct.get("patch-diff-map"),
                "pocs": f_pocs, "crashes": f_crashes, "verification": fv,
                # The highest rung a VERIFIED PoC reached -- the level every renderer claims.
                "level": best_verified_level({"pocs": f_pocs}) or None,
                # The operator's verdict, beside (never instead of) the tool's evidence.
                "curation": _cur,
                "created_at": _iso(f.created_at), "updated_at": _iso(f.updated_at),
            })
            # The confirmation ladder for this finding (why this rung, what climbs it) -- derived
            # from the finding dict just built, so report and GUI share one account.
            findings_out[-1]["analysis"] = _finding_analysis(findings_out[-1])
            # Exploitability: class primitive, the target's mitigations in the way, the honest
            # ceiling (doc 49 per-finding detail).
            _expl = _finding_exploitability(findings_out[-1], t.mitigations)
            if _expl:
                findings_out[-1]["exploitability"] = _expl
            tot_findings += 1
            by_state[f.state] = by_state.get(f.state, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            for p in f_pocs:
                if p.get("verified") and p.get("level"):
                    poc_levels[p["level"]] = poc_levels.get(p["level"], 0) + 1

        if findings_out or finding_ids is None:
            tout = {
                "id": t.id, "filename": t.filename, "sha256": t.sha256, "md5": t.md5,
                "sha1": t.sha1, "size": t.size, "file_type": t.file_type, "arch": t.arch,
                "bits": t.bits, "endianness": t.endianness, "linking": t.linking,
                "stripped": t.stripped, "mitigations": t.mitigations or {},
                "runtime": _runtime(t),
                "entropy": t.entropy, "ingested_at": _iso(t.ingested_at),
                "fuzz_coverage": _best_coverage(store, _target_runs),
                "execution": execution,
                # WHY each dynamic engine did or did not contribute -- the run's own verdict, so
                # a static-only result is never presented as a clean binary.
                "engine_health": engine_health(execution),
                "exploited_build": _exploited_build(store, case_id, t.id),
                "findings": findings_out,
            }
            # Static figures (doc 49 Theme 4). Call edges are fetched once and fed to the target's
            # call graph AND each finding's reachability path. None where there is nothing to draw.
            try:
                _edges = CallEdgeDAO(store.conn).list_by_target(t.id)
            except Exception:                       # noqa: BLE001
                observe.absorbed(_log, "call edges unavailable")
                _edges = []
            tout["figures"] = {"call_graph": _call_graph_svg(_edges, findings_out),
                               "patch_diff": _patch_diff_map_svg(findings_out)}
            # The vulnerable SOURCE lines around each finding's site -- read once from the archived
            # tree so the report shows the code, not just a file:line.
            _attach_source_snippets(store, t, findings_out)
            for _f in findings_out:
                _f["figures"] = {"provenance": _provenance_chain_svg(_f),
                                 "reachability": _reachability_path_svg(_edges, _f)}
                # Structured per-finding reachability (doc 49 per-finding detail): the same hops the
                # figure draws, plus whether it is on the fuzzed attack surface -- so the GUI and a
                # machine reader get the path as data, not only a picture.
                _steps = _reachability_steps(_edges, _f)
                _surface = _attack_surface(_f)
                if _steps or _surface:
                    _f["reachability"] = {"attack_surface": _surface,
                                          "path": [s["label"] for s in (_steps or [])]}
                # The verification verdict (de-noise + prove-out shortlist), with the call-graph
                # path as the bonus `reachable` signal when one was found (doc 49 #3).
                _f["verification"] = _finding_verification(_f, reachable=bool(_steps))
                # The directed prove-out plan for a shortlisted finding (doc 49 #5): how lykos would
                # raise it to poc-backed. A plan, not a demonstrated exploit; None off the shortlist.
                _pp = _prove_out_plan(_f, _f["verification"])
                if _pp:
                    _f["prove_out"] = _pp
            tout["execution"]["has_gaps"] = has_execution_gaps(tout)
            tout["verdict"] = target_verdict(tout)
            targets_out.append(tout)

    # Cross-target DEDUP. Because the targets in a source case are built from ONE tree, the same
    # bug is filed once per target that compiles the file -- so the raw finding count overcounts
    # the distinct issues (a multi-target source case can inflate it several-fold). A "distinct
    # issue" is one dedup_key; each finding also learns how many targets it spans (`target_span`),
    # which the report/GUI show as "N targets" so a reader is never misled by the inflated total.
    # best verification verdict per distinct issue (shortlist beats off-surface beats noise)
    _VERDICT_RANK = {"prove-out-shortlist": 3, "off-surface": 2, "unclassified": 1,
                     "instrumentation-noise": 0}
    _clusters: dict[str, dict] = {}
    for _t in targets_out:
        for _f in _t["findings"]:
            dk = _f.get("dedup_key")
            if not dk:
                continue
            _v = (_f.get("verification") or {}).get("verdict") or "unclassified"
            c = _clusters.setdefault(dk, {"targets": set(), "severity": _f["severity"],
                                          "state": _f["state"], "verdict": _v})
            c["targets"].add(_t["id"])
            if _rank(FINDING_STATES, _f["state"]) > _rank(FINDING_STATES, c["state"]):
                c["state"] = _f["state"]
            if _rank(SEVERITIES, _f["severity"]) > _rank(SEVERITIES, c["severity"]):
                c["severity"] = _f["severity"]
            if _VERDICT_RANK.get(_v, 1) > _VERDICT_RANK.get(c["verdict"], 1):
                c["verdict"] = _v
    _span = {dk: len(c["targets"]) for dk, c in _clusters.items()}
    for _t in targets_out:
        for _f in _t["findings"]:
            _f["target_span"] = _span.get(_f.get("dedup_key"), 1)
    _d_sev: dict[str, int] = {}
    _d_state: dict[str, int] = {}
    for c in _clusters.values():
        _d_sev[c["severity"]] = _d_sev.get(c["severity"], 0) + 1
        _d_state[c["state"]] = _d_state.get(c["state"], 0) + 1
    distinct = {
        "issues": len(_clusters),
        "raw_findings": tot_findings,
        "multi_target": sum(1 for c in _clusters.values() if len(c["targets"]) > 1),
        "by_severity": {s: _d_sev.get(s, 0) for s in reversed(SEVERITIES) if _d_sev.get(s)},
        "by_state": {s: _d_state.get(s, 0) for s in FINDING_STATES if _d_state.get(s)},
    }
    # Verification rollup over DISTINCT issues: the de-noised prove-out shortlist (real + on the
    # fuzzed attack surface), the off-surface remainder, and the instrumentation artifacts. This is
    # the "verify it's an actual finding" triage -- it never sets the earned `confirmed` state.
    verification = {
        "shortlist": sum(1 for c in _clusters.values() if c["verdict"] == "prove-out-shortlist"),
        "off_surface": sum(1 for c in _clusters.values() if c["verdict"] == "off-surface"),
        "noise": sum(1 for c in _clusters.values() if c["verdict"] == "instrumentation-noise"),
    }

    engines = _engines(rdao, case_id)
    # Case-level rollups the executive summary leads with: the WORST engine-health verdict across
    # targets, and the strongest verified level.
    _hv = [t["engine_health"]["verdict"] for t in targets_out]
    _health = next((v for v in _HEALTH_ORDER if v in _hv), None) if _hv else None
    _levels = [t["verdict"]["level"] for t in targets_out if t["verdict"]["level"]]

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
            # Deduped headline: how many DISTINCT issues the raw findings represent, so a
            # source case built into N targets is not read as N x the bugs.
            "distinct": distinct,
            # The verification triage over distinct issues: prove-out shortlist / off-surface / noise.
            "verification": verification,
            "by_state": {s: by_state.get(s, 0) for s in FINDING_STATES if by_state.get(s)},
            "by_severity": {s: by_severity.get(s, 0)
                            for s in reversed(SEVERITIES) if by_severity.get(s)},
            "confirmed": by_state.get("confirmed", 0) + by_state.get("poc-backed", 0),
            "poc_backed": by_state.get("poc-backed", 0),
            "poc_levels": poc_levels,
            # The strongest VERIFIED rung across the case ('' when nothing was demonstrated).
            "highest_level": max(_levels) if _levels else "",
            "engine_health": {
                "verdict": _health,
                "targets_nothing_executed": sum(
                    1 for t in targets_out if t["verdict"]["nothing_executed"]),
                "targets_with_failed_engines": sum(
                    1 for t in targets_out if t["engine_health"]["failed"]),
            },
            # Operator triage counts. `findings` above stays the TOOL's count: a false positive
            # is demoted in presentation, never subtracted from what the tool reported.
            "curation": {s: cur_counts[s] for s in CURATION_STATUSES if cur_counts.get(s)},
        },
        "targets": targets_out,
        # The coverage ledger: what was checked (classes), what was weaponized, how much code was
        # exercised, and the gaps worklist -- the measurement that makes "how close to 100%" a number.
        "coverage_ledger": _safe_ledger(store, case_id),
        # How long each technique took + the overall analysis time, with yield (findings/crashes)
        # beside the cost -- so a technique that ate the clock for nothing is self-evident.
        "timing": _safe_timing(store, case_id, all_runs),
        # Case-level static figures (doc 49 Themes 2a/4). HTML/PDF embed these; SARIF stays
        # machine-faithful and ignores them.
        "figures": {
            "coverage": _coverage_figure(targets_out),
            "engagement": _engagement_map_svg(
                targets_out, findings=tot_findings,
                highest_level=(max(_levels) if _levels else ""),
                poc_backed=by_state.get("poc-backed", 0),
                confirmed=by_state.get("confirmed", 0) + by_state.get("poc-backed", 0)),
        },
    }


def _safe_timing(store, case_id: str, all_runs) -> Optional[dict]:
    """Timing, best-effort -- a timing failure must never take down the whole report. The model is
    derived by `analyze.timing` (the one source the GUI's timing panel also uses)."""
    try:
        from ..analyze.timing import timing_model
        return timing_model(all_runs, store, case_id)
    except Exception:                                        # noqa: BLE001
        observe.absorbed(_log, "timing unavailable")
        return None


def _safe_ledger(store, case_id: str) -> Optional[dict]:
    """The coverage ledger, best-effort -- a ledger failure must never take down the whole report."""
    try:
        from ..analyze.coverage_ledger import build_ledger
        return build_ledger(store, case_id)
    except Exception:                                        # noqa: BLE001
        observe.absorbed(_log, "coverage ledger unavailable")
        return None


def _exploited_build(store, case_id: str, target_id: str) -> dict:
    """Which IMAGE the exploit was built and confirmed against, when it is not the ingested one.

    For a source drop the ingested target is the ASan+UBSan build, and L3 is impossible on it --
    it abort()s at the overflow copy before the corrupted return is reached. `build_exploit`
    therefore works against the uninstrumented build of the same source and records the swap
    (`exploit.build_choice`). The report has to say so, because the target header prints the
    INGESTED sha and every offset in the findings below it belongs to the other image. A reader
    who takes the two to be the same binary is being misled by omission -- the PoC bundle's own
    `meta.json` already carries `exploited_sha256` and the report was the last place that did not.

    `{}` when no swap happened, which is the normal case for an ingested binary.
    """
    try:
        from ..db.dao import EventDAO
        for pl in EventDAO(store.conn).payloads_of_type(
                "exploit.build_choice", case_id=case_id, target_id=target_id):
            if pl.get("build"):
                return {"build": pl.get("build"), "bytes": pl.get("bytes"),
                        "note": pl.get("note")}
    except Exception:                                    # noqa: BLE001 -- the report must render
        return {}
    return {}


#: diagnostic events that carry a human `note` explaining why a dynamic stage did little or
#: nothing -- the actionable "why" an operator needs in the deliverable (a missing shared library,
#: a target that needs a config/args, a campaign that never reached the parser, coverage that could
#: not be measured). These are the difference between "0 crashes" reading as clean vs. as blocked.
_DIAGNOSTIC_EVENTS = (
    "coverage.deps", "coverage.noprogress", "coverage.starved", "coverage.coverage_unavailable",
    "fuzz.noprogress", "directed_fuzz.noprogress", "fuzz.coverage_unavailable",
)


def _diagnostics(store, case_id: str, target_id: str) -> list:
    """Deduped diagnostic notes for a target -- why a dynamic stage did little or nothing. These
    make a thin result legible in the deliverable instead of a silent clean zero. Best-effort."""
    out: list = []
    seen: set = set()
    try:
        from ..db.dao import EventDAO
        dao = EventDAO(store.conn)
        for et in _DIAGNOSTIC_EVENTS:
            for pl in dao.payloads_of_type(et, case_id=case_id, target_id=target_id):
                note = (pl.get("note") or "").strip()
                if note and note not in seen:
                    seen.add(note)
                    out.append({"stage": et.split(".")[0], "note": note})
    except Exception:                                    # noqa: BLE001 -- the report must render
        return out
    return out


_GATE_NOTE = ("the target exits at a startup gate (it needs a config file, data directory or "
              "environment variable) that could not be supplied, so every dynamic result for it "
              "measured that early exit -- set the invocation (e.g. `-c @@` with a config as the "
              "seed) and re-run")


def _runtime_env_state(store, case_id: str, target_id: str) -> Optional[dict]:
    """The target's latest runtime-environment result, or None when it needed nothing (or was never
    probed). `gate_closed` is True when the target was found gated and nothing opened the gate."""
    try:
        from ..db.dao import EventDAO
        pls = EventDAO(store.conn).payloads_of_type("runtime_env", case_id=case_id,
                                                    target_id=target_id)
    except Exception:                                    # noqa: BLE001 -- the report must render
        return None
    if not pls:
        return None
    p = pls[-1]                                          # a reuse event carries the same record
    applied, gated = bool(p.get("applied")), bool(p.get("gated"))
    if not (applied or gated):
        return None
    sup = []
    for x in (p.get("supplied") or [])[:12]:
        if not isinstance(x, dict):
            sup.append(str(x)[:200])
        elif x.get("kind") == "env":
            sup.append(f"env {x.get('name')}={x.get('value')}"[:200])
        else:
            sup.append(f"{x.get('kind')} {x.get('at') or x.get('path')}"[:200])
    return {"applied": applied, "gate_closed": gated and not applied, "note": p.get("note") or "",
            "supplied": sup,
            "degraded": [f"{d.get('path')}: {d.get('why')}" for d in (p.get("degraded") or [])
                         if isinstance(d, dict)][:12]}


def _scorecard(store, case_id: str, target_id: str) -> dict:
    """The autopilot's own record of the work done on this target, or {} if it never ran.

    Read from the event the autopilot writes (`orchestrate.SCORECARD_EVENT`) rather than
    re-derived here: two derivations of "how many executions" would drift, and this one has to
    agree with what the operator watched happen.
    """
    try:
        from ..analyze.orchestrate import SCORECARD_EVENT
        from ..db.dao import EventDAO
        # Asked for by type. This scanned the case's first 8,000 events for the scorecard, and
        # the scorecard is emitted LAST -- the first thing a window cuts. A 420-second run on one
        # small ELF already produces ~2,100 events, so a longer budget or a multi-target case
        # would have silently rendered the whole "what this run did" card as empty.
        best = None
        for pl in EventDAO(store.conn).payloads_of_type(SCORECARD_EVENT, case_id=case_id):
            if pl.get("target_id") == target_id:
                best = pl
        if not best:
            return {}
    except Exception:                                    # noqa: BLE001 -- the report must render
        return {}
    ex = best.get("executions") or {}
    return {
        "baseline": best.get("baseline"),
        "executions_attempted": ex.get("total"),
        "executions_per_second": ex.get("per_second"),
        "executions_by_engine": ex.get("by_engine") or {},
        "stage_counts": best.get("stages") or {},
        "stages_skipped_for_budget": best.get("stages_skipped_for_budget") or [],
        "budget": best.get("budget") or {},
        # WHITELISTED, which is why these were missing: the card carries them and the report
        # dropped them on the floor. `in_process` is which doors into a library were fuzzed (a
        # library fuzzed through one of six entry points and through all six report the same
        # execution count); the other three are the ladder and the search behind it, which the
        # CLI prints and the kept artifact did not.
        "in_process": best.get("in_process") or {},
        "search_seconds": best.get("search_seconds"),
        "crashes_recorded": best.get("crashes"),
        "poc": best.get("poc") or {},
        # Errors the run absorbed on purpose, counted per site. The report already distinguishes
        # "ran and found nothing" from "never ran"; this is the third case it could not express --
        # "ran, and some steps inside it failed quietly". Zero is the useful reading: it says a
        # thin result is the target's doing and not ours.
        "absorbed": best.get("absorbed") or {},
        # False means a stage was still finishing when the card was built, so every count above
        # is a FLOOR rather than a total. A reader weighing "0 executions" has to know which they
        # are looking at: that is precisely how a wrong zero gets believed.
        "settled": best.get("settled", True),
        # The per-engine dynamic health verdict (R1, `analyze.fuzz.health.summarize`). The card
        # has carried it since R1 and the CLI and GUI both print it -- this whitelist dropped it,
        # so the deliverable was the one surface that could not say "no fuzzer could execute this
        # target" next to a static-only result.
        "fuzz_health": best.get("fuzz_health") or {},
        # Which capabilities did their job / declined / errored / were never scheduled, and WHY
        # each decline happened -- classified "target" (its nature) vs "ours" (our defect), the
        # same split the CLI prints as [OUR DEFECT].
        "capability": best.get("capability") or {},
        "declined": _classified_declines(best.get("declined") or {}),
    }


def _classified_declines(declined: dict) -> list:
    """[{stage, reason, kind}] with kind "target" | "ours" | "unknown" (`classify_decline`)."""
    if not isinstance(declined, dict):
        return []
    try:
        from ..analyze.capabilities import classify_decline
    except Exception:                                    # noqa: BLE001 -- still report the reasons
        observe.absorbed(_log, "declines left unclassified")

        def classify_decline(_why):                      # noqa: E306 -- local fallback
            return "unknown"
    return [{"stage": s, "reason": str(why or ""), "kind": classify_decline(str(why or ""))}
            for s, why in sorted(declined.items())]


def _crash_dict(d) -> dict:
    return {
        "id": d.id, "signal": d.signal_name, "exit_code": d.exit_code,
        "input_mode": d.input_mode, "input_sha": d.input_sha,
        "isolation": d.isolation, "duration_ms": d.duration_ms,
        "timed_out": d.timed_out, "note": d.note,
    }


def _engines(rdao, case_id: str) -> list[dict]:
    """Distinct (tool, version) pairs used in this case, and whether they COMPLETED.

    Run status was discarded here, and used in exactly one other place in the whole report, so
    an engine that aborted having executed nothing still appeared under "engines actually used"
    -- afl-fuzz failing its dry run was indistinguishable from afl-fuzz finding no crash. The
    counts are what let a reader tell a tool that ran from a tool that was merely invoked.
    """
    seen: dict[tuple, dict] = {}
    for r in rdao.list_by_case(case_id):
        if not r.tool:
            continue
        e = seen.setdefault((r.tool, r.tool_version), {
            "tool": r.tool, "version": r.tool_version, "runs": 0, "completed": 0, "failed": 0,
        })
        e["runs"] += 1
        if r.status == "done":
            e["completed"] += 1
        elif r.status in ("error", "timeout"):
            e["failed"] += 1
    for e in seen.values():
        # The distinction that matters to a reader: did this engine ever finish a run here?
        e["ran"] = e["completed"] > 0
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
