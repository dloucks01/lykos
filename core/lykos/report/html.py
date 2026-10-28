"""Self-contained, print-optimized HTML report (doc 08 §8.5, doc 09 §7).

Single file, inlined CSS, no external assets (offline clean). Severity/state colors
come from the same design tokens the app UI uses (doc 09 §design-system) so the report
reads as one system. PoC bundles, when embedded, are offered as `data:` download links
so the report is a portable, reproducible deliverable. `@media print` yields a clean
PDF via the browser's print-to-PDF in addition to the native PDF exporter.
"""
from __future__ import annotations

import html as _html
from typing import Any

from . import model as _model

_SEV_COLOR = {
    "critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
    "low": "#46a758", "info": "#8b8d98",
}
_STATE_COLOR = {
    "candidate": "#8b8d98", "corroborated": "#5b9dd9",
    "confirmed": "#46a758", "poc-backed": "#8e4ec6",
}

_LEVEL_COLOR = {"L0": "#8b8d98", "L1": "#5b9dd9", "L2": "#f76808", "L3": "#e5484d"}
_CURATION_COLOR = {"false_positive": "#8b8d98", "true_positive": "#46a758",
                   "needs_review": "#d29922"}
#: Engine-health status colours: a failure is a fix-this signal, a decline is not a fault.
_HEALTH_COLOR = {"ok": "#46a758", "no_gain": "#d29922", "idle": "#d29922",
                 "noprogress": "#f76808", "starved": "#f76808", "stalled": "#f76808", "degraded": "#f76808",
                 "failed": "#e5484d", "error": "#e5484d", "none": "#e5484d",
                 "declined": "#8b8d98", "skipped": "#8b8d98", "not_run": "#8b8d98",
                 "unrecorded": "#8b8d98"}
#: What each rung MEANS, in one line -- the impact ladder, so a reader who does not live in it
#: can read the verdict. Canonical source: bundle._LEVEL_MEANING.
_LEVEL_GLOSS = {
    "L0": "observed (a crash was seen)",
    "L1": "reproduced — a verified reproducer exists",
    "L2": "exploitation primitive — attacker control of a corruption/injection established",
    "L3": "working exploit — the attacker's end goal was realised (control hijack, injected "
          "command/query/read carried out, or a denial of service)",
}

#: CWE -> concise, actionable remediation. Keyed by the exact CWE; `_remediation` falls back along
#: the family and then to a sane default, so a report never shows a finding with no guidance.
_REMEDIATION = {
    "CWE-120": "Bound every copy to the destination size; replace unbounded copies (strcpy/"
               "sprintf/gets) with their sized forms (strlcpy/snprintf) and validate input length.",
    "CWE-121": "Do not size stack buffers from untrusted length; use sized copies and enable "
               "stack canaries (-fstack-protector-strong) and FORTIFY_SOURCE.",
    "CWE-122": "Validate allocation sizes and copy bounds before writing into heap buffers; "
               "prefer allocators/containers that track capacity.",
    "CWE-125": "Bounds-check the index/offset before reading; reject out-of-range input at the "
               "trust boundary.",
    "CWE-787": "Bounds-check before writing; use sized copies, and build with FORTIFY_SOURCE and a "
               "stack protector so an overflow is caught rather than exploited.",
    "CWE-134": "Never pass untrusted data as the format string; use a constant format and pass the "
               "data as an argument (printf(\"%s\", s), not printf(s)).",
    "CWE-416": "Null the pointer on free and never reuse it; adopt RAII/smart pointers or a "
               "use-after-free sanitizer in CI to catch reclaimed-object access.",
    "CWE-415": "Free each allocation exactly once; null after free and centralise ownership so a "
               "second free is impossible.",
    "CWE-476": "Check every allocation/return for NULL before dereferencing; fail closed on the "
               "error path.",
    "CWE-190": "Validate and range-check arithmetic on untrusted values; use checked/widening "
               "arithmetic before it feeds an allocation or index.",
    "CWE-191": "Guard subtractions that can wrap on untrusted operands before they size an "
               "allocation or a copy.",
    "CWE-78": "Never build a shell command from untrusted input; use execve with an argument "
              "vector (no shell), and allowlist/validate arguments.",
    "CWE-89": "Use parameterised queries / prepared statements; never concatenate untrusted input "
              "into SQL.",
    "CWE-22": "Canonicalise and confine paths to an allowlisted base directory; reject '..' and "
              "absolute paths from untrusted input.",
    "CWE-611": "Disable external entity and DTD processing in the XML parser.",
    "CWE-918": "Allowlist destinations server-side and resolve/validate the target host; block "
               "internal address ranges and redirects.",
    "CWE-401": "Free every allocation on all paths, including error paths; run a leak sanitizer in "
               "CI to catch the regression.",
    "CWE-400": "Bound resource consumption from untrusted input (size/time/recursion caps) and "
               "fail closed when a limit is reached.",
    "CWE-674": "Convert unbounded recursion to iteration or cap the depth; reject input that would "
               "exceed it.",
    "CWE-789": "Validate the requested allocation size against a sane maximum before allocating.",
    "CWE-770": "Enforce quotas/limits on resources allocated from untrusted input.",
    "CWE-457": "Initialise every variable before use; build with an uninitialised-memory sanitizer "
               "in CI.",
    "CWE-200": "Do not return pointers, addresses, or uninitialised memory to untrusted callers; "
               "scrub buffers before they cross the boundary.",
    "CWE-362": "Protect shared state with appropriate locking/atomics; run a thread sanitizer in CI.",
    "CWE-369": "Reject a zero (or INT_MIN/-1) divisor from untrusted input before dividing.",
    "CWE-798": "Remove embedded credentials/keys; load secrets from a managed store or environment "
               "at runtime and rotate the exposed ones.",
    "CWE-295": "Verify the full certificate chain and hostname; never disable validation.",
    "CWE-502": "Do not deserialize untrusted data into live objects; use a data-only format with a "
               "strict schema.",
}
#: Family roots, tried before the default, so an unlisted buffer-overflow CWE still gets overflow
#: guidance rather than the generic line.
_REMEDIATION_FAMILY = {
    "CWE-119": _REMEDIATION["CWE-787"],
    "CWE-131": _REMEDIATION["CWE-190"],
}
_REMEDIATION_DEFAULT = ("Validate and sanitise the untrusted input at the trust boundary, fail "
                        "closed on the error path, and add a regression test that exercises this "
                        "input so the fix is verified and stays fixed.")


def _remediation(cwe: str | None) -> str:
    if not cwe:
        return _REMEDIATION_DEFAULT
    return _REMEDIATION.get(cwe) or _REMEDIATION_FAMILY.get(cwe) or _REMEDIATION_DEFAULT


def _finding_level(f: dict) -> tuple:
    """(level_str, verified_bool) -- the highest PoC rung this finding reached, '' if none."""
    best, ver = "", False
    for pc in f.get("pocs") or []:
        lvl = pc.get("level") or ""
        if lvl and (best == "" or lvl > best):
            best, ver = lvl, bool(pc.get("verified"))
        elif lvl and lvl == best and pc.get("verified"):
            ver = True
    return best, ver


def _target_verdict(t: dict) -> dict:
    """The target's verdict -- the model's own (`model.target_verdict`), so HTML, PDF and SARIF
    can never disagree about a level. Recomputed only for a report dict built before the model
    carried it. Only a VERIFIED PoC sets the level: an unverified one used to headline "Exploited
    (L3)" here while the summary's verified-only `poc_levels` said otherwise."""
    return t.get("verdict") or _model.target_verdict(t)


def esc(s: Any) -> str:
    return _html.escape("" if s is None else str(s))


def _num(v: Any) -> float:
    """A sort key for a count that might be missing or non-numeric."""
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


def _n(v: Any) -> str:
    """A count with thousands separators, tolerant of None/str -- `f"{v:,}"` on a missing field
    raised and took the whole report down with it."""
    if isinstance(v, bool) or v is None:
        return "?" if v is None else str(v)
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, float):
        return f"{v:,.0f}" if v.is_integer() else f"{v:,.1f}"
    return str(v)


def _g(v: Any) -> str:
    """A float in `:g` form, tolerant of None/str."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return f"{v:g}"
    return "0" if v is None else str(v)


def _badge(text: str, color: str) -> str:
    return (f'<span class="badge" style="--bc:{color}">{esc(text)}</span>')


def _kv(rows: list[tuple[str, Any]]) -> str:
    cells = "".join(
        f'<div class="k">{esc(k)}</div><div class="v mono">{esc(v)}</div>'
        for k, v in rows if v not in (None, "", {}))
    return f'<div class="kv">{cells}</div>' if cells else ""


def to_html(report: dict[str, Any]) -> str:
    case = report.get("case", {})
    summ = report.get("summary", {})
    parts: list[str] = []
    parts.append(_HEAD.replace("__TITLE__", esc(case.get("name") or "Case report")))
    parts.append('<div class="wrap">')

    # ---- header ----
    parts.append('<header class="rpt-head">')
    parts.append('<div class="eyebrow">Vulnerability analysis report</div>')
    parts.append(f'<h1>{esc(case.get("name") or "Untitled case")}</h1>')
    meta = [
        ("Generated", report.get("generated_at")),
        ("Tool", f'{report.get("tool", {}).get("name")} {report.get("tool", {}).get("version")}'),
        ("Engagement", case.get("engagement_ref")),
        ("Case created", case.get("created_at")),
    ]
    parts.append(_kv(meta))
    if case.get("notes"):
        parts.append(f'<p class="notes">{esc(case["notes"])}</p>')
    parts.append('</header>')

    # ---- executive summary ----
    targets = report.get("targets", [])
    verdicts = [(t, _target_verdict(t)) for t in targets]
    # Impact FIRST: the strongest outcome across the whole case, in one sentence, before any count.
    levels_seen = [v["level"] for _t, v in verdicts if v["level"]]
    top_level = max(levels_seen) if levels_seen else ""
    n_exploited = sum(1 for _t, v in verdicts if v["level"] == "L3")
    n_prim = sum(1 for _t, v in verdicts if v["level"] == "L2")
    n_repro = sum(1 for _t, v in verdicts if v["level"] == "L1")
    if top_level:
        headline = {"L3": f"Working exploit demonstrated (L3) on {n_exploited} of {len(targets)} "
                          "target(s).",
                    "L2": f"Exploitation primitive established (L2) on {n_prim} of {len(targets)} "
                          "target(s); no full exploit demonstrated.",
                    "L1": f"Crash reproduced (L1) on {n_repro} of {len(targets)} target(s); no "
                          "exploitation primitive demonstrated."}[top_level]
        htone = {"L3": "critical", "L2": "high", "L1": "high"}[top_level]
    elif any(t.get("findings") for t in targets):
        headline = "Static findings reported; none demonstrated dynamically in this run."
        htone = "medium"
    else:
        headline = "No defects were demonstrated on the targets in scope."
        htone = "info"
    # Qualify a level-less headline with WHY nothing escalated. "No defects demonstrated" and
    # "static findings only" both read as a property of the binary; when no dynamic engine could
    # execute the target they are a property of the run, and the reader must be told first.
    n_dark = sum(1 for _t, v in verdicts if v.get("nothing_executed"))
    if not top_level and targets and n_dark:
        headline += (f" No dynamic engine executed {n_dark} of {len(targets)} target(s), so "
                     "nothing there could escalate past L0 — a tooling/setup outcome, not a clean "
                     "result. See each target's engine health.")
        if htone == "info":
            htone = "medium"
    elif not top_level and any(v.get("engine_health") == "degraded" for _t, v in verdicts):
        headline += " Dynamic analysis was degraded on at least one target (an engine failed)."
    parts.append('<section class="card"><h2>Executive summary</h2>')
    parts.append(f'<p class="headline tone-{htone}">{esc(headline)}</p>')
    parts.append('<div class="stats">')
    parts.append(_stat(summ.get("targets", 0), "targets"))
    parts.append(_stat(summ.get("findings", 0), "findings"))
    parts.append(_stat(top_level or "—", "highest impact"))
    parts.append(_stat(summ.get("poc_backed", 0), "PoC-backed"))
    parts.append('</div>')
    bysev = summ.get("by_severity", {})
    if bysev:
        parts.append('<div class="chips">' + "".join(
            _badge(f"{k} · {v}", _SEV_COLOR.get(k, "#8b8d98")) for k, v in bysev.items())
            + '</div>')
    cur = summ.get("curation") or {}
    if cur:
        # The operator's triage, stated beside the tool's counts (which it never changes).
        parts.append('<div class="chips">' + "".join(
            _badge(f'{_model.CURATION_LABEL.get(k, k)} · {v}', _CURATION_COLOR.get(k, "#8b8d98"))
            for k, v in cur.items()) + '</div>')
    # Per-target verdict at a glance -- the reader sees which binary is the problem before scrolling.
    if len(targets) >= 1:
        parts.append('<table class="verdicts"><tbody>')
        for t, v in verdicts:
            lvlb = _badge(v["level"], _LEVEL_COLOR.get(v["level"], "#8b8d98")) if v["level"] else ""
            parts.append(
                f'<tr><td class="mono vt-name">{esc(t.get("filename"))}</td>'
                f'<td class="vt-verdict"><span class="vdot tone-{esc(v["tone"])}"></span>'
                f'{esc(v["label"])} {lvlb}</td></tr>')
        parts.append('</tbody></table>')
    parts.append('</section>')

    # ---- reproducibility ----
    eng = report.get("engines", [])
    parts.append('<section class="card"><h2>Reproducibility</h2>')
    if eng:
        # An engine that ABORTED is not an engine that ran: afl-fuzz failing its dry run
        # executed nothing, and a bare `tool version` badge said the same thing as a clean
        # campaign that found no crash.
        parts.append('<div class="chips">' + "".join(
            _badge(f'{e["tool"]} {e.get("version") or ""}'.strip()
                   + ("" if e.get("ran", True) else " — did not complete"),
                   "#5b9dd9" if e.get("ran", True) else "#b06a4a") for e in eng)
            + '</div>')
    else:
        parts.append('<p class="muted">No external analysis engines recorded for this case.</p>')
    parts.append('<p class="muted">Every finding below is anchored to the input hashes '
                 'in each target header; re-running the same tool versions on the same '
                 'inputs reproduces these results.</p>')
    parts.append('</section>')

    # ---- case-level coverage figure (doc 49 Theme 4) ----
    cov_fig = (report.get("figures") or {}).get("coverage")
    if cov_fig:
        parts.append('<section class="card"><h2>Fuzzing coverage</h2>'
                     '<p class="muted">How much of each binary\'s recovered code the search '
                     'actually exercised.</p>' + cov_fig + '</section>')

    # ---- targets + findings ----
    for t in report.get("targets", []):
        parts.append(_target_html(t))

    if not any(t.get("findings") for t in report.get("targets", [])):
        parts.append('<section class="card"><p class="muted">No findings matched the '
                     'report filters.</p></section>')

    ver = esc(report.get("tool", {}).get("version"))
    parts.append(f'<footer class="rpt-foot muted">lykos {ver}'
                 f' · {esc(report.get("generated_at"))} · authorized use only</footer>')
    parts.append('</div></body></html>')
    return "".join(parts)


def _stat(n: Any, label: str) -> str:
    return (f'<div class="stat"><div class="num">{esc(n)}</div>'
            f'<div class="lbl">{esc(label)}</div></div>')


def _target_html(t: dict) -> str:
    p = ['<section class="card target">']
    p.append(f'<h2 class="tname mono">{esc(t.get("filename"))}</h2>')
    # Verdict banner: the one line a reader needs before the detail -- what was proven, how far.
    v = _target_verdict(t)
    lvlb = (_badge(f'{v["level"]} · {_LEVEL_GLOSS.get(v["level"], "")}',
                   _LEVEL_COLOR.get(v["level"], "#8b8d98")) if v["level"] else "")
    p.append(f'<div class="verdict tone-{esc(v["tone"])}"><span class="vdot tone-{esc(v["tone"])}">'
             f'</span><span class="vlabel">{esc(v["label"])}</span>{lvlb}</div>')
    mits = t.get("mitigations") or {}
    mit_txt = " ".join(f"{k}={v}" for k, v in mits.items()) if mits else "—"
    rt = t.get("runtime") or {}
    rows = [("SHA-256", t.get("sha256")), ("MD5", t.get("md5")), ("Size", t.get("size")),
            ("Type", t.get("file_type"))]
    if rt.get("describes_cpu", True):
        rows += [("Arch", f'{t.get("arch") or "?"}/{t.get("bits") or "?"} '
                          f'{t.get("endianness") or ""}'.strip()),
                 ("Linking", ("stripped " if t.get("stripped") else "")
                             + (t.get("linking") or "")),
                 ("Mitigations", mit_txt)]
    else:
        # arch/bits/endianness are placeholders triage fills for a substrate that has no
        # processor; printing "jvm/64 big" describes nothing and reads like a CPU.
        rows.append(("Runtime", rt.get("label")))
    # Immediately after the hashes, because it is what qualifies them: this row says the
    # offsets below belong to a DIFFERENT image from the SHA-256 above. See
    # `model._exploited_build`.
    xb = t.get("exploited_build") or {}
    if xb.get("build") and xb["build"] != "ingested":
        rows.append(("Exploited build",
                     f'{xb["build"]} build of the same source'
                     + (f' ({xb["bytes"]} bytes)' if xb.get("bytes") else "")
                     + " — the offsets in the findings below are against THIS image, not the "
                       "SHA-256 above"))
    cov = t.get("fuzz_coverage")
    if cov:
        cov_txt = (f'{cov.get("pct")}% of blocks ({cov.get("blocks_hit")}/{cov.get("blocks_known")})'
                   if cov.get("kind") == "block" and cov.get("pct") is not None
                   else f'{cov.get("edges")} edges' if cov.get("kind") == "edge"
                   else "—")
        rows.append(("Fuzz coverage", cov_txt))
    ex = t.get("execution") or {}
    # THE SCORECARD. A null result is only worth what the work behind it was worth, so the work
    # is stated next to it: whether the program ever started, how many times it was executed and
    # how fast, and which stages ran out of time. Measured before this existed: one stock binary
    # finished the pipeline with 2,756 executions and no crash while another was executed ZERO
    # times, and the two reports read identically.
    base = ex.get("baseline")
    if base is not None:
        # NOT pre-escaped: `_kv` escapes every value, and escaping here too rendered a reason
        # like "needs <config>" as the literal text "needs &lt;config&gt;".
        why = str(base.get("note") or base.get("isolation") or "no reason given")
        rows.append(("Baseline execution",
                     "ran, exited normally" if base.get("ran") and not base.get("crashed")
                     else "ran, FAULTED" if base.get("ran")
                     else "DID NOT RUN — " + why))
    if ex.get("executions_attempted") is not None:
        rate = ex.get("executions_per_second")
        rows.append(("Executions", _n(ex["executions_attempted"])
                     + (f' ({_g(rate)}/s)' if rate else "")))
        by = ex.get("executions_by_engine") or {}
        if by:
            rows.append(("By engine", ", ".join(
                f"{k} {_n(v)}" for k, v in sorted(by.items(), key=lambda kv: -_num(kv[1])))))
    ip = ex.get("in_process") or {}
    if ip.get("doors"):
        # WHICH DOORS. In-process fuzzing goes through one harness at a time, so naming the entry
        # points is the difference between "2,501 executions" meaning the parser and meaning one
        # string helper.
        rows.append(("Entry points", "; ".join(
            f"{d.get('entry')} ({_n(d.get('execs'))} execs"
            + (f", {d['findings']} finding(s)" if d.get("findings") else "") + ")"
            if d.get("built") else f"{d.get('entry')} (not built)"
            for d in ip["doors"][:8] if isinstance(d, dict))))
    bg = ex.get("budget") or {}
    if bg.get("total"):
        rows.append(("Time budget", f'{_g(bg.get("elapsed"))}s of {_g(bg["total"])}s used'))
    _adv = bg.get("advice") or {}
    if _adv.get("note"):
        rows.append(("Execution rate", _adv["note"]))
    # Errors the run absorbed on purpose. The card already separates "ran and found nothing" from
    # "never ran"; this is the third reading it could not express -- "ran, and steps inside it
    # failed quietly" -- and a reader weighing a null result needs it. Nothing absorbed is the
    # claim worth printing: it says the thin result is the target's doing, not ours.
    if ex.get("settled") is False:
        rows.append(("Incomplete", "a stage was still finishing when this card was built — the "
                                   "counts above are a floor, not a total"))
    ab = ex.get("absorbed") or {}
    if ab:
        n, sites = ab.get("total") or 0, ab.get("sites") or 0
        if n:
            top = "; ".join(f'{r.get("count")}x {r.get("site")}' for r in (ab.get("top") or [])[:3])
            rows.append(("Absorbed errors",
                         f"{n} best-effort step(s) failed quietly at {sites} site(s)"
                         + (f" — {top}" if top else "")))
        else:
            rows.append(("Absorbed errors", "none — no step failed quietly in this run"))
    p.append(_kv(rows))
    skipped = ex.get("stages_skipped_for_budget") or []
    never_ran = (base is not None and not base.get("ran"))
    if ex.get("did_not_run_count") or ex.get("failed_stages") or skipped or never_ran:
        # The distinction this whole platform is built on, in the artefact a human opens: an
        # empty crash list because nothing FOUND a defect, versus an empty crash list because
        # nothing RAN. Without this they render identically.
        p.append('<p class="ceiling"><b>Execution gaps.</b> ')
        if never_ran:
            p.append('The baseline execution never started this target, so every dynamic '
                     'result below is absent for that reason and not for want of a defect. ')
        if skipped:
            p.append('Ran out of time before: ' + esc(", ".join(skipped[:8]))
                     + ('' if len(skipped) <= 8 else f' (+{len(skipped) - 8} more)')
                     + '. Give the run a larger budget to reach them. ')
        if ex.get("did_not_run_count"):
            reasons = "; ".join(
                esc((d.get("reason") or d.get("isolation") or "").strip())
                for d in ex.get("did_not_run", [])[:3] if d)
            p.append(f'{ex["did_not_run_count"]} execution(s) never ran: {reasons}. ')
        if ex.get("failed_stages"):
            p.append('Stages that failed: ' + esc(", ".join(ex["failed_stages"])) + '. ')
        p.append('An absent result from these is not evidence of absence.</p>')
    # The actionable WHY: a missing shared library, a target that needs a config/args, a campaign
    # that never reached the parser. This is what turns "fix it" from guesswork into a to-do list.
    diags = ex.get("diagnostics") or []
    if diags:
        p.append('<div class="diags"><b>Why a dynamic stage did little or nothing</b><ul>')
        for d in diags[:8]:
            p.append(f'<li><span class="diag-stage">{esc(d.get("stage"))}</span> '
                     f'{esc(d.get("note"))}</li>')
        p.append('</ul></div>')
    renv = ex.get("runtime_env") or {}
    if renv.get("applied"):
        # The results above ran WITH this environment; a reader reproducing them needs it too.
        p.append('<p class="muted"><b>Runtime environment supplied to every run</b> (inside the '
                 'sandbox; recorded in each PoC bundle): '
                 + esc("; ".join(renv.get("supplied") or []) or renv.get("note") or "") + '.')
        if renv.get("degraded"):
            p.append(' Could not be supplied: ' + esc("; ".join(renv["degraded"])) + '.')
        p.append('</p>')
    p.append(_engine_health_html(t))
    # Call-graph figure (doc 49 Theme 4) -- the structure the GUI's Code tab shows, as a static
    # SVG. Trusted, internally-escaped markup from report.figures: inserted raw, never through esc.
    cg = (t.get("figures") or {}).get("call_graph")
    if cg:
        p.append('<div class="figure callgraph"><div class="fig-h">Call graph '
                 '<span class="muted">— the recovered call structure; the finding\'s function is '
                 'highlighted</span></div>' + cg + '</div>')
    if rt.get("ceiling_why"):
        p.append(f'<p class="ceiling"><b>Analysis ceiling — {esc(rt.get("ceiling"))}.</b> '
                 f'{esc(rt["ceiling_why"])}</p>')
    findings = t.get("findings") or []
    if not findings:
        # "No reportable findings" is the sentence a reader takes as CLEAN, so it must not stand
        # alone when part of the analysis never executed -- including when no dynamic ENGINE
        # executed it (engine health `none`), which the gap test above did not cover.
        gaps = ex.get("has_gaps")
        if gaps is None:
            gaps = _model.has_execution_gaps(t)
        if gaps or v.get("nothing_executed"):
            p.append('<p class="muted">No reportable findings for this target — but see the '
                     'execution gaps / engine health above: this is not a clean result.</p>'
                     '</section>')
        else:
            p.append('<p class="muted">No reportable findings for this target.</p></section>')
        return "".join(p)
    # Operator-dismissed false positives are DEMOTED, not dropped: listed after the rest under
    # their own heading, with the tool's evidence intact, so a reader can audit the dismissal.
    fp = [f for f in findings if (f.get("curation") or {}).get("status") == "false_positive"]
    fp_ids = {id(f) for f in fp}
    for f in findings:
        if id(f) not in fp_ids:
            p.append(_finding_html(f))
    if fp:
        p.append(f'<h3 class="fp-head">Dismissed by the operator as false positive ({len(fp)})'
                 '</h3><p class="muted fp-note">Shown for audit. The tool\'s state, severity and '
                 'level are unchanged; the dismissal is the operator\'s judgement, not the '
                 'tool\'s.</p>')
        for f in fp:
            p.append(_finding_html(f))
    p.append('</section>')
    return "".join(p)


def _engine_health_html(t: dict) -> str:
    """The run's per-engine dynamic verdict (`analyze.fuzz.health`): which engines executed the
    target, which failed / declined / gained nothing, and why. This is what makes a static-only
    result readable as "the fuzzers could not run here" rather than as a clean binary."""
    eh = t.get("engine_health") or _model.engine_health(t.get("execution") or {})
    hv = eh.get("verdict") or "unrecorded"
    p = [f'<div class="health"><b>Dynamic engine health — '
         f'{_badge(hv, _HEALTH_COLOR.get(hv, "#8b8d98"))}</b>']
    if eh.get("note"):
        p.append(f'<p class="hnote">{esc(eh["note"])}</p>')
    rows = []
    for e in eh.get("engines") or []:
        st = e.get("status") or "?"
        cov = e.get("coverage")
        rows.append(f'<tr><td class="mono">{esc(e.get("engine"))}</td>'
                    f'<td>{_badge(st, _HEALTH_COLOR.get(st, "#8b8d98"))}</td>'
                    f'<td class="num">{esc(_n(e.get("execs")) if e.get("execs") else "—")}</td>'
                    f'<td class="mono">{esc(cov or "—")}</td>'
                    f'<td>{esc(e.get("reason") or "")}</td></tr>')
    if rows:
        p.append('<table class="htab"><thead><tr><th>engine</th><th>status</th><th>execs</th>'
                 '<th>coverage</th><th>why</th></tr></thead><tbody>' + "".join(rows)
                 + '</tbody></table>')
    dec = [d for d in ((t.get("execution") or {}).get("declined") or []) if isinstance(d, dict)]
    if dec:
        mark = {"ours": " [our defect — this run's null results are unproven]",
                "unknown": " [unclassified]"}
        p.append('<div class="hdec"><b>Declined stages</b><ul>' + "".join(
            f'<li><span class="mono">{esc(d.get("stage"))}</span> {esc(d.get("reason"))}'
            f'{esc(mark.get(d.get("kind"), ""))}</li>' for d in dec[:12]) + '</ul></div>')
    p.append('</div>')
    return "".join(p)


def _finding_html(f: dict) -> str:
    sev = f.get("severity") or "info"
    state = f.get("state") or "candidate"
    # Severity rides on the article as a class so the stylesheet can colour a left border -- a
    # reader scans the report by severity at a glance instead of reading every badge.
    p = [f'<article class="finding sev-{esc(sev)}">']
    p.append('<div class="fhead">')
    p.append(f'<span class="ftitle">{esc(f.get("title") or f.get("cwe") or "finding")}</span>')
    p.append(_badge(sev, _SEV_COLOR.get(sev, "#8b8d98")))
    # The impact rung FIRST after severity: a reader triages by "was it exploited?" before "what
    # kind of bug is it?".
    lvl, lvl_ver = _finding_level(f)
    if lvl:
        p.append(_badge(f'{lvl}{"" if lvl_ver else " (unverified)"}',
                        _LEVEL_COLOR.get(lvl, "#8b8d98")))
    p.append(_badge(state, _STATE_COLOR.get(state, "#8b8d98")))
    cur = f.get("curation") or {}
    if cur.get("status"):
        p.append(_badge(cur.get("label") or _model.CURATION_LABEL.get(cur["status"], cur["status"]),
                        _CURATION_COLOR.get(cur["status"], "#8b8d98")))
    v = f.get("verification")
    if v and v.get("runs"):
        ok = v.get("crashed") == v.get("runs")
        p.append(_badge(f'{"verified" if ok else "flaky"} {v.get("crashed")}/{v.get("runs")}',
                        "#3fb950" if ok else "#d29922"))
    p.append('</div>')
    if lvl and lvl_ver:
        p.append(f'<div class="fimpact">Impact: {esc(_LEVEL_GLOSS.get(lvl, ""))}</div>')
    elif lvl:
        # An unverified PoC demonstrates nothing; printing the rung's gloss ("working exploit --
        # the attacker's end goal was realised") next to it overstated the result.
        p.append(f'<div class="fimpact">Impact: not demonstrated — a PoC was built at {esc(lvl)} '
                 'but its reproducer did not verify, so that level is not claimed.</div>')
    if cur.get("note") or cur.get("status"):
        p.append(f'<div class="fcur"><b>Operator triage'
                 f'{" — " + esc(cur.get("label") or cur.get("status")) if cur.get("status") else ""}'
                 f'</b>{" · " + esc(cur.get("updated_at")) if cur.get("updated_at") else ""}'
                 f'{"<br>" + esc(cur.get("note")) if cur.get("note") else ""}</div>')
    cwe = f.get("cwe")
    p.append(_kv([
        ("CWE", f'{cwe} — {f.get("cwe_name")}' if cwe else None),
        ("Detector", f.get("detector")),
        ("Confidence", f.get("confidence")),
        ("Function", f.get("function_addr")),
        ("Site", f.get("site_addr")),
    ]))
    ev = f.get("evidence", [])
    if ev:
        p.append('<div class="evlabel">Evidence trail</div><ul class="ev">')
        for e in ev:
            ch = e.get("channel", "")
            p.append(f'<li><span class="chan">{esc(ch)}</span> {esc(e.get("detail"))}</li>')
        p.append('</ul>')
    crashes = f.get("crashes", [])
    if crashes:
        p.append('<div class="evlabel">Reproduced crashes</div><ul class="ev">')
        for c in crashes:
            iso = f' · {esc(c.get("isolation"))}' if c.get("isolation") else ""
            p.append(f'<li class="mono">{esc(c.get("signal") or "signal?")} '
                     f'via {esc(c.get("input_mode"))} · '
                     f'input {esc((c.get("input_sha") or "")[:16])}…{iso}</li>')
        p.append('</ul>')
    pocs = f.get("pocs", [])
    if pocs:
        p.append('<div class="evlabel">Proof-of-Concept</div><div class="pocs">')
        for pc in pocs:
            lvl = pc.get("level") or "?"
            ok = "verified" if pc.get("verified") else "unverified"
            dl = ""
            if pc.get("bundle_b64"):
                fn = f'poc-{(pc.get("bundle_sha") or lvl)[:12]}.tar.gz'
                dl = (f' <a class="dl" download="{esc(fn)}" '
                      f'href="data:application/gzip;base64,{esc(pc["bundle_b64"])}">download bundle</a>')
            elif pc.get("bundle_same_as"):
                # the same PoC backs several findings; the bundle is embedded once above
                dl = (f' <span class="muted mono">same bundle as above '
                      f'({esc(pc["bundle_same_as"][:12])}…)</span>')
            elif pc.get("bundle_sha"):
                # Not embedded (too large, or the report's embed budget is spent). Say where
                # it is instead of showing a bare hash with nothing to do about it.
                where = pc.get("bundle_href")
                dl = f' <span class="muted mono">bundle {esc(pc["bundle_sha"][:16])}…</span>'
                if where:
                    dl += (f' <span class="muted">not embedded — fetch from '
                           f'<span class="mono">{esc(where)}</span> on the analysis server'
                           f'</span>')
            p.append(f'<div class="poc">{_badge(lvl, "#8e4ec6")} '
                     f'<span class="mono">{esc(pc.get("signal") or "")}</span> '
                     f'<span class="muted">{ok}</span>{dl}</div>')
        p.append('</div>')
    # How to reproduce: the concrete recipe a reader re-runs -- the channel, the crashing input
    # hash, and the PoC bundle. Anchored to hashes so it is deterministic.
    crashes = f.get("crashes", [])
    repro = crashes[0] if crashes else None
    if repro:
        chan = esc(repro.get("input_mode") or "stdin")
        ish = esc((repro.get("input_sha") or "")[:16])
        p.append('<div class="evlabel">Reproduction</div>'
                 f'<div class="repro mono">Feed input <b>{ish}…</b> via the <b>{chan}</b> channel; '
                 f'the target raises {esc(repro.get("signal") or "a fault")}. The PoC bundle above '
                 'carries the exact bytes and the invocation.</div>')
    # Remediation: every finding ends with what to DO about it -- the report is a fix list, not
    # just an inventory.
    p.append('<div class="evlabel">Remediation</div>'
             f'<div class="remed">{esc(_remediation(f.get("cwe")))}</div>')
    p.append('</article>')
    return "".join(p)


_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__ — lykos report</title>
<style>
:root{
  --bg:#f7f7f8; --surface:#fff; --surface-2:#f0f0f2; --border:#e4e4e7;
  --text:#1a1a1e; --muted:#6b6b74; --faint:#9a9aa2; --accent:#5b6cff;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0e0e11; --surface:#17171b; --surface-2:#1e1e24; --border:#2a2a31;
  --text:#e8e8ea; --muted:#9a9aa2; --faint:#6b6b74; --accent:#7c8bff;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:14px;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:900px;margin:0 auto;padding:32px 24px 64px}
.mono{font-family:var(--mono);font-size:.85em}
.muted{color:var(--muted)}
.ceiling{margin:8px 0 0;padding:8px 10px;border-left:3px solid #7aa2c8;
  background:rgba(122,162,200,.08);font-size:12.5px;line-height:1.5}
.diags{margin:8px 0 0;padding:8px 10px;border-left:3px solid var(--accent);
  background:color-mix(in srgb,var(--accent) 7%,transparent);font-size:12.5px}
.diags b{display:block;margin-bottom:4px}
.diags ul{margin:0;padding-left:16px}
.diags li{margin:3px 0;line-height:1.45}
.diag-stage{font-family:var(--mono);font-size:.82em;color:var(--accent);margin-right:4px}
/* tone tokens shared by the headline, verdict banner and verdict dots */
.tone-critical{--tone:#e5484d} .tone-high{--tone:#f76808} .tone-medium{--tone:#ffb224}
.tone-low{--tone:#46a758} .tone-info{--tone:#8b8d98}
.headline{font-size:16px;font-weight:650;line-height:1.45;margin:0 0 14px;padding-left:12px;
  border-left:4px solid var(--tone,#8b8d98)}
.verdicts{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
.verdicts td{padding:7px 10px;border-top:1px solid var(--border);vertical-align:top}
.vt-name{white-space:nowrap;color:var(--muted);width:1%}
.vt-verdict{line-height:1.6}
.vdot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--tone,#8b8d98);
  margin-right:7px;vertical-align:middle}
.verdict{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin:2px 0 14px;padding:10px 12px;
  border-radius:9px;background:color-mix(in srgb,var(--tone,#8b8d98) 10%,transparent);
  border:1px solid color-mix(in srgb,var(--tone,#8b8d98) 35%,transparent);font-weight:600}
.vlabel{font-size:14px}
.fimpact{font-size:12.5px;color:var(--muted);margin:2px 0 6px}
.repro{margin:2px 0;padding:8px 10px;border-radius:7px;background:var(--surface-2);
  font-size:12px;line-height:1.5;word-break:break-word}
.remed{margin:2px 0;padding:8px 10px;border-left:3px solid #46a758;
  background:color-mix(in srgb,#46a758 8%,transparent);font-size:12.5px;line-height:1.5}
.eyebrow{text-transform:uppercase;letter-spacing:.08em;font-size:11px;color:var(--faint);
  font-weight:600}
h1{font-size:28px;margin:6px 0 14px;letter-spacing:-.022em;font-weight:700}
h2{font-size:16px;margin:0 0 12px;letter-spacing:-.01em}
/* A thin accent band across the top of the page -- a small masthead cue that this is a report. */
.wrap::before{content:"";display:block;height:3px;border-radius:999px;margin:0 0 26px;
  background:linear-gradient(90deg,var(--accent),color-mix(in srgb,var(--accent) 25%,transparent))}
.rpt-head{margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border)}
.notes{margin:12px 0 0;color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:22px;margin:16px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 16px;margin:4px 0}
.kv .k{color:var(--faint);font-size:12px;white-space:nowrap}
.kv .v{word-break:break-all}
/* Stat tiles as little surface cards, so the summary reads as a scorecard rather than loose text. */
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:var(--surface-2);border:1px solid var(--border);border-radius:10px;
  padding:12px 16px;min-width:88px}
.stat .num{font-size:30px;font-weight:700;letter-spacing:-.03em;line-height:1.05}
.stat .lbl{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.06em}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
.figure{margin:12px 0;overflow-x:auto}
.figure .fig-h{font-weight:600;font-size:13px;margin-bottom:6px}
.figure svg{max-width:100%;height:auto}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:999px;
  font-size:11px;font-weight:600;color:var(--bc);border:1px solid var(--bc);
  background:color-mix(in srgb,var(--bc) 12%,transparent);white-space:nowrap}
.target>.tname{font-size:15px;word-break:break-all}
/* Each finding carries a severity-coloured left border so the page is scannable by risk. */
.finding{border-top:1px solid var(--border);padding:16px 0 4px 14px;margin-top:12px;
  border-left:3px solid var(--sev,#8b8d98);border-top-left-radius:2px}
.finding.sev-critical{--sev:#e5484d} .finding.sev-high{--sev:#f76808}
.finding.sev-medium{--sev:#ffb224} .finding.sev-low{--sev:#46a758} .finding.sev-info{--sev:#8b8d98}
.fhead{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}
.ftitle{font-weight:600;font-size:14px}
.evlabel{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);
  margin:12px 0 4px;font-weight:600}
ul.ev{margin:0;padding-left:18px}
ul.ev li{margin:2px 0}
.chan{display:inline-block;font-family:var(--mono);font-size:11px;color:var(--accent);
  margin-right:6px}
.pocs .poc{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:4px 0}
a.dl{color:var(--accent);text-decoration:none;font-size:12px;border:1px solid var(--accent);
  padding:1px 8px;border-radius:6px}
a.dl:hover{background:color-mix(in srgb,var(--accent) 14%,transparent)}
.health{margin:10px 0 0;padding:8px 10px;border-left:3px solid var(--accent);
  background:var(--surface-2);font-size:12.5px}
.health .hnote{margin:4px 0 6px;line-height:1.45}
.htab{width:100%;border-collapse:collapse;font-size:12px;margin-top:4px}
.htab th{text-align:left;color:var(--faint);font-weight:600;font-size:11px;padding:3px 6px}
.htab td{padding:4px 6px;border-top:1px solid var(--border);vertical-align:top;word-break:break-word}
.htab td.num{text-align:right;white-space:nowrap}
.hdec ul{margin:2px 0 0;padding-left:16px}
.fcur{margin:6px 0 2px;padding:6px 10px;border-left:3px solid #d29922;font-size:12.5px;
  background:color-mix(in srgb,#d29922 7%,transparent);word-break:break-word}
.fp-head{font-size:13px;margin:22px 0 2px;color:var(--muted)}
.fp-note{font-size:12px;margin:0 0 4px}
.rpt-foot{margin-top:28px;padding-top:16px;border-top:1px solid var(--border);
  text-align:center;font-size:11px}
@media print{
  body{background:#fff;color:#000;font-size:11px}
  .wrap{max-width:none;padding:0}
  .card{border:1px solid #ccc;box-shadow:none;break-inside:avoid;page-break-inside:avoid}
  .finding{break-inside:avoid;page-break-inside:avoid}
  a.dl{display:none}
}
</style></head><body>"""
