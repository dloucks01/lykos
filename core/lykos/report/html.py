"""Self-contained, print-optimized HTML report (doc 08 §8.5, doc 09 §7).

Single file, inlined CSS, no external assets (air-gap clean). Severity/state colors
come from the same design tokens the app UI uses (doc 09 §design-system) so the report
reads as one system. PoC bundles, when embedded, are offered as `data:` download links
so the report is a portable, reproducible deliverable. `@media print` yields a clean
PDF via the browser's print-to-PDF in addition to the native PDF exporter.
"""
from __future__ import annotations

import html as _html
from typing import Any

_SEV_COLOR = {
    "critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
    "low": "#46a758", "info": "#8b8d98",
}
_STATE_COLOR = {
    "candidate": "#8b8d98", "corroborated": "#5b9dd9",
    "confirmed": "#46a758", "poc-backed": "#8e4ec6",
}


def esc(s: Any) -> str:
    return _html.escape("" if s is None else str(s))


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

    # ---- summary ----
    parts.append('<section class="card"><h2>Summary</h2>')
    parts.append('<div class="stats">')
    parts.append(_stat(summ.get("findings", 0), "findings"))
    parts.append(_stat(summ.get("targets", 0), "targets"))
    parts.append(_stat(summ.get("confirmed", 0), "confirmed"))
    parts.append(_stat(summ.get("poc_backed", 0), "PoC-backed"))
    parts.append('</div>')
    bysev = summ.get("by_severity", {})
    bystate = summ.get("by_state", {})
    if bysev:
        parts.append('<div class="chips">' + "".join(
            _badge(f"{k} · {v}", _SEV_COLOR.get(k, "#8b8d98")) for k, v in bysev.items())
            + '</div>')
    if bystate:
        parts.append('<div class="chips">' + "".join(
            _badge(f"{k} · {v}", _STATE_COLOR.get(k, "#8b8d98")) for k, v in bystate.items())
            + '</div>')
    parts.append('</section>')

    # ---- reproducibility ----
    eng = report.get("engines", [])
    parts.append('<section class="card"><h2>Reproducibility</h2>')
    if eng:
        parts.append('<div class="chips">' + "".join(
            _badge(f'{e["tool"]} {e.get("version") or ""}'.strip(), "#5b9dd9") for e in eng)
            + '</div>')
    else:
        parts.append('<p class="muted">No external analysis engines recorded for this case.</p>')
    parts.append('<p class="muted">Every finding below is anchored to the input hashes '
                 'in each target header; re-running the same tool versions on the same '
                 'inputs reproduces these results.</p>')
    parts.append('</section>')

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
    cov = t.get("fuzz_coverage")
    if cov:
        cov_txt = (f'{cov.get("pct")}% of blocks ({cov.get("blocks_hit")}/{cov.get("blocks_known")})'
                   if cov.get("kind") == "block" and cov.get("pct") is not None
                   else f'{cov.get("edges")} edges' if cov.get("kind") == "edge"
                   else "—")
        rows.append(("Fuzz coverage", cov_txt))
    p.append(_kv(rows))
    if rt.get("ceiling_why"):
        p.append(f'<p class="ceiling"><b>Analysis ceiling — {esc(rt.get("ceiling"))}.</b> '
                 f'{esc(rt["ceiling_why"])}</p>')
    findings = t.get("findings", [])
    if not findings:
        p.append('<p class="muted">No reportable findings for this target.</p></section>')
        return "".join(p)
    for f in findings:
        p.append(_finding_html(f))
    p.append('</section>')
    return "".join(p)


def _finding_html(f: dict) -> str:
    sev = f.get("severity", "info")
    state = f.get("state", "candidate")
    p = ['<article class="finding">']
    p.append('<div class="fhead">')
    p.append(f'<span class="ftitle">{esc(f.get("title") or f.get("cwe") or "finding")}</span>')
    p.append(_badge(sev, _SEV_COLOR.get(sev, "#8b8d98")))
    p.append(_badge(state, _STATE_COLOR.get(state, "#8b8d98")))
    v = f.get("verification")
    if v and v.get("runs"):
        ok = v.get("crashed") == v.get("runs")
        p.append(_badge(f'{"verified" if ok else "flaky"} {v.get("crashed")}/{v.get("runs")}',
                        "#3fb950" if ok else "#d29922"))
    p.append('</div>')
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
                      f'href="data:application/gzip;base64,{pc["bundle_b64"]}">download bundle</a>')
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
.eyebrow{text-transform:uppercase;letter-spacing:.08em;font-size:11px;color:var(--faint);
  font-weight:600}
h1{font-size:26px;margin:6px 0 14px;letter-spacing:-.02em}
h2{font-size:16px;margin:0 0 12px;letter-spacing:-.01em}
.rpt-head{margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border)}
.notes{margin:12px 0 0;color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:20px;margin:16px 0}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 16px;margin:4px 0}
.kv .k{color:var(--faint);font-size:12px;white-space:nowrap}
.kv .v{word-break:break-all}
.stats{display:flex;gap:28px;flex-wrap:wrap;margin-bottom:12px}
.stat .num{font-size:30px;font-weight:700;letter-spacing:-.03em}
.stat .lbl{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.06em}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
.badge{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:999px;
  font-size:11px;font-weight:600;color:var(--bc);border:1px solid var(--bc);
  background:color-mix(in srgb,var(--bc) 12%,transparent);white-space:nowrap}
.target>.tname{font-size:15px;word-break:break-all}
.finding{border-top:1px solid var(--border);padding:16px 0 4px;margin-top:12px}
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
