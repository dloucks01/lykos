"""Render the benchmark history as a regression dashboard (text + offline HTML).

Groups runs into series (stage / min_state), shows the metric trend per series with the
delta versus the previous run, and highlights regressions. The HTML is fully self-contained
(inline CSS + inline SVG sparklines) so it works air-gapped.
"""
from __future__ import annotations

import datetime as _dt
import html as _html

from .history import regressions, series


def _pct(x):
    return "  -  " if not isinstance(x, (int, float)) else f"{x:5.2f}"


def _short_ts(ts):
    try:
        return _dt.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)


def _delta(cur, prev, key, *, good_up=True):
    a, b = cur.get(key), prev.get(key)
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return ""
    d = a - b
    if abs(d) < 1e-9:
        return "="
    arrow = "▲" if d > 0 else "▼"
    worse = (d < 0) if good_up else (d > 0)
    return f"{arrow}{abs(d):.2f}{'!' if worse else ''}"


def render_text(history) -> str:
    if not history:
        return "no benchmark history yet (run `lykos eval --record`)."
    lines = []
    regs = regressions(history)
    lines.append("REGRESSIONS: " + (", ".join(r["series"] + " (" + "; ".join(r["reasons"]) + ")"
                                              for r in regs) if regs else "none"))
    for key, runs in series(history).items():
        lines.append("")
        lines.append(f"== {key} ==  ({len(runs)} run{'s' if len(runs) != 1 else ''})")
        lines.append("  when              git       recall  prec  fp_rate   Δrecall Δfp")
        for i, r in enumerate(runs[-8:]):
            o = r.get("overall", {})
            prev = runs[runs.index(r) - 1].get("overall", {}) if runs.index(r) > 0 else {}
            lines.append(
                f"  {_short_ts(r.get('ts')):<17} {(r.get('git') or '-'):<8} "
                f"{_pct(o.get('recall'))} {_pct(o.get('precision'))} {_pct(o.get('fp_rate'))}"
                f"   {_delta(o, prev, 'recall'):<7} {_delta(o, prev, 'fp_rate', good_up=False)}")
    return "\n".join(lines)


def _spark(values, *, w=120, h=24, invert=False):
    """A tiny inline SVG sparkline for a 0..1 metric series."""
    vals = [v if isinstance(v, (int, float)) else 0.0 for v in values]
    if not vals:
        return ""
    n = len(vals)
    step = w / max(n - 1, 1)
    def y(v):
        v = 1 - v if invert else v
        return round(h - 2 - v * (h - 4), 1)
    pts = " ".join(f"{round(i * step, 1)},{y(v)}" for i, v in enumerate(vals))
    last = vals[-1]
    color = "#e5484d" if (last < 1.0 and not invert) or (invert and last > 0.0) else "#30a46c"
    dot = f'<circle cx="{round((n-1)*step,1)}" cy="{y(last)}" r="2.5" fill="{color}"/>'
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'style="vertical-align:middle">'
            f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="1.5"/>'
            f'{dot}</svg>')


def render_html(history, *, title="Lykos detection-quality dashboard") -> str:
    regs = regressions(history)
    reg_keys = {r["series"] for r in regs}
    esc = _html.escape
    parts = [f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>
:root{{--bg:#f6f7f9;--fg:#1a1d21;--mut:#6b7280;--card:#fff;--line:#e5e7eb;--good:#30a46c;--bad:#e5484d}}
@media(prefers-color-scheme:dark){{:root{{--bg:#14171a;--fg:#e6e8eb;--mut:#9aa1a9;--card:#1c2024;--line:#2a2f36}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}}.sub{{color:var(--mut);margin:0 0 20px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:14px 16px;margin:0 0 16px}}
.banner{{border-left:4px solid var(--bad);background:color-mix(in srgb,var(--bad) 10%,transparent)}}
.ok{{border-left:4px solid var(--good)}}
table{{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}}
th,td{{text-align:right;padding:5px 8px;border-bottom:1px solid var(--line)}}
th:first-child,td:first-child{{text-align:left}}
.mut{{color:var(--mut)}}.bad{{color:var(--bad)}}.good{{color:var(--good)}}
code{{font-family:ui-monospace,monospace}}
</style></head><body><div class="wrap">
<h1>{esc(title)}</h1>
<p class="sub">Detection quality over time — recall, precision, false-positive rate
per benchmark series (doc 14).</p>"""]

    if regs:
        items = "".join(f"<li><b>{esc(r['series'])}</b>: {esc('; '.join(r['reasons']))} "
                        f"(<code>{esc(r.get('git') or '-')}</code>)</li>" for r in regs)
        parts.append(f'<div class="card banner"><b class="bad">⚠ {len(regs)} regression(s)</b>'
                     f'<ul style="margin:6px 0 0">{items}</ul></div>')
    else:
        parts.append('<div class="card ok"><b class="good">✓ No regressions</b> — '
                     'every series held or improved versus its previous run.</div>')

    if not history:
        parts.append('<div class="card">No runs recorded yet. Run '
                     '<code>lykos eval --record</code>.</div>')

    for key, runs in series(history).items():
        recalls = [r.get("overall", {}).get("recall") for r in runs]
        fprs = [r.get("overall", {}).get("fp_rate") for r in runs]
        flag = ' <span class="bad">(regressed)</span>' if key in reg_keys else ""
        rows = []
        for i, r in enumerate(runs[-12:]):
            o = r.get("overall", {})
            def cell(v):
                return _pct(v).strip()
            rows.append(
                f"<tr><td>{esc(_short_ts(r.get('ts')))}</td>"
                f"<td><code>{esc(r.get('git') or '-')}</code></td>"
                f"<td>{cell(o.get('recall'))}</td><td>{cell(o.get('precision'))}</td>"
                f"<td>{cell(o.get('f1'))}</td><td>{cell(o.get('fp_rate'))}</td>"
                f"<td class='mut'>{o.get('tp',0)}/{o.get('fp',0)}/"
                f"{o.get('fn',0)}/{o.get('tn',0)}</td></tr>")
        parts.append(f"""<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center">
<b>{esc(key)}</b>{flag}<span class="mut">{len(runs)} runs</span></div>
<div style="margin:8px 0"><span class="mut">recall</span> {_spark(recalls)}
&nbsp;&nbsp;<span class="mut">fp-rate</span> {_spark(fprs, invert=True)}</div>
<table><thead><tr><th>when</th><th>git</th><th>recall</th><th>prec</th><th>F1</th>
<th>fp-rate</th><th class="mut">tp/fp/fn/tn</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>""")

    parts.append("</div></body></html>")
    return "".join(parts)
