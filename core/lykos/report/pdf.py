"""Pure-stdlib PDF writer + report layout (no external deps -- offline clean).

PDF is a text container format; this emits a genuine multi-page US-Letter PDF using
the base-14 Helvetica fonts (no font embedding needed), with headings, wrapped body
text, colored severity/state labels, rules, and page numbers. It is intentionally
minimal -- a faithful text rendering of the same model the HTML report uses -- not a
full typesetter. For pixel-perfect styling, print the HTML report to PDF instead.
"""
from __future__ import annotations

from typing import Any, Optional

from . import model as _model

# US Letter, points
PAGE_W, PAGE_H = 612.0, 792.0
MARGIN = 54.0
CONTENT_W = PAGE_W - 2 * MARGIN

# base-14 fonts we reference
_FONTS = {"H": "Helvetica", "HB": "Helvetica-Bold", "HO": "Helvetica-Oblique"}
# average glyph width as a fraction of font size (rough, for wrapping)
_AVGW = {"H": 0.50, "HB": 0.53, "HO": 0.50}

_SEV_RGB = {
    "critical": (0.90, 0.28, 0.30), "high": (0.97, 0.41, 0.03),
    "medium": (0.85, 0.60, 0.00), "low": (0.27, 0.66, 0.35), "info": (0.55, 0.55, 0.60),
}
_STATE_RGB = {
    "candidate": (0.55, 0.55, 0.60), "corroborated": (0.36, 0.62, 0.85),
    "confirmed": (0.27, 0.66, 0.35), "poc-backed": (0.56, 0.31, 0.78),
}


def _esc(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if o > 255:
            ch = "?"
        if ch in "\\()":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _wrap(text: str, font: str, size: float, width: float, indent: float) -> list[str]:
    avail = width - indent
    max_chars = max(4, int(avail / (size * _AVGW.get(font, 0.5))))
    words = text.split()
    if not words:
        return [""]
    lines, cur = [], ""
    for w in words:
        cand = w if not cur else cur + " " + w
        if len(cand) <= max_chars:
            cur = cand
        else:
            if cur:
                lines.append(cur)
            # hard-break over-long tokens (hashes, addresses)
            while len(w) > max_chars:
                lines.append(w[:max_chars])
                w = w[max_chars:]
            cur = w
    if cur:
        lines.append(cur)
    return lines


class _Line:
    __slots__ = ("text", "font", "size", "indent", "gap", "color", "rule")

    def __init__(self, text, font="H", size=10.0, indent=0.0, gap=0.0,
                 color: Optional[tuple] = None, rule: bool = False):
        self.text = text
        self.font = font
        self.size = size
        self.indent = indent
        self.gap = gap
        self.color = color
        self.rule = rule   # a horizontal rule, not text -- see _content_stream


def _flow(text, font, size, indent, gap, color=None) -> list[_Line]:
    return [_Line(t, font, size, indent, gap if i == 0 else 0.0, color)
            for i, t in enumerate(_wrap(text, font, size, CONTENT_W, indent))]


# ---- figures (doc 49 Theme 4): embed a lykos SVG figure as PDF vector graphics --------------
# The report figures (report.figures) are a small, self-generated SVG subset -- rects, cubic/line
# paths, and text. PDF draws vector graphics natively, so rather than rasterize (which would need a
# non-stdlib engine and break the air-gap guarantee) we translate that SVG straight into PDF content
# operators. One geometry source (the SVG), no new dependency. The PDF is a single, light-themed
# document, so the figures' theme CSS variables resolve to this fixed light palette here.

def _hexrgb(h: str) -> tuple:
    h = h.lstrip("#")
    return (int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0)


# class token(s) -> (fill hex or None, stroke hex or None, line-width). Mirrors figures._STYLE's
# light defaults. A token set is matched most-specific first.
_FILL = {
    ("node", "focus"): ("#e3efff", "#1f6feb", 2.0),
    ("node",): ("#f4f7fb", "#c4d2e3", 1.2),
    ("pill", "source"): ("#e3efff", "#1f6feb", 1.2),
    ("pill", "sink"): ("#f4f7fb", "#c0392b", 1.6),
    ("pill",): ("#f4f7fb", "#c4d2e3", 1.2),
    ("bar-bg",): ("#f4f7fb", "#c4d2e3", 1.0),
    ("bar-fill", "good"): ("#1f8a4c", None, 0.0),
    ("bar-fill", "warn"): ("#b9770e", None, 0.0),
    ("bar-fill", "bad"): ("#c0392b", None, 0.0),
    ("edge",): (None, "#9fb0c3", 1.4),
    ("arrow",): (None, "#9fb0c3", 1.6),
}
# text class -> (hex, size)
_TEXT = {"nlabel": ("#1b2430", 12.0), "plabel": ("#1b2430", 12.0),
         "nsub": ("#5b6b7d", 10.0), "psub": ("#5b6b7d", 10.0), "cap": ("#5b6b7d", 11.0)}


def _shape_style(tokens: list[str]):
    ts = set(tokens)
    for key, val in _FILL.items():
        if set(key) <= ts:
            return val
    return (None, None, 1.0)


class _Figure:
    """A figure block in the flow: a lykos SVG scaled to fit the content width (and page height),
    drawn as PDF vector graphics. Treated by the paginator as one unit that never splits."""
    __slots__ = ("svg", "w", "h", "scale", "draw_w", "draw_h", "gap", "rule")

    def __init__(self, svg: str, gap: float = 10.0):
        import re as _re
        self.svg = svg
        self.rule = False
        self.gap = gap
        m = _re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)
        self.w, self.h = (float(m.group(1)), float(m.group(2))) if m else (CONTENT_W, 40.0)
        max_h = PAGE_H - 2 * MARGIN - 40        # never taller than a page's content area
        self.scale = min(CONTENT_W / self.w, max_h / self.h, 1.0)
        self.draw_w = self.w * self.scale
        self.draw_h = self.h * self.scale


def _fig_block(svg, gap: float = 10.0):
    return [_Figure(svg, gap)] if svg else []


def _pdf_str(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _nums(d: str) -> list:
    import re as _re
    return [float(x) for x in _re.findall(r"-?\d+\.?\d*", d)]


def _svg_to_pdf_ops(svg: str, x0: float, yt: float, scale: float) -> list:
    """Translate one lykos figure SVG into PDF content operators, top-left at (x0, yt), scaled by
    `scale`. Per-point transform (no CTM flip) so text stays upright. Only the self-generated subset
    (rect / cubic+line path / text) is handled; defs/markers/style are skipped."""
    import xml.dom.minidom as _md
    try:
        doc = _md.parseString(svg)
    except Exception:                               # noqa: BLE001 -- a malformed figure is skipped
        return []
    ops: list = []

    def px(v):
        return x0 + v * scale

    def py(v):
        return yt - v * scale

    def rgb(h):
        r, g, b = _hexrgb(h)
        return f"{r:.3f} {g:.3f} {b:.3f}"

    def emit(el):
        tag = el.tagName
        toks = (el.getAttribute("class") or "").split()
        if tag == "rect":
            sx, sy = float(el.getAttribute("x")), float(el.getAttribute("y"))
            sw, sh = float(el.getAttribute("width")), float(el.getAttribute("height"))
            fill, stroke, lw = _shape_style(toks)
            if fill:
                ops.append(f"{rgb(fill)} rg")
            if stroke:
                ops.append(f"{rgb(stroke)} RG {lw * scale:.2f} w")
            ops.append(f"{px(sx):.2f} {py(sy + sh):.2f} {sw * scale:.2f} {sh * scale:.2f} re")
            ops.append("B" if (fill and stroke) else ("f" if fill else "S"))
        elif tag == "path":
            _, stroke, lw = _shape_style(toks)
            n = _nums(el.getAttribute("d"))
            stroke = stroke or "#9fb0c3"
            ops.append(f"{rgb(stroke)} RG {lw * scale:.2f} w")
            if "C" in el.getAttribute("d") and len(n) >= 8:
                ops.append(f"{px(n[0]):.2f} {py(n[1]):.2f} m "
                           f"{px(n[2]):.2f} {py(n[3]):.2f} {px(n[4]):.2f} {py(n[5]):.2f} "
                           f"{px(n[6]):.2f} {py(n[7]):.2f} c S")
            elif len(n) >= 4:
                ops.append(f"{px(n[0]):.2f} {py(n[1]):.2f} m {px(n[2]):.2f} {py(n[3]):.2f} l S")
                if "arrow" in toks:
                    _arrowhead(ops, px(n[0]), py(n[1]), px(n[2]), py(n[3]), rgb(stroke))
        elif tag == "text":
            hexc, size = _TEXT.get(next((t for t in toks if t in _TEXT), ""), ("#1b2430", 11.0))
            content = el.firstChild.data if el.firstChild else ""
            sx, sy = float(el.getAttribute("x")), float(el.getAttribute("y"))
            ops.append(f"{rgb(hexc)} rg")
            ops.append(f"BT /H {size * scale:.1f} Tf {px(sx):.2f} {py(sy):.2f} Td "
                       f"({_pdf_str(content)}) Tj ET")

    def walk(node):
        for ch in node.childNodes:
            if ch.nodeType != ch.ELEMENT_NODE:
                continue
            if ch.tagName in ("defs", "style", "title", "desc", "marker"):
                continue
            if ch.tagName in ("rect", "path", "text"):
                emit(ch)
            walk(ch)

    walk(doc.documentElement)
    return ops


def _arrowhead(ops, x1, y1, x2, y2, rgbstr):
    """A small filled triangle at (x2,y2) pointing along (x1,y1)->(x2,y2) (PDF has no line marker)."""
    import math
    dx, dy = x2 - x1, y2 - y1
    d = math.hypot(dx, dy) or 1.0
    ux, uy = dx / d, dy / d
    size = 4.5
    bx, by = x2 - ux * size, y2 - uy * size           # base centre, back from the tip
    lx, ly = bx - uy * size * 0.6, by + ux * size * 0.6
    rx, ry = bx + uy * size * 0.6, by - ux * size * 0.6
    ops.append(f"{rgbstr} rg")
    ops.append(f"{x2:.2f} {y2:.2f} m {lx:.2f} {ly:.2f} l {rx:.2f} {ry:.2f} l f")


def _report_lines(report: dict[str, Any]) -> list[_Line]:
    L: list[_Line] = []
    case = report.get("case", {})
    summ = report.get("summary", {})

    L.append(_Line("VULNERABILITY ANALYSIS REPORT", "HB", 8, 0, 0, (0.6, 0.6, 0.65)))
    L += _flow(case.get("name") or "Untitled case", "HB", 20, 0, 13)
    for k, v in (("Generated", report.get("generated_at")),
                 ("Tool", f'{report.get("tool", {}).get("name")} '
                          f'{report.get("tool", {}).get("version")}'),
                 ("Engagement", case.get("engagement_ref")),
                 ("Case created", case.get("created_at"))):
        if v:
            L += _flow(f"{k}: {v}", "H", 9, 0, 1, (0.4, 0.4, 0.45))
    if case.get("notes"):
        L += _flow(case["notes"], "HO", 9, 0, 4, (0.35, 0.35, 0.4))

    # summary
    L.append(_Line("Summary", "HB", 13, 0, 16))
    L.append(_Line("", "H", 1, 0, 3, rule=True))
    L += _flow(
        f'{summ.get("findings", 0)} findings across {summ.get("targets", 0)} targets  ·  '
        f'{summ.get("confirmed", 0)} confirmed  ·  {summ.get("poc_backed", 0)} PoC-backed',
        "H", 10, 0, 4)
    # Impact first, and never a level-less result without WHY: the same verdicts the HTML leads
    # with (`model.target_verdict`), so the two deliverables cannot disagree about a level.
    targets = report.get("targets", [])
    verdicts = [(t, t.get("verdict") or _model.target_verdict(t)) for t in targets]
    top = max((v["level"] for _t, v in verdicts if v.get("level")), default="")
    L += _flow("Highest demonstrated impact: " + (top or "none (no verified PoC)"),
               "HB", 10, 0, 4)
    n_dark = sum(1 for _t, v in verdicts if v.get("nothing_executed"))
    if n_dark and not top:
        L += _flow(f"No dynamic engine executed {n_dark} of {len(targets)} target(s), so nothing "
                   "there could escalate past L0 -- a tooling/setup outcome, not a clean result.",
                   "HB", 9, 0, 2, (0.75, 0.3, 0.2))
    for t, v in verdicts:
        L += _flow(f'- {t.get("filename") or "(target)"}: {v.get("label")}', "H", 9, 8, 1)
    cur = summ.get("curation") or {}
    if cur:
        L += _flow("Operator triage: " + ", ".join(
            f"{_model.CURATION_LABEL.get(k, k)} {n}" for k, n in cur.items())
            + " (the tool's counts above are unchanged)", "HO", 9, 0, 4, (0.4, 0.4, 0.45))
    bysev = summ.get("by_severity", {})
    if bysev:
        L.append(_Line("By severity:", "HB", 9, 0, 6))
        for k, v in bysev.items():
            L.append(_Line(f"  {k}: {v}", "H", 9, 8, 1, _SEV_RGB.get(k)))
    bystate = summ.get("by_state", {})
    if bystate:
        L.append(_Line("By state:", "HB", 9, 0, 6))
        for k, v in bystate.items():
            L.append(_Line(f"  {k}: {v}", "H", 9, 8, 1, _STATE_RGB.get(k)))

    # reproducibility
    L.append(_Line("Reproducibility", "HB", 13, 0, 16))
    L.append(_Line("", "H", 1, 0, 3, rule=True))
    eng = report.get("engines", [])
    if eng:
        for e in eng:
            # An engine that aborted executed nothing; a bare tool/version line read the same
            # as a campaign that ran and found no crash.
            _note = "" if e.get("ran", True) else "  (did not complete)"
            L += _flow(f'- {e["tool"]} {e.get("version") or ""}'.strip() + _note, "H", 9, 8, 1)
    else:
        L += _flow("No external analysis engines recorded for this case.", "HO", 9, 0, 2,
                   (0.4, 0.4, 0.45))
    L += _flow("Findings are anchored to the input hashes in each target header; "
               "re-running the same tool versions on the same inputs reproduces these "
               "results.", "HO", 8.5, 0, 4, (0.4, 0.4, 0.45))

    # Case-level coverage figure (doc 49 Theme 4), as in the HTML report.
    _cov = (report.get("figures") or {}).get("coverage")
    if _cov:
        L.append(_Line("Fuzzing coverage", "HB", 10, 0, 16, (0.2, 0.2, 0.25)))
        L += _fig_block(_cov)

    # targets + findings
    for t in report.get("targets", []):
        L.append(_Line("Target", "HB", 8, 0, 20, (0.6, 0.6, 0.65)))
        L += _flow(t.get("filename") or "(target)", "HB", 13, 0, 2)
        L.append(_Line("", "H", 1, 0, 3, rule=True))
        mits = t.get("mitigations") or {}
        mit_txt = " ".join(f"{k}={v}" for k, v in mits.items()) if mits else "-"
        rt = t.get("runtime") or {}
        rows = [("SHA-256", t.get("sha256")), ("Type", t.get("file_type"))]
        # Only a machine-code image has an `arch` naming a PROCESSOR. For a managed target
        # triage puts the RUNTIME there, so this row printed `Arch: jvm/64 big` -- the exact
        # meaningless line the HTML renderer learned to drop and this one never did. Name the
        # runtime instead.
        if rt.get("describes_cpu", True):
            rows.append(("Arch", f'{t.get("arch") or "?"}/{t.get("bits") or "?"} '
                                 f'{t.get("endianness") or ""}'.strip()))
        elif rt.get("label"):
            rows.append(("Runs on", rt["label"]))
        rows += [("Linking", ("stripped " if t.get("stripped") else "")
                             + (t.get("linking") or "")),
                 ("Mitigations", mit_txt)]
        for k, v in rows:
            if v not in (None, "", "-") or k == "Mitigations":
                L += _flow(f"{k}: {v}", "H", 8.5, 0, 1, (0.4, 0.4, 0.45))
        if rt.get("ceiling_why"):
            L += _flow(f'Analysis ceiling - {rt.get("ceiling")}. {rt["ceiling_why"]}',
                       "HO", 8.5, 0, 2, (0.35, 0.35, 0.4))
        ex = t.get("execution") or {}
        v = t.get("verdict") or _model.target_verdict(t)
        L += _flow(f'Verdict: {v.get("label")}', "HB", 9, 0, 3,
                   _SEV_RGB.get(v.get("tone")) if v.get("tone") in _SEV_RGB else None)
        base = ex.get("baseline")
        never_ran = base is not None and not base.get("ran")
        skipped = ex.get("stages_skipped_for_budget") or []
        if ex.get("did_not_run_count") or ex.get("failed_stages") or never_ran or skipped:
            bits = []
            if never_ran:
                bits.append("the baseline execution never started this target ("
                            + str(base.get("note") or base.get("isolation") or "no reason given")
                            + ")")
            if skipped:
                bits.append("ran out of time before: " + ", ".join(map(str, skipped[:8])))
            if ex.get("did_not_run_count"):
                why = "; ".join((d.get("reason") or d.get("isolation") or "").strip()
                                for d in ex.get("did_not_run", [])[:2] if d)
                bits.append(f'{ex["did_not_run_count"]} execution(s) never ran: {why}')
            if ex.get("failed_stages"):
                bits.append("stages that failed: " + ", ".join(ex["failed_stages"]))
            L += _flow("Execution gaps - " + ". ".join(bits)
                       + ". An absent result from these is not evidence of absence.",
                       "HO", 8.5, 0, 3, (0.5, 0.35, 0.3))
        for d in (ex.get("diagnostics") or [])[:6]:
            L += _flow(f'Why {d.get("stage")} did little: {d.get("note")}', "HO", 8.5, 0, 1,
                       (0.5, 0.35, 0.3))
        renv = ex.get("runtime_env") or {}
        if renv.get("applied"):
            txt = ("Runtime environment supplied to every run (inside the sandbox; recorded in "
                   "each PoC bundle): " + ("; ".join(renv.get("supplied") or [])
                                          or renv.get("note") or ""))
            if renv.get("degraded"):
                txt += ". Could not be supplied: " + "; ".join(renv["degraded"])
            L += _flow(txt, "HO", 8.5, 0, 1, (0.4, 0.4, 0.45))
        L += _health_lines(t)
        # Figures (doc 49 Theme 4): the call graph and the patch-diff map, as in the HTML report.
        _tf = t.get("figures") or {}
        L += _fig_block(_tf.get("call_graph"))
        L += _fig_block(_tf.get("patch_diff"))

        findings = t.get("findings") or []
        if not findings:
            # "No reportable findings" is the sentence a reader takes as CLEAN, so it must not
            # be printed bare when part of the analysis never executed -- the same test the HTML
            # uses (`model.has_execution_gaps`), which this renderer used to apply only in part.
            gaps = ex.get("has_gaps")
            if gaps is None:
                gaps = _model.has_execution_gaps(t)
            _bare = not (gaps or v.get("nothing_executed"))
            L += _flow("No reportable findings for this target." if _bare else
                       "No reportable findings for this target -- but see the execution gaps / "
                       "engine health above: this is not a clean result.", "HO", 9, 0, 6,
                       (0.4, 0.4, 0.45))
            continue
        fp = [f for f in findings if (f.get("curation") or {}).get("status") == "false_positive"]
        fp_ids = {id(f) for f in fp}
        for f in findings:
            if id(f) not in fp_ids:
                L += _finding_lines(f)
        if fp:
            L.append(_Line(f"Dismissed by the operator as false positive ({len(fp)})", "HB", 10,
                           0, 14, (0.45, 0.45, 0.5)))
            L += _flow("Shown for audit; the tool's state, severity and level are unchanged.",
                       "HO", 8.5, 0, 1, (0.45, 0.45, 0.5))
            for f in fp:
                L += _finding_lines(f)
    return L


def _health_lines(t: dict) -> list[_Line]:
    """The per-engine dynamic verdict, as in the HTML's engine-health block."""
    eh = t.get("engine_health") or _model.engine_health(t.get("execution") or {})
    L: list[_Line] = []
    hv = eh.get("verdict") or "unrecorded"
    col = (0.75, 0.3, 0.2) if hv in ("none", "degraded") else (0.4, 0.4, 0.45)
    L += _flow(f"Dynamic engine health: {hv}. {eh.get('note') or ''}".strip(), "HB", 8.5, 0, 4,
               col)
    for e in (eh.get("engines") or [])[:12]:
        bits = [str(e.get("engine")), str(e.get("status"))]
        if e.get("execs"):
            bits.append(f"{e['execs']} execs")
        if e.get("coverage"):
            bits.append(str(e["coverage"]))
        line = "  ".join(bits) + (f" -- {e['reason']}" if e.get("reason") else "")
        L += _flow("- " + line, "H", 8, 8, 1, col if e.get("status") in ("failed", "error")
                   else None)
    for d in ((t.get("execution") or {}).get("declined") or [])[:8]:
        if isinstance(d, dict):
            tag = {"ours": " [our defect]", "unknown": " [unclassified]"}.get(d.get("kind"), "")
            L += _flow(f'- declined {d.get("stage")}: {d.get("reason")}{tag}', "H", 8, 8, 1)
    return L


def _finding_lines(f: dict) -> list[_Line]:
    L: list[_Line] = []
    sev = f.get("severity") or "info"
    state = f.get("state") or "candidate"
    L += _flow(f.get("title") or f.get("cwe") or "finding", "HB", 11, 0, 12)
    lvl = f.get("level") or _model.best_verified_level(f)
    built = _model.best_unverified_level(f)
    lvl_txt = (f"  [{lvl}]" if lvl else
               f"  [{built} built, NOT verified]" if built else "")
    L.append(_Line(f"[{sev}]  [{state}]{lvl_txt}  confidence {f.get('confidence')}", "HB", 8.5,
                   0, 2, _SEV_RGB.get(sev)))
    cur = f.get("curation") or {}
    if cur.get("status") or cur.get("note"):
        L += _flow("Operator triage: "
                   + (cur.get("label") or _model.CURATION_LABEL.get(cur.get("status"), "")
                      or str(cur.get("status") or "note"))
                   + (f" ({cur['updated_at']})" if cur.get("updated_at") else "")
                   + (f" -- {cur['note']}" if cur.get("note") else ""),
                   "HO", 8.5, 0, 2, (0.55, 0.42, 0.1))
    if f.get("cwe"):
        L += _flow(f'{f["cwe"]} - {f.get("cwe_name")}', "H", 9, 0, 2)
    loc = []
    if f.get("detector"):
        loc.append(f'detector={f["detector"]}')
    if f.get("function_addr"):
        loc.append(f'func={f["function_addr"]}')
    if f.get("site_addr"):
        loc.append(f'site={f["site_addr"]}')
    if loc:
        L += _flow("  ".join(loc), "H", 8.5, 0, 1, (0.4, 0.4, 0.45))
    # Per-finding figures (doc 49 Theme 4): provenance chain + source-reachability, as in the HTML.
    _ff = f.get("figures") or {}
    L += _fig_block(_ff.get("provenance"))
    L += _fig_block(_ff.get("reachability"))
    ev = f.get("evidence", [])
    if ev:
        L.append(_Line("Evidence trail", "HB", 8, 0, 6, (0.5, 0.5, 0.55)))
        for e in ev:
            L += _flow(f'- [{e.get("channel", "")}] {e.get("detail", "")}', "H", 8.5, 8, 1)
    crashes = f.get("crashes", [])
    if crashes:
        L.append(_Line("Reproduced crashes", "HB", 8, 0, 6, (0.5, 0.5, 0.55)))
        for c in crashes:
            L += _flow(f'- {c.get("signal") or "signal?"} via {c.get("input_mode")} '
                       f'(input {(c.get("input_sha") or "")[:16]})', "H", 8.5, 8, 1)
    pocs = f.get("pocs", [])
    if pocs:
        L.append(_Line("Proof-of-Concept", "HB", 8, 0, 6, (0.5, 0.5, 0.55)))
        for p in pocs:
            ok = "verified" if p.get("verified") else "unverified"
            L += _flow(f'- {p.get("level") or "?"} {p.get("signal") or ""} ({ok}, '
                       f'bundle {(p.get("bundle_sha") or "")[:16]})', "H", 8.5, 8, 1,
                       _STATE_RGB.get("poc-backed"))
    return L


def to_pdf(report: dict[str, Any]) -> bytes:
    lines = _report_lines(report)
    pages = _paginate(lines)
    return _emit(pages, report)


def _paginate(lines: list[_Line]) -> list[list[tuple]]:
    top = PAGE_H - MARGIN
    bottom = MARGIN + 24  # room for footer
    pages: list[list[tuple]] = []
    cur: list[tuple] = []
    y = top
    for ln in lines:
        lh = ln.draw_h if isinstance(ln, _Figure) else ln.size * 1.32
        y -= ln.gap
        if y - lh < bottom:
            pages.append(cur)
            cur = []
            y = top
        cur.append((ln, y))
        y -= lh
    pages.append(cur)
    return pages


def _content_stream(page: list[tuple], page_no: int, total: int, report: dict) -> bytes:
    ops: list[str] = []
    for ln, y in page:
        if isinstance(ln, _Figure):
            ops.append("q")
            ops += _svg_to_pdf_ops(ln.svg, MARGIN, y, ln.scale)
            ops.append("Q")
            continue
        x = MARGIN + ln.indent
        if ln.rule:
            ops.append("0.85 0.85 0.87 RG 0.7 w")
            ops.append(f"{MARGIN:.1f} {y + 4:.1f} m {PAGE_W - MARGIN:.1f} {y + 4:.1f} l S")
            continue
        r, g, b = ln.color if ln.color else (0.1, 0.1, 0.12)
        ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        ops.append(f"BT /{ln.font} {ln.size:.1f} Tf {x:.1f} {y:.1f} Td "
                   f"({_esc(ln.text)}) Tj ET")
    # footer
    foot = f'lykos {report.get("tool", {}).get("version")}  ·  page {page_no} of {total}'
    ops.append("0.6 0.6 0.65 rg")
    ops.append(f"BT /H 8 Tf {MARGIN:.1f} {MARGIN - 6:.1f} Td ({_esc(foot)}) Tj ET")
    return "\n".join(ops).encode("latin-1", "replace")


def _emit(pages: list[list[tuple]], report: dict) -> bytes:
    objs: list[bytes] = []

    def add(b: bytes) -> int:
        objs.append(b)
        return len(objs)  # 1-based object number

    total = len(pages)
    font_objs = {tag: add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} "
                          f"/Encoding /WinAnsiEncoding >>".encode())
                 for tag, name in _FONTS.items()}
    res = ("<< /Font << " + " ".join(f"/{t} {n} 0 R" for t, n in font_objs.items())
           + " >> >>")

    pages_obj_no = len(objs) + 1  # reserve next number for Pages
    objs.append(b"")  # placeholder for Pages (filled after we know kids)

    page_obj_nos: list[int] = []
    for i, page in enumerate(pages):
        stream = _content_stream(page, i + 1, total, report)
        content_no = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream
                         + b"\nendstream")
        page_no = add(
            (f"<< /Type /Page /Parent {pages_obj_no} 0 R "
             f"/MediaBox [0 0 {PAGE_W:.0f} {PAGE_H:.0f}] "
             f"/Resources {res} /Contents {content_no} 0 R >>").encode())
        page_obj_nos.append(page_no)

    kids = " ".join(f"{n} 0 R" for n in page_obj_nos)
    objs[pages_obj_no - 1] = (f"<< /Type /Pages /Kids [{kids}] "
                              f"/Count {total} >>").encode()

    catalog_no = add(f"<< /Type /Catalog /Pages {pages_obj_no} 0 R >>".encode())

    # serialize with xref
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (len(objs) + 1)
    for i, body in enumerate(objs, start=1):
        offsets[i] = len(out)
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    n = len(objs) + 1
    out += f"xref\n0 {n}\n".encode()
    out += b"0000000000 65535 f \n"
    for i in range(1, n):
        out += f"{offsets[i]:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {n} /Root {catalog_no} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n").encode()
    return bytes(out)
