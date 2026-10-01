"""Pure-stdlib PDF writer + report layout (no external deps -- offline clean).

PDF is a text container format; this emits a genuine multi-page US-Letter PDF using
the base-14 Helvetica fonts (no font embedding needed), with headings, wrapped body
text, colored severity/state labels, rules, and page numbers. It is intentionally
minimal -- a faithful text rendering of the same model the HTML report uses -- not a
full typesetter. For pixel-perfect styling, print the HTML report to PDF instead.
"""
from __future__ import annotations

from typing import Any, Optional

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
            L += _flow(f'- {e["tool"]} {e.get("version") or ""}'.strip(), "H", 9, 8, 1)
    else:
        L += _flow("No external analysis engines recorded for this case.", "HO", 9, 0, 2,
                   (0.4, 0.4, 0.45))
    L += _flow("Findings are anchored to the input hashes in each target header; "
               "re-running the same tool versions on the same inputs reproduces these "
               "results.", "HO", 8.5, 0, 4, (0.4, 0.4, 0.45))

    # targets + findings
    for t in report.get("targets", []):
        L.append(_Line("Target", "HB", 8, 0, 20, (0.6, 0.6, 0.65)))
        L += _flow(t.get("filename") or "(target)", "HB", 13, 0, 2)
        L.append(_Line("", "H", 1, 0, 3, rule=True))
        mits = t.get("mitigations") or {}
        mit_txt = " ".join(f"{k}={v}" for k, v in mits.items()) if mits else "-"
        for k, v in (("SHA-256", t.get("sha256")),
                     ("Type", t.get("file_type")),
                     ("Arch", f'{t.get("arch") or "?"}/{t.get("bits") or "?"} '
                              f'{t.get("endianness") or ""}'.strip()),
                     ("Linking", ("stripped " if t.get("stripped") else "")
                                 + (t.get("linking") or "")),
                     ("Mitigations", mit_txt)):
            if v not in (None, "", "-") or k == "Mitigations":
                L += _flow(f"{k}: {v}", "H", 8.5, 0, 1, (0.4, 0.4, 0.45))

        findings = t.get("findings", [])
        if not findings:
            L += _flow("No reportable findings for this target.", "HO", 9, 0, 6,
                       (0.4, 0.4, 0.45))
            continue
        for f in findings:
            L += _finding_lines(f)
    return L


def _finding_lines(f: dict) -> list[_Line]:
    L: list[_Line] = []
    sev = f.get("severity", "info")
    state = f.get("state", "candidate")
    L += _flow(f.get("title") or f.get("cwe") or "finding", "HB", 11, 0, 12)
    L.append(_Line(f"[{sev}]  [{state}]  confidence {f.get('confidence')}", "HB", 8.5, 0, 2,
                   _SEV_RGB.get(sev)))
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
        lh = ln.size * 1.32
        y -= ln.gap
        if y - lh < bottom:
            pages.append(cur)
            cur = []
            y = top
            y -= 0  # first line at top
        cur.append((ln, y))
        y -= lh
    pages.append(cur)
    return pages


def _content_stream(page: list[tuple], page_no: int, total: int, report: dict) -> bytes:
    ops: list[str] = []
    for ln, y in page:
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
